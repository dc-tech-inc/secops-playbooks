#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'SecOpsToolkit/SecOpsToolkit.psd1') -Force
}

Describe 'Get-IocMatch' {
    BeforeAll {
        $root = Join-Path $TestDrive 'share'
        New-Item -ItemType Directory -Path (Join-Path $root 'sub') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'known-bad.txt') -Value 'synthetic indicator sample' -NoNewline
        Set-Content -LiteralPath (Join-Path $root 'sub/also-bad.bin') -Value 'second synthetic sample' -NoNewline
        Set-Content -LiteralPath (Join-Path $root 'clean.txt') -Value 'nothing to see' -NoNewline

        $bad1 = (Get-FileHash -LiteralPath (Join-Path $root 'known-bad.txt')).Hash
        $bad2 = (Get-FileHash -LiteralPath (Join-Path $root 'sub/also-bad.bin')).Hash
        $ioc = Join-Path $TestDrive 'iocs.csv'
        @(
            'sha256,indicator'
            "$($bad1.ToLowerInvariant()),drill-sample-1"
            "$bad2,drill-sample-2"
            'not-a-hash,broken-line'
        ) | Set-Content -LiteralPath $ioc
    }

    It 'finds matching files recursively, case-insensitive on the hash' {
        $hits = @(Get-IocMatch -Path $root -IocFile $ioc -WarningAction SilentlyContinue)
        $hits.Count | Should -Be 2
        ($hits.Indicator | Sort-Object) | Should -Be @('drill-sample-1', 'drill-sample-2')
    }

    It 'warns about malformed IOC lines' {
        Get-IocMatch -Path $root -IocFile $ioc -WarningVariable warn -WarningAction SilentlyContinue | Out-Null
        $warn.Count | Should -Be 1
        "$warn" | Should -Match 'not-a-hash'
    }

    It 'does not report clean files' {
        $hits = Get-IocMatch -Path $root -IocFile $ioc -WarningAction SilentlyContinue
        $hits.Path | Should -Not -Contain (Join-Path $root 'clean.txt')
    }

    It 'rejects a missing path' {
        { Get-IocMatch -Path (Join-Path $TestDrive 'nope') -IocFile $ioc } | Should -Throw
    }
}

Describe 'ConvertTo-IncidentTimeline' {
    BeforeAll {
        $edr = Join-Path $TestDrive 'edr.jsonl'
        $fw = Join-Path $TestDrive 'firewall.jsonl'
        @(
            '{"timestamp":"2026-10-01T10:05:00-04:00","host":"WS-07","message":"powershell -enc launched"}'
            '{"timestamp":"2026-10-01T13:59:00Z","host":"WS-07","message":"user signed in"}'
            'this is not json'
            ''
        ) | Set-Content -LiteralPath $edr
        @(
            '{"timestamp":"2026-10-01T14:06:30+00:00","source":"gw-hq","message":"outbound 443 to 203.0.113.50 blocked"}'
            '{"timestamp":"2026-09-30T23:00:00Z","source":"gw-hq","message":"earlier noise"}'
        ) | Set-Content -LiteralPath $fw
    }

    It 'merges files, normalizes to UTC and sorts' {
        $t = @(ConvertTo-IncidentTimeline -Path $edr, $fw -WarningAction SilentlyContinue)
        $t.Count | Should -Be 4
        $t[0].Message | Should -Be 'earlier noise'
        $t[1].TimeUtc | Should -Be '2026-10-01T13:59:00.000Z'
        $t[2].TimeUtc | Should -Be '2026-10-01T14:05:00.000Z'
        $t[2].Source | Should -Be 'edr'
        $t[3].Source | Should -Be 'gw-hq'
    }

    It 'filters by window' {
        $t = @(ConvertTo-IncidentTimeline -Path $edr, $fw -Since '2026-10-01T14:00:00Z' -Until '2026-10-01T14:06:00Z' -WarningAction SilentlyContinue)
        $t.Count | Should -Be 1
        $t[0].Message | Should -Be 'powershell -enc launched'
    }

    It 'warns about unreadable lines with file and line number' {
        ConvertTo-IncidentTimeline -Path $edr -WarningVariable warn -WarningAction SilentlyContinue | Out-Null
        "$warn" | Should -Match 'edr.jsonl:3'
    }
}

Describe 'Find-BruteForceCandidate' {
    BeforeAll {
        $csv = Join-Path $TestDrive 'signins.csv'
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add('timestamp,user,source_ip,result')
        $t0 = [datetimeoffset]'2026-10-01T02:00:00Z'
        # 12 failures in 2 minutes from one documentation-range IP against 3 users, then a success.
        for ($i = 0; $i -lt 12; $i++) {
            $lines.Add(('{0},user{1}@example.com,198.51.100.7,failure' -f $t0.AddSeconds($i * 10).ToString('o'), ($i % 3)))
        }
        $lines.Add(('{0},user1@example.com,198.51.100.7,success' -f $t0.AddMinutes(3).ToString('o')))
        # 12 failures spread over 2 hours: slow, under the per-window threshold.
        for ($i = 0; $i -lt 12; $i++) {
            $lines.Add(('{0},user9@example.com,192.0.2.44,failure' -f $t0.AddMinutes($i * 10).ToString('o')))
        }
        # Normal user who mistyped twice.
        $lines.Add(('{0},user5@example.com,10.10.20.31,failure' -f $t0.ToString('o')))
        $lines.Add(('{0},user5@example.com,10.10.20.31,success' -f $t0.AddSeconds(30).ToString('o')))
        $lines | Set-Content -LiteralPath $csv
    }

    It 'flags the burst source and the account that then signed in' {
        $hits = @(Find-BruteForceCandidate -Path $csv -Threshold 10 -WindowMinutes 5)
        $hits.Count | Should -Be 1
        $hits[0].SourceIp | Should -Be '198.51.100.7'
        $hits[0].PeakFailures | Should -Be 12
        $hits[0].UsersTargeted | Should -Be 3
        $hits[0].SuccessAfterBurst | Should -BeTrue
        $hits[0].CompromisedUsers | Should -Be @('user1@example.com')
    }

    It 'catches the slow source when the window is widened' {
        $hits = @(Find-BruteForceCandidate -Path $csv -Threshold 10 -WindowMinutes 120)
        $hits.SourceIp | Should -Contain '192.0.2.44'
        ($hits | Where-Object SourceIp -EQ '192.0.2.44').SuccessAfterBurst | Should -BeFalse
    }

    It 'validates the threshold' {
        { Find-BruteForceCandidate -Path $csv -Threshold 1 } | Should -Throw
    }
}

Describe 'Module quality' {
    It 'exports exactly the documented functions' {
        $exported = (Get-Module SecOpsToolkit).ExportedFunctions.Keys | Sort-Object
        $exported | Should -Be @('ConvertTo-IncidentTimeline', 'Find-BruteForceCandidate', 'Get-IocMatch')
    }

    It 'has comment-based help with an example for every function' {
        foreach ($name in (Get-Module SecOpsToolkit).ExportedFunctions.Keys) {
            $help = Get-Help $name -Full
            $help.Synopsis | Should -Not -BeNullOrEmpty
            @($help.Examples.Example).Count | Should -BeGreaterThan 0
        }
    }
}
