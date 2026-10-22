#Requires -Version 5.1
Set-StrictMode -Version Latest

<#
  SecOpsToolkit: small, read-only triage helpers for incident responders.
  Nothing here modifies the files or logs it reads, and nothing touches the network.
#>

function Get-IocMatch {
    <#
    .SYNOPSIS
    Hash files under a folder and report the ones whose SHA256 is on an indicator list.

    .PARAMETER Path
    Folder (searched recursively) or single file to hash.

    .PARAMETER IocFile
    CSV with columns sha256,indicator (for example from a threat-intel export).

    .EXAMPLE
    Get-IocMatch -Path C:\Users\Public\Downloads -IocFile .\iocs.csv
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ })][string]$Path,
        [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$IocFile
    )

    $iocs = @{}
    foreach ($row in Import-Csv -LiteralPath $IocFile) {
        $hash = "$($row.sha256)".Trim().ToUpperInvariant()
        if ($hash -notmatch '^[0-9A-F]{64}$') {
            Write-Warning "Skipping malformed IOC line: '$($row.sha256)'"
            continue
        }
        $iocs[$hash] = $row.indicator
    }

    Get-ChildItem -LiteralPath $Path -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        if ($iocs.ContainsKey($hash)) {
            [pscustomobject]@{
                Path      = $_.FullName
                Sha256    = $hash
                Indicator = $iocs[$hash]
                SizeBytes = $_.Length
            }
        }
    }
}

function ConvertTo-IncidentTimeline {
    <#
    .SYNOPSIS
    Merge JSON-lines events from several sources into one UTC timeline.

    .DESCRIPTION
    Each input line is a JSON object with at least "timestamp" (ISO 8601 with offset) and
    "message"; "source" and "host" are optional. Output is sorted by time and can be limited
    to a window with -Since / -Until. Malformed lines are reported as warnings, not dropped silently.

    .EXAMPLE
    ConvertTo-IncidentTimeline -Path .\edr.jsonl, .\firewall.jsonl -Since '2026-10-01T00:00:00Z'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string[]]$Path,
        [datetimeoffset]$Since = [datetimeoffset]::MinValue,
        [datetimeoffset]$Until = [datetimeoffset]::MaxValue
    )

    $events = foreach ($file in $Path) {
        $lineNo = 0
        foreach ($line in Get-Content -LiteralPath $file) {
            $lineNo++
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $obj = $line | ConvertFrom-Json -ErrorAction Stop
                $when = [datetimeoffset]::Parse($obj.timestamp, [Globalization.CultureInfo]::InvariantCulture)
            } catch {
                Write-Warning "${file}:${lineNo}: unreadable event skipped"
                continue
            }
            if ($when -lt $Since -or $when -gt $Until) { continue }
            $source = if ($obj.PSObject.Properties['source']) { $obj.source } else { [IO.Path]::GetFileNameWithoutExtension($file) }
            $hostName = if ($obj.PSObject.Properties['host']) { $obj.host } else { '' }
            [pscustomobject]@{
                TimeUtc = $when.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                Source  = $source
                Host    = $hostName
                Message = $obj.message
                Sort    = $when.UtcTicks
            }
        }
    }

    $events | Sort-Object -Property Sort | Select-Object -Property TimeUtc, Source, Host, Message
}

function Find-BruteForceCandidate {
    <#
    .SYNOPSIS
    Find source IPs with many failed sign-ins in a short window, and successes right after.

    .PARAMETER Path
    CSV with columns timestamp,user,source_ip,result (result = success | failure).

    .PARAMETER Threshold
    Failures from one source inside -WindowMinutes that make it a candidate.

    .EXAMPLE
    Find-BruteForceCandidate -Path .\signins.csv -Threshold 10 -WindowMinutes 5
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$Path,
        [ValidateRange(2, 10000)][int]$Threshold = 10,
        [ValidateRange(1, 1440)][int]$WindowMinutes = 5
    )

    $rows = Import-Csv -LiteralPath $Path | ForEach-Object {
        [pscustomobject]@{
            Time   = [datetimeoffset]::Parse($_.timestamp, [Globalization.CultureInfo]::InvariantCulture)
            User   = $_.user
            Source = $_.source_ip
            Result = "$($_.result)".ToLowerInvariant()
        }
    }

    foreach ($group in ($rows | Group-Object -Property Source)) {
        $ordered = @($group.Group | Sort-Object -Property Time)
        $failures = @($ordered | Where-Object Result -EQ 'failure')
        if ($failures.Count -lt $Threshold) { continue }

        # Sliding window: largest number of failures within WindowMinutes.
        $peak = 0
        $peakEnd = $null
        $start = 0
        for ($end = 0; $end -lt $failures.Count; $end++) {
            while (($failures[$end].Time - $failures[$start].Time).TotalMinutes -gt $WindowMinutes) { $start++ }
            $count = $end - $start + 1
            if ($count -gt $peak) { $peak = $count; $peakEnd = $failures[$end].Time }
        }
        if ($peak -lt $Threshold) { continue }

        $successAfter = @($ordered | Where-Object { $_.Result -eq 'success' -and $_.Time -ge $peakEnd })
        [pscustomobject]@{
            SourceIp          = $group.Name
            PeakFailures      = $peak
            WindowMinutes     = $WindowMinutes
            UsersTargeted     = @($failures | Select-Object -ExpandProperty User -Unique).Count
            SuccessAfterBurst = $successAfter.Count -gt 0
            CompromisedUsers  = @($successAfter | Select-Object -ExpandProperty User -Unique)
        }
    }
}

Export-ModuleMember -Function Get-IocMatch, ConvertTo-IncidentTimeline, Find-BruteForceCandidate
