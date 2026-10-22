# SecOpsToolkit (PowerShell)

Read-only triage helpers for incident responders. They run on Windows PowerShell 5.1 and PowerShell 7 (Windows, Linux, macOS), read files only, and never touch the network.

| Function | Input | Answers |
|---|---|---|
| `Get-IocMatch` | a folder + CSV `sha256,indicator` | Which files on this share match known-bad hashes? |
| `ConvertTo-IncidentTimeline` | JSON-lines event files | What happened, in order, in UTC, across EDR, firewall and app logs? |
| `Find-BruteForceCandidate` | CSV `timestamp,user,source_ip,result` | Which sources sprayed passwords, and did any sign-in succeed afterwards? |

```powershell
Import-Module ./powershell/SecOpsToolkit/SecOpsToolkit.psd1
Get-Help Find-BruteForceCandidate -Examples
Find-BruteForceCandidate -Path ./signins.csv -Threshold 10 -WindowMinutes 5
```

Tests: [`tests/SecOpsToolkit.Tests.ps1`](tests/SecOpsToolkit.Tests.ps1) (Pester 5, synthetic data in `TestDrive:`). Lint: PSScriptAnalyzer with warnings as failures. Both run in CI on `pwsh`.

```powershell
Invoke-Pester ./powershell/tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./powershell -Recurse -Severity Warning,Error
```

## Limitations

- `Get-IocMatch` only does exact SHA256 matching; it is not an antivirus and does not unpack archives.
- `Find-BruteForceCandidate` treats each source IP independently, so a distributed spray from many IPs needs the per-user view instead (roadmap).
- Input formats are simple CSV / JSON lines; mapping a real log source to them is left to the analyst.

## References

- Pester: <https://pester.dev/docs/quick-start>
- PSScriptAnalyzer: <https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/overview>
- Get-FileHash: <https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/get-filehash>
