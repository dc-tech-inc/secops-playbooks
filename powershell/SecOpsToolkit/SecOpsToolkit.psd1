@{
    RootModule        = 'SecOpsToolkit.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '60471d87-e6c5-45ad-b6b8-d1de4dfd0cfb'
    Author            = 'DCtech.'
    CompanyName       = 'DCtech.'
    Copyright         = '(c) 2026 DC TECH INC. MIT License.'
    Description       = 'Read-only incident triage helpers: IOC hash matching, timeline merge, brute-force detection.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-IocMatch', 'ConvertTo-IncidentTimeline', 'Find-BruteForceCandidate')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('security', 'incident-response', 'dfir')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
