// Microsoft Defender for Cloud plans and alert contact at subscription scope,
// the Bicep twin of ../terraform/defender.tf. Validated in CI, never deployed from here.
// Deploy: az deployment sub create -l <region> -f defender.bicep
targetScope = 'subscription'

@description('Defender plans (pricing names) to set to the Standard tier.')
param plans array = [
  'CloudPosture'
  'VirtualMachines'
  'StorageAccounts'
  'KeyVaults'
  'Arm'
  'AppServices'
]

@description('Alert mailbox. Placeholder address only in this reference.')
param securityContactEmail string = 'security@example.com'

@batchSize(1)
resource pricing 'Microsoft.Security/pricings@2024-01-01' = [for plan in plans: {
  // checkov:skip=CKV_AZURE_87: KeyVaults is in the plans array; checkov cannot resolve names inside a for-loop
  name: plan
  properties: {
    pricingTier: 'Standard'
  }
}]

resource contact 'Microsoft.Security/securityContacts@2023-12-01-preview' = {
  // checkov:skip=CKV_AZURE_21: checkov reads the 2017 alertNotifications field; this API version uses notificationsSources
  // checkov:skip=CKV_AZURE_22: same as above for alertsToAdmins; notificationsByRole notifies Owners
  // checkov:skip=CKV_AZURE_20: no phone number by repository policy (no personal data)
  name: 'default'
  properties: {
    emails: securityContactEmail
    isEnabled: true
    notificationsByRole: {
      state: 'On'
      roles: [
        'Owner'
      ]
    }
    notificationsSources: [
      {
        sourceType: 'Alert'
        minimalSeverity: 'Medium'
      }
    ]
  }
}

output enabledPlans array = [for (plan, i) in plans: pricing[i].name]
