// Negative fixture: CI expects scripts/validate-bicep.sh to REJECT this file,
// proving that unknown properties fail the build instead of passing silently.
resource waf 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2025-03-01' = {
  name: 'negativefixture'
  location: 'Global'
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      notARealSetting: true
    }
  }
}
