// Front Door Premium WAF policy, the Bicep twin of ../terraform/main.tf (policy only).
// Validated with `bicep build` and `bicep lint` in CI; never deployed from this repository.
// Deploy (resource group scope): az deployment group create -g <rg> -f frontdoor-waf.bicep

@description('Letters and digits only.')
@minLength(3)
@maxLength(64)
param policyName string = 'excoportalwaf'

@allowed([
  'Prevention'
  'Detection'
])
param mode string = 'Prevention'

@minValue(10)
@maxValue(5000)
param rateLimitPerMinute int = 100

param tags object = {
  project: 'exco-portal'
  managed_by: 'bicep'
  purpose: 'reference'
}

resource wafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2025-03-01' = {
  name: policyName
  location: 'Global'
  tags: tags
  sku: {
    name: 'Premium_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: mode
      requestBodyCheck: 'Enabled'
      customBlockResponseStatusCode: 403
    }
    customRules: {
      rules: [
        {
          name: 'RateLimitLogin'
          enabledState: 'Enabled'
          priority: 100
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: rateLimitPerMinute
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestUri'
              operator: 'Contains'
              matchValue: [
                '/login'
                '/api/auth'
              ]
              transforms: [
                'Lowercase'
              ]
            }
          ]
        }
        {
          name: 'AllowKnownMethodsOnly'
          enabledState: 'Enabled'
          priority: 200
          ruleType: 'MatchRule'
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RequestMethod'
              operator: 'Equal'
              negateCondition: true
              matchValue: [
                'GET'
                'POST'
                'PUT'
                'PATCH'
                'DELETE'
                'HEAD'
                'OPTIONS'
              ]
            }
          ]
        }
      ]
    }
    managedRules: {
      managedRuleSets: [
        {
          ruleSetType: 'Microsoft_DefaultRuleSet'
          ruleSetVersion: '2.1'
          ruleSetAction: 'Block'
        }
        {
          ruleSetType: 'Microsoft_BotManagerRuleSet'
          ruleSetVersion: '1.0'
          ruleSetAction: 'Block'
        }
      ]
    }
  }
}

output policyId string = wafPolicy.id
