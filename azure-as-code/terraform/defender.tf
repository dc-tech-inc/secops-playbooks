# Microsoft Defender for Cloud: subscription-level plans and the alert contact.
# Note: Standard tiers are billed per protected resource. This reference is never applied.

resource "azurerm_security_center_subscription_pricing" "plans" {
  for_each      = var.defender_plans
  tier          = "Standard"
  resource_type = each.value
}

resource "azurerm_security_center_contact" "soc" {
  # checkov:skip=CKV_AZURE_20: no phone number by repository policy (no personal data in a public repo)
  name                = "default1"
  email               = var.security_contact_email
  alert_notifications = true
  alerts_to_admins    = true
}
