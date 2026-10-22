output "frontdoor_endpoint_host" {
  description = "Default *.azurefd.net host name of the endpoint."
  value       = azurerm_cdn_frontdoor_endpoint.this.host_name
}

output "waf_policy_id" {
  description = "ID of the Front Door WAF policy."
  value       = azurerm_cdn_frontdoor_firewall_policy.this.id
}

output "defender_plans" {
  description = "Defender for Cloud plans set to Standard."
  value       = sort([for p in azurerm_security_center_subscription_pricing.plans : p.resource_type])
}

output "security_workspace_id" {
  description = "Log Analytics workspace receiving WAF and access logs."
  value       = azurerm_log_analytics_workspace.security.id
}
