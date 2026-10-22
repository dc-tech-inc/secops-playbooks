# Offline plan tests: the azurerm provider is mocked, so no subscription or credentials are needed.
mock_provider "azurerm" {}

run "waf_defaults_are_safe" {
  command = plan

  assert {
    condition     = azurerm_cdn_frontdoor_profile.this.sku_name == "Premium_AzureFrontDoor"
    error_message = "Managed WAF rule sets need the Premium Front Door SKU."
  }

  assert {
    condition     = azurerm_cdn_frontdoor_firewall_policy.this.mode == "Prevention" && azurerm_cdn_frontdoor_firewall_policy.this.enabled
    error_message = "The WAF policy must be enabled and blocking by default."
  }

  assert {
    condition = anytrue([
      for r in azurerm_cdn_frontdoor_firewall_policy.this.managed_rule :
      r.type == "Microsoft_DefaultRuleSet" && r.version == "2.1" && r.action == "Block"
    ])
    error_message = "DRS 2.1 must be attached with anomaly-score blocking."
  }

  assert {
    condition     = contains([for r in azurerm_cdn_frontdoor_firewall_policy.this.managed_rule : r.type], "Microsoft_BotManagerRuleSet")
    error_message = "The bot manager rule set must be attached."
  }

  assert {
    condition     = length(azurerm_cdn_frontdoor_firewall_policy.this.custom_rule) == 2
    error_message = "Without blocked countries only the rate-limit and method rules exist."
  }

  assert {
    condition     = azurerm_cdn_frontdoor_firewall_policy.this.request_body_check_enabled
    error_message = "Managed rules must inspect request bodies."
  }
}

run "routing_is_https_only" {
  command = plan

  assert {
    condition     = azurerm_cdn_frontdoor_route.app.https_redirect_enabled && azurerm_cdn_frontdoor_route.app.forwarding_protocol == "HttpsOnly"
    error_message = "HTTP must redirect to HTTPS and the origin must be reached over HTTPS."
  }

  assert {
    condition     = azurerm_cdn_frontdoor_origin.app.certificate_name_check_enabled
    error_message = "Origin certificate name checks must stay on."
  }

  assert {
    condition     = one(azurerm_cdn_frontdoor_security_policy.this.security_policies[0].firewall[0].association[0].patterns_to_match) == "/*"
    error_message = "The WAF must cover every path."
  }
}

run "logs_and_defender" {
  command = plan

  assert {
    condition     = contains([for l in azurerm_monitor_diagnostic_setting.frontdoor.enabled_log : l.category], "FrontDoorWebApplicationFirewallLog")
    error_message = "WAF logs must be shipped to the security workspace."
  }

  assert {
    condition     = azurerm_log_analytics_workspace.security.retention_in_days >= 90
    error_message = "Keep at least 90 days of security logs."
  }

  assert {
    condition     = length(azurerm_security_center_subscription_pricing.plans) == 6 && alltrue([for p in azurerm_security_center_subscription_pricing.plans : p.tier == "Standard"])
    error_message = "All requested Defender plans must be on the Standard tier."
  }

  assert {
    condition     = azurerm_security_center_contact.soc.alert_notifications && azurerm_security_center_contact.soc.alerts_to_admins
    error_message = "Defender alerts must notify the contact and the subscription admins."
  }
}

run "geo_block_rule_is_added_when_requested" {
  command = plan

  variables {
    blocked_countries = ["AQ"]
  }

  assert {
    condition     = length(azurerm_cdn_frontdoor_firewall_policy.this.custom_rule) == 3
    error_message = "A geo-match rule must be added when countries are listed."
  }
}

run "detection_mode_is_allowed" {
  command = plan

  variables {
    waf_mode = "Detection"
  }

  assert {
    condition     = azurerm_cdn_frontdoor_firewall_policy.this.mode == "Detection"
    error_message = "Detection mode should be selectable for tuning."
  }
}

run "rejects_bad_waf_mode" {
  command = plan

  variables {
    waf_mode = "Off"
  }

  expect_failures = [var.waf_mode]
}

run "rejects_real_contact_email" {
  command = plan

  variables {
    security_contact_email = "soc@realcompany.io"
  }

  expect_failures = [var.security_contact_email]
}

run "rejects_unknown_defender_plan" {
  command = plan

  variables {
    defender_plans = ["VirtualMachines", "Mainframes"]
  }

  expect_failures = [var.defender_plans]
}

run "rejects_lowercase_country" {
  command = plan

  variables {
    blocked_countries = ["aq"]
  }

  expect_failures = [var.blocked_countries]
}
