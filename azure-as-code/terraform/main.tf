locals {
  tags = {
    project    = var.name
    managed_by = "terraform"
    purpose    = "reference"
  }
  # WAF policy names allow letters and digits only.
  waf_policy_name = "${replace(var.name, "-", "")}waf"
}

resource "azurerm_resource_group" "this" {
  name     = "${var.name}-edge-rg"
  location = var.location
  tags     = local.tags
}

# ---- Front Door (Premium: required for managed WAF rule sets) -------------

resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = "${var.name}-afd"
  resource_group_name      = azurerm_resource_group.this.name
  sku_name                 = "Premium_AzureFrontDoor"
  response_timeout_seconds = 60
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_endpoint" "this" {
  name                     = "${var.name}-ep"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  tags                     = local.tags
}

resource "azurerm_cdn_frontdoor_origin_group" "app" {
  name                     = "app"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    protocol            = "Https"
    path                = "/healthz"
    request_type        = "GET"
    interval_in_seconds = 60
  }
}

resource "azurerm_cdn_frontdoor_origin" "app" {
  name                           = "app"
  cdn_frontdoor_origin_group_id  = azurerm_cdn_frontdoor_origin_group.app.id
  enabled                        = true
  host_name                      = var.origin_host_name
  origin_host_header             = var.origin_host_name
  certificate_name_check_enabled = true
  https_port                     = 443
  http_port                      = 80
  priority                       = 1
  weight                         = 1000
}

resource "azurerm_cdn_frontdoor_route" "app" {
  name                          = "app"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.this.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.app.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.app.id]
  patterns_to_match             = ["/*"]
  supported_protocols           = ["Http", "Https"]
  https_redirect_enabled        = true
  forwarding_protocol           = "HttpsOnly"
  link_to_default_domain        = true
}

# ---- WAF policy -------------------------------------------------------------

resource "azurerm_cdn_frontdoor_firewall_policy" "this" {
  name                              = local.waf_policy_name
  resource_group_name               = azurerm_resource_group.this.name
  sku_name                          = azurerm_cdn_frontdoor_profile.this.sku_name
  enabled                           = true
  mode                              = var.waf_mode
  request_body_check_enabled        = true
  custom_block_response_status_code = 403
  tags                              = local.tags

  # Brute-force protection on the login path, per client IP.
  custom_rule {
    name                           = "RateLimitLogin"
    enabled                        = true
    priority                       = 100
    type                           = "RateLimitRule"
    rate_limit_duration_in_minutes = 1
    rate_limit_threshold           = var.rate_limit_per_minute
    action                         = "Block"

    match_condition {
      match_variable = "RequestUri"
      operator       = "Contains"
      match_values   = ["/login", "/api/auth"]
      transforms     = ["Lowercase"]
    }
  }

  # Only the HTTP methods the application uses.
  custom_rule {
    name     = "AllowKnownMethodsOnly"
    enabled  = true
    priority = 200
    type     = "MatchRule"
    action   = "Block"

    match_condition {
      match_variable     = "RequestMethod"
      operator           = "Equal"
      negation_condition = true
      match_values       = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    }
  }

  dynamic "custom_rule" {
    for_each = length(var.blocked_countries) > 0 ? [1] : []
    content {
      name     = "GeoBlock"
      enabled  = true
      priority = 300
      type     = "MatchRule"
      action   = "Block"

      match_condition {
        match_variable = "SocketAddr"
        operator       = "GeoMatch"
        match_values   = var.blocked_countries
      }
    }
  }

  # OWASP-style managed rules with anomaly scoring (DRS 2.x).
  managed_rule {
    type    = "Microsoft_DefaultRuleSet"
    version = "2.1"
    action  = "Block"
  }

  managed_rule {
    type    = "Microsoft_BotManagerRuleSet"
    version = "1.0"
    action  = "Block"
  }
}

resource "azurerm_cdn_frontdoor_security_policy" "this" {
  name                     = "${var.name}-waf"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  security_policies {
    firewall {
      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.this.id

      association {
        domain {
          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.this.id
        }
        patterns_to_match = ["/*"]
      }
    }
  }
}

# ---- WAF and access logs (what RB-04 queries) -------------------------------

resource "azurerm_log_analytics_workspace" "security" {
  name                = "${var.name}-sec-law"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.tags
}

resource "azurerm_monitor_diagnostic_setting" "frontdoor" {
  name                       = "to-security-workspace"
  target_resource_id         = azurerm_cdn_frontdoor_profile.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.security.id

  enabled_log {
    category = "FrontDoorWebApplicationFirewallLog"
  }

  enabled_log {
    category = "FrontDoorAccessLog"
  }

  metric {
    category = "AllMetrics"
  }
}
