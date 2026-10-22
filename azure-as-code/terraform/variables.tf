variable "name" {
  description = "Short name used as a prefix for every resource."
  type        = string
  default     = "exco-portal"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name))
    error_message = "name must be 3-21 lowercase letters, digits or dashes, starting with a letter."
  }
}

variable "location" {
  description = "Azure region for the resource group (Front Door itself is global)."
  type        = string
  default     = "eastus2"
}

variable "origin_host_name" {
  description = "Backend host name Front Door forwards to. Placeholder: example.com only."
  type        = string
  default     = "app.example.com"
}

variable "waf_mode" {
  description = "Prevention blocks; Detection only logs. Start in Detection, then switch."
  type        = string
  default     = "Prevention"

  validation {
    condition     = contains(["Prevention", "Detection"], var.waf_mode)
    error_message = "waf_mode must be Prevention or Detection."
  }
}

variable "rate_limit_per_minute" {
  description = "Requests per minute per client IP to the login path before blocking."
  type        = number
  default     = 100

  validation {
    condition     = var.rate_limit_per_minute >= 10 && var.rate_limit_per_minute <= 5000
    error_message = "rate_limit_per_minute must be between 10 and 5000."
  }
}

variable "blocked_countries" {
  description = "ISO 3166-1 alpha-2 country codes blocked by a geo-match rule. Empty disables the rule."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for c in var.blocked_countries : can(regex("^[A-Z]{2}$", c))])
    error_message = "blocked_countries must be two-letter uppercase ISO codes."
  }
}

variable "defender_plans" {
  description = "Defender for Cloud plans (resource_type values) to set to the Standard tier."
  type        = set(string)
  default     = ["CloudPosture", "VirtualMachines", "StorageAccounts", "KeyVaults", "Arm", "AppServices"]

  validation {
    condition = alltrue([for p in var.defender_plans : contains([
      "Api", "AppServices", "Arm", "CloudPosture", "Containers", "ContainerRegistry", "CosmosDbs", "Dns",
      "KeyVaults", "KubernetesService", "OpenSourceRelationalDatabases", "SqlServers",
      "SqlServerVirtualMachines", "StorageAccounts", "VirtualMachines",
    ], p)])
    error_message = "defender_plans contains an unknown Defender plan."
  }
}

variable "security_contact_email" {
  description = "Mailbox that receives Defender alerts. Must be a placeholder in this reference."
  type        = string
  default     = "security@example.com"

  validation {
    condition     = can(regex("@example[.](com|org|net)$", var.security_contact_email))
    error_message = "Use an example.com/org/net address in this reference repository."
  }
}
