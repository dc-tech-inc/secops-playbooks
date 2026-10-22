terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
  }
}

# The azurerm provider requires an (empty) features block. No credentials live here:
# CI only runs validate and `terraform test` with a mocked provider.
provider "azurerm" {
  features {}
}
