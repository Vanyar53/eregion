terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

provider "azurerm" {
  features {}
  subscription_id = "44a4dc83-3e79-4e4e-aa93-1b4f8e3ede80"
}

# Baseline resource group — porte le nom canonique sur le workspace "default",
# suffixé "-<instance>" sur tout autre workspace (stack éphémère).
resource "azurerm_resource_group" "celebrimbor" {
  name     = local.base_rg
  location = local.cfg.location
  tags     = local.common_tags
}
