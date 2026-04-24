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

resource "azurerm_resource_group" "annatar" {
  name     = local.cfg.resource_group_name
  location = local.cfg.location

  tags = {
    "annatar-test" = "true"
    "project"      = "annatar"
    "managed-by"   = "terraform"
  }
}
