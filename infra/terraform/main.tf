terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
  required_version = ">= 1.5"
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "sechaos" {
  name     = var.resource_group_name
  location = var.location

  tags = {
    "sechaos-test" = "true"
    "project"      = "sechaos"
    "managed-by"   = "terraform"
  }
}
