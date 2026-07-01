terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

# subscription_id : jamais en dur (repo public). Résolu, dans l'ordre :
#   1. var.subscription_id (terraform.tfvars ou TF_VAR_subscription_id) ;
#   2. sinon null → le provider lit ARM_SUBSCRIPTION_ID de l'env.
# Le Makefile mappe l'AZURE_SUBSCRIPTION_ID de .envrc → ARM_SUBSCRIPTION_ID.
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
}

# Baseline resource group — porte le nom canonique sur le workspace "default",
# suffixé "-<instance>" sur tout autre workspace (stack éphémère).
resource "azurerm_resource_group" "celebrimbor" {
  name     = local.base_rg
  location = local.cfg.location
  tags     = local.common_tags
}
