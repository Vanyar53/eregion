terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    # G1 : la cible Microsoft-Agent de Chaos Studio (chaos.tf), qu'azurerm ne sait pas déclarer.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.0"
    }
    # IDI1 : l'identité de test du banc dans Entra ID (entra_identity.tf), désactivée par défaut.
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
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

provider "azapi" {
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
}

# Le az login de l'opérateur, sur son tenant courant (celui de l'abonnement du banc) : jamais un
# principal. Ne sert qu'à entra_identity.tf.
provider "azuread" {}

# Baseline resource group — porte le nom canonique sur le workspace "default",
# suffixé "-<instance>" sur tout autre workspace (stack éphémère).
#
# IDI1 : il nomme aussi l'identité de test du banc qu'il inscrit (eregion-identities,
# entra_identity.tf) — la clé ARM de l'inscription d'une identité ; sans l'identité, rien de plus.
resource "azurerm_resource_group" "celebrimbor" {
  name     = local.base_rg
  location = local.cfg.location
  tags     = merge(local.common_tags, local.identity_tags)
}
