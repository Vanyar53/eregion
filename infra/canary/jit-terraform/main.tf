# Canary for Glorfindel's just-in-time isolation (docs/design/module-isolation-iac.md).
#
# The isolation puts Glorfindel's quarantine NSG on a NIC for the time of an incident
# and relies on a measured property of the azurerm provider: Terraform neither reports
# nor reverts that change. run.sh re-checks it on the LATEST provider version and fails
# if it changed, so we learn it before an apply silently lifts an isolation.
#
# Throwaway stack: own state, no VM, free resources only (VNet, NSG, NICs), destroyed by
# run.sh, success or not. Least privilege (P-04): it creates NO resource group — it works in
# one that exists, created once (rg-eregion-canary), where the canary's principal is
# Contributor and nothing more. Every name carries the run's suffix: the three lines of the
# CI's matrix run side by side in that group.
terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
}

variable "suffix" {
  type = string
  validation {
    condition     = can(regex("^[a-z0-9-]{1,40}$", var.suffix))
    error_message = "suffix: 1 to 40 of a-z, 0-9, -."
  }
}

# The group the canary works in, never created nor deleted here.
variable "resource_group" {
  type    = string
  default = "rg-eregion-canary"
}

variable "nic_tag" {
  type    = string
  default = "v1"
}

data "azurerm_resource_group" "t" {
  name = var.resource_group
}

locals {
  location = data.azurerm_resource_group.t.location
  # What run.sh's sweep finds when a destroy fails: this run's resources, by their tag.
  tags = { purpose = "eregion-canary-jit", "canary-run" = var.suffix }
}

resource "azurerm_virtual_network" "t" {
  name                = "vnet-canary-${var.suffix}"
  address_space       = ["10.250.0.0/16"]
  location            = local.location
  resource_group_name = data.azurerm_resource_group.t.name
  tags                = local.tags
}

resource "azurerm_subnet" "t" {
  name                 = "default"
  resource_group_name  = data.azurerm_resource_group.t.name
  virtual_network_name = azurerm_virtual_network.t.name
  address_prefixes     = ["10.250.1.0/24"]
}

# The customer's NSG, managed as code.
resource "azurerm_network_security_group" "customer" {
  name                = "nsg-customer-${var.suffix}"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.t.name
  tags                = local.tags
}

# A NIC whose NSG is set as code (association resource).
resource "azurerm_network_interface" "with_nsg" {
  name                = "nic-with-nsg-${var.suffix}"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.t.name
  tags                = merge(local.tags, { rev = var.nic_tag })
  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.t.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "with_nsg" {
  network_interface_id      = azurerm_network_interface.with_nsg.id
  network_security_group_id = azurerm_network_security_group.customer.id
}

# A NIC with no NSG of its own.
resource "azurerm_network_interface" "no_nsg" {
  name                = "nic-no-nsg-${var.suffix}"
  location            = local.location
  resource_group_name = data.azurerm_resource_group.t.name
  tags                = merge(local.tags, { rev = var.nic_tag })
  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.t.id
    private_ip_address_allocation = "Dynamic"
  }
}
