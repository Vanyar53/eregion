# Canary for Glorfindel's just-in-time isolation (docs/design/module-isolation-iac.md).
#
# The isolation puts Glorfindel's quarantine NSG on a NIC for the time of an incident
# and relies on a measured property of the azurerm provider: Terraform neither reports
# nor reverts that change. run.sh re-checks it on the LATEST provider version and fails
# if it changed, so we learn it before an apply silently lifts an isolation.
#
# Throwaway stack: own state, own resource group, no VM. Free resources only
# (resource group, VNet, NSG, NICs). Destroyed by run.sh, success or not.
terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {
    # The quarantine NSG is created outside Terraform, in this resource group.
    resource_group { prevent_deletion_if_contains_resources = false }
  }
}

variable "suffix" {
  type = string
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "nic_tag" {
  type    = string
  default = "v1"
}

resource "azurerm_resource_group" "t" {
  name     = "rg-eregion-canary-jit-${var.suffix}"
  location = var.location
  tags     = { purpose = "eregion-canary-jit" }
}

resource "azurerm_virtual_network" "t" {
  name                = "vnet-canary"
  address_space       = ["10.250.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.t.name
}

resource "azurerm_subnet" "t" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.t.name
  virtual_network_name = azurerm_virtual_network.t.name
  address_prefixes     = ["10.250.1.0/24"]
}

# The customer's NSG, managed as code.
resource "azurerm_network_security_group" "customer" {
  name                = "nsg-customer"
  location            = var.location
  resource_group_name = azurerm_resource_group.t.name
}

# A NIC whose NSG is set as code (association resource).
resource "azurerm_network_interface" "with_nsg" {
  name                = "nic-with-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.t.name
  tags                = { rev = var.nic_tag }
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
  name                = "nic-no-nsg"
  location            = var.location
  resource_group_name = azurerm_resource_group.t.name
  tags                = { rev = var.nic_tag }
  ip_configuration {
    name                          = "ipconfig1"
    subnet_id                     = azurerm_subnet.t.id
    private_ip_address_allocation = "Dynamic"
  }
}
