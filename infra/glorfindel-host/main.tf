# Glorfindel hébergé (H0) — une petite VM où Glorfindel tourne en continu, War Room et bot
# Discord compris (groupe rg-glorfindel).
#
# État Terraform séparé de Celebrimbor : détruire le banc ne détruit pas le défenseur, et
# inversement. La VM vit hors du groupe du banc, sans tag `eregion-target` et sans DCR vers le
# Log Analytics du banc : la découverte (Heartbeat) ne la voit pas, Glorfindel ne peut pas
# l'isoler. Son identité managée lit le banc, rien de plus (pré-observation : `human_only`,
# `GLORFINDEL_READ_ONLY=1`). README.md pour le déroulé.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

# subscription_id : jamais en dur (repo public). var.subscription_id, sinon ARM_SUBSCRIPTION_ID
# (le Makefile le dérive de l'AZURE_SUBSCRIPTION_ID de .envrc).
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
}

locals {
  name = "glorfindel"
  tags = {
    project    = local.name
    managed-by = "terraform"
    eregion    = "defender"
    # Volontairement PAS de `eregion-target` ni d'`eregion-zone` : ce n'est pas une cible.
  }
}

# ── Ce que Glorfindel observe : le banc de Celebrimbor (lu, jamais créé ici) ──────────────
data "azurerm_resource_group" "bench" {
  name = var.bench_resource_group
}

data "azurerm_log_analytics_workspace" "bench" {
  name                = var.bench_workspace
  resource_group_name = data.azurerm_resource_group.bench.name
}

# ── Le défenseur ──────────────────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "host" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# Un VNet à lui, sans peering avec le banc : Glorfindel parle aux API d'Azure, pas aux VMs.
resource "azurerm_virtual_network" "host" {
  name                = "vnet-${local.name}"
  address_space       = ["10.20.0.0/24"]
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags
}

resource "azurerm_subnet" "host" {
  name                 = "snet-${local.name}"
  resource_group_name  = azurerm_resource_group.host.name
  virtual_network_name = azurerm_virtual_network.host.name
  address_prefixes     = ["10.20.0.0/26"]
  # SEC5 (V-31) : le compte du canal d'Orodruin n'admet H0 que par ce point de terminaison de
  # service (gratuit) : une règle d'IP n'a pas d'effet depuis la même région que le compte.
  service_endpoints = ["Microsoft.Storage"]

  # Un VNet recréé (changement de région, 16/10) emporte son sous-réseau, mais le nom ne change
  # pas : sans ce lien, Terraform garde l'ancien sous-réseau dans son état et la carte réseau
  # échoue (« subnet not found »).
  lifecycle {
    replace_triggered_by = [azurerm_virtual_network.host.id]
  }
}

# Entrée : SSH depuis l'IP de l'opérateur seulement. La War Room reste sur 127.0.0.1 de la VM
# (docker-compose.yml) et s'ouvre par un tunnel SSH. Sortie : celle d'Azure par défaut (API
# d'Azure, API du modèle, Discord, GitHub et registres pour construire l'image).
resource "azurerm_network_security_group" "host" {
  name                = "nsg-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags

  security_rule {
    name                       = "allow-ssh-operator"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.operator_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "host" {
  name                = "pip-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "host" {
  name                = "nic-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.host.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.host.id
  }
}

resource "azurerm_network_interface_security_group_association" "host" {
  network_interface_id      = azurerm_network_interface.host.id
  network_security_group_id = azurerm_network_security_group.host.id
}

resource "azurerm_linux_virtual_machine" "host" {
  name                  = "vm-${local.name}"
  resource_group_name   = azurerm_resource_group.host.name
  location              = azurerm_resource_group.host.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.host.id]
  tags                  = local.tags

  # Identité managée : pas de secret Azure sur la VM. DefaultAzureCredential la prend quand
  # AZURE_CLIENT_ID/SECRET sont vides (host.env ne les définit pas).
  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 32
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Docker et le dépôt seulement. Rien ne démarre avant `make glorfindel-host-push` (host.env,
  # config) puis `make glorfindel-host-start`. Changer ce bloc remplace la VM : l'état de
  # Glorfindel (~/.glorfindel, mémoire) est perdu avec elle.
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q docker.io docker-compose-v2 git make
    usermod -aG docker ${var.admin_username}
    sudo -u ${var.admin_username} git clone --branch ${var.eregion_ref} ${var.eregion_repo} /home/${var.admin_username}/eregion
    sudo -u ${var.admin_username} mkdir -p /home/${var.admin_username}/.glorfindel /home/${var.admin_username}/.cache/chroma /home/${var.admin_username}/eregion/runs
    touch /home/${var.admin_username}/.eregion-host-ready
  EOF
  )
}

# ── Droits : lire le banc, rien d'autre (pré-observation) ─────────────────────────────────
# Les droits d'écriture (isoler, bloquer) viendront avec les exercices de R1 et G0, sur
# décision de Jonathan.
resource "azurerm_role_assignment" "bench_reader" {
  scope                = data.azurerm_resource_group.bench.id
  role_definition_name = "Reader"
  principal_id         = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

resource "azurerm_role_assignment" "bench_logs_reader" {
  scope                = data.azurerm_log_analytics_workspace.bench.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_linux_virtual_machine.host.identity[0].principal_id
}
