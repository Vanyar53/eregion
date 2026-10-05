# ── Topologie 8 — 2 VMs, leurs NICs partagent UN NSG de NIC ────────────────────
# Valide le correctif « NSG de NIC partagé » (revue 2026-10) : un NSG associé à
# plusieurs NICs était traité comme « cette VM seule » → isolate_vm y posait un
# deny any/any priorité 100 qui coupait AUSSI la VM voisine. Attendu désormais :
# deny scopé à l'IP de la VM cible, priorité libre, aucune règle client déplacée,
# la VM voisine reste joignable (chacune a sa PIP pour le vérifier en SSH).
#
# Gated par topologies.sharednsg.enabled (ou `make celebrimbor-up TOPO=sharednsg`).
# Ressources dans leur propre RG (ttl=destroy-after-test) → `make celebrimbor-down
# TOPO=sharednsg` ciblé, jamais le RG baseline. VMs reliées au DCR/LAW baseline
# pour être découvertes par Glorfindel (Heartbeat).

locals {
  sharednsg_on   = try(local.topo_enabled.sharednsg, false) ? 1 : 0
  sharednsg_vms  = local.sharednsg_on == 1 ? toset(["a", "b"]) : toset([])
  sharednsg_tags = merge(local.common_tags, { ttl = "destroy-after-test", topo = "sharednsg" })
}

resource "azurerm_resource_group" "sharednsg" {
  count    = local.sharednsg_on
  name     = "rg-${local.project}-sharednsg${local.ns}"
  location = local.cfg.location
  tags     = local.sharednsg_tags
}

resource "azurerm_virtual_network" "sharednsg" {
  count               = local.sharednsg_on
  name                = "vnet-${local.project}-sharednsg${local.ns}"
  address_space       = ["10.21.0.0/16"]
  location            = azurerm_resource_group.sharednsg[0].location
  resource_group_name = azurerm_resource_group.sharednsg[0].name
  tags                = local.sharednsg_tags
}

resource "azurerm_subnet" "sharednsg" {
  count                = local.sharednsg_on
  name                 = "subnet-${local.project}-sharednsg"
  resource_group_name  = azurerm_resource_group.sharednsg[0].name
  virtual_network_name = azurerm_virtual_network.sharednsg[0].name
  address_prefixes     = ["10.21.1.0/24"]
}

# UN seul NSG, associé au niveau NIC aux DEUX NICs (pas au subnet) : le cas « un NSG
# par tier ». allow-ssh en 1000, hors de la plage de Glorfindel (voir network.tf).
resource "azurerm_network_security_group" "sharednsg" {
  count               = local.sharednsg_on
  name                = "nsg-${local.project}-sharednsg${local.ns}"
  location            = azurerm_resource_group.sharednsg[0].location
  resource_group_name = azurerm_resource_group.sharednsg[0].name
  tags                = local.sharednsg_tags

  security_rule {
    name                       = "allow-ssh"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_public_ip" "sharednsg" {
  for_each            = local.sharednsg_vms
  name                = "pip-${local.project}-sharednsg-${each.key}${local.ns}"
  location            = azurerm_resource_group.sharednsg[0].location
  resource_group_name = azurerm_resource_group.sharednsg[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.sharednsg_tags
}

resource "azurerm_network_interface" "sharednsg" {
  for_each            = local.sharednsg_vms
  name                = "nic-${local.project}-sharednsg-${each.key}${local.ns}"
  location            = azurerm_resource_group.sharednsg[0].location
  resource_group_name = azurerm_resource_group.sharednsg[0].name
  tags                = local.sharednsg_tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.sharednsg[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sharednsg[each.key].id
  }
}

# Le même NSG sur les deux NICs — c'est ce partage que le correctif doit détecter.
resource "azurerm_network_interface_security_group_association" "sharednsg" {
  for_each                  = local.sharednsg_vms
  network_interface_id      = azurerm_network_interface.sharednsg[each.key].id
  network_security_group_id = azurerm_network_security_group.sharednsg[0].id
}

resource "azurerm_linux_virtual_machine" "sharednsg" {
  for_each            = local.sharednsg_vms
  name                = "vm-${local.project}-sharednsg-${each.key}${local.ns}"
  resource_group_name = azurerm_resource_group.sharednsg[0].name
  location            = azurerm_resource_group.sharednsg[0].location
  size                = local.cfg.vm_size
  admin_username      = local.cfg.admin_username
  tags                = local.sharednsg_tags

  network_interface_ids = [azurerm_network_interface.sharednsg[each.key].id]

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = local.cfg.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = local.cfg.os_disk.caching
    storage_account_type = local.cfg.os_disk.storage_account_type
  }

  source_image_reference {
    publisher = local.cfg.vm_image.publisher
    offer     = local.cfg.vm_image.offer
    sku       = local.cfg.vm_image.sku
    version   = local.cfg.vm_image.version
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "sharednsg" {
  for_each              = local.sharednsg_vms
  virtual_machine_id    = azurerm_linux_virtual_machine.sharednsg[each.key].id
  location              = azurerm_resource_group.sharednsg[0].location
  enabled               = true
  daily_recurrence_time = local.cfg.vm_shutdown_time
  timezone              = "UTC"

  notification_settings {
    enabled         = true
    time_in_minutes = 15
    email           = local.cfg.vm_shutdown_email
  }
}

# Découverte par Glorfindel : AMA + association au DCR baseline → Heartbeat dans le LAW.
resource "azurerm_virtual_machine_extension" "sharednsg_ama" {
  for_each                   = local.sharednsg_vms
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.sharednsg[each.key].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_monitor_data_collection_rule_association" "sharednsg" {
  for_each                = local.sharednsg_vms
  name                    = "dcra-${local.project}-sharednsg-${each.key}${local.ns}"
  target_resource_id      = azurerm_linux_virtual_machine.sharednsg[each.key].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.celebrimbor.id
}

resource "azurerm_role_assignment" "sharednsg_ama_dcr" {
  for_each             = local.sharednsg_vms
  scope                = azurerm_monitor_data_collection_rule.celebrimbor.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_linux_virtual_machine.sharednsg[each.key].identity[0].principal_id
}
