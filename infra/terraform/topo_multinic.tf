# ── Topologie 1 — VM à 2 NICs, 1 NSG par NIC (niveau NIC) ────────────────────
# Valide l'isolation multi-NIC (7603a3e) : isolate_vm / block_suspicious_ip
# doivent poser des règles sur LES DEUX NSG (le bug : seule la NIC primaire
# couverte → la 2e NIC reste ouverte → faux "isolé").
#
# Gated par topologies.multinic.enabled (ou `make celebrimbor-up TOPO=multinic`).
# Ressources dans leur propre RG (ttl=destroy-after-test) → celebrimbor-down ciblé, jamais le
# RG baseline. La VM est reliée au DCR/LAW baseline pour être découverte par
# Glorfindel (Heartbeat).

locals {
  multinic_on   = local.topo_enabled.multinic ? 1 : 0
  multinic_tags = merge(local.common_tags, { ttl = "destroy-after-test", topo = "multinic" })
}

resource "azurerm_resource_group" "multinic" {
  count    = local.multinic_on
  name     = "rg-${local.project}-multinic${local.ns}"
  location = local.cfg.location
  tags     = local.multinic_tags
}

resource "azurerm_virtual_network" "multinic" {
  count               = local.multinic_on
  name                = "vnet-${local.project}-multinic${local.ns}"
  address_space       = ["10.20.0.0/16"]
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  tags                = local.multinic_tags
}

resource "azurerm_subnet" "multinic" {
  count                = local.multinic_on
  name                 = "subnet-${local.project}-multinic"
  resource_group_name  = azurerm_resource_group.multinic[0].name
  virtual_network_name = azurerm_virtual_network.multinic[0].name
  address_prefixes     = ["10.20.1.0/24"]
}

# Un NSG distinct PAR NIC, associé au niveau NIC (le cas que le fix multi-NIC couvre).
resource "azurerm_network_security_group" "multinic_nic0" {
  count               = local.multinic_on
  name                = "nsg-${local.project}-multinic-nic0${local.ns}"
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  tags                = local.multinic_tags

  security_rule {
    name                       = "allow-ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_group" "multinic_nic1" {
  count               = local.multinic_on
  name                = "nsg-${local.project}-multinic-nic1${local.ns}"
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  tags                = local.multinic_tags
}

resource "azurerm_public_ip" "multinic" {
  count               = local.multinic_on
  name                = "pip-${local.project}-multinic${local.ns}"
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.multinic_tags
}

# NIC0 — primaire (porte la PIP d'accès), NSG nic0.
resource "azurerm_network_interface" "multinic_nic0" {
  count               = local.multinic_on
  name                = "nic-${local.project}-multinic-0${local.ns}"
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  tags                = local.multinic_tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.multinic[0].id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.multinic[0].id
  }
}

# NIC1 — secondaire, interne, NSG nic1. C'est CELLE qui restait ouverte avant le fix.
resource "azurerm_network_interface" "multinic_nic1" {
  count               = local.multinic_on
  name                = "nic-${local.project}-multinic-1${local.ns}"
  location            = azurerm_resource_group.multinic[0].location
  resource_group_name = azurerm_resource_group.multinic[0].name
  tags                = local.multinic_tags

  ip_configuration {
    name                          = "secondary"
    subnet_id                     = azurerm_subnet.multinic[0].id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface_security_group_association" "multinic_nic0" {
  count                     = local.multinic_on
  network_interface_id      = azurerm_network_interface.multinic_nic0[0].id
  network_security_group_id = azurerm_network_security_group.multinic_nic0[0].id
}

resource "azurerm_network_interface_security_group_association" "multinic_nic1" {
  count                     = local.multinic_on
  network_interface_id      = azurerm_network_interface.multinic_nic1[0].id
  network_security_group_id = azurerm_network_security_group.multinic_nic1[0].id
}

resource "azurerm_linux_virtual_machine" "multinic" {
  count               = local.multinic_on
  name                = "vm-${local.project}-multinic${local.ns}"
  resource_group_name = azurerm_resource_group.multinic[0].name
  location            = azurerm_resource_group.multinic[0].location
  size                = local.cfg.vm_size
  admin_username      = local.cfg.admin_username
  tags                = local.multinic_tags

  # Premier id = NIC primaire. Les deux NICs sont attachées → isolate_vm doit
  # couvrir les deux NSG.
  network_interface_ids = [
    azurerm_network_interface.multinic_nic0[0].id,
    azurerm_network_interface.multinic_nic1[0].id,
  ]

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = local.cfg.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = local.cfg.vm_image.publisher
    offer     = local.cfg.vm_image.offer
    sku       = local.cfg.vm_image.sku
    version   = local.cfg.vm_image.version
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "multinic" {
  count                 = local.multinic_on
  virtual_machine_id    = azurerm_linux_virtual_machine.multinic[0].id
  location              = azurerm_resource_group.multinic[0].location
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
resource "azurerm_virtual_machine_extension" "multinic_ama" {
  count                      = local.multinic_on
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.multinic[0].id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}

resource "azurerm_monitor_data_collection_rule_association" "multinic" {
  count                   = local.multinic_on
  name                    = "dcra-${local.project}-multinic${local.ns}"
  target_resource_id      = azurerm_linux_virtual_machine.multinic[0].id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.celebrimbor.id
}

resource "azurerm_role_assignment" "multinic_ama_dcr" {
  count                = local.multinic_on
  scope                = azurerm_monitor_data_collection_rule.celebrimbor.id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_linux_virtual_machine.multinic[0].identity[0].principal_id
}
