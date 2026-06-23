resource "azurerm_virtual_network" "celebrimbor" {
  name                = "vnet-${local.project}${local.ns}"
  address_space       = [local.cfg.vnet_address_space]
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  tags                = local.common_tags
}

resource "azurerm_subnet" "celebrimbor" {
  name                 = "subnet-${local.project}"
  resource_group_name  = azurerm_resource_group.celebrimbor.name
  virtual_network_name = azurerm_virtual_network.celebrimbor.name
  address_prefixes     = [local.cfg.subnet_address_prefix]
}

# NSG niveau SUBNET pour le baseline (un seul NSG partagé). Les topos NIC-level
# (multinic, mix_nsg) montent leurs propres NSG associés aux NICs.
resource "azurerm_network_security_group" "celebrimbor" {
  name                = "nsg-${local.project}${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  tags                = local.common_tags

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

  security_rule {
    name                       = "deny-inbound-default"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "celebrimbor" {
  subnet_id                 = azurerm_subnet.celebrimbor.id
  network_security_group_id = azurerm_network_security_group.celebrimbor.id
}

resource "azurerm_public_ip" "celebrimbor_vm" {
  for_each            = local.vms
  name                = each.value.pip_name
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_network_interface" "celebrimbor_vm" {
  for_each            = local.vms
  name                = each.value.nic_name
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  tags                = local.common_tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.celebrimbor.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.celebrimbor_vm[each.key].id
  }
}
