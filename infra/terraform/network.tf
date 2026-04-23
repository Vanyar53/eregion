resource "azurerm_virtual_network" "sechaos" {
  name                = "vnet-sechaos"
  address_space       = ["10.10.0.0/16"]
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  tags                = azurerm_resource_group.sechaos.tags
}

resource "azurerm_subnet" "sechaos" {
  name                 = "subnet-sechaos"
  resource_group_name  = azurerm_resource_group.sechaos.name
  virtual_network_name = azurerm_virtual_network.sechaos.name
  address_prefixes     = ["10.10.1.0/24"]
}

resource "azurerm_network_security_group" "sechaos" {
  name                = "nsg-sechaos"
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  tags                = azurerm_resource_group.sechaos.tags

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

resource "azurerm_subnet_network_security_group_association" "sechaos" {
  subnet_id                 = azurerm_subnet.sechaos.id
  network_security_group_id = azurerm_network_security_group.sechaos.id
}

resource "azurerm_public_ip" "sechaos_vm" {
  name                = "pip-sechaos-vm"
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = azurerm_resource_group.sechaos.tags
}

resource "azurerm_network_interface" "sechaos_vm" {
  name                = "nic-sechaos-vm"
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  tags                = azurerm_resource_group.sechaos.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.sechaos.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.sechaos_vm.id
  }
}
