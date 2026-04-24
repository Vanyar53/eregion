resource "azurerm_virtual_network" "annatar" {
  name                = "vnet-annatar"
  address_space       = [local.cfg.vnet_address_space]
  location            = azurerm_resource_group.annatar.location
  resource_group_name = azurerm_resource_group.annatar.name
  tags                = azurerm_resource_group.annatar.tags
}

resource "azurerm_subnet" "annatar" {
  name                 = "subnet-annatar"
  resource_group_name  = azurerm_resource_group.annatar.name
  virtual_network_name = azurerm_virtual_network.annatar.name
  address_prefixes     = [local.cfg.subnet_address_prefix]
}

resource "azurerm_network_security_group" "annatar" {
  name                = "nsg-annatar"
  location            = azurerm_resource_group.annatar.location
  resource_group_name = azurerm_resource_group.annatar.name
  tags                = azurerm_resource_group.annatar.tags

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

resource "azurerm_subnet_network_security_group_association" "annatar" {
  subnet_id                 = azurerm_subnet.annatar.id
  network_security_group_id = azurerm_network_security_group.annatar.id
}

resource "azurerm_public_ip" "annatar_vm" {
  name                = "pip-annatar-vm"
  location            = azurerm_resource_group.annatar.location
  resource_group_name = azurerm_resource_group.annatar.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = azurerm_resource_group.annatar.tags
}

resource "azurerm_network_interface" "annatar_vm" {
  name                = "nic-annatar-vm"
  location            = azurerm_resource_group.annatar.location
  resource_group_name = azurerm_resource_group.annatar.name
  tags                = azurerm_resource_group.annatar.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.annatar.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.annatar_vm.id
  }
}
