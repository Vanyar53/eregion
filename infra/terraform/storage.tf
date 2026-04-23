resource "azurerm_storage_account" "exfil" {
  name                     = "stsechaosexfil"
  resource_group_name      = azurerm_resource_group.sechaos.name
  location                 = azurerm_resource_group.sechaos.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = azurerm_resource_group.sechaos.tags
}

resource "azurerm_storage_container" "exfil" {
  name                  = "exfil-target"
  storage_account_name  = azurerm_storage_account.exfil.name
  container_access_type = "private"
}
