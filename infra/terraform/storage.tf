resource "azurerm_storage_account" "exfil" {
  name                     = "stannatarexfil"
  resource_group_name      = azurerm_resource_group.annatar.name
  location                 = azurerm_resource_group.annatar.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = azurerm_resource_group.annatar.tags
}

resource "azurerm_storage_container" "exfil" {
  name               = "exfil-target"
  storage_account_id = azurerm_storage_account.exfil.id
}
