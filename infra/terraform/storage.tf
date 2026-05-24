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

# VM managed identity needs to write blobs for exfil simulation
resource "azurerm_role_assignment" "vm_storage_exfil" {
  scope                = azurerm_storage_account.exfil.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_virtual_machine.victim.identity[0].principal_id
}

# Diagnostic logs → law-annatar: StorageBlobLogs populated in seconds (vs 10 min for Traffic Analytics)
# CallerIpAddress in StorageBlobLogs gives us the source IP for block_suspicious_ip.
resource "azurerm_monitor_diagnostic_setting" "exfil_storage" {
  name                       = "diag-stannatarexfil"
  target_resource_id         = "${azurerm_storage_account.exfil.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.annatar.id

  enabled_log {
    category = "StorageWrite"
  }
}
