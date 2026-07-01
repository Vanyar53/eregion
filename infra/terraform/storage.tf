resource "azurerm_storage_account" "exfil" {
  name                     = local.exfil_storage_name
  resource_group_name      = azurerm_resource_group.celebrimbor.name
  location                 = azurerm_resource_group.celebrimbor.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.common_tags
}

# Staging SA du restore Azure Backup IaaS : Glorfindel (restore_from_backup) y
# stage les disques restaurés. SA dédié (pas de diag setting → n'alimente PAS le
# StorageWrite du LAW, contrairement à l'exfil), même région/souscription.
resource "azurerm_storage_account" "restore_staging" {
  name                     = local.staging_storage_name
  resource_group_name      = azurerm_resource_group.celebrimbor.name
  location                 = azurerm_resource_group.celebrimbor.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  tags                     = local.common_tags
}

resource "azurerm_storage_container" "exfil" {
  name               = "exfil-target"
  storage_account_id = azurerm_storage_account.exfil.id
}

# VM managed identity needs to write blobs for exfil simulation
resource "azurerm_role_assignment" "vm_storage_exfil" {
  for_each             = local.vms
  scope                = azurerm_storage_account.exfil.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_virtual_machine.baseline[each.key].identity[0].principal_id
}

# Diagnostic logs → LAW: StorageBlobLogs populated in seconds (vs 10 min for Traffic Analytics)
# CallerIpAddress in StorageBlobLogs gives us the source IP for block_suspicious_ip.
resource "azurerm_monitor_diagnostic_setting" "exfil_storage" {
  name                       = "diag-${local.project}-exfil${local.ns}"
  target_resource_id         = "${azurerm_storage_account.exfil.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.celebrimbor.id

  enabled_log {
    category = "StorageWrite"
  }
}
