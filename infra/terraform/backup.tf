resource "azurerm_recovery_services_vault" "celebrimbor" {
  name                = "rsv-${local.project}-${local.cfg.rsv_name}${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  sku                 = "Standard"
  storage_mode_type   = local.cfg.vault_storage_mode
  immutability        = local.cfg.vault_immutability
  tags                = local.common_tags
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "policy-${local.project}-daily"
  resource_group_name = azurerm_resource_group.celebrimbor.name
  recovery_vault_name = azurerm_recovery_services_vault.celebrimbor.name

  backup {
    frequency = "Daily"
    time      = local.cfg.backup_time
  }

  retention_daily {
    count = local.cfg.backup_retention_days
  }
}

resource "azurerm_backup_protected_vm" "baseline" {
  for_each            = local.vms
  resource_group_name = azurerm_resource_group.celebrimbor.name
  recovery_vault_name = azurerm_recovery_services_vault.celebrimbor.name
  source_vm_id        = azurerm_linux_virtual_machine.baseline[each.key].id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
