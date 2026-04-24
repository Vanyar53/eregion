resource "azurerm_recovery_services_vault" "annatar" {
  name                = "rsv-annatar"
  location            = azurerm_resource_group.annatar.location
  resource_group_name = azurerm_resource_group.annatar.name
  sku                 = "Standard"
  storage_mode_type   = local.cfg.vault_storage_mode
  immutability        = local.cfg.vault_immutability
  tags                = azurerm_resource_group.annatar.tags
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "policy-annatar-daily"
  resource_group_name = azurerm_resource_group.annatar.name
  recovery_vault_name = azurerm_recovery_services_vault.annatar.name

  backup {
    frequency = "Daily"
    time      = local.cfg.backup_time
  }

  retention_daily {
    count = local.cfg.backup_retention_days
  }
}

resource "azurerm_backup_protected_vm" "victim" {
  resource_group_name = azurerm_resource_group.annatar.name
  recovery_vault_name = azurerm_recovery_services_vault.annatar.name
  source_vm_id        = azurerm_linux_virtual_machine.victim.id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
