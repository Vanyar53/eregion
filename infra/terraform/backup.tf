resource "azurerm_recovery_services_vault" "sechaos" {
  name                = "rsv-sechaos"
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  sku                 = "Standard"
  soft_delete_enabled = false
  tags                = azurerm_resource_group.sechaos.tags
}

resource "azurerm_backup_policy_vm" "daily" {
  name                = "policy-sechaos-daily"
  resource_group_name = azurerm_resource_group.sechaos.name
  recovery_vault_name = azurerm_recovery_services_vault.sechaos.name

  backup {
    frequency = "Daily"
    time      = "02:00"
  }

  retention_daily {
    count = 7
  }
}

resource "azurerm_backup_protected_vm" "victim" {
  resource_group_name = azurerm_resource_group.sechaos.name
  recovery_vault_name = azurerm_recovery_services_vault.sechaos.name
  source_vm_id        = azurerm_linux_virtual_machine.victim.id
  backup_policy_id    = azurerm_backup_policy_vm.daily.id
}
