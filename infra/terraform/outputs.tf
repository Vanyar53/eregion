output "resource_group" {
  value = azurerm_resource_group.annatar.name
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.victim.name
}

output "vm_public_ip" {
  value = azurerm_public_ip.annatar_vm.ip_address
}

output "log_analytics_workspace_id" {
  value       = azurerm_log_analytics_workspace.annatar.workspace_id
  description = "Use this value in your scenario YAML as log_analytics_workspace_id"
}

output "recovery_vault_name" {
  value = azurerm_recovery_services_vault.annatar.name
}

output "exfil_storage_account" {
  value = azurerm_storage_account.exfil.name
}
