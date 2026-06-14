output "resource_group" {
  value = azurerm_resource_group.annatar.name
}

output "vm_names" {
  value       = { for k, vm in azurerm_linux_virtual_machine.victim : k => vm.name }
  description = "Map clé VM → nom Azure de la VM"
}

output "vm_public_ips" {
  value       = { for k, pip in azurerm_public_ip.annatar_vm : k => pip.ip_address }
  description = "Map clé VM → IP publique"
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
