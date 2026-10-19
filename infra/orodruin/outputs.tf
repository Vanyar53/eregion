output "public_ip" {
  description = "IP publique de la VM (SSH depuis operator_cidr seulement)."
  value       = azurerm_public_ip.host.ip_address
}

output "ssh" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.host.ip_address}"
}

output "principal_id" {
  description = "Identité managée de la VM — ce que orodruin-kill révoque."
  value       = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

output "vm_id" {
  description = "La VM que orodruin-kill désalloue."
  value       = azurerm_linux_virtual_machine.host.id
}

output "workspace_id" {
  description = "Log Analytics du banc, pour la cible des scénarios."
  value       = data.azurerm_log_analytics_workspace.bench.workspace_id
}

output "channel_url" {
  description = "EREGION_EXERCISE_CHANNEL — dans orodruin.env et dans le host.env de Glorfindel."
  value       = "${azurerm_storage_account.channel.primary_blob_endpoint}${azurerm_storage_container.exercises.name}"
}

output "channel_scope" {
  description = "EREGION_CHANNEL_SCOPE — dans orodruin.env : la portée que le contrat accepte hors du banc."
  value       = azurerm_storage_container.exercises.id
}
