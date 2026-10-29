output "public_ip" {
  description = "IP publique de la VM (SSH depuis operator_cidr seulement)."
  value       = azurerm_public_ip.host.ip_address
}

output "ssh" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.host.ip_address}"
}

output "war_room_tunnel" {
  description = "Ouvre la War Room sur http://localhost:7007 de ton poste."
  value       = "ssh -N -L 7007:127.0.0.1:7007 ${var.admin_username}@${azurerm_public_ip.host.ip_address}"
}

output "principal_id" {
  description = "Identité managée de la VM (Reader sur le banc, Log Analytics Reader sur son workspace)."
  value       = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

output "subnet_id" {
  description = "Sous-réseau de H0 — watch_subnet_id d'infra/orodruin, admis par le pare-feu du canal (SEC5)."
  value       = azurerm_subnet.host.id
}

output "workspace_id" {
  description = "AZURE_WORKSPACE_ID à mettre dans host.env."
  value       = data.azurerm_log_analytics_workspace.bench.workspace_id
}
