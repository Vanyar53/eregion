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

output "watch_channel_url" {
  description = "EREGION_WATCH_CHANNEL — dans orodruin.env et dans le host.env de Glorfindel (#159)."
  value       = "${azurerm_storage_account.channel.primary_blob_endpoint}${azurerm_storage_container.watch.name}"
}

output "watch_channel_scope" {
  description = "EREGION_WATCH_CHANNEL_SCOPE — dans orodruin.env : le contrat n'y accepte qu'un rôle de lecture."
  value       = azurerm_storage_container.watch.id
}

# IDI1 (#546) : ce que la garde d'une identité d'Entra ID sait avant de lire — dans orodruin.env.
# Les valeurs ne vont jamais dans le dépôt : `terraform -chdir=infra/orodruin output -raw <nom>`.
output "tenant_id" {
  description = "EREGION_TENANT_ID — le tenant du banc (celui de l'abonnement) : une identité d'un autre tenant est refusée."
  value       = data.azurerm_subscription.current.tenant_id
}

output "operator_object_id" {
  description = "EREGION_OPERATOR_OBJECT_ID — l'opérateur qui applique (son az login) : jamais une cible ; sans lui, la garde refuse toute identité."
  value       = data.azurerm_client_config.operator.object_id
}

output "protected_identities" {
  description = "EREGION_PROTECTED_IDENTITIES — l'identité d'Orodruin et celles des watches (H0, les watches listées) : jamais des cibles."
  value       = join(",", distinct(compact(concat([lower(azurerm_linux_virtual_machine.host.identity[0].principal_id)], local.watch_writers))))
}
