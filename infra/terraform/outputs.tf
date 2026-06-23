output "instance" {
  value       = local.instance
  description = "Workspace Terraform = instance (stack). \"default\" = stack canonique."
}

output "resource_group" {
  value = azurerm_resource_group.celebrimbor.name
}

output "baseline_vm_names" {
  value       = { for k, vm in azurerm_linux_virtual_machine.baseline : k => vm.name }
  description = "Map clé hôte → nom Azure de la VM baseline"
}

output "baseline_vm_resource_ids" {
  value       = { for k, vm in azurerm_linux_virtual_machine.baseline : k => vm.id }
  description = "Map clé hôte → resource_id (à câbler dans les scénarios / detection_rules)"
}

output "baseline_vm_public_ips" {
  value = { for k, pip in azurerm_public_ip.celebrimbor_vm : k => pip.ip_address }
}

output "law_workspace_id" {
  value       = azurerm_log_analytics_workspace.celebrimbor.workspace_id
  description = "workspace_id (GUID) du LAW baseline — monitoring_backends de glorfindel-config.yaml"
}

output "law_name" {
  value = azurerm_log_analytics_workspace.celebrimbor.name
}

output "rsv_name" {
  value = azurerm_recovery_services_vault.celebrimbor.name
}

output "exfil_storage_account" {
  value = azurerm_storage_account.exfil.name
}

output "enabled_topologies" {
  value       = [for name, on in local.topo_enabled : name if on]
  description = "Topologies de test actives sur cette instance"
}

output "multinic_vm_resource_id" {
  value       = local.multinic_on == 1 ? azurerm_linux_virtual_machine.multinic[0].id : null
  description = "resource_id de la VM multi-NIC (null si la topo est désactivée)"
}

# ── Pont infra → Glorfindel ──────────────────────────────────────────────────
# Fragment glorfindel-config.yaml prêt à coller (ou écrit par un pipeline).
# Évite tout copier-coller manuel des resource_ids / workspace_id / vault.
output "glorfindel_config_fragment" {
  description = "Fragment glorfindel-config.yaml pour cette instance"
  value       = <<-YAML
    # Généré par Terraform — instance "${local.instance}"
    monitoring_backends:
      - name: ${azurerm_log_analytics_workspace.celebrimbor.name}
        type: azure_monitor
        workspace_id: ${azurerm_log_analytics_workspace.celebrimbor.workspace_id}

    action_backends:
      - name: ${azurerm_recovery_services_vault.celebrimbor.name}
        type: azure_backup_vault
        vault_name: ${azurerm_recovery_services_vault.celebrimbor.name}
        resource_group: ${azurerm_resource_group.celebrimbor.name}
  YAML
}
