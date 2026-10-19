# Chaos Studio (G0) — les pannes déclarées que Gothmog lance depuis Orodruin.
#
# Activable par la config (chaos.enabled, défaut false). Pour chaque VM de chaos.shutdown_vms :
#   - la VM inscrite auprès du moteur : cible Microsoft-VirtualMachine + capacité Shutdown-1.0 ;
#   - une expérience d'arrêt PROPRE (abruptShutdown = false) de chaos.shutdown_duration ;
#     Chaos Studio redémarre la VM en fin de panne ou à l'annulation ;
#   - l'identité de l'expérience, avec un rôle sur mesure attribué sur CETTE VM seule : la
#     lire, l'éteindre, la démarrer — pas la supprimer (le rôle intégré Virtual Machine
#     Contributor de l'exemple Microsoft le permettrait).
#
# Experiments (classic) : Workspaces, le modèle vers lequel Microsoft migre, est en préversion
# publique (09/2026) et hors du provider azurerm. Orodruin démarre, suit et annule l'expérience
# (eregion_core/orodruin.py, REQUIRED_ACTIONS) ; il n'agit jamais lui-même sur la VM pendant la
# panne. Gothmog relit les cibles dans l'expérience et les passe par l'inscription (O0).
# Une VM non inscrite (bree, enrolled: false) est refusée au plan.

locals {
  chaos_enabled = try(local.cfg.chaos.enabled, false)
  chaos_vms = local.chaos_enabled ? {
    for key in try(local.cfg.chaos.shutdown_vms, []) : key => local.vms[key]
  } : {}
}

resource "azurerm_chaos_studio_target" "vm" {
  for_each           = local.chaos_vms
  location           = azurerm_resource_group.celebrimbor.location
  target_resource_id = azurerm_linux_virtual_machine.baseline[each.key].id
  target_type        = "Microsoft-VirtualMachine"

  lifecycle {
    precondition {
      condition     = try(each.value.enrolled, true)
      error_message = "Chaos Studio : ${each.key} n'est pas inscrite (enrolled: false) — aucune panne ne la vise."
    }
  }
}

resource "azurerm_chaos_studio_capability" "shutdown" {
  for_each               = local.chaos_vms
  chaos_studio_target_id = azurerm_chaos_studio_target.vm[each.key].id
  capability_type        = "Shutdown-1.0"
}

resource "azurerm_chaos_studio_experiment" "shutdown" {
  for_each            = local.chaos_vms
  name                = "exp-${local.project}-${each.key}-shutdown${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name

  identity {
    type = "SystemAssigned"
  }

  selectors {
    name                    = each.key
    chaos_studio_target_ids = [azurerm_chaos_studio_target.vm[each.key].id]
  }

  steps {
    name = "shutdown"
    branch {
      name = each.key
      actions {
        urn           = azurerm_chaos_studio_capability.shutdown[each.key].urn
        selector_name = each.key
        action_type   = "continuous"
        duration      = try(local.cfg.chaos.shutdown_duration, "PT5M")
        parameters = {
          abruptShutdown = "false"
        }
      }
    }
  }
}

# Ce que l'expérience fait à la VM, et rien d'autre.
resource "azurerm_role_definition" "chaos_vm_shutdown" {
  count       = local.chaos_enabled ? 1 : 0
  name        = "eregion-chaos-vm-shutdown-${azurerm_resource_group.celebrimbor.name}"
  scope       = azurerm_resource_group.celebrimbor.id
  description = "Chaos Studio (Eregion G0) : arrêter proprement puis redémarrer une VM du banc."

  permissions {
    actions = [
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/powerOff/action",
      "Microsoft.Compute/virtualMachines/start/action",
    ]
    not_actions = []
  }

  assignable_scopes = [azurerm_resource_group.celebrimbor.id]
}

resource "azurerm_role_assignment" "chaos_vm_shutdown" {
  for_each           = local.chaos_vms
  scope              = azurerm_linux_virtual_machine.baseline[each.key].id
  role_definition_id = azurerm_role_definition.chaos_vm_shutdown[0].role_definition_resource_id
  principal_id       = azurerm_chaos_studio_experiment.shutdown[each.key].identity[0].principal_id
  principal_type     = "ServicePrincipal"
}

output "chaos_experiments" {
  value       = { for k, e in azurerm_chaos_studio_experiment.shutdown : k => e.name }
  description = "Map clé hôte → expérience Chaos Studio (engine_ref des pannes de gothmog/experiments/)"
}
