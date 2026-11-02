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

# ── G1 — le bruit bénin (chaos.noise_vms, vide par défaut : rien de créé) ──────────────────────
#
# Des pannes qui ne doivent rien déclencher de disruptif chez Glorfindel : des écritures disque
# au-dessus du seuil de ransomware-disk-write, une charge CPU, un redémarrage. Pour chaque VM de
# chaos.noise_vms (déjà dans shutdown_vms : le redémarrage passe par sa cible Microsoft-VirtualMachine) :
#   - l'agent Chaos sur la VM : une identité assignée par l'utilisateur, portée par la VM (vm.tf),
#     sans aucun rôle (elle ne sert qu'à authentifier l'agent auprès de Chaos Studio), et
#     l'extension ChaosLinuxAgent ;
#   - sa cible Microsoft-Agent, qui nomme cette identité. azurerm ne sait pas la déclarer
#     (azurerm_chaos_studio_target n'a pas de propriétés) : azapi, choisi avec Jonathan le 31/10 ;
#   - les capacités CPUPressure-1.0 et LinuxDiskIOPressure-1.1 (stress-ng) sur l'agent ;
#   - trois expériences : disk et cpu (chaos.noise_duration, 10 min), restart (chaos.restart_duration,
#     1 min, arrêt propre). Les pannes vues par Gothmog : gothmog/experiments/vm-disk-write.yaml,
#     vm-cpu-pressure.yaml et vm-restart.yaml ;
#   - leurs identités : Reader sur CETTE VM pour disk et cpu (ce que Microsoft demande pour une faute à
#     agent : lire la VM, rien écrire), le rôle sur mesure de G0 pour restart.
#
# Pas encore appliqué ni mesuré. À vérifier au premier plan avec Jonathan : stress-ng installé par
# l'extension, l'agent qui joint Chaos Studio, et le Heartbeat de la VM après l'ajout de l'identité
# (l'agent Azure Monitor garde l'identité système ; `make gothmog-preflight` le lit).

locals {
  # chaos.noise_vms du config.yaml, sauf si la variable le remplace (un plan de test).
  chaos_noise_keys = var.chaos_noise_vms != null ? var.chaos_noise_vms : try(local.cfg.chaos.noise_vms, [])
  chaos_noise_vms = local.chaos_enabled ? {
    for key in local.chaos_noise_keys : key => local.vms[key]
  } : {}
}

resource "azurerm_user_assigned_identity" "chaos_agent" {
  for_each            = local.chaos_noise_vms
  name                = "id-${local.project}-${each.key}-chaos-agent${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name
  tags                = local.common_tags

  lifecycle {
    precondition {
      condition     = try(each.value.enrolled, true)
      error_message = "Chaos Studio : ${each.key} n'est pas inscrite (enrolled: false) — aucun bruit ne la vise."
    }
    precondition {
      condition     = contains(keys(local.chaos_vms), each.key)
      error_message = "Chaos Studio : ${each.key} est dans noise_vms sans être dans shutdown_vms — le redémarrage passe par sa cible Microsoft-VirtualMachine."
    }
  }
}

resource "azapi_resource" "chaos_agent_target" {
  for_each  = local.chaos_noise_vms
  type      = "Microsoft.Chaos/targets@2024-01-01"
  name      = "Microsoft-Agent"
  parent_id = azurerm_linux_virtual_machine.baseline[each.key].id
  location  = azurerm_resource_group.celebrimbor.location

  body = {
    properties = {
      identities = [{
        type     = "AzureManagedIdentity"
        clientId = azurerm_user_assigned_identity.chaos_agent[each.key].client_id
        tenantId = azurerm_user_assigned_identity.chaos_agent[each.key].tenant_id
      }]
    }
  }

  # L'extension de l'agent attend le profil que Chaos Studio attribue à la cible.
  response_export_values = ["properties.agentProfileId"]

  lifecycle {
    precondition {
      condition     = try(each.value.enrolled, true)
      error_message = "Chaos Studio : ${each.key} n'est pas inscrite (enrolled: false) — aucun bruit ne la vise."
    }
  }
}

resource "azurerm_virtual_machine_extension" "chaos_agent" {
  for_each                   = local.chaos_noise_vms
  name                       = "ChaosLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.baseline[each.key].id
  publisher                  = "Microsoft.Azure.Chaos"
  type                       = "ChaosLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  settings = jsonencode({
    "profile"           = azapi_resource.chaos_agent_target[each.key].output.properties.agentProfileId
    "auth.msi.clientid" = azurerm_user_assigned_identity.chaos_agent[each.key].client_id
    "appinsightskey"    = ""
  })
}

resource "azurerm_chaos_studio_capability" "cpu" {
  for_each               = local.chaos_noise_vms
  chaos_studio_target_id = azapi_resource.chaos_agent_target[each.key].id
  capability_type        = "CPUPressure-1.0"
}

resource "azurerm_chaos_studio_capability" "disk" {
  for_each               = local.chaos_noise_vms
  chaos_studio_target_id = azapi_resource.chaos_agent_target[each.key].id
  capability_type        = "LinuxDiskIOPressure-1.1"
}

resource "azurerm_chaos_studio_experiment" "disk" {
  for_each            = local.chaos_noise_vms
  name                = "exp-${local.project}-${each.key}-disk${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name

  identity {
    type = "SystemAssigned"
  }

  selectors {
    name                    = each.key
    chaos_studio_target_ids = [azapi_resource.chaos_agent_target[each.key].id]
  }

  steps {
    name = "disk"
    branch {
      name = each.key
      actions {
        urn           = azurerm_chaos_studio_capability.disk[each.key].urn
        selector_name = each.key
        action_type   = "continuous"
        duration      = try(local.cfg.chaos.noise_duration, "PT10M")
        # La charge ; le débit atteint dépend du disque. L'effet déclaré par Gothmog dit s'il a
        # passé le seuil de la règle (25 MB/s) : sinon, le run échoue et ne compte pas.
        parameters = {
          workerCount         = tostring(try(local.cfg.chaos.disk_workers, 2))
          fileSizePerWorker   = try(local.cfg.chaos.disk_file_size, "1g")
          blockSize           = try(local.cfg.chaos.disk_block_size, "1m")
          targetTempDirectory = "/tmp/"
        }
      }
    }
  }
}

resource "azurerm_chaos_studio_experiment" "cpu" {
  for_each            = local.chaos_noise_vms
  name                = "exp-${local.project}-${each.key}-cpu${local.ns}"
  location            = azurerm_resource_group.celebrimbor.location
  resource_group_name = azurerm_resource_group.celebrimbor.name

  identity {
    type = "SystemAssigned"
  }

  selectors {
    name                    = each.key
    chaos_studio_target_ids = [azapi_resource.chaos_agent_target[each.key].id]
  }

  steps {
    name = "cpu"
    branch {
      name = each.key
      actions {
        urn           = azurerm_chaos_studio_capability.cpu[each.key].urn
        selector_name = each.key
        action_type   = "continuous"
        duration      = try(local.cfg.chaos.noise_duration, "PT10M")
        parameters = {
          pressureLevel = tostring(try(local.cfg.chaos.cpu_pressure, 95))
        }
      }
    }
  }
}

resource "azurerm_chaos_studio_experiment" "restart" {
  for_each            = local.chaos_noise_vms
  name                = "exp-${local.project}-${each.key}-restart${local.ns}"
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
    name = "restart"
    branch {
      name = each.key
      actions {
        urn           = azurerm_chaos_studio_capability.shutdown[each.key].urn
        selector_name = each.key
        action_type   = "continuous"
        duration      = try(local.cfg.chaos.restart_duration, "PT1M")
        parameters = {
          abruptShutdown = "false"
        }
      }
    }
  }
}

# Une faute à agent ne lit que la VM : Reader sur elle seule.
resource "azurerm_role_assignment" "chaos_disk_read" {
  for_each             = local.chaos_noise_vms
  scope                = azurerm_linux_virtual_machine.baseline[each.key].id
  role_definition_name = "Reader"
  principal_id         = azurerm_chaos_studio_experiment.disk[each.key].identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "chaos_cpu_read" {
  for_each             = local.chaos_noise_vms
  scope                = azurerm_linux_virtual_machine.baseline[each.key].id
  role_definition_name = "Reader"
  principal_id         = azurerm_chaos_studio_experiment.cpu[each.key].identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

# Le redémarrage : le rôle sur mesure de G0 (lire, éteindre, démarrer — pas supprimer), sur elle seule.
resource "azurerm_role_assignment" "chaos_restart" {
  for_each           = local.chaos_noise_vms
  scope              = azurerm_linux_virtual_machine.baseline[each.key].id
  role_definition_id = azurerm_role_definition.chaos_vm_shutdown[0].role_definition_resource_id
  principal_id       = azurerm_chaos_studio_experiment.restart[each.key].identity[0].principal_id
  principal_type     = "ServicePrincipal"
}

output "chaos_noise_experiments" {
  value = {
    for k in keys(local.chaos_noise_vms) : k => {
      disk    = azurerm_chaos_studio_experiment.disk[k].name
      cpu     = azurerm_chaos_studio_experiment.cpu[k].name
      restart = azurerm_chaos_studio_experiment.restart[k].name
    }
  }
  description = "Map clé hôte → expériences de bruit bénin (G1, engine_ref de gothmog/experiments/)"
}
