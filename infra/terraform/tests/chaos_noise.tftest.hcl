# G1 (#76) : le bruit bénin de Chaos Studio (chaos.tf), planifié contre de faux azurerm, azapi et
# null — aucun appel à Azure, comme le test d'ID1 (diagnostic_settings.tftest.hcl) :
#   terraform -chdir=infra/terraform init -backend=false
#   terraform -chdir=infra/terraform test
# Deux cas : la config du dépôt (chaos.noise_vms: []), dont le plan ne doit rien changer au banc ;
# le bruit sur gondolin, qui ne touche qu'elle. tests/unit/test_gothmog_noise.py tient le même
# contrat en lisant les fichiers.

mock_provider "azurerm" {}
mock_provider "azapi" {}
mock_provider "null" {}

variables {
  # La clé jetable du test d'ID1 (sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  # Hermétique face au terraform.tfvars de l'opérateur.
  activity_log_enabled = false
  entra_logs_enabled   = false
}

run "noise_off_the_bench_plan_is_unchanged" {
  command = plan

  variables {
    chaos_noise_vms = null # la config du dépôt, chaos.noise_vms
  }

  assert {
    condition = (length(azurerm_user_assigned_identity.chaos_agent) + length(azapi_resource.chaos_agent_target)
      + length(azurerm_virtual_machine_extension.chaos_agent) + length(azurerm_chaos_studio_capability.cpu)
      + length(azurerm_chaos_studio_capability.disk) + length(azurerm_chaos_studio_experiment.disk)
      + length(azurerm_chaos_studio_experiment.cpu) + length(azurerm_chaos_studio_experiment.restart)
      + length(azurerm_role_assignment.chaos_disk_read) + length(azurerm_role_assignment.chaos_cpu_read)
    + length(azurerm_role_assignment.chaos_restart)) == 0
    error_message = "une ressource de G1 est planifiée alors que chaos.noise_vms est vide"
  }
  assert {
    condition = alltrue([for k, vm in azurerm_linux_virtual_machine.baseline :
    vm.identity[0].type == "SystemAssigned" && length(coalesce(vm.identity[0].identity_ids, [])) == 0])
    error_message = "l'identité d'une VM du banc change alors que chaos.noise_vms est vide"
  }
  assert {
    condition     = keys(azurerm_chaos_studio_experiment.shutdown) == ["gondolin"] && length(azurerm_role_assignment.chaos_vm_shutdown) == 1
    error_message = "l'arrêt de G0 a changé"
  }
}

run "noise_on_gondolin_touches_gondolin_only" {
  command = plan

  variables {
    chaos_noise_vms = ["gondolin"]
  }

  assert {
    condition     = azurerm_linux_virtual_machine.baseline["gondolin"].identity[0].type == "SystemAssigned, UserAssigned"
    error_message = "gondolin ne porte pas l'identité de l'agent Chaos à côté de son identité système"
  }
  assert {
    condition = alltrue([for k, vm in azurerm_linux_virtual_machine.baseline :
    vm.identity[0].type == "SystemAssigned" && length(coalesce(vm.identity[0].identity_ids, [])) == 0 if k != "gondolin"])
    error_message = "une autre VM que gondolin (bree) change d'identité"
  }
  assert {
    condition     = keys(azapi_resource.chaos_agent_target) == ["gondolin"] && azapi_resource.chaos_agent_target["gondolin"].name == "Microsoft-Agent"
    error_message = "la cible Microsoft-Agent n'est pas sur gondolin seule"
  }
  assert {
    condition = (azurerm_chaos_studio_experiment.disk["gondolin"].name == "exp-celebrimbor-gondolin-disk"
      && azurerm_chaos_studio_experiment.cpu["gondolin"].name == "exp-celebrimbor-gondolin-cpu"
    && azurerm_chaos_studio_experiment.restart["gondolin"].name == "exp-celebrimbor-gondolin-restart")
    error_message = "les expériences ne sont pas les engine_ref de gothmog/experiments/"
  }
  assert {
    condition = (length(azurerm_role_assignment.chaos_disk_read) == 1 && length(azurerm_role_assignment.chaos_cpu_read) == 1
    && length(azurerm_role_assignment.chaos_restart) == 1)
    error_message = "les rôles des expériences de bruit ne sont pas trois, un par expérience"
  }
  assert {
    condition     = azurerm_role_assignment.chaos_disk_read["gondolin"].role_definition_name == "Reader" && azurerm_role_assignment.chaos_cpu_read["gondolin"].role_definition_name == "Reader"
    error_message = "une faute à agent reçoit plus que Reader"
  }
}
