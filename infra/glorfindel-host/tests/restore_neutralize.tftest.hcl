# SEC17 : la neutralisation avant un restore (Run Command), VM par VM, aux VM que le restore défend
# (restore_vms), pour chaque principal qui restaure (restore_principals) — planifiée contre un faux
# azurerm, aucun appel à Azure. La CI le lance à chaque PR (ci.yml, job terraform-test, avec le
# reste du dossier tests/) ; à la main :
#   terraform -chdir=infra/glorfindel-host init -backend=false -lockfile=readonly
#   terraform -chdir=infra/glorfindel-host test
# Les cas : la liste du dépôt (restore.auto.tfvars) ; une attribution par principal et par VM,
# jamais au groupe, jamais à l'identité de H0 ; sans principal, rien ; un nom en double (la casse
# ignorée), un chemin à la place d'un nom, un principal qui n'est pas un object id, refusés ; et la
# même règle de casse pour session_drain_vms.
# tests/unit/test_glorfindel_host.py tient le même contrat en lisant les fichiers.

mock_provider "azurerm" {
  mock_data "azurerm_resource_group" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor"
    }
  }
  mock_data "azurerm_log_analytics_workspace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-celebrimbor"
    }
  }
}

override_data {
  target = data.azurerm_virtual_machine.session_drain["vm-celebrimbor-gondolin"]
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
  }
}

override_data {
  target = data.azurerm_virtual_machine.session_drain["vm-celebrimbor-bree"]
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"
  }
}

override_data {
  target = data.azurerm_virtual_machine.restore["vm-celebrimbor-gondolin"]
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
  }
}

override_data {
  target = data.azurerm_virtual_machine.restore["vm-celebrimbor-bree"]
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"
  }
}

variables {
  # Une clé jetable (celle du test d'ID1 : sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  operator_cidr        = "203.0.113.7/32"
  # Deux principaux d'exemple (aucun réel) : la console et le bot.
  restore_principals = {
    console = "aaaaaaaa-0000-0000-0000-000000000001"
    bot     = "aaaaaaaa-0000-0000-0000-000000000002"
  }
}

run "the_repositorys_list_gives_the_neutralization_on_gondolin_and_bree_to_each_principal" {
  command = plan

  assert {
    condition     = toset(keys(azurerm_role_assignment.restore_neutralize)) == toset(["bot/vm-celebrimbor-bree", "bot/vm-celebrimbor-gondolin", "console/vm-celebrimbor-bree", "console/vm-celebrimbor-gondolin"])
    error_message = "la liste du dépôt (restore.auto.tfvars) ne donne pas la neutralisation à gondolin et bree, pour la console et le bot"
  }
}

run "one_assignment_per_principal_and_vm_never_on_the_group" {
  command = plan

  variables {
    restore_vms = ["vm-celebrimbor-gondolin"]
  }

  assert {
    condition     = toset(keys(azurerm_role_assignment.restore_neutralize)) == toset(["bot/vm-celebrimbor-gondolin", "console/vm-celebrimbor-gondolin"])
    error_message = "la neutralisation ne va pas à la seule VM listée, pour chaque principal"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.restore_neutralize : a.scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"])
    error_message = "la neutralisation n'est pas attribuée à la portée de la VM"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.restore_neutralize : a.scope != data.azurerm_resource_group.bench.id])
    error_message = "la neutralisation est attribuée sur tout le groupe du banc"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.restore_neutralize : a.role_definition_name == "Eregion Glorfindel Restore Neutralize"])
    error_message = "la neutralisation n'est pas le rôle « Eregion Glorfindel Restore Neutralize »"
  }
  assert {
    condition     = azurerm_role_assignment.restore_neutralize["console/vm-celebrimbor-gondolin"].principal_id == "aaaaaaaa-0000-0000-0000-000000000001" && azurerm_role_assignment.restore_neutralize["bot/vm-celebrimbor-gondolin"].principal_id == "aaaaaaaa-0000-0000-0000-000000000002"
    error_message = "la neutralisation ne va pas aux principaux qui restaurent"
  }
  assert {
    condition     = data.azurerm_virtual_machine.restore["vm-celebrimbor-gondolin"].resource_group_name == "rg-celebrimbor"
    error_message = "la VM n'est pas cherchée dans le groupe du banc"
  }
  # La coupure des sessions, elle, reste à H0 seul, sur sa propre liste.
  assert {
    condition     = length(azurerm_role_assignment.session_drain) == 2
    error_message = "la liste du restore a changé la coupure des sessions"
  }
}

run "without_a_principal_nothing_is_given" {
  command = plan

  variables {
    restore_principals = {}
  }

  assert {
    condition     = length(azurerm_role_assignment.restore_neutralize) == 0
    error_message = "sans principal qui restaure, la neutralisation est quand même attribuée"
  }
}

run "h0_s_own_identity_never_restores" {
  command = plan

  # L'identité managée de H0, celle que le faux rend ; restore_principals la nomme.
  override_resource {
    target          = azurerm_linux_virtual_machine.host
    override_during = plan
    values = {
      identity = {
        type         = "SystemAssigned"
        principal_id = "11111111-1111-1111-1111-111111111111"
        tenant_id    = "22222222-2222-2222-2222-222222222222"
      }
    }
  }

  variables {
    restore_vms = ["vm-celebrimbor-gondolin"]
    restore_principals = {
      console = "11111111-1111-1111-1111-111111111111"
    }
  }

  expect_failures = [azurerm_role_assignment.restore_neutralize]
}

run "a_restore_vm_named_twice_whatever_its_case_is_refused" {
  command = plan

  variables {
    restore_vms = ["vm-celebrimbor-gondolin", "VM-Celebrimbor-Gondolin"]
  }

  expect_failures = [var.restore_vms]
}

run "a_path_for_a_restore_vm_is_refused" {
  command = plan

  variables {
    restore_vms = ["/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-other/providers/Microsoft.Compute/virtualMachines/vm-x"]
  }

  expect_failures = [var.restore_vms]
}

run "a_principal_that_is_not_an_object_id_is_refused" {
  command = plan

  variables {
    restore_principals = {
      console = "eregion-glorfindel-console"
    }
  }

  expect_failures = [var.restore_principals]
}

run "one_principal_under_two_names_is_refused" {
  command = plan

  variables {
    restore_principals = {
      console = "aaaaaaaa-0000-0000-0000-000000000001"
      bot     = "AAAAAAAA-0000-0000-0000-000000000001"
    }
  }

  expect_failures = [var.restore_principals]
}

run "a_drain_vm_named_twice_whatever_its_case_is_refused" {
  command = plan

  variables {
    session_drain_vms = ["vm-celebrimbor-gondolin", "VM-CELEBRIMBOR-GONDOLIN"]
  }

  expect_failures = [var.session_drain_vms]
}

# La console du poste isole elle-même ce qu'un humain approuve : la coupure des sessions, VM par VM,
# sur les VM de session_drain_vms (relecture de SEC17) ; jamais au groupe, jamais l'identité de H0.
run "the_console_gets_the_session_drain_on_each_drain_vm" {
  command = plan

  variables {
    session_drain_principals = {
      console = "aaaaaaaa-0000-0000-0000-000000000001"
    }
  }

  assert {
    condition     = toset(keys(azurerm_role_assignment.session_drain_principals)) == toset(["console/vm-celebrimbor-gondolin", "console/vm-celebrimbor-bree"])
    error_message = "la console ne reçoit pas la coupure sur chaque VM de session_drain_vms"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.session_drain_principals : a.role_definition_name == "Eregion Glorfindel Session Drain" && a.scope != data.azurerm_resource_group.bench.id && a.principal_id == "aaaaaaaa-0000-0000-0000-000000000001"])
    error_message = "la coupure de la console n'est pas Session Drain, à la portée d'une VM, pour son principal"
  }
  assert {
    condition     = azurerm_role_assignment.session_drain_principals["console/vm-celebrimbor-gondolin"].scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
    error_message = "la coupure de la console n'est pas à la portée de sa VM"
  }
}

run "without_a_drain_principal_only_h0_has_the_drain" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.session_drain_principals) == 0 && length(azurerm_role_assignment.session_drain) == 2
    error_message = "sans principal du poste, la coupure n'est pas celle de H0 seul"
  }
}

run "h0_s_own_identity_is_no_drain_principal" {
  command = plan

  override_resource {
    target          = azurerm_linux_virtual_machine.host
    override_during = plan
    values = {
      identity = {
        type         = "SystemAssigned"
        principal_id = "11111111-1111-1111-1111-111111111111"
        tenant_id    = "22222222-2222-2222-2222-222222222222"
      }
    }
  }

  variables {
    session_drain_principals = {
      console = "11111111-1111-1111-1111-111111111111"
    }
  }

  expect_failures = [azurerm_role_assignment.session_drain_principals]
}
