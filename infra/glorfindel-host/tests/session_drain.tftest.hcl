# SEC11 (R-03) : la coupure des sessions, VM par VM, aux VM que Glorfindel défend (session_drain_vms)
# — planifiée contre un faux azurerm, aucun appel à Azure. La CI le lance à chaque PR (ci.yml, job
# terraform-test) ; à la main :
#   terraform -chdir=infra/glorfindel-host init -backend=false -lockfile=readonly
#   terraform -chdir=infra/glorfindel-host test
# Quatre cas : la liste du dépôt (session_drain.auto.tfvars, lue par le test comme par un plan) ;
# une attribution par VM listée, jamais au groupe ; une liste vide, rien ; un nom refusé.
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

# Chaque VM lue sur Azure : son id, celui que le faux rend pour son nom.
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

variables {
  # Une clé jetable (celle du test d'ID1 : sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  operator_cidr        = "203.0.113.7/32"
}

run "the_repositorys_list_gives_the_drain_to_gondolin_and_bree" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.session_drain) == 2 && contains(keys(azurerm_role_assignment.session_drain), "vm-celebrimbor-gondolin") && contains(keys(azurerm_role_assignment.session_drain), "vm-celebrimbor-bree")
    error_message = "la liste du dépôt (session_drain.auto.tfvars) ne donne pas la coupure à gondolin et bree"
  }
}

run "one_assignment_per_listed_vm_never_on_the_group" {
  command = plan

  variables {
    session_drain_vms = ["vm-celebrimbor-gondolin"]
  }

  assert {
    condition     = keys(azurerm_role_assignment.session_drain) == ["vm-celebrimbor-gondolin"]
    error_message = "la coupure ne va pas à la seule VM listée"
  }
  assert {
    condition     = azurerm_role_assignment.session_drain["vm-celebrimbor-gondolin"].scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
    error_message = "la coupure n'est pas attribuée à la portée de la VM"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.session_drain : a.scope != data.azurerm_resource_group.bench.id])
    error_message = "la coupure est attribuée sur tout le groupe du banc"
  }
  assert {
    condition     = alltrue([for a in azurerm_role_assignment.session_drain : a.role_definition_name == "Eregion Glorfindel Session Drain"])
    error_message = "la coupure n'est pas le rôle « Eregion Glorfindel Session Drain »"
  }
  assert {
    condition     = data.azurerm_virtual_machine.session_drain["vm-celebrimbor-gondolin"].resource_group_name == "rg-celebrimbor"
    error_message = "la VM n'est pas cherchée dans le groupe du banc"
  }
}

run "an_empty_list_gives_nothing" {
  command = plan

  variables {
    session_drain_vms = []
  }

  assert {
    condition     = length(azurerm_role_assignment.session_drain) == 0 && length(data.azurerm_virtual_machine.session_drain) == 0
    error_message = "une liste vide donne quand même la coupure"
  }
  assert {
    condition     = azurerm_role_assignment.bench_reader.role_definition_name == "Reader" && azurerm_role_assignment.bench_logs_reader.role_definition_name == "Log Analytics Reader"
    error_message = "les lectures de H0 ont changé"
  }
}

run "a_name_twice_or_a_path_is_refused" {
  command = plan

  variables {
    session_drain_vms = ["vm-celebrimbor-gondolin", "vm-celebrimbor-gondolin"]
  }

  expect_failures = [var.session_drain_vms]
}
