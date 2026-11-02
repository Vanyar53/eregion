# SEC11 (R-03) : la coupure des sessions, VM par VM, aux seules VM inscrites — planifiée contre un
# faux azurerm, aucun appel à Azure. La CI le lance à chaque PR (ci.yml, job terraform-test) ; à la
# main :
#   terraform -chdir=infra/glorfindel-host init -backend=false
#   terraform -chdir=infra/glorfindel-host test
# Trois cas : le défaut (H0 lecteur : aucun droit de plus) ; la coupure demandée, une attribution
# par VM inscrite et aucune sur le groupe ; une instance nommée du banc, dont le tag cherché suit
# le nom du groupe. tests/unit/test_glorfindel_host.py tient le même contrat en lisant les fichiers.

mock_provider "azurerm" {
  # Une VM inscrite du banc (gondolin) ; bree, jamais inscrite, n'est pas dans la liste : le
  # filtre par tag est celui d'Azure (required_tags), que le faux ne rejoue pas.
  mock_data "azurerm_resources" {
    defaults = {
      resources = [{
        id       = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
        name     = "vm-celebrimbor-gondolin"
        type     = "Microsoft.Compute/virtualMachines"
        location = "westeurope"
        tags     = { "eregion-target" = "celebrimbor", "eregion-zone" = "bench" }
      }]
    }
  }
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

variables {
  # Une clé jetable (celle du test d'ID1 : sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  operator_cidr        = "203.0.113.7/32"
}

run "by_default_h0_holds_no_session_drain" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.session_drain) == 0 && length(data.azurerm_resources.enrolled_vms) == 0
    error_message = "H0 reçoit la coupure des sessions sans session_drain = true"
  }
  assert {
    condition     = azurerm_role_assignment.bench_reader.role_definition_name == "Reader" && azurerm_role_assignment.bench_logs_reader.role_definition_name == "Log Analytics Reader"
    error_message = "les lectures de H0 ont changé"
  }
}

run "session_drain_goes_on_each_enrolled_vm_never_on_the_group" {
  command = plan

  variables {
    session_drain = true
  }

  assert {
    condition     = keys(azurerm_role_assignment.session_drain) == ["vm-celebrimbor-gondolin"]
    error_message = "la coupure ne va pas à la seule VM inscrite"
  }
  assert {
    condition     = endswith(azurerm_role_assignment.session_drain["vm-celebrimbor-gondolin"].scope, "/virtualMachines/vm-celebrimbor-gondolin")
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
    condition     = data.azurerm_resources.enrolled_vms[0].required_tags["eregion-target"] == "celebrimbor" && data.azurerm_resources.enrolled_vms[0].type == "Microsoft.Compute/virtualMachines"
    error_message = "les VM ne sont pas choisies par leur inscription (eregion-target=celebrimbor)"
  }
}

run "a_named_bench_looks_for_its_own_tag" {
  command = plan

  variables {
    session_drain        = true
    bench_resource_group = "rg-celebrimbor-ci"
  }

  assert {
    condition     = data.azurerm_resources.enrolled_vms[0].required_tags["eregion-target"] == "celebrimbor-ci"
    error_message = "une instance nommée du banc ne cherche pas son propre tag"
  }
}
