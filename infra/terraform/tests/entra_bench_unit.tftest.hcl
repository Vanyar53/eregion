# IDI1b (#573) : l'unité administrative restreinte du banc, épinglée par son id ; ses utilisateurs de
# test, sans rôle, l'attribut d'inscription posé avant leur appartenance ; les trois rôles de
# l'exécuteur d'IR1, chacun à sa portée et vérifié contre la liste des modèles du tenant ; désactivé
# par défaut. Planifié contre de faux azurerm, azapi, null et azuread : aucun appel à Azure ni à
# Graph ; tous les identifiants sont des exemples (les modèles de rôle, ceux, publics, de Microsoft).
# À la main :
#   terraform -chdir=infra/terraform init -backend=false -lockfile=readonly
#   terraform -chdir=infra/terraform test
# tests/unit/test_bench_users.py tient le même contrat en lisant les fichiers.

mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000000"
      tenant_id = "00000000-0000-0000-0000-0000000000f0"
    }
  }
}
mock_provider "azapi" {}
mock_provider "null" {}
mock_provider "azuread" {
  mock_data "azuread_domains" {
    defaults = {
      domains = [{
        admin_managed       = true
        authentication_type = "Managed"
        default             = true
        domain_name         = "example.onmicrosoft.com"
        initial             = true
        root                = true
        supported_services  = []
        verified            = true
      }]
    }
  }
  mock_data "azuread_directory_role_templates" {
    defaults = {
      role_templates = [
        { display_name = "User Administrator", object_id = "fe930be7-5e62-47db-91af-98c3a49a38b1", description = "" },
        { display_name = "Directory Readers", object_id = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", description = "" },
        { display_name = "Attribute Assignment Reader", object_id = "ffd52fa5-98dc-465c-991d-fc073eb59f8f", description = "" },
        { display_name = "Global Administrator", object_id = "62e90394-69f5-4237-9190-012177145e10", description = "" },
      ]
    }
  }
}

override_resource {
  target          = azuread_user.bench_test
  override_during = plan
  values = {
    object_id = "00000000-0000-0000-0000-0000000000c5"
  }
}

variables {
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  # Hermétique face au terraform.tfvars de l'opérateur (qui peut les activer).
  activity_log_enabled              = false
  entra_logs_enabled                = false
  auditd_enabled                    = false
  entra_test_identity_enabled       = false
  entra_bench_unit_enabled          = false
  bench_reader_enabled              = false
  entra_bench_unit_id               = ""
  entra_test_users                  = ["tuor"]
  entra_identity_executor_object_id = ""
}

run "off_nothing_in_the_tenant" {
  command = plan

  assert {
    condition     = length(data.azuread_administrative_unit.bench) == 0 && length(data.azuread_domains.initial) == 0
    error_message = "désactivée, l'unité ou le domaine du tenant est lu quand même"
  }
  assert {
    condition     = length(azuread_user.bench_test) == 0 && length(azuread_administrative_unit_member.bench_test) == 0 && length(terraform_data.bench_test_user_attributes) == 0
    error_message = "désactivée, un utilisateur de test, son attribut ou son appartenance est posé quand même"
  }
  assert {
    condition     = length(azuread_directory_role_assignment.identity_executor) == 0 && length(data.azuread_directory_role_templates.all) == 0
    error_message = "désactivée, un rôle d'annuaire est attribué quand même"
  }
  assert {
    condition     = output.entra_bench_unit_id == "" && length(output.entra_test_user_object_ids) == 0
    error_message = "désactivée, une sortie nomme une unité ou un utilisateur"
  }
}

run "on_the_unit_pinned_its_users_held_after_their_attribute" {
  command = plan

  variables {
    entra_bench_unit_enabled = true
    entra_bench_unit_id      = "00000000-0000-0000-0000-0000000000d0"
  }

  assert {
    condition     = output.entra_bench_unit_id == "00000000-0000-0000-0000-0000000000d0"
    error_message = "l'id de l'unité ne sort pas tel qu'épinglé"
  }
  assert {
    condition     = output.entra_attribute_set == "Eregion"
    error_message = "l'ensemble d'attributs ne sort pas sous le nom que l'exécuteur lit"
  }
  assert {
    condition     = data.azuread_administrative_unit.bench[0].object_id == "00000000-0000-0000-0000-0000000000d0"
    error_message = "l'unité n'est pas lue par son id épinglé"
  }
  assert {
    condition     = keys(azuread_user.bench_test) == ["tuor"] && azuread_user.bench_test["tuor"].user_principal_name == "tuor.celebrimbor@example.onmicrosoft.com"
    error_message = "l'utilisateur de test n'est pas celui du banc, dans le domaine initial du tenant"
  }
  assert {
    condition     = azuread_user.bench_test["tuor"].account_enabled == true
    error_message = "l'utilisateur de test est créé désactivé : l'exécuteur n'aurait rien à désactiver"
  }
  assert {
    condition     = azuread_administrative_unit_member.bench_test["tuor"].administrative_unit_object_id == "00000000-0000-0000-0000-0000000000d0" && azuread_administrative_unit_member.bench_test["tuor"].member_object_id == "00000000-0000-0000-0000-0000000000c5"
    error_message = "l'utilisateur de test n'entre pas dans l'unité épinglée"
  }
  assert {
    condition     = terraform_data.bench_test_user_attributes["tuor"].triggers_replace == ["00000000-0000-0000-0000-0000000000c5", "celebrimbor", "bench"]
    error_message = "l'attribut d'inscription ne nomme pas l'utilisateur, le banc et la zone du banc"
  }
  assert {
    condition     = length(azuread_directory_role_assignment.identity_executor) == 0
    error_message = "sans exécuteur nommé, un rôle d'annuaire est attribué"
  }
  assert {
    condition     = length(output.entra_test_user_object_ids) == 1 && output.entra_test_user_object_ids["tuor"] == "00000000-0000-0000-0000-0000000000c5"
    error_message = "la sortie ne nomme pas l'utilisateur de test"
  }
}

run "on_the_executor_three_roles_each_at_its_scope" {
  command = plan

  variables {
    entra_bench_unit_enabled          = true
    entra_bench_unit_id               = "00000000-0000-0000-0000-0000000000d0"
    entra_identity_executor_object_id = "00000000-0000-0000-0000-0000000000a7"
  }

  assert {
    condition     = toset(keys(azuread_directory_role_assignment.identity_executor)) == toset(["user_administrator", "directory_readers", "attribute_assignment_reader"])
    error_message = "l'exécuteur ne reçoit pas exactement ses trois rôles"
  }
  assert {
    condition     = azuread_directory_role_assignment.identity_executor["user_administrator"].role_id == "fe930be7-5e62-47db-91af-98c3a49a38b1" && azuread_directory_role_assignment.identity_executor["user_administrator"].directory_scope_id == "/administrativeUnits/00000000-0000-0000-0000-0000000000d0"
    error_message = "User Administrator n'est pas borné à l'unité du banc"
  }
  assert {
    condition     = azuread_directory_role_assignment.identity_executor["directory_readers"].role_id == "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" && azuread_directory_role_assignment.identity_executor["directory_readers"].directory_scope_id == "/"
    error_message = "Directory Readers n'est pas au tenant"
  }
  assert {
    condition     = azuread_directory_role_assignment.identity_executor["attribute_assignment_reader"].role_id == "ffd52fa5-98dc-465c-991d-fc073eb59f8f" && azuread_directory_role_assignment.identity_executor["attribute_assignment_reader"].directory_scope_id == "/attributeSets/Eregion"
    error_message = "Attribute Assignment Reader n'est pas borné à l'ensemble Eregion"
  }
  assert {
    condition     = alltrue([for a in azuread_directory_role_assignment.identity_executor : a.principal_object_id == "00000000-0000-0000-0000-0000000000a7"])
    error_message = "un rôle va à un autre principal que l'exécuteur : un utilisateur de test n'en tient aucun"
  }
}

run "on_without_the_pinned_unit_the_plan_stops" {
  command = plan

  variables {
    entra_bench_unit_enabled = true
    entra_bench_unit_id      = ""
  }

  expect_failures = [data.azuread_administrative_unit.bench]
}

run "a_role_template_the_tenant_names_otherwise_stops_the_plan" {
  command = plan

  variables {
    entra_bench_unit_enabled          = true
    entra_bench_unit_id               = "00000000-0000-0000-0000-0000000000d0"
    entra_identity_executor_object_id = "00000000-0000-0000-0000-0000000000a7"
  }

  override_data {
    target = data.azuread_directory_role_templates.all
    values = {
      role_templates = [
        { display_name = "Global Administrator", object_id = "fe930be7-5e62-47db-91af-98c3a49a38b1", description = "" },
        { display_name = "Directory Readers", object_id = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b", description = "" },
        { display_name = "Attribute Assignment Reader", object_id = "ffd52fa5-98dc-465c-991d-fc073eb59f8f", description = "" },
      ]
    }
  }

  expect_failures = [azuread_directory_role_assignment.identity_executor]
}

run "a_unit_id_that_is_no_object_id_is_refused" {
  command = plan

  variables {
    entra_bench_unit_enabled = true
    entra_bench_unit_id      = "au-celebrimbor-bench"
  }

  expect_failures = [var.entra_bench_unit_id]
}
