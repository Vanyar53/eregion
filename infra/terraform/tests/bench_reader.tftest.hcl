# BRO1 (#614) : l'identité de lecture de la session Banc — une application mono-tenant, son principal,
# un certificat PUBLIC, et Log Analytics Reader sur le seul workspace du banc —, désactivée par défaut.
# Planifié contre de faux azurerm, azapi, null et azuread : aucun appel à Azure ni à Graph ; tous les
# identifiants sont des exemples, le certificat un certificat jetable (sa clé jamais gardée). À la main :
#   terraform -chdir=infra/terraform init -backend=false -lockfile=readonly
#   terraform -chdir=infra/terraform test -filter=tests/bench_reader.tftest.hcl
# tests/unit/test_bench_reader.py tient le même contrat en lisant les fichiers.

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
mock_provider "azuread" {}

# Connus dès le plan : ce que le rôle et la sortie nomment.
override_resource {
  target          = azuread_application.bench_reader
  override_during = plan
  values = {
    id        = "/applications/00000000-0000-0000-0000-0000000000b1"
    object_id = "00000000-0000-0000-0000-0000000000b1"
    client_id = "00000000-0000-0000-0000-0000000000b2"
  }
}

override_resource {
  target          = azuread_service_principal.bench_reader
  override_during = plan
  values = {
    object_id = "00000000-0000-0000-0000-0000000000b3"
  }
}

override_resource {
  target          = azuread_application_certificate.bench_reader
  override_during = plan
  values = {
    end_date = "2026-12-06T00:00:00Z"
  }
}

override_resource {
  target          = azurerm_log_analytics_workspace.celebrimbor
  override_during = plan
  values = {
    id           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-celebrimbor-example"
    workspace_id = "00000000-0000-0000-0000-0000000000a1"
  }
}

variables {
  # La clé jetable du test d'ID1 (sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  # Hermétique face au terraform.tfvars de l'opérateur (qui peut les activer).
  activity_log_enabled          = false
  entra_logs_enabled            = false
  auditd_enabled                = false
  entra_test_identity_enabled   = false
  entra_bench_unit_enabled      = false
  bench_reader_enabled          = false
  bench_reader_certificate_file = "tests/fixtures/bench_reader.crt"
}

run "off_nothing_in_the_tenant_nothing_on_the_workspace" {
  command = plan

  assert {
    condition = (length(azuread_application.bench_reader) == 0 && length(azuread_service_principal.bench_reader) == 0
    && length(azuread_application_certificate.bench_reader) == 0 && length(azurerm_role_assignment.bench_reader) == 0)
    error_message = "désactivée, l'identité de lecture est créée quand même"
  }
  assert {
    condition     = output.bench_reader == null
    error_message = "désactivée, la sortie nomme une identité de lecture"
  }
  assert {
    condition     = local.bench_reader_certificate == ""
    error_message = "désactivée, le certificat est lu quand même"
  }
}

run "on_the_exact_role_on_the_workspace_alone" {
  command = plan

  variables {
    bench_reader_enabled = true
  }

  assert {
    condition = (length(azuread_application.bench_reader) == 1 && length(azuread_service_principal.bench_reader) == 1
    && length(azuread_application_certificate.bench_reader) == 1 && length(azurerm_role_assignment.bench_reader) == 1)
    error_message = "activée, l'application, son principal, son certificat ou son rôle manque"
  }
  assert {
    condition     = azurerm_role_assignment.bench_reader[0].role_definition_name == "Log Analytics Reader"
    error_message = "le rôle n'est pas exactement Log Analytics Reader"
  }
  assert {
    condition     = azurerm_role_assignment.bench_reader[0].scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-celebrimbor-example"
    error_message = "le rôle n'est pas à la portée du seul workspace du banc"
  }
  assert {
    condition     = azurerm_role_assignment.bench_reader[0].principal_id == "00000000-0000-0000-0000-0000000000b3" && azurerm_role_assignment.bench_reader[0].principal_type == "ServicePrincipal"
    error_message = "le rôle ne va pas au principal de l'identité de lecture"
  }
  assert {
    condition     = azuread_service_principal.bench_reader[0].client_id == "00000000-0000-0000-0000-0000000000b2"
    error_message = "le principal n'est pas celui de l'application de lecture"
  }
  assert {
    condition     = azuread_application.bench_reader[0].sign_in_audience == "AzureADMyOrg"
    error_message = "l'application de lecture n'est pas mono-tenant"
  }
  assert {
    condition     = length(azuread_application.bench_reader[0].required_resource_access) == 0
    error_message = "l'application de lecture demande une permission"
  }
  assert {
    condition     = azuread_application_certificate.bench_reader[0].application_id == "/applications/00000000-0000-0000-0000-0000000000b1" && azuread_application_certificate.bench_reader[0].type == "AsymmetricX509Cert"
    error_message = "le certificat ne va pas à l'application de lecture, ou n'est pas un certificat"
  }
  assert {
    condition     = azuread_application_certificate.bench_reader[0].value == file("tests/fixtures/bench_reader.crt")
    error_message = "le certificat posé n'est pas celui du fichier nommé"
  }
  # Elle n'est pas une cible : ni la clé Entra, ni la clé ARM d'IDI1.
  assert {
    condition     = !contains(keys(azurerm_resource_group.celebrimbor.tags), "eregion-identities")
    error_message = "activée, le groupe du banc nomme une identité"
  }
  assert {
    condition = output.bench_reader == {
      tenant_id             = "00000000-0000-0000-0000-0000000000f0"
      client_id             = "00000000-0000-0000-0000-0000000000b2"
      workspace_id          = "00000000-0000-0000-0000-0000000000a1"
      workspace_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-celebrimbor-example"
      role                  = "Log Analytics Reader"
      certificate_end_date  = "2026-12-06T00:00:00Z"
    }
    error_message = "la sortie n'est pas exactement le tenant, l'application, le workspace, le rôle et la fin du certificat"
  }
}

run "on_a_private_key_beside_the_certificate_stops_the_plan" {
  command = plan

  variables {
    bench_reader_enabled          = true
    bench_reader_certificate_file = "tests/fixtures/bench_reader_two_blocks.pem"
  }

  expect_failures = [azuread_application_certificate.bench_reader]
}

run "on_no_certificate_file_stops_the_plan" {
  command = plan

  variables {
    bench_reader_enabled          = true
    bench_reader_certificate_file = "tests/fixtures/absent.crt"
  }

  expect_failures = [azuread_application_certificate.bench_reader]
}
