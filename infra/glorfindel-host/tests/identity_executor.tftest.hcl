# IR1b (#572) : l'application de l'exécuteur d'identité — son principal, ses deux permissions de
# Microsoft Graph (la liste fermée du contrat), Log Analytics Reader sur le workspace du banc, la
# partie publique de son certificat — désactivée par défaut. Planifiée contre de faux azurerm et
# azuread, aucun appel à Azure ni à Graph ; tous les identifiants sont des exemples. La CI le lance
# avec le reste du dossier (ci.yml, job terraform-test) ; à la main :
#   terraform -chdir=infra/glorfindel-host init -backend=false -lockfile=readonly
#   terraform -chdir=infra/glorfindel-host test
# tests/unit/test_identity_executor_host.py tient le même contrat en lisant les fichiers.

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
  mock_data "azurerm_subscription" {
    defaults = {
      id        = "/subscriptions/00000000-0000-0000-0000-000000000000"
      tenant_id = "00000000-0000-0000-0000-0000000000f0"
    }
  }
}

# Microsoft Graph tel que le tenant le publie : son principal et quelques-uns de ses rôles
# d'application, écritures larges comprises — le module ne doit en prendre que deux.
mock_provider "azuread" {
  mock_data "azuread_application_published_app_ids" {
    defaults = {
      result = { MicrosoftGraph = "00000000-0000-0000-0000-0000000000a9" }
    }
  }
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-0000000000a8"
      app_role_ids = {
        "Application.ReadWrite.OwnedBy"      = "00000000-0000-0000-0000-0000000000d1"
        "User.RevokeSessions.All"            = "00000000-0000-0000-0000-0000000000d2"
        "Application.ReadWrite.All"          = "00000000-0000-0000-0000-0000000000d3"
        "RoleManagement.ReadWrite.Directory" = "00000000-0000-0000-0000-0000000000d4"
        "Directory.ReadWrite.All"            = "00000000-0000-0000-0000-0000000000d5"
      }
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

# Le principal de l'exécuteur, tel que le tenant le rendrait.
override_resource {
  target          = azuread_service_principal.identity_executor
  override_during = plan
  values = {
    object_id = "00000000-0000-0000-0000-0000000000e2"
  }
}

override_resource {
  target          = azuread_application.identity_executor
  override_during = plan
  values = {
    id        = "/applications/00000000-0000-0000-0000-0000000000e3"
    client_id = "00000000-0000-0000-0000-0000000000e1"
  }
}

variables {
  # Une clé jetable (celle du test d'ID1 : sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  operator_cidr        = "203.0.113.7/32"
  # Hermétique face à un identity_executor.auto.tfvars de l'opérateur (qui peut l'activer).
  identity_executor_enabled     = false
  identity_executor_certificate = ""
}

run "by_default_nothing_in_the_tenant" {
  command = plan

  assert {
    condition     = length(azuread_application.identity_executor) == 0 && length(azuread_service_principal.identity_executor) == 0
    error_message = "par défaut, l'application de l'exécuteur est créée"
  }
  assert {
    condition     = length(azuread_app_role_assignment.identity_executor) == 0 && length(azurerm_role_assignment.identity_executor_logs_reader) == 0
    error_message = "par défaut, un droit est donné à l'exécuteur"
  }
  assert {
    condition     = length(data.azuread_service_principal.identity_executor_msgraph) == 0 && length(data.azuread_application_published_app_ids.identity_executor) == 0
    error_message = "désactivé, le tenant est lu quand même"
  }
  assert {
    condition     = output.identity_executor_client_id == "" && output.identity_executor_object_id == ""
    error_message = "désactivé, une identité de l'exécuteur est rendue"
  }
}

run "enabled_its_two_permissions_alone_to_its_own_principal" {
  command = plan

  variables {
    identity_executor_enabled = true
  }

  assert {
    condition     = toset(keys(azuread_app_role_assignment.identity_executor)) == toset(["Application.ReadWrite.OwnedBy", "User.RevokeSessions.All"])
    error_message = "activé, l'exécuteur ne reçoit pas exactement ses deux permissions de Graph"
  }
  assert {
    condition     = toset([for a in azuread_app_role_assignment.identity_executor : a.app_role_id]) == toset(["00000000-0000-0000-0000-0000000000d1", "00000000-0000-0000-0000-0000000000d2"])
    error_message = "une permission donnée n'est pas une des deux du contrat (une écriture large, un autre droit)"
  }
  assert {
    condition     = alltrue([for a in azuread_app_role_assignment.identity_executor : a.principal_object_id == "00000000-0000-0000-0000-0000000000e2"])
    error_message = "une permission va à une autre identité que celle de l'exécuteur (la VM de H0, la watch)"
  }
  assert {
    condition     = alltrue([for a in azuread_app_role_assignment.identity_executor : a.resource_object_id == "00000000-0000-0000-0000-0000000000a8"])
    error_message = "une permission est prise sur un autre principal que Microsoft Graph"
  }
  assert {
    condition     = azuread_application.identity_executor[0].sign_in_audience == "AzureADMyOrg"
    error_message = "l'application de l'exécuteur n'est pas mono-tenant"
  }
  assert {
    condition     = toset([for r in one(azuread_application.identity_executor[0].required_resource_access).resource_access : r.id]) == toset(["00000000-0000-0000-0000-0000000000d1", "00000000-0000-0000-0000-0000000000d2"])
    error_message = "l'application demande d'autres permissions que les deux du contrat"
  }
  assert {
    condition     = length(azuread_application_certificate.identity_executor) == 0
    error_message = "sans certificat donné, un identifiant est ajouté"
  }
  assert {
    condition     = output.identity_executor_client_id == "00000000-0000-0000-0000-0000000000e1" && output.identity_executor_object_id == "00000000-0000-0000-0000-0000000000e2"
    error_message = "les sorties ne sont pas l'application et le principal de l'exécuteur"
  }
}

run "enabled_it_reads_the_benchs_workspace_and_nothing_else_on_azure" {
  command = plan

  variables {
    identity_executor_enabled = true
  }

  assert {
    condition     = azurerm_role_assignment.identity_executor_logs_reader[0].scope == "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-celebrimbor"
    error_message = "la lecture de la preuve n'est pas à la portée du workspace du banc"
  }
  assert {
    condition     = azurerm_role_assignment.identity_executor_logs_reader[0].role_definition_name == "Log Analytics Reader" && azurerm_role_assignment.identity_executor_logs_reader[0].principal_id == "00000000-0000-0000-0000-0000000000e2"
    error_message = "l'exécuteur reçoit sur Azure autre chose que la lecture du workspace"
  }
}

run "its_certificate_is_its_public_part" {
  command = plan

  variables {
    identity_executor_enabled     = true
    identity_executor_certificate = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n"
  }

  assert {
    condition     = azuread_application_certificate.identity_executor[0].type == "AsymmetricX509Cert" && azuread_application_certificate.identity_executor[0].application_id == "/applications/00000000-0000-0000-0000-0000000000e3"
    error_message = "le certificat n'est pas posé sur l'application de l'exécuteur"
  }
}

run "a_private_key_is_refused" {
  command = plan

  variables {
    identity_executor_enabled     = true
    identity_executor_certificate = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIEexample\n-----END PRIVATE KEY-----\n"
  }

  expect_failures = [var.identity_executor_certificate]
}

run "what_is_no_certificate_is_refused" {
  command = plan

  variables {
    identity_executor_certificate = "ssh-ed25519 AAAAexample"
  }

  expect_failures = [var.identity_executor_certificate]
}
