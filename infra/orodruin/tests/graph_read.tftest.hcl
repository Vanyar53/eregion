# IDI1 (#546) : les seuls droits d'Orodruin dans Microsoft Graph — Application.Read.All et
# RoleManagement.Read.Directory, pour la garde d'une identité d'Entra ID — désactivés par défaut ; et
# ce que la garde sait avant de lire (le tenant, l'opérateur, les identités protégées). Planifié contre
# de faux azurerm et azuread, aucun appel à Azure ni à Graph ; tous les identifiants sont des exemples.
# À la main :
#   terraform -chdir=infra/orodruin init -backend=false -lockfile=readonly
#   terraform -chdir=infra/orodruin test
# tests/unit/test_bench_identity.py tient le même contrat en lisant les fichiers.

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
      id              = "/subscriptions/00000000-0000-0000-0000-000000000000"
      subscription_id = "00000000-0000-0000-0000-000000000000"
      tenant_id       = "00000000-0000-0000-0000-0000000000f0"
    }
  }
  mock_data "azurerm_client_config" {
    defaults = {
      object_id = "00000000-0000-0000-0000-0000000000ee"
    }
  }
}

# Microsoft Graph tel que le tenant le publie : son principal et deux de ses rôles d'application.
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
        "Application.Read.All"               = "00000000-0000-0000-0000-0000000000d1"
        "Application.ReadWrite.All"          = "00000000-0000-0000-0000-0000000000d2"
        "RoleManagement.Read.Directory"      = "00000000-0000-0000-0000-0000000000d3"
        "RoleManagement.ReadWrite.Directory" = "00000000-0000-0000-0000-0000000000d4"
      }
    }
  }
}

override_resource {
  target          = azurerm_storage_container.exercises
  override_during = plan
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-orodruin/providers/Microsoft.Storage/storageAccounts/storodruinexample/blobServices/default/containers/exercises"
  }
}

override_resource {
  target          = azurerm_storage_container.watch
  override_during = plan
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-orodruin/providers/Microsoft.Storage/storageAccounts/storodruinexample/blobServices/default/containers/watch"
  }
}

override_resource {
  target          = azurerm_linux_virtual_machine.host
  override_during = plan
  values = {
    id       = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-orodruin/providers/Microsoft.Compute/virtualMachines/vm-orodruin"
    identity = { principal_id = "00000000-0000-0000-0000-0000000000a0", tenant_id = "00000000-0000-0000-0000-0000000000f0" }
  }
}

variables {
  # Une clé jetable (celle du test d'ID1 : sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  operator_cidr        = "203.0.113.7/32"
  watch_principal_id   = "00000000-0000-0000-0000-0000000000b0"
  watch_subnet_id      = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-glorfindel/providers/Microsoft.Network/virtualNetworks/vnet-glorfindel/subnets/snet-glorfindel"
  # Hermétique face au terraform.tfvars d'Orodruin de l'opérateur (qui peut l'activer).
  graph_read_enabled = false
}

run "by_default_no_right_in_microsoft_graph" {
  command = plan

  assert {
    condition     = length(azuread_app_role_assignment.graph_read) == 0
    error_message = "par défaut, Orodruin reçoit un rôle de Microsoft Graph"
  }
  assert {
    condition     = length(data.azuread_service_principal.msgraph) == 0 && length(data.azuread_application_published_app_ids.well_known) == 0
    error_message = "désactivé, le tenant est lu quand même"
  }
}

run "enabled_the_two_reads_alone_to_orodruin" {
  command = plan

  variables {
    graph_read_enabled = true
  }

  assert {
    condition     = toset(keys(azuread_app_role_assignment.graph_read)) == toset(["Application.Read.All", "RoleManagement.Read.Directory"])
    error_message = "graph_read_enabled = true ne donne pas exactement les deux lectures de Graph"
  }
  assert {
    condition     = toset([for a in azuread_app_role_assignment.graph_read : a.app_role_id]) == toset(["00000000-0000-0000-0000-0000000000d1", "00000000-0000-0000-0000-0000000000d3"])
    error_message = "un rôle donné n'est pas une des deux lectures (une écriture, ou un autre droit)"
  }
  assert {
    condition     = alltrue([for a in azuread_app_role_assignment.graph_read : a.principal_object_id == "00000000-0000-0000-0000-0000000000a0"])
    error_message = "un rôle va à une autre identité que celle d'Orodruin"
  }
  assert {
    condition     = alltrue([for a in azuread_app_role_assignment.graph_read : a.resource_object_id == "00000000-0000-0000-0000-0000000000a8"])
    error_message = "un rôle est pris sur un autre principal que Microsoft Graph"
  }
}

run "what_the_guard_knows_before_reading" {
  command = plan

  assert {
    condition     = output.tenant_id == "00000000-0000-0000-0000-0000000000f0"
    error_message = "le tenant donné à la garde n'est pas celui de l'abonnement"
  }
  assert {
    condition     = output.operator_object_id == "00000000-0000-0000-0000-0000000000ee"
    error_message = "l'opérateur donné à la garde n'est pas celui qui applique"
  }
  assert {
    condition     = toset(split(",", output.protected_identities)) == toset(["00000000-0000-0000-0000-0000000000a0", "00000000-0000-0000-0000-0000000000b0"])
    error_message = "les identités protégées ne sont pas Orodruin et H0"
  }
}

run "the_listed_watches_are_protected_too" {
  command = plan

  variables {
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000c0", "00000000-0000-0000-0000-0000000000B0"]
  }

  assert {
    condition     = toset(split(",", output.protected_identities)) == toset(["00000000-0000-0000-0000-0000000000a0", "00000000-0000-0000-0000-0000000000b0", "00000000-0000-0000-0000-0000000000c0"])
    error_message = "une watch listée n'est pas protégée"
  }
}
