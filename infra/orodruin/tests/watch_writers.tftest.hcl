# WC1 (#523) : qui écrit le canal retour et lit celui des fenêtres — la watch hébergée (H0) par
# défaut, comme avant WC1 ; sinon la watch d'un poste ou d'une équipe, une ou plusieurs. Planifié
# contre un faux azurerm, aucun appel à Azure ; tous les identifiants sont des exemples. À la main :
#   terraform -chdir=infra/orodruin init -backend=false -lockfile=readonly
#   terraform -chdir=infra/orodruin test
# tests/unit/test_orodruin.py tient le même contrat en lisant les fichiers.

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
    }
  }
  mock_data "azurerm_client_config" {
    defaults = {
      object_id = "00000000-0000-0000-0000-0000000000ee"
    }
  }
}

# IDI1 : azuread faux lui aussi (graph_read_enabled, désactivé par défaut) — aucun appel à Graph.
mock_provider "azuread" {}

# Les deux conteneurs et l'identité d'Orodruin, connus dès le plan : ce que les attributions visent.
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
  # H0 : son identité et son sous-réseau, comme le Makefile les lit dans son état.
  watch_principal_id = "00000000-0000-0000-0000-0000000000b0"
  watch_subnet_id    = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-glorfindel/providers/Microsoft.Network/virtualNetworks/vnet-glorfindel/subnets/snet-glorfindel"
}

run "by_default_the_hosted_watch_alone_as_before" {
  command = plan

  assert {
    condition     = length(azurerm_role_assignment.watch_channel_writer) == 1 && length(azurerm_role_assignment.channel_watch_reader) == 1
    error_message = "par défaut, H0 n'écrit plus le canal retour ou ne lit plus les fenêtres"
  }
  assert {
    condition     = azurerm_role_assignment.watch_channel_writer[0].principal_id == "00000000-0000-0000-0000-0000000000b0" && azurerm_role_assignment.channel_watch_reader[0].principal_id == "00000000-0000-0000-0000-0000000000b0"
    error_message = "par défaut, les droits du canal vont à une autre identité que celle de H0"
  }
  assert {
    condition     = length(azurerm_role_assignment.watch_channel_station_writer) == 0 && length(azurerm_role_assignment.channel_station_watch_reader) == 0
    error_message = "par défaut, une watch de poste reçoit des droits"
  }
}

run "a_station_watch_alone_writes_watch_and_reads_exercises" {
  command = plan

  variables {
    watch_principal_id  = ""
    watch_subnet_id     = ""
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000c1"]
  }

  assert {
    condition     = keys(azurerm_role_assignment.watch_channel_station_writer) == ["00000000-0000-0000-0000-0000000000c1"] && keys(azurerm_role_assignment.channel_station_watch_reader) == ["00000000-0000-0000-0000-0000000000c1"]
    error_message = "la watch du poste ne reçoit pas ses deux droits"
  }
  assert {
    condition     = azurerm_role_assignment.watch_channel_station_writer["00000000-0000-0000-0000-0000000000c1"].scope == azurerm_storage_container.watch.id && azurerm_role_assignment.watch_channel_station_writer["00000000-0000-0000-0000-0000000000c1"].role_definition_name == "Storage Blob Data Contributor"
    error_message = "la watch du poste n'écrit pas le conteneur watch, ou l'écrit d'un autre rôle"
  }
  assert {
    condition     = azurerm_role_assignment.channel_station_watch_reader["00000000-0000-0000-0000-0000000000c1"].scope == azurerm_storage_container.exercises.id && azurerm_role_assignment.channel_station_watch_reader["00000000-0000-0000-0000-0000000000c1"].role_definition_name == "Storage Blob Data Reader"
    error_message = "la watch du poste ne lit pas les fenêtres, ou les lit d'un rôle qui écrit"
  }
  assert {
    condition     = alltrue([for a in concat(values(azurerm_role_assignment.watch_channel_station_writer), values(azurerm_role_assignment.channel_station_watch_reader)) : a.principal_type == "ServicePrincipal" && a.principal_id == "00000000-0000-0000-0000-0000000000c1"])
    error_message = "un droit du canal va à une autre identité que celle de la watch du poste"
  }
  assert {
    condition     = length(azurerm_role_assignment.watch_channel_writer) == 0 && length(azurerm_role_assignment.channel_watch_reader) == 0
    error_message = "sans H0, une attribution de la watch hébergée est planifiée"
  }
}

run "several_watches_one_assignment_each_h0_kept_where_it_was" {
  command = plan

  variables {
    # H0 listé (en capitales : la casse ne compte pas), une watch de poste et celle d'une équipe.
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000B0", "00000000-0000-0000-0000-0000000000c1", "00000000-0000-0000-0000-0000000000c2"]
  }

  assert {
    condition     = length(azurerm_role_assignment.watch_channel_writer) == 1 && length(azurerm_role_assignment.channel_watch_reader) == 1
    error_message = "H0 listé perd ses attributions d'avant WC1 (son plan changerait)"
  }
  assert {
    condition     = toset(keys(azurerm_role_assignment.watch_channel_station_writer)) == toset(["00000000-0000-0000-0000-0000000000c1", "00000000-0000-0000-0000-0000000000c2"]) && toset(keys(azurerm_role_assignment.channel_station_watch_reader)) == toset(["00000000-0000-0000-0000-0000000000c1", "00000000-0000-0000-0000-0000000000c2"])
    error_message = "les watches de poste et d'équipe n'ont pas une attribution chacune, ou H0 en reçoit une seconde"
  }
  assert {
    condition     = alltrue([for a in values(azurerm_role_assignment.watch_channel_station_writer) : a.scope == azurerm_storage_container.watch.id]) && alltrue([for a in values(azurerm_role_assignment.channel_station_watch_reader) : a.scope == azurerm_storage_container.exercises.id])
    error_message = "une watch reçoit un droit hors de son conteneur"
  }
}

run "a_list_without_h0_leaves_h0_out" {
  command = plan

  variables {
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000c1"]
  }

  assert {
    condition     = length(azurerm_role_assignment.watch_channel_writer) == 0 && length(azurerm_role_assignment.channel_watch_reader) == 0
    error_message = "une liste qui ne nomme pas H0 lui laisse le canal"
  }
  assert {
    condition     = keys(azurerm_role_assignment.watch_channel_station_writer) == ["00000000-0000-0000-0000-0000000000c1"]
    error_message = "la watch du poste ne reçoit pas l'écriture du canal retour"
  }
}

run "an_empty_list_gives_the_channel_to_nobody" {
  command = plan

  variables {
    watch_principal_ids = []
  }

  assert {
    condition     = length(azurerm_role_assignment.watch_channel_writer) + length(azurerm_role_assignment.channel_watch_reader) + length(azurerm_role_assignment.watch_channel_station_writer) + length(azurerm_role_assignment.channel_station_watch_reader) == 0
    error_message = "une liste vide donne quand même un droit du canal"
  }
}

run "what_is_no_guid_is_refused" {
  command = plan

  variables {
    watch_principal_ids = ["eregion-glorfindel-watch"]
  }

  expect_failures = [var.watch_principal_ids]
}

run "a_path_for_an_identity_is_refused" {
  command = plan

  variables {
    watch_principal_ids = ["/subscriptions/00000000-0000-0000-0000-000000000000"]
  }

  expect_failures = [var.watch_principal_ids]
}

run "an_identity_named_twice_is_refused" {
  command = plan

  variables {
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000c1", "00000000-0000-0000-0000-0000000000C1"]
  }

  expect_failures = [var.watch_principal_ids]
}

run "orodruins_own_identity_never_writes_the_watch_channel" {
  command = plan

  variables {
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000A0"]
  }

  expect_failures = [azurerm_role_assignment.watch_channel_station_writer, azurerm_role_assignment.channel_station_watch_reader]
}

run "the_operators_own_login_never_writes_the_watch_channel" {
  command = plan

  variables {
    # Le object_id du faux azurerm_client_config : l'opérateur qui applique.
    watch_principal_ids = ["00000000-0000-0000-0000-0000000000EE"]
  }

  expect_failures = [azurerm_role_assignment.watch_channel_station_writer, azurerm_role_assignment.channel_station_watch_reader]
}

run "the_hosted_watch_without_its_subnet_is_still_refused" {
  command = plan

  variables {
    watch_subnet_id = ""
  }

  expect_failures = [azurerm_storage_account.channel]
}
