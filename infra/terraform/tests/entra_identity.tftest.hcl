# IDI1 (#546) : l'identité de test du banc dans Entra ID, inscrite par les deux clés — ses tags
# Graph (le banc, la zone) et `eregion-identities` sur le groupe du banc —, désactivée par défaut.
# Planifié contre de faux azurerm, azapi, null et azuread : aucun appel à Azure ni à Graph ; tous
# les identifiants sont des exemples. À la main :
#   terraform -chdir=infra/terraform init -backend=false -lockfile=readonly
#   terraform -chdir=infra/terraform test
# tests/unit/test_bench_identity.py tient le même contrat en lisant les fichiers.

mock_provider "azurerm" {}
mock_provider "azapi" {}
mock_provider "null" {}
mock_provider "azuread" {}

# L'application, connue dès le plan : ce que le groupe du banc nomme.
override_resource {
  target          = azuread_application.bench_test
  override_during = plan
  values = {
    object_id = "00000000-0000-0000-0000-0000000000c1"
    client_id = "00000000-0000-0000-0000-0000000000c2"
  }
}

variables {
  # La clé jetable du test d'ID1 (sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  # Hermétique face au terraform.tfvars de l'opérateur (qui peut les activer).
  activity_log_enabled        = false
  entra_logs_enabled          = false
  auditd_enabled              = false
  entra_test_identity_enabled = false
}

run "off_nothing_in_the_tenant_the_group_as_always" {
  command = plan

  assert {
    condition     = length(azuread_application.bench_test) == 0 && length(azuread_service_principal.bench_test) == 0
    error_message = "désactivée, l'identité de test est créée quand même"
  }
  assert {
    condition     = !contains(keys(azurerm_resource_group.celebrimbor.tags), "eregion-identities")
    error_message = "désactivée, le groupe du banc nomme une identité"
  }
  assert {
    condition     = azurerm_resource_group.celebrimbor.tags["eregion-target"] == "celebrimbor" && azurerm_resource_group.celebrimbor.tags["eregion-zone"] == "bench"
    error_message = "le groupe du banc perd son inscription"
  }
}

run "on_both_keys_one_per_plane" {
  command = plan

  variables {
    entra_test_identity_enabled = true
  }

  assert {
    condition     = length(azuread_application.bench_test) == 1 && length(azuread_service_principal.bench_test) == 1
    error_message = "activée, l'application ou son principal manque"
  }
  assert {
    condition     = toset(azuread_application.bench_test[0].tags) == toset(["eregion-target=celebrimbor", "eregion-zone=bench"])
    error_message = "la clé Entra n'est pas exactement le banc et sa zone"
  }
  assert {
    condition     = azuread_application.bench_test[0].sign_in_audience == "AzureADMyOrg"
    error_message = "l'application de test n'est pas mono-tenant : elle atteindrait d'autres tenants"
  }
  assert {
    condition     = azurerm_resource_group.celebrimbor.tags["eregion-identities"] == "00000000-0000-0000-0000-0000000000c1"
    error_message = "la clé ARM ne nomme pas l'application (son object id) sur le groupe du banc"
  }
  assert {
    condition     = azuread_service_principal.bench_test[0].client_id == "00000000-0000-0000-0000-0000000000c2"
    error_message = "le principal n'est pas celui de l'application de test"
  }
  assert {
    condition     = azurerm_resource_group.celebrimbor.tags["eregion-target"] == "celebrimbor" && azurerm_resource_group.celebrimbor.tags["eregion-zone"] == "bench"
    error_message = "activée, le groupe du banc perd son inscription"
  }
}
