# ID1 : les paramètres de diagnostic du banc, planifiés contre un faux azurerm — aucun appel
# à Azure (mock_provider : ni identifiant, ni jeton, ni lecture de l'abonnement ou du tenant).
#   terraform -chdir=infra/terraform init -backend=false
#   terraform -chdir=infra/terraform test
# (le provider vient du registre, ou d'un cache : `init -plugin-dir=…`). La CI ne l'exécute
# pas (pas de Terraform) ; tests/unit/test_bench_logs.py tient le même contrat en lisant les
# fichiers.

# Des identifiants de forme Azure (le provider les analyse au plan), aucun réel.
mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000"
    }
  }
  mock_resource "azurerm_log_analytics_workspace" {
    defaults = {
      id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.OperationalInsights/workspaces/law-test"
    }
  }
}
mock_provider "null" {}

variables {
  # Une clé jetable, générée pour ce test (sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
}

run "disabled_by_default_nothing_of_the_subscription_nor_the_tenant" {
  command = plan

  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.activity_log) == 0
    error_message = "le journal d'activité est posé par défaut"
  }
  assert {
    condition     = length(data.azurerm_subscription.current) == 0
    error_message = "l'abonnement est lu alors que le journal d'activité est désactivé"
  }
  assert {
    condition     = length(azurerm_monitor_aad_diagnostic_setting.entra) == 0
    error_message = "les journaux du tenant sont envoyés par défaut"
  }
}

run "activity_log_alone_administrative_only" {
  command = plan

  variables {
    activity_log_enabled = true
  }

  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.activity_log) == 1
    error_message = "activity_log_enabled = true ne pose pas le paramètre de l'abonnement"
  }
  assert {
    condition     = [for l in azurerm_monitor_diagnostic_setting.activity_log[0].enabled_log : l.category] == ["Administrative"]
    error_message = "le journal d'activité envoie autre chose que la catégorie Administrative"
  }
  assert {
    condition     = length(azurerm_monitor_aad_diagnostic_setting.entra) == 0
    error_message = "le journal d'activité entraîne les journaux du tenant"
  }
}

run "entra_alone_the_two_categories_the_rules_read" {
  command = plan

  variables {
    entra_logs_enabled = true
  }

  assert {
    condition     = length(azurerm_monitor_aad_diagnostic_setting.entra) == 1
    error_message = "entra_logs_enabled = true ne pose pas le paramètre du tenant"
  }
  assert {
    condition     = toset([for l in azurerm_monitor_aad_diagnostic_setting.entra[0].enabled_log : l.category]) == toset(["AuditLogs", "ServicePrincipalSignInLogs"])
    error_message = "le tenant envoie d'autres catégories que celles que lisent les règles"
  }
  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.activity_log) == 0 && length(data.azurerm_subscription.current) == 0
    error_message = "les journaux du tenant entraînent le journal d'activité"
  }
}
