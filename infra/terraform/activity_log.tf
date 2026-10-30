# Journal d'activité de l'abonnement → Log Analytics (AL1, #225 ; ID1, #281).
#
# Les règles `source: azure_activity` de Glorfindel (glorfindel/rules/azure/
# detection_rules.yaml : NSG modifié hors de Glorfindel, attribution de rôle, snapshot)
# lisent la table AzureActivity du workspace du banc. Elle n'y arrive PAS par défaut :
# seulement par un paramètre de diagnostic posé sur l'abonnement. Sans lui, la table est
# vide et ces règles ne voient rien (aucune erreur).
#
# Désactivé par défaut : `activity_log_enabled = true` dans terraform.tfvars (variables.tf),
# puis `make celebrimbor-logs-plan`, puis `make celebrimbor-logs-up YES=1` (docs/operations.md,
# « Les journaux d'activité et d'Entra ID au banc »). Contraintes :
#   - un paramètre de diagnostic d'abonnement vit à l'échelle de l'abonnement, pas du
#     groupe : 5 au plus par ressource (« Each resource can have up to five diagnostic
#     settings », learn.microsoft.com/azure/azure-monitor/platform/diagnostic-settings) ;
#     deux paramètres qui envoient la même catégorie au même workspace doublent les lignes
#     → posé seulement par l'instance canonique (workspace Terraform "default"), jamais par
#     une stack éphémère ;
#   - il disparaît avec la stack (`make celebrimbor-down`), le workspace avec lui ;
#   - droit requis : écrire des paramètres de diagnostic au niveau de l'abonnement —
#     Monitoring Contributor sur l'abonnement (Microsoft.Insights/DiagnosticSettings/*, et
#     Microsoft.OperationalInsights/workspaces/sharedKeys/action pour le workspace ;
#     learn.microsoft.com/azure/role-based-access-control/built-in-roles/monitor).
# Lecture côté Glorfindel : aucun droit de plus (Log Analytics Reader sur le workspace).
#
# Coût : aucun à l'ingestion — « There are no data ingestion charges for activity logs »
# (learn.microsoft.com/azure/azure-monitor/platform/activity-log) ; AzureActivity est une
# table gratuite (learn.microsoft.com/azure/azure-monitor/logs/cost-logs).
#
# Catégorie : Administrative seule — « all create, update, delete, and action operations
# performed through Resource Manager … any changes to Azure role-based access control »
# (learn.microsoft.com/azure/azure-monitor/platform/activity-log-schema) : ce que lisent
# les règles (tests/unit/test_bench_logs.py le vérifie). `Security` (les alertes de
# Defender for Cloud) n'est lue par aucune règle ; un lot qui lira Defender l'ajoutera avec
# sa règle. Latence d'ingestion : « 3 to 20 minutes » (la même page) — à mesurer sur le banc.
#
# Désactivé, rien ne s'exécute : ni le paramètre ni la lecture de l'abonnement (même
# `count`).

locals {
  activity_log_enabled = var.activity_log_enabled && local.instance == "default"
}

data "azurerm_subscription" "current" {
  count = local.activity_log_enabled ? 1 : 0
}

resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  count = local.activity_log_enabled ? 1 : 0

  name                       = "diag-${local.project}-activity"
  target_resource_id         = data.azurerm_subscription.current[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.celebrimbor.id

  enabled_log {
    category = "Administrative"
  }
}

# Une instance éphémère ne pose ni l'un ni l'autre des deux paramètres (abonnement, tenant) :
# le dire, plutôt qu'un plan muet qui laisserait croire qu'ils viennent.
check "diagnostic_settings_on_the_canonical_instance" {
  assert {
    condition     = local.instance == "default" || !(var.activity_log_enabled || var.entra_logs_enabled)
    error_message = "activity_log_enabled / entra_logs_enabled : sans effet sur l'instance « ${local.instance} » — les paramètres de diagnostic de l'abonnement et du tenant ne sont posés que par l'instance canonique (workspace Terraform default)."
  }
}
