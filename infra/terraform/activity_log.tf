# Journal d'activité de l'abonnement → Log Analytics (AL1, #225) — PROPOSITION.
#
# Les règles `source: azure_activity` de Glorfindel (glorfindel/rules/azure/
# detection_rules.yaml : NSG modifié hors de Glorfindel, attribution de rôle, snapshot)
# lisent la table AzureActivity du workspace du banc. Elle n'y arrive PAS par défaut :
# seulement par un paramètre de diagnostic posé sur l'abonnement. Sans lui, la table est
# vide et ces règles ne voient rien (aucune erreur).
#
# Désactivé par défaut (`activity_log.enabled: false` dans config.yaml) : à activer par
# Jonathan, puis `make celebrimbor-up` (plan montré avant). Contraintes :
#   - un paramètre de diagnostic d'abonnement vit à l'échelle de l'abonnement, pas du
#     groupe : 5 au plus par abonnement, et Azure refuse deux paramètres qui envoient la
#     même catégorie au même workspace → posé seulement par l'instance canonique
#     (workspace Terraform "default"), jamais par une stack éphémère ;
#   - il disparaît avec la stack (`make celebrimbor-down`), le workspace avec lui ;
#   - droit requis : écrire des paramètres de diagnostic au niveau de l'abonnement
#     (Monitoring Contributor ou Contributor sur l'abonnement), pas seulement sur le groupe.
# Lecture côté Glorfindel : aucun droit de plus (Log Analytics Reader sur le workspace).
#
# Catégorie : Administrative seule (écritures, suppressions, actions sur les ressources :
# ce que lisent les règles). `Security` (les alertes de Defender for Cloud) n'est lue par
# aucune règle : retirée — de l'ingestion payée pour rien ; un lot qui lira Defender
# l'ajoutera avec sa règle. Latence d'ingestion à mesurer sur le banc (hypothèse :
# quelques minutes, parfois plus de dix).
#
# Désactivé, rien ne s'exécute : ni le paramètre ni la lecture de l'abonnement (même
# `count`).

locals {
  activity_log_enabled = try(local.cfg.activity_log.enabled, false) && local.instance == "default"
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
