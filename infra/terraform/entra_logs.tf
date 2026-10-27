# Journaux d'Entra ID du tenant → Log Analytics (C2, #199) — PROPOSITION.
#
# Les règles `source: azure_entra` de Glorfindel (glorfindel/rules/azure/
# detection_rules.yaml : identifiant ajouté, consentement d'application, rôle d'annuaire
# privilégié, connexion inhabituelle d'un principal de service) lisent les tables
# AuditLogs et AADServicePrincipalSignInLogs du workspace du banc. Elles n'y arrivent PAS
# par défaut : seulement par un paramètre de diagnostic posé sur le TENANT Entra ID (pas
# sur l'abonnement, contrairement au journal d'activité d'activity_log.tf). Sans lui, les
# tables sont vides et ces règles ne voient rien (aucune erreur).
#
# Désactivé par défaut (`entra_logs.enabled: false` dans config.yaml) : à activer par
# Jonathan, sur le tenant qu'il aura tranché (un tenant de test dédié, de préférence),
# puis `make celebrimbor-up` (plan montré avant). Contraintes — hypothèses de la
# documentation, à vérifier sur le tenant :
#   - un paramètre de diagnostic de tenant vit à l'échelle du TENANT entier : il voit
#     toutes les identités du tenant, pas seulement celles du banc → posé seulement par
#     l'instance canonique (workspace Terraform "default"), jamais par une stack
#     éphémère ; un nombre limité par tenant (5) ;
#   - droit requis : Administrateur général ou Administrateur de la sécurité sur le
#     tenant (pas un rôle Azure sur l'abonnement) ;
#   - licence : AuditLogs sans licence particulière ; les journaux de connexion
#     (ServicePrincipalSignInLogs) dans un workspace demandent Entra ID P1 ou P2 ;
#   - il disparaît avec la stack (`make celebrimbor-down`), le workspace avec lui.
# Lecture côté Glorfindel : aucun droit de plus (Log Analytics Reader sur le workspace) ;
# aucun droit sur Entra ID (Glorfindel n'y agit jamais).
#
# Catégories : AuditLogs et ServicePrincipalSignInLogs seules — ce que lisent les règles.
# SignInLogs (connexions interactives des utilisateurs), NonInteractiveUserSignInLogs,
# ManagedIdentitySignInLogs ne sont lues par aucune règle : de l'ingestion payée pour
# rien ; un lot qui les lira les ajoutera avec sa règle. Latence d'ingestion à mesurer
# sur le banc (hypothèse : quelques minutes, parfois plus de dix).
#
# Désactivé, rien ne s'exécute : aucune lecture du tenant, aucun paramètre (`count`).

locals {
  entra_logs_enabled = try(local.cfg.entra_logs.enabled, false) && local.instance == "default"
}

resource "azurerm_monitor_aad_diagnostic_setting" "entra" {
  count = local.entra_logs_enabled ? 1 : 0

  name                       = "diag-${local.project}-entra"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.celebrimbor.id

  enabled_log {
    category = "AuditLogs"
  }

  enabled_log {
    category = "ServicePrincipalSignInLogs"
  }
}
