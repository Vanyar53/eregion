# Journaux d'Entra ID du tenant → Log Analytics (C2, #199 ; ID1, #281).
#
# Les règles `source: azure_entra` de Glorfindel (glorfindel/rules/azure/
# detection_rules.yaml : identifiant ajouté, consentement d'application, rôle d'annuaire
# privilégié, connexion inhabituelle d'un principal de service) lisent les tables
# AuditLogs et AADServicePrincipalSignInLogs du workspace du banc. Elles n'y arrivent PAS
# par défaut : seulement par un paramètre de diagnostic posé sur le TENANT Entra ID (pas
# sur l'abonnement, contrairement au journal d'activité d'activity_log.tf). Sans lui, les
# tables sont vides et ces règles ne voient rien (aucune erreur).
#
# Désactivé par défaut : `entra_logs_enabled = true` dans terraform.tfvars (variables.tf),
# sur le tenant de l'abonnement du banc (celui du provider), puis `make
# celebrimbor-logs-plan`, puis `make celebrimbor-logs-up YES=1` (docs/operations.md, « Les
# journaux d'activité et d'Entra ID au banc »). Contraintes :
#   - un paramètre de diagnostic de tenant vit à l'échelle du TENANT entier : il voit
#     toutes les identités du tenant, pas seulement celles du banc → posé seulement par
#     l'instance canonique (workspace Terraform "default"), jamais par une stack
#     éphémère ;
#   - droit requis : le rôle d'Entra Administrateur de la sécurité (« Security
#     Administrator is the least privileged role required to configure diagnostic
#     settings », learn.microsoft.com/entra/identity/monitoring-health/
#     howto-access-activity-logs) ou Administrateur général — pas un rôle Azure sur
#     l'abonnement. Un principal de service, lui, demande Contributor à la portée
#     /providers/Microsoft.aadiam, attribué par un administrateur de l'accès élevé à la
#     racine (documentation du provider azurerm) : appliquer sous `az login`, jamais sous un
#     principal ;
#   - licence : Audit logs et Sign-in logs « Yes » pour Entra ID Free
#     (learn.microsoft.com/entra/fundamentals/licensing) ; ce qu'exige l'envoi des journaux
#     de connexion des principaux de service vers un workspace n'y est pas dit — à mesurer
#     (l'apply le dira) ;
#   - il disparaît avec la stack (`make celebrimbor-down`), le workspace avec lui.
# Lecture côté Glorfindel : aucun droit de plus (Log Analytics Reader sur le workspace) ;
# aucun droit sur Entra ID (Glorfindel n'y agit jamais).
#
# Coût : payé à l'ingestion (Analytics Logs, au Go ; 31 jours de rétention inclus) — un
# événement d'audit pèse environ 2 Ko, une connexion 11,5 Ko en moyenne
# (learn.microsoft.com/entra/identity/monitoring-health/
# concept-log-monitoring-integration-options-considerations). Estimation pour le banc :
# docs/operations.md.
#
# Catégories : AuditLogs et ServicePrincipalSignInLogs seules — ce que lisent les règles
# (tests/unit/test_bench_logs.py le vérifie). SignInLogs (connexions interactives des
# utilisateurs), NonInteractiveUserSignInLogs, ManagedIdentitySignInLogs ne sont lues par
# aucune règle : de l'ingestion payée pour rien ; un lot qui les lira les ajoutera avec sa
# règle. Latence : les événements partent par lots d'environ 5 minutes (même page) ; de
# bout en bout, à mesurer sur le banc.
#
# Désactivé, rien ne s'exécute : aucune lecture du tenant, aucun paramètre (`count`).

locals {
  entra_logs_enabled = var.entra_logs_enabled && local.instance == "default"
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
