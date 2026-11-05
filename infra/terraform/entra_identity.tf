# Une identité de test du banc dans Entra ID, inscrite (IDI1, #546) — la cible des techniques
# d'identité (R2 : Stratus Red Team), lue par les règles de C2 (entra_logs.tf).
#
# Une identité d'Entra ID ne porte pas de tag ARM : elle s'inscrit par deux clés, une par plan
# (eregion_core/inscription.py, identity_enrollment) :
#   - Entra : les `tags` de l'APPLICATION nomment le banc et la zone, `eregion-target=<banc>` et
#     `eregion-zone=bench` ;
#   - ARM : le groupe du banc la nomme, `eregion-identities=<object id de l'application>`
#     (main.tf), sa zone concordant.
# Une clé seule n'ouvre rien : n'importe quel membre peut enregistrer une application et la
# taguer, pas écrire sur le groupe du banc. La garde exige aussi : le tenant du banc, une
# application mono-tenant (AzureADMyOrg) et son principal de type Application ; jamais
# l'identité de Glorfindel, d'Orodruin ni de l'opérateur.
#
# Ce que ce fichier pose, et rien d'autre : une application mono-tenant, sans secret ni
# certificat ni identifiant fédéré (aucun `azuread_application_password` : une technique en
# ajoute un, et la règle entra-credential-added le voit), sans permission demandée, sans
# propriétaire nommé ; son principal de service. Ils n'ont aucun droit : aucun rôle Azure,
# aucun rôle d'annuaire, aucun consentement.
#
# Désactivé par défaut : `entra_test_identity_enabled = true` dans terraform.tfvars (variables.tf),
# puis `make celebrimbor-identity-plan`, puis `make celebrimbor-identity-up YES=1` (docs/operations.md,
# « L'identité de test du banc (IDI1) »). Contraintes :
#   - instance canonique seule (workspace Terraform "default") : une identité vit dans le tenant,
#     pas dans une stack ; une autre instance ne la pose pas, et le plan le dit
#     (check "entra_test_identity_on_the_canonical_instance", ci-dessous) ;
#   - droit requis : créer une application dans le tenant — le rôle d'Entra Développeur
#     d'applications, ou plus (Administrateur d'applications, général) ; ou le réglage par défaut
#     « Les utilisateurs peuvent inscrire des applications » ; appliquer sous `az login`, jamais
#     sous un principal ;
#   - elle disparaît avec la stack (`make celebrimbor-down`), ou remise à false.
# Lecture côté Orodruin (la garde) : `Application.Read.All` dans Microsoft Graph
# (infra/orodruin, graph_read_enabled) et Reader sur le groupe du banc (déjà là).
#
# Désactivé, rien ne s'exécute : aucune lecture ni écriture du tenant (`count`).

locals {
  entra_test_identity_enabled = var.entra_test_identity_enabled && local.instance == "default"

  # La clé Entra : le banc et la zone, tels que l'inscription d'une VM les porte (locals.tf).
  identity_enrollment_tags = [
    "eregion-target=${local.common_tags["eregion-target"]}",
    "eregion-zone=${local.common_tags["eregion-zone"]}",
  ]

  # La clé ARM, posée sur le groupe du banc (main.tf) : l'object id de l'application.
  identity_tags = local.entra_test_identity_enabled ? {
    "eregion-identities" = azuread_application.bench_test[0].object_id
  } : {}
}

resource "azuread_application" "bench_test" {
  count = local.entra_test_identity_enabled ? 1 : 0

  display_name     = "app-${local.project}-test"
  description      = "Eregion (IDI1) : identité de test du banc, cible des techniques d'identité. Aucun droit."
  sign_in_audience = "AzureADMyOrg"
  tags             = local.identity_enrollment_tags
}

resource "azuread_service_principal" "bench_test" {
  count = local.entra_test_identity_enabled ? 1 : 0

  client_id                    = azuread_application.bench_test[0].client_id
  app_role_assignment_required = true
  description                  = "Eregion (IDI1) : principal de l'identité de test du banc. Aucun droit."
}

# Une instance éphémère ne la pose pas : le dire, plutôt qu'un plan muet.
check "entra_test_identity_on_the_canonical_instance" {
  assert {
    condition     = local.instance == "default" || !var.entra_test_identity_enabled
    error_message = "entra_test_identity_enabled : sans effet sur l'instance « ${local.instance} » — l'identité de test vit dans le tenant, une seule, posée par l'instance canonique (workspace Terraform default)."
  }
}
