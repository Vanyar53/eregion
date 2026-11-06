# L'identité de lecture du banc (BRO1, #614) — la session Claude « Banc » lit les détections et les
# rapports du banc (KQL sur le workspace Log Analytics du banc) sans demander chaque fois à Jonathan.
# Décision de Jonathan (06/11) : Log Analytics Reader sur le SEUL workspace du banc, aucun droit
# d'écriture ; jamais pour un lot de code, seulement la session « Banc ». docs/operations.md,
# « L'identité de lecture du banc (BRO1) » ; docs/design/modele-de-menace.md, frontière 8.
#
# Le type d'identité : une application mono-tenant et son principal de service, authentifiés par un
# CERTIFICAT dont la clé privée est tirée sur le poste de l'opérateur (make celebrimbor-reader-key :
# scripts/bench_reader.py keygen, 30 jours par défaut, 90 au plus). Terraform ne reçoit que le
# certificat PUBLIC : la clé privée n'entre jamais dans l'état (infra/terraform/terraform.tfstate,
# local, lisible par toute session qui tourne sous le même utilisateur). Un secret
# (azuread_application_password) y entrerait en clair ; une identité managée ne s'attache pas à un
# poste sous WSL ; un identifiant fédéré exige un émetteur OIDC que le poste n'a pas ; le compte de
# l'opérateur porte tous ses droits. Comparaison : docs/operations.md.
#
# Ce que ce fichier pose, et rien d'autre :
#   - une application mono-tenant (AzureADMyOrg), sans permission demandée (aucun
#     required_resource_access), sans propriétaire nommé, SANS les tags d'inscription (elle n'est pas
#     une cible : ni eregion-target ni eregion-zone, jamais nommée par eregion-identities) ;
#   - son principal de service ;
#   - un certificat public sur l'application, lu du fichier que bench_reader_certificate_file
#     nomme : un seul bloc CERTIFICATE, rien d'autre (une clé privée collée là par erreur arrête le
#     plan avant d'entrer dans l'état, et le diagnostic ne la montre pas : la valeur est sensible) ;
#     sa fin est celle du certificat, lue de bench_reader_certificate_end_file (keygen l'écrit),
#     91 jours au plus après le plan ;
#   - UNE attribution de rôle Azure : Log Analytics Reader, à la portée du workspace du banc seul —
#     ni le groupe, ni l'abonnement, ni H0 (rg-glorfindel), ni un autre workspace. Aucun rôle
#     d'annuaire, aucun consentement dans Microsoft Graph.
#
# Désactivé par défaut : `bench_reader_enabled = true` dans terraform.tfvars (persistant, jamais en
# `-var` d'une seule commande : le prochain apply sans lui la retirerait), puis
# `make celebrimbor-reader-key`, `make celebrimbor-reader-plan`, `make celebrimbor-reader-up YES=1`,
# `make celebrimbor-reader-profile`. Contraintes :
#   - instance canonique seule (workspace Terraform "default") : l'application vit dans le tenant ;
#     une autre instance ne la pose pas, et le plan le dit (check ci-dessous) ;
#   - droits de l'apply (un az login, jamais un principal) : créer une application (Développeur
#     d'applications, ou plus) ; attribuer un rôle sur le workspace (Propriétaire ou Administrateur
#     de l'accès utilisateur sur le groupe du banc, ce que l'apply du banc a déjà) ;
#   - remise à false, le même `make celebrimbor-reader-up` retire l'application, son principal, son
#     certificat et son rôle.
#
# Désactivé, rien ne s'exécute : aucune lecture du fichier, aucune lecture ni écriture du tenant (count).

variable "bench_reader_enabled" {
  description = "L'identité de lecture de la session Banc (BRO1) : une application mono-tenant, son principal, un certificat public tiré sur le poste de l'opérateur (la clé privée n'entre jamais dans l'état), et Log Analytics Reader sur le seul workspace du banc. Instance canonique seule. Droits : créer une application, attribuer un rôle sur le workspace. Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

variable "bench_reader_certificate_file" {
  description = "Le certificat PUBLIC (PEM, un seul bloc CERTIFICATE) de l'identité de lecture, tiré par make celebrimbor-reader-key. Lu seulement quand bench_reader_enabled ; jamais la clé privée."
  type        = string
  default     = "~/.config/eregion-banc/reader.crt"
  nullable    = false
}

variable "bench_reader_certificate_end_file" {
  description = "La fin du certificat (RFC 3339, UTC), écrite par make celebrimbor-reader-key à côté du certificat : la fin de l'identifiant posé sur l'application, 91 jours au plus après le plan. Lu seulement quand bench_reader_enabled."
  type        = string
  default     = "~/.config/eregion-banc/reader.end"
  nullable    = false
}

locals {
  bench_reader_enabled = var.bench_reader_enabled && local.instance == "default"

  # Le rôle, et lui seul : lire et interroger le workspace (*/read, query, search), sans ses clés
  # partagées (définition intégrée d'Azure). Il porterait aussi Microsoft.Support/* (ouvrir un ticket
  # de support), sans prise sur le workspace : hypothèse jusqu'à la mesure (docs/operations.md,
  # « À mesurer au banc »).
  bench_reader_role = "Log Analytics Reader"

  # Lu seulement activé ; un fichier absent donne "" et la précondition du certificat le dit. Sensible :
  # une clé privée collée là par erreur n'apparaît pas dans le diagnostic de la précondition.
  bench_reader_certificate = local.bench_reader_enabled ? sensitive(try(file(pathexpand(var.bench_reader_certificate_file)), "")) : ""

  # La fin du certificat, que keygen écrit à côté (RFC 3339, UTC) : posée telle quelle sur
  # l'identifiant. Sans elle, l'API choisit (« typiquement deux ans », dit le fournisseur azuread).
  bench_reader_certificate_end = local.bench_reader_enabled ? trimspace(try(file(pathexpand(var.bench_reader_certificate_end_file)), "")) : ""
}

resource "azuread_application" "bench_reader" {
  count = local.bench_reader_enabled ? 1 : 0

  display_name     = "app-${local.project}-bench-reader"
  description      = "Eregion (BRO1) : la session Banc lit les journaux du banc. Log Analytics Reader sur le workspace du banc, rien d'autre."
  sign_in_audience = "AzureADMyOrg"
}

resource "azuread_service_principal" "bench_reader" {
  count = local.bench_reader_enabled ? 1 : 0

  client_id                    = azuread_application.bench_reader[0].client_id
  app_role_assignment_required = true
  description                  = "Eregion (BRO1) : principal de l'identité de lecture du banc. Log Analytics Reader sur le workspace du banc, rien d'autre."
}

resource "azuread_application_certificate" "bench_reader" {
  count = local.bench_reader_enabled ? 1 : 0

  application_id = azuread_application.bench_reader[0].id
  type           = "AsymmetricX509Cert"
  encoding       = "pem"
  value          = local.bench_reader_certificate
  end_date       = local.bench_reader_certificate_end

  lifecycle {
    # nonsensitive : le seul résultat du test (vrai ou faux), jamais le contenu du fichier.
    precondition {
      condition     = nonsensitive(can(regex("^\\s*-----BEGIN CERTIFICATE-----\\s+[A-Za-z0-9+/=\\s]+-----END CERTIFICATE-----\\s*$", local.bench_reader_certificate)))
      error_message = "bench_reader_certificate_file : un seul bloc CERTIFICATE (PEM), et rien d'autre — absent, ou une clé privée à côté. Tirer la paire d'abord (make celebrimbor-reader-key) ; jamais la clé privée dans Terraform."
    }
    # Une identité à durée courte : la fin du certificat, 91 jours au plus après le plan (90, et un
    # jour de marge pour l'heure du keygen). Pas de borne basse, ni de bloc check : une fin déjà
    # passée passe le plan (des plans stables, des tests qui ne vieillissent pas) ; c'est
    # `bench_reader.py status` qui la dit passée.
    precondition {
      condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", local.bench_reader_certificate_end)) && try(timecmp(local.bench_reader_certificate_end, timeadd(plantimestamp(), "2184h")) <= 0, false)
      error_message = "bench_reader_certificate_end_file : la fin du certificat en RFC 3339 (UTC), 91 jours au plus après le plan — absente, illisible ou trop lointaine. Tirer la paire (make celebrimbor-reader-key) : elle l'écrit."
    }
  }
}

resource "azurerm_role_assignment" "bench_reader" {
  count = local.bench_reader_enabled ? 1 : 0

  scope                = azurerm_log_analytics_workspace.celebrimbor.id
  role_definition_name = local.bench_reader_role
  principal_id         = azuread_service_principal.bench_reader[0].object_id
  principal_type       = "ServicePrincipal"
  description          = "Eregion (BRO1) : la session Banc lit le workspace du banc, rien d'autre."
}

# Une instance éphémère ne la pose pas : le dire, plutôt qu'un plan muet.
check "bench_reader_on_the_canonical_instance" {
  assert {
    condition     = local.instance == "default" || !var.bench_reader_enabled
    error_message = "bench_reader_enabled : sans effet sur l'instance « ${local.instance} » — l'identité de lecture vit dans le tenant, une seule, posée par l'instance canonique (workspace Terraform default)."
  }
}

# Ce que `make celebrimbor-reader-profile` écrit dans le profil de la session Banc : des identifiants,
# aucun secret (la clé privée n'est jamais passée par Terraform). null, désactivée.
output "bench_reader" {
  description = "L'identité de lecture du banc (BRO1) : tenant, application, workspace (GUID et id ARM), rôle, fin du certificat — aucun secret. null si bench_reader_enabled est false."
  value = local.bench_reader_enabled ? {
    tenant_id             = data.azurerm_subscription.bench.tenant_id
    client_id             = azuread_application.bench_reader[0].client_id
    workspace_id          = azurerm_log_analytics_workspace.celebrimbor.workspace_id
    workspace_resource_id = azurerm_log_analytics_workspace.celebrimbor.id
    role                  = local.bench_reader_role
    certificate_end_date  = azuread_application_certificate.bench_reader[0].end_date
  } : null
}
