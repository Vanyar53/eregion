# L'unité administrative restreinte du banc et ses utilisateurs de test, inscrits (IDI1b, #573) — la
# cible des verbes d'IR1 sur un utilisateur (désactiver, réactiver, révoquer les sessions), et des
# techniques d'identité de R2 qui visent un utilisateur. docs/design/reponse-identite.md §3.6.
#
# Un utilisateur ne porte pas de tag : il s'inscrit par deux moitiés, comme une VM par son groupe et
# elle-même (eregion_core/inscription.py, user_enrollment) :
#   - l'unité : l'unité administrative RESTREINTE du banc le tient ; son id est épinglé ici
#     (entra_bench_unit_id), jamais cherché par son nom ;
#   - l'attribut : un attribut de sécurité personnalisé de l'ensemble « Eregion », sur l'utilisateur,
#     nomme le banc et la zone (Eregion.eregionTarget, Eregion.eregionZone : un nom d'attribut
#     n'admet pas le tiret). User Administrator ne l'écrit pas : l'exécuteur ne peut ni inscrire ni
#     désinscrire un utilisateur.
#
# Hypothèse 13 (mesurée sur le schéma du fournisseur verrouillé, azuread 3.10.0 : `terraform providers
# schema -json`) : azuread NE SAIT PAS créer une unité restreinte — `azuread_administrative_unit` n'a
# que display_name, description, hidden_membership_enabled, members, prevent_duplicate_names ; le
# modèle du SDK embarqué connaît isMemberManagementRestricted, la ressource ne le pose jamais — ni un
# ensemble d'attributs, ni une définition, ni la valeur d'un attribut sur un utilisateur (aucune
# ressource, aucun argument de `azuread_user`). Il sait, en revanche, l'appartenance à une unité
# (`azuread_administrative_unit_member`) et un rôle d'annuaire à la portée d'une unité
# (`azuread_directory_role_assignment`, directory_scope_id). Ce qu'il ne sait pas passe par l'API de
# Graph, dans scripts/entra_bench_unit.py, que lancent `make celebrimbor-unit-prepare` (l'ensemble, ses
# deux définitions, l'unité restreinte : une fois, avant ce fichier) et, pour l'attribut de chaque
# utilisateur, le terraform_data ci-dessous.
#
# Ce que ce fichier pose, et rien d'autre :
#   - l'unité, lue par son id épinglé (data) : son id sort en output, ce que la garde et l'exécuteur
#     épinglent (EREGION_BENCH_ADMIN_UNIT_ID) ;
#   - des utilisateurs de test (entra_test_users), membres du tenant, sans rôle, sans groupe, sans
#     licence (aucun azuread_user_license, aucun usage_location), un mot de passe que personne ne
#     connaît (tiré à l'apply, gardé dans l'état local seul) ;
#   - l'attribut sur chacun, PUIS son appartenance à l'unité : dans une unité restreinte, un
#     administrateur du tenant ne modifie plus ses membres (doc) — l'attribut se pose avant ;
#   - pour l'exécuteur d'identité d'IR1 (entra_identity_executor_object_id, vide : rien), trois rôles
#     d'annuaire et aucun autre : User Administrator à la portée de l'unité seule, Directory Readers au
#     tenant (la doc l'exige pour qu'un principal se serve d'un rôle borné), Attribute Assignment
#     Reader à la portée de l'ensemble d'Eregion (relire l'attribut ; hypothèse 15).
#
# Désactivé par défaut : `entra_bench_unit_enabled = true` et `entra_bench_unit_id = "<id>"` dans
# terraform.tfvars, puis `make celebrimbor-users-plan`, puis `make celebrimbor-users-up YES=1`
# (docs/operations.md, « Les utilisateurs de test du banc (IDI1b) »). Contraintes :
#   - instance canonique seule (workspace "default") : l'unité et ses membres vivent dans le tenant ;
#   - droits de l'apply (un az login, jamais un principal) : Administrateur des rôles privilégiés
#     (l'unité, ses membres, les rôles de l'exécuteur), Administrateur des utilisateurs (créer un
#     utilisateur), Administrateur d'attribution d'attributs (poser l'attribut) — l'Administrateur
#     général n'a pas, par défaut, les droits sur les attributs de sécurité (doc) ;
#   - rien ici ne donne un rôle à un utilisateur de test : la garde refuserait l'utilisateur.
#
# Désactivé, rien ne s'exécute : aucune lecture ni écriture du tenant (count, for_each vides).

variable "entra_bench_unit_enabled" {
  description = "L'unité administrative restreinte du banc (créée par make celebrimbor-unit-prepare, son id épinglé dans entra_bench_unit_id), ses utilisateurs de test (entra_test_users) membres, sans rôle, portant l'attribut d'inscription Eregion, et les rôles de l'exécuteur d'IR1. Instance canonique seule. Droits : Administrateur des rôles privilégiés, Administrateur des utilisateurs, Administrateur d'attribution d'attributs. Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

variable "entra_bench_unit_id" {
  description = "L'object id de l'unité administrative restreinte du banc, tel que make celebrimbor-unit-prepare l'a dit — épinglé, jamais cherché par le nom. Vide : aucune unité."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.entra_bench_unit_id == "" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.entra_bench_unit_id))
    error_message = "entra_bench_unit_id : un object id (GUID, en minuscules), ou vide."
  }
}

variable "entra_test_users" {
  description = "Les utilisateurs de test du banc, par leur clé (le début de leur UPN : <clé>.celebrimbor@<domaine initial du tenant>). Chacun : membre de l'unité du banc, sans rôle ni licence."
  type        = set(string)
  default     = ["tuor"]
  nullable    = false
  validation {
    condition     = alltrue([for k in var.entra_test_users : can(regex("^[a-z][a-z0-9]{1,19}$", k))])
    error_message = "entra_test_users : des clés de 2 à 20 caractères, minuscules et chiffres, une lettre d'abord."
  }
}

variable "entra_identity_executor_object_id" {
  description = "L'object id du principal de service de l'exécuteur d'identité d'IR1 (IR1b le crée) : il reçoit User Administrator à la portée de l'unité du banc, Directory Readers au tenant, Attribute Assignment Reader à la portée de l'ensemble Eregion. Vide : aucun rôle."
  type        = string
  default     = ""
  nullable    = false
  validation {
    condition     = var.entra_identity_executor_object_id == "" || can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.entra_identity_executor_object_id))
    error_message = "entra_identity_executor_object_id : un object id (GUID, en minuscules), ou vide."
  }
}

locals {
  entra_bench_unit_enabled = var.entra_bench_unit_enabled && local.instance == "default"

  # L'ensemble d'attributs d'Eregion et ses deux noms, tels que la garde les lit
  # (eregion_core/inscription.py, ATTRIBUTE_SET, ATTRIBUTE_NAMES) et que le script les définit.
  entra_attribute_set = "Eregion"

  entra_test_users = local.entra_bench_unit_enabled ? var.entra_test_users : toset([])

  # Les modèles de rôle d'annuaire intégrés (identifiants publics, les mêmes dans tout tenant :
  # « Microsoft Entra built-in roles »), chacun vérifié contre la liste du tenant au plan (la
  # précondition ci-dessous) : un identifiant faux arrête le plan, il n'attribue jamais un autre rôle.
  entra_role_templates = {
    "User Administrator"          = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Directory Readers"           = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
    "Attribute Assignment Reader" = "ffd52fa5-98dc-465c-991d-fc073eb59f8f"
  }

  # Les rôles de l'exécuteur, et leur portée : aucun autre, nulle part ailleurs.
  identity_executor_roles = local.entra_bench_unit_enabled && var.entra_identity_executor_object_id != "" ? {
    user_administrator          = { role = "User Administrator", scope = "/administrativeUnits/${var.entra_bench_unit_id}" }
    directory_readers           = { role = "Directory Readers", scope = "/" }
    attribute_assignment_reader = { role = "Attribute Assignment Reader", scope = "/attributeSets/${local.entra_attribute_set}" }
  } : {}
}

# L'unité, créée restreinte par l'API de Graph (make celebrimbor-unit-prepare), lue par son id.
data "azuread_administrative_unit" "bench" {
  count     = local.entra_bench_unit_enabled ? 1 : 0
  object_id = var.entra_bench_unit_id

  lifecycle {
    precondition {
      condition     = var.entra_bench_unit_id != ""
      error_message = "entra_bench_unit_enabled sans entra_bench_unit_id : créer l'unité restreinte d'abord (make celebrimbor-unit-prepare YES=1), puis épingler son id dans terraform.tfvars."
    }
  }
}

# Le domaine initial du tenant (<tenant>.onmicrosoft.com) : l'UPN des utilisateurs de test.
data "azuread_domains" "initial" {
  count        = local.entra_bench_unit_enabled ? 1 : 0
  only_initial = true
}

resource "azuread_user" "bench_test" {
  for_each = local.entra_test_users

  user_principal_name = "${each.key}.${local.project}@${data.azuread_domains.initial[0].domains[0].domain_name}"
  display_name        = "Eregion test user ${each.key} (${local.project})"
  account_enabled     = true
  # Tiré à l'apply (uuid : 122 bits aléatoires), jamais montré ; gardé dans l'état local seul. Une
  # technique qui doit se connecter pose le sien.
  password = "${uuid()}A!"

  # account_enabled : l'exécuteur d'IR1 désactive et réactive l'utilisateur — un plan ne doit ni le
  # réactiver, ni échouer sur un membre de l'unité restreinte, que Terraform ne modifie plus.
  lifecycle {
    ignore_changes = [password, account_enabled]
  }
}

# L'attribut d'inscription sur chaque utilisateur, par Graph (azuread ne le sait pas) : le banc et la
# zone du banc, tels que les porte une VM (locals.tf). Sous l'az login de l'apply ; une valeur relue.
resource "terraform_data" "bench_test_user_attributes" {
  for_each = azuread_user.bench_test

  triggers_replace = [each.value.object_id, local.common_tags["eregion-target"], local.common_tags["eregion-zone"]]

  provisioner "local-exec" {
    command     = "python3 scripts/entra_bench_unit.py assign"
    working_dir = path.module
    environment = {
      EREGION_USER_OBJECT_ID = each.value.object_id
      EREGION_ATTR_TARGET    = local.common_tags["eregion-target"]
      EREGION_ATTR_ZONE      = local.common_tags["eregion-zone"]
    }
  }
}

# L'appartenance, après l'attribut : la moitié que pose Celebrimbor, et qu'un administrateur du
# tenant ne retire plus sans geste tracé.
resource "azuread_administrative_unit_member" "bench_test" {
  for_each = azuread_user.bench_test

  administrative_unit_object_id = data.azuread_administrative_unit.bench[0].object_id
  member_object_id              = each.value.object_id

  depends_on = [terraform_data.bench_test_user_attributes]
}

# La liste des modèles de rôle du tenant : chaque identifiant ci-dessus y nomme le rôle attendu.
data "azuread_directory_role_templates" "all" {
  count = length(local.identity_executor_roles) > 0 ? 1 : 0
}

resource "azuread_directory_role_assignment" "identity_executor" {
  for_each = local.identity_executor_roles

  role_id             = local.entra_role_templates[each.value.role]
  principal_object_id = var.entra_identity_executor_object_id
  directory_scope_id  = each.value.scope

  lifecycle {
    precondition {
      condition = contains([
        for t in data.azuread_directory_role_templates.all[0].role_templates : t.display_name
        if t.object_id == local.entra_role_templates[each.value.role]
      ], each.value.role)
      error_message = "le modèle de rôle ${local.entra_role_templates[each.value.role]} ne nomme pas « ${each.value.role} » dans ce tenant : rien n'est attribué."
    }
  }
}

# Une instance éphémère ne les pose pas : le dire, plutôt qu'un plan muet.
check "entra_bench_unit_on_the_canonical_instance" {
  assert {
    condition     = local.instance == "default" || !var.entra_bench_unit_enabled
    error_message = "entra_bench_unit_enabled : sans effet sur l'instance « ${local.instance} » — l'unité du banc et ses utilisateurs vivent dans le tenant, posés par l'instance canonique (workspace Terraform default)."
  }
}

output "entra_bench_unit_id" {
  value       = local.entra_bench_unit_enabled ? data.azuread_administrative_unit.bench[0].object_id : ""
  description = "L'object id de l'unité administrative restreinte du banc (entra_bench_unit_enabled), vide sinon : ce que la garde et l'exécuteur épinglent (EREGION_BENCH_ADMIN_UNIT_ID)."
}

output "entra_test_user_object_ids" {
  value       = { for k, u in azuread_user.bench_test : k => u.object_id }
  description = "Les object ids des utilisateurs de test du banc, par clé : ce que la garde juge (python -m eregion_core.inscription user <l'un>), une fois les droits de lecture du lecteur posés."
}

# IR1b : l'exécuteur lit le nom de l'ensemble (EREGION_IDENTITY_ATTRIBUTE_SET) et l'unité
# (EREGION_BENCH_ADMIN_UNIT_ID) — docs/operations.md, « Les utilisateurs de test du banc (IDI1b) ».
output "entra_attribute_set" {
  value       = local.entra_attribute_set
  description = "L'ensemble d'attributs de sécurité d'Eregion (son nom est son id) : EREGION_IDENTITY_ATTRIBUTE_SET de l'exécuteur d'IR1."
}
