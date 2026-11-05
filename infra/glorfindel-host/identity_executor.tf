# L'exécuteur d'identité (IR1b, #572 ; docs/design/reponse-identite.md §3.3, §3.4) — son application
# dans Entra ID, son principal et ses permissions, rien d'autre. Il sera un conteneur de H0 (IR1c) à
# qui le point de jeton de la VM est coupé : il a donc son propre principal, jamais l'identité
# managée de la VM, qui est celle de la watch. La watch n'écrit jamais sur Entra ID ; lui n'agit que
# sur une demande signée, rattachée à une proposition signée par la watch, après un humain.
#
# Ce que ce fichier pose, et rien d'autre :
#   - une application mono-tenant (AzureADMyOrg), sans secret, sans propriétaire nommé, et son
#     principal ;
#   - deux permissions d'application de Microsoft Graph, la liste fermée du contrat
#     (glorfindel/providers/azure/identity_contract.py, ADMITTED_PERMISSIONS) :
#       Application.ReadWrite.OwnedBy  les identifiants et l'état des seules applications dont il est
#                                      propriétaire (celles qu'IDI1 inscrit, la propriété posée par
#                                      Celebrimbor, jamais ici ni par lui) ;
#       User.RevokeSessions.All        la révocation des sessions, bornée par le code aux
#                                      utilisateurs inscrits (décision du Q3, 05/11) ;
#   - Log Analytics Reader sur le workspace du banc : il relit lui-même la preuve d'un constat ;
#   - la partie publique de son certificat, si elle est donnée (identity_executor_certificate) : la
#     clé est tirée sur H0, dans un répertoire que lui seul monte, jamais ici ni dans l'état.
# Pas ici : User Administrator à la portée de l'unité administrative du banc, Directory Readers au
# tenant, Attribute Assignment Reader (IDI1b, Celebrimbor), ni la propriété des applications inscrites
# (IDI1). Jamais nulle part : un droit de la liste refusée (REFUSED_PERMISSIONS, REFUSED_ROLES) — le
# contrat le relit au démarrage, et tout droit en trop le rend passif (beyond_contract).
#
# Désactivé par défaut : `identity_executor_enabled = true` dans identity_executor.auto.tfvars (ignoré
# par git ; identity_executor.auto.tfvars.example), puis `make glorfindel-host-plan`, relu, puis
# `make glorfindel-host-up` sans YES — par Jonathan, sous un az login qui peut créer une application et
# consentir des permissions d'application de Microsoft Graph (Administrateur des rôles privilégiés) :
# attribuer un rôle d'application de Graph, c'est le consentement d'administrateur. Les gestes, dans
# l'ordre : docs/operations.md, « L'exécuteur d'identité ». Graph est trouvé par son identifiant
# publié, jamais écrit ici. Désactivé, rien ne s'exécute dans le tenant (`count`, `for_each`).

locals {
  identity_executor_permissions = var.identity_executor_enabled ? toset(["Application.ReadWrite.OwnedBy", "User.RevokeSessions.All"]) : toset([])
}

data "azuread_application_published_app_ids" "identity_executor" {
  count = var.identity_executor_enabled ? 1 : 0
}

data "azuread_service_principal" "identity_executor_msgraph" {
  count     = var.identity_executor_enabled ? 1 : 0
  client_id = data.azuread_application_published_app_ids.identity_executor[0].result["MicrosoftGraph"]
}

resource "azuread_application" "identity_executor" {
  count            = var.identity_executor_enabled ? 1 : 0
  display_name     = "eregion-glorfindel-identity-executor"
  sign_in_audience = "AzureADMyOrg"

  # Les permissions demandées, pour que le portail dise ce qui est consenti ; le consentement
  # lui-même, ce sont les attributions ci-dessous.
  required_resource_access {
    resource_app_id = data.azuread_application_published_app_ids.identity_executor[0].result["MicrosoftGraph"]

    dynamic "resource_access" {
      for_each = local.identity_executor_permissions
      content {
        id   = data.azuread_service_principal.identity_executor_msgraph[0].app_role_ids[resource_access.value]
        type = "Role"
      }
    }
  }
}

resource "azuread_service_principal" "identity_executor" {
  count     = var.identity_executor_enabled ? 1 : 0
  client_id = azuread_application.identity_executor[0].client_id
}

resource "azuread_app_role_assignment" "identity_executor" {
  for_each            = local.identity_executor_permissions
  app_role_id         = data.azuread_service_principal.identity_executor_msgraph[0].app_role_ids[each.value]
  principal_object_id = azuread_service_principal.identity_executor[0].object_id
  resource_object_id  = data.azuread_service_principal.identity_executor_msgraph[0].object_id
}

resource "azuread_application_certificate" "identity_executor" {
  count          = var.identity_executor_enabled && var.identity_executor_certificate != "" ? 1 : 0
  application_id = azuread_application.identity_executor[0].id
  type           = "AsymmetricX509Cert"
  value          = var.identity_executor_certificate
}

resource "azurerm_role_assignment" "identity_executor_logs_reader" {
  count                = var.identity_executor_enabled ? 1 : 0
  scope                = data.azurerm_log_analytics_workspace.bench.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azuread_service_principal.identity_executor[0].object_id
  principal_type       = "ServicePrincipal"
}
