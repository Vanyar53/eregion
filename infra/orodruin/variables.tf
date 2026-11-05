variable "admin_ssh_public_key" {
  description = "Clé SSH publique de l'opérateur — la même que Celebrimbor (le Makefile passe infra/terraform/terraform.tfvars)."
  type        = string
  sensitive   = true
}

variable "subscription_id" {
  description = "Abonnement Azure. Vide (défaut) → le provider lit ARM_SUBSCRIPTION_ID. Jamais en dur dans le repo public."
  type        = string
  default     = ""
}

variable "operator_cidr" {
  description = "Seule source autorisée en SSH (ton IP publique, en /32). Sans valeur, le Makefile la détecte."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0)) && var.operator_cidr != "0.0.0.0/0"
    error_message = "operator_cidr doit être un CIDR précis (ton IP en /32), jamais 0.0.0.0/0."
  }
}

variable "location" {
  description = "Région de la VM. Orodruin ne parle qu'aux API d'Azure : elle peut différer de celle du banc."
  type        = string
  default     = "francecentral"
}

variable "vm_size" {
  description = "Taille de la VM — à confirmer à l'étape 0 d'O1 (quota de la famille, restrictions de SKU, prix). Repli connu : D2als_v6 en francecentral (capacité et quota vérifiés par H0 le 16/10) ; éteinte entre les sessions (orodruin-stop), quelques euros par mois."
  type        = string
  default     = "Standard_D2als_v6"
}

variable "admin_username" {
  description = "Utilisateur de la VM ; les injecteurs tournent sous son HOME et n'en montent que ~/runs (aucun docker run ne monte ~/.annatar, SEC20)."
  type        = string
  default     = "orodruin"
}

variable "bench_resource_group" {
  description = "Le groupe du banc, seule portée des droits d'Orodruin (Celebrimbor, workspace default)."
  type        = string
  default     = "rg-celebrimbor"
}

variable "bench_id" {
  description = "La valeur du tag eregion-target des VM inscrites (O0) : seules elles reçoivent le droit d'agir d'Orodruin (SEC5). Vide (défaut) → tirée du groupe du banc : rg-celebrimbor → celebrimbor, rg-celebrimbor-<instance> → celebrimbor-<instance>, comme Celebrimbor la pose."
  type        = string
  default     = ""
}

variable "channel_retention_days" {
  description = "Jours après sa dernière écriture où un blob de bloc du canal (fenêtre, campagne, rapport de run, détection) est supprimé (SEC5, V-21). Doit dépasser la purge de la watch (7 jours après le dernier moment d'une fenêtre, soit 7 jours + 2 h 15 après sa dernière écriture)."
  type        = number
  default     = 9

  validation {
    condition     = var.channel_retention_days >= 8
    error_message = "channel_retention_days doit dépasser la purge de la watch (7 jours + 2 h 15) : au moins 8."
  }
}

variable "journal_retention_days" {
  description = "Jours où le journal d'Orodruin poussé dans le canal (audit/) est gardé (SEC5, V-29)."
  type        = number
  default     = 90
}

variable "watch_subnet_id" {
  description = "Sous-réseau du Glorfindel hébergé (H0), admis par le pare-feu du compte du canal (SEC5, V-31). Le Makefile le lit dans l'état de infra/glorfindel-host ; vide → H0 n'atteint plus le canal."
  type        = string
  default     = ""
}

variable "watch_public_ip" {
  description = "IP publique de H0, admise par le pare-feu du compte du canal si H0 n'est pas dans sa région (SEC5, V-31). Le Makefile la lit dans l'état de infra/glorfindel-host."
  type        = string
  default     = ""
}

variable "bench_workspace" {
  description = "Log Analytics du banc (le collecteur d'Annatar y lit le Heartbeat)."
  type        = string
  default     = "law-celebrimbor-amonsul"
}

variable "model_api_prefixes" {
  description = "Adresses de l'API du modèle autorisées en sortie. api.anthropic.com : 160.79.104.0/23, plage publiée par Anthropic (platform.claude.com/docs/en/api/ip-addresses) ; à mesurer depuis la VM."
  type        = list(string)
  default     = ["160.79.104.0/23"]
}

variable "egress_locked" {
  description = "Sortie fermée hors périmètre. false seulement pour le premier apply (installation de Docker) ; `make orodruin-lock` la referme. Ouverte, le contrat reste passive."
  type        = bool
  default     = true
}

variable "contract_reader" {
  description = "Lecture des attributions de rôle sur tout l'abonnement. Mesuré le 19/10 : sans elle, Azure ne liste que les attributions que l'identité peut lire (celle du workspace, pas celle du banc) — l'absence de droits ailleurs n'est pas prouvée, le contrat reste passive (identity_unprovable)."
  type        = bool
  default     = true
}

variable "storage_service_tag" {
  description = "Sortie vers le canal des fenêtres : le tag du stockage de la région d'Orodruin."
  type        = string
  default     = "Storage.FranceCentral"
}

variable "watch_principal_id" {
  description = "Identité managée du Glorfindel hébergé (H0) : lectrice du canal des fenêtres, rédactrice du canal retour (#159), sauf si watch_principal_ids la laisse de côté. Le Makefile la lit dans l'état de infra/glorfindel-host ; vide → pas de watch hébergée."
  type        = string
  default     = ""
}

# WC1 (#523) : sans H0, la watch d'un poste ou d'une équipe parle à Orodruin. Chacune de ces
# identités lit le canal des fenêtres (`exercises`) et écrit le canal retour (`watch`), rien
# d'autre. null (défaut) → la seule watch hébergée, watch_principal_id, comme avant WC1.
variable "watch_principal_ids" {
  description = "Les identités des watches qui écrivent le canal retour et lisent celui des fenêtres : l'object id de leur principal de service (jamais son client id), ou de l'identité managée de H0. null (défaut) → [watch_principal_id]. Le Makefile la passe par WATCH_PRINCIPALS=<id>[,<id>…], sur la ligne de commande seulement."
  type        = list(string)
  default     = null

  validation {
    condition     = alltrue([for id in (var.watch_principal_ids == null ? [] : var.watch_principal_ids) : can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))])
    error_message = "watch_principal_ids : des object ids d'Entra ID (un GUID chacun), rien d'autre."
  }

  validation {
    condition     = var.watch_principal_ids == null ? true : length(var.watch_principal_ids) == length(distinct([for id in var.watch_principal_ids : lower(id)]))
    error_message = "watch_principal_ids : une identité nommée deux fois (la casse ne compte pas) — la seconde attribution échouerait à l'apply."
  }
}

# IDI1 (#546) : la lecture de Microsoft Graph, pour la garde des identités d'Entra ID (R2).
variable "graph_read_enabled" {
  description = "Le rôle d'application Microsoft Graph Application.Read.All pour l'identité d'Orodruin : la garde d'une identité d'Entra ID lit l'application et son principal (IDI1). Rien d'autre dans Graph — le contrat le relit dans son jeton. L'apply demande un az login Administrateur des rôles privilégiés (ou général). Défaut false."
  type        = bool
  default     = false
  nullable    = false
}
