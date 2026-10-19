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
  description = "Utilisateur de la VM ; les injecteurs tournent sous son HOME (~/runs, ~/.annatar)."
  type        = string
  default     = "orodruin"
}

variable "bench_resource_group" {
  description = "Le groupe du banc, seule portée des droits d'Orodruin (Celebrimbor, workspace default)."
  type        = string
  default     = "rg-celebrimbor"
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
  description = "Lecture de ses propres attributions au niveau de l'abonnement — seulement si la mesure montre que le contrat ne peut pas être lu sans elle."
  type        = bool
  default     = false
}
