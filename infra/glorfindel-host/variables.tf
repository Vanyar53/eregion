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
  description = "Seule source autorisée en SSH (ton IP publique, en /32). `make glorfindel-host-plan OPERATOR_CIDR=…` ; sans valeur, le Makefile la détecte."
  type        = string

  validation {
    condition     = can(cidrhost(var.operator_cidr, 0)) && var.operator_cidr != "0.0.0.0/0"
    error_message = "operator_cidr doit être un CIDR précis (ton IP en /32), jamais 0.0.0.0/0."
  }
}

variable "location" {
  description = "Région de la VM. francecentral (16/10, choix de Jonathan) ; elle peut différer de celle du banc (westeurope) : Glorfindel ne parle qu'aux API d'Azure."
  type        = string
  default     = "francecentral"
}

variable "vm_size" {
  description = "Taille de la VM. B2s (4 Go, ~31 €/mois en continu, 16/10) : watch + War Room ~300 Mo au repos, la construction de l'image demande plus."
  type        = string
  default     = "Standard_B2s"
}

variable "admin_username" {
  description = "Utilisateur de la VM ; Glorfindel tourne sous son HOME (~/.glorfindel, ~/.cache/chroma)."
  type        = string
  default     = "glorfindel"
}

variable "eregion_repo" {
  description = "Dépôt cloné sur la VM."
  type        = string
  default     = "https://github.com/Vanyar53/eregion.git"
}

variable "eregion_ref" {
  description = "Branche ou tag cloné au premier démarrage (ensuite : `make glorfindel-host-start` fait un git pull)."
  type        = string
  default     = "main"
}

variable "bench_resource_group" {
  description = "Groupe du banc que Glorfindel lit (Celebrimbor, workspace default)."
  type        = string
  default     = "rg-celebrimbor"
}

variable "bench_workspace" {
  description = "Log Analytics du banc."
  type        = string
  default     = "law-celebrimbor-amonsul"
}
