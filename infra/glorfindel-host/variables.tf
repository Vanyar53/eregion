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
  description = "Taille de la VM — celle déployée le 16/10 : D2als_v6 (2 vCPU, 4 Go, ~61 €/mois en continu). B2s manquait de capacité en francecentral, et le quota Basv2 de l'abonnement est à 0 : avec 2 cœurs Basv2 accordés, passer à Standard_B2als_v2 (~27 €/mois, même RAM). Image construite en 2 min 44 s, ~300 Mo au repos."
  type        = string
  default     = "Standard_D2als_v6"
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
  description = "Branche ou tag cloné au premier démarrage ; ensuite `make glorfindel-host-start` déploie un tag ou un commit, détaché (M-3). Changer cette valeur remplace la VM (custom_data)."
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
