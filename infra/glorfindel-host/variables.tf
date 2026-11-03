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

variable "session_drain_vms" {
  description = "SEC11 (R-03) : les VM du groupe du banc que Glorfindel défend et dont il coupe les sessions à l'isolation — « Eregion Glorfindel Session Drain » (Run Command) sur chacune, jamais sur le groupe. Gardée dans session_drain.auto.tfvars (commité). Vide (défaut) : aucune coupure. Le rôle doit exister dans le tenant (docs/operations.md, « Identités Azure »)."
  type        = list(string)
  default     = []

  # Une VM chacune une fois, la casse ignorée comme Azure ignore celle d'un nom de VM (SEC17) :
  # ["vm-a", "VM-A"] ferait deux attributions sur la même VM, la seconde refusée à l'apply (409).
  validation {
    condition     = length(var.session_drain_vms) == length(distinct([for n in var.session_drain_vms : lower(n)])) && alltrue([for n in var.session_drain_vms : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", n))])
    error_message = "session_drain_vms : des noms de VM, chacun une fois (la casse ignorée)."
  }
}

variable "session_drain_principals" {
  description = "SEC17 (relecture) : les principaux du poste qui isolent eux-mêmes ce qu'un humain approuve, et coupent donc les sessions — la console (son object id, jamais son appId) : { console = \"<object id>\" }. « Eregion Glorfindel Session Drain » sur chaque VM de session_drain_vms, comme à H0, jamais sur le groupe. Pas le bot : il n'isole pas (Restore, Revert). Hors du dépôt : principals.auto.tfvars, ignoré par git. Jamais l'identité de H0, qui l'a déjà. Vide (défaut) : rien de plus."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, v in var.session_drain_principals : can(regex("^[a-z][a-z0-9-]{0,31}$", k)) && can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", v))]) && length(values(var.session_drain_principals)) == length(distinct([for v in values(var.session_drain_principals) : lower(v)]))
    error_message = "session_drain_principals : un nom (console) vers l'object id d'un principal, chacun une fois."
  }
}

variable "restore_vms" {
  description = "SEC17 : les VM du groupe du banc que le restore défend — « Eregion Glorfindel Restore Neutralize » (Run Command, la neutralisation de la dernière commande avant l'échange des disques) sur chacune, pour chaque principal de restore_principals, jamais sur le groupe. Gardée dans restore.auto.tfvars (commité). Une VM hors de la liste est restaurée quand même ; sa neutralisation est refusée, et dite sur la carte. Le rôle doit exister dans le tenant (docs/operations.md, « Identités Azure »)."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.restore_vms) == length(distinct([for n in var.restore_vms : lower(n)])) && alltrue([for n in var.restore_vms : can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", n))])
    error_message = "restore_vms : des noms de VM, chacun une fois (la casse ignorée)."
  }
}

variable "restore_principals" {
  description = "SEC17 : les principaux qui restaurent — celui de la console et celui du bot (leur object id, jamais leur appId), nommés : { console = \"<object id>\", bot = \"<object id>\" }. Hors du dépôt : principals.auto.tfvars, ignoré par git, sur le poste de l'opérateur (principals.auto.tfvars.example). Jamais l'identité de H0 : Glorfindel hébergé ne restaure pas. Vide (défaut) : aucune neutralisation attribuée."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k, v in var.restore_principals : can(regex("^[a-z][a-z0-9-]{0,31}$", k)) && can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", v))]) && length(values(var.restore_principals)) == length(distinct([for v in values(var.restore_principals) : lower(v)]))
    error_message = "restore_principals : un nom (console, bot) vers l'object id d'un principal, chacun une fois."
  }
}

variable "bench_workspace" {
  description = "Log Analytics du banc."
  type        = string
  default     = "law-celebrimbor-amonsul"
}
