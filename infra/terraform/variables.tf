variable "admin_ssh_public_key" {
  description = "SSH public key for VM access (set in terraform.tfvars)"
  type        = string
  sensitive   = true
}

variable "subscription_id" {
  description = "Azure subscription id. Vide (défaut) → le provider lit ARM_SUBSCRIPTION_ID de l'env (mappé depuis AZURE_SUBSCRIPTION_ID par le Makefile). Jamais en dur dans le repo public."
  type        = string
  default     = ""
}

variable "vm_shutdown_email" {
  description = "Adresse prévenue 15 min avant l'extinction automatique des VMs. Dans terraform.tfvars (ignoré par git), jamais dans config.yaml (suivi, repo public). Vide → pas de notification."
  type        = string
  default     = ""
}

variable "topo_filter" {
  description = "Surcharge des topologies actives (depuis `make celebrimbor-up TOPO=a,b`). Vide = on respecte topologies.<name>.enabled du config.yaml."
  type        = list(string)
  default     = []
}
