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

variable "topo_filter" {
  description = "Surcharge des topologies actives (depuis `make celebrimbor-up TOPO=a,b`). Vide = on respecte topologies.<name>.enabled du config.yaml."
  type        = list(string)
  default     = []
}
