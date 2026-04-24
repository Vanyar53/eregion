variable "admin_ssh_public_key" {
  description = "SSH public key for VM access (set in terraform.tfvars)"
  type        = string
  sensitive   = true
}
