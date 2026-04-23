variable "resource_group_name" {
  default = "rg-sechaos-test"
}

variable "location" {
  default = "westeurope"
}

variable "vm_size" {
  default = "Standard_B2s"
}

variable "admin_username" {
  default = "sechaosadmin"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}
