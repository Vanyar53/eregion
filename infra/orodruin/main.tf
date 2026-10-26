# Orodruin (O1) — la VM d'où les injecteurs agissent (Annatar, puis Gothmog), groupe
# rg-orodruin. Celebrimbor forge les cibles, Orodruin ce qui les éprouve.
#
# État Terraform séparé de Celebrimbor et de Glorfindel : un apply ou un down de l'un ne
# touche jamais l'autre. Le contrat (docs/design/orodruin-contract.md) est vérifié au
# démarrage de chaque run par eregion_core/orodruin.py : identité contenue dans le groupe du
# banc, sortie réseau fermée hors périmètre, plafond déclaré. Ce module pose les mécanismes ;
# la vérification les relit, elle ne leur fait pas confiance. README.md pour le déroulé.

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

# subscription_id : jamais en dur (repo public). var.subscription_id, sinon ARM_SUBSCRIPTION_ID.
provider "azurerm" {
  # Le compte du canal n'a pas de clé partagée, et l'opérateur n'a de droit sur ses données
  # que sur `exercises` (channel_operator, pour l'arrêt d'urgence) : le provider ne touche que
  # l'API de contrôle (le conteneur est créé par storage_account_id). Sans ce réglage, la création du compte a attendu ~4 min sur la
  # vérification du data plane (19/10), le compte déjà créé mais hors de l'état.
  features {
    storage {
      data_plane_available = false
    }
  }
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
}

data "azurerm_subscription" "current" {}

locals {
  name = "orodruin"
  tags = {
    project    = local.name
    managed-by = "terraform"
    eregion    = "injector-host"
    # Volontairement PAS de `eregion-target` ni d'`eregion-zone` : ce n'est pas une cible.
  }
}

# ── Ce qu'Orodruin éprouve : le banc de Celebrimbor (lu, jamais créé ici) ─────────────────
data "azurerm_resource_group" "bench" {
  name = var.bench_resource_group
}

data "azurerm_log_analytics_workspace" "bench" {
  name                = var.bench_workspace
  resource_group_name = data.azurerm_resource_group.bench.name
}

# ── L'hôte ────────────────────────────────────────────────────────────────────────────────
resource "azurerm_resource_group" "host" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# Un VNet à lui, sans peering avec le banc : Run Command passe par l'API de contrôle
# d'Azure, Orodruin n'a aucune route vers les VMs.
resource "azurerm_virtual_network" "host" {
  name                = "vnet-${local.name}"
  address_space       = ["10.30.0.0/24"]
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags
}

resource "azurerm_subnet" "host" {
  name                 = "snet-${local.name}"
  resource_group_name  = azurerm_resource_group.host.name
  virtual_network_name = azurerm_virtual_network.host.name
  address_prefixes     = ["10.30.0.0/26"]

  lifecycle {
    replace_triggered_by = [azurerm_virtual_network.host.id]
  }
}

# Règles en ressources séparées (azurerm refuse de mélanger blocs en ligne et ressources) :
# la fermeture de la sortie se pose ou se retire seule, par var.egress_locked.
resource "azurerm_network_security_group" "host" {
  name                = "nsg-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags
}

resource "azurerm_network_security_rule" "ssh_operator" {
  name                        = "allow-ssh-operator"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = var.operator_cidr
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.host.name
  network_security_group_name = azurerm_network_security_group.host.name
}

# Le périmètre : l'API de contrôle d'Azure, Entra ID, l'API du modèle — plus DNS et IMDS
# (l'identité managée prend son jeton par IMDS), autorisés nommément au-dessus du refus.
locals {
  egress_allow = {
    arm   = { priority = 100, dest = "AzureResourceManager", port = "443" }
    entra = { priority = 110, dest = "AzureActiveDirectory", port = "443" }
    dns   = { priority = 130, dest = "168.63.129.16", port = "53" }
    imds  = { priority = 140, dest = "169.254.169.254", port = "80" }
    # Le canal des fenêtres d'exercice (ci-dessous). Le tag couvre tous les comptes de stockage
    # de la région : une sortie possible, bornée à la région — à resserrer (point de
    # terminaison privé) si Orodruin quitte le banc.
    storage = { priority = 150, dest = var.storage_service_tag, port = "443" }
  }
}

resource "azurerm_network_security_rule" "egress_allow" {
  for_each                    = local.egress_allow
  name                        = "allow-out-${each.key}"
  priority                    = each.value.priority
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = each.value.port
  source_address_prefix       = "*"
  destination_address_prefix  = each.value.dest
  resource_group_name         = azurerm_resource_group.host.name
  network_security_group_name = azurerm_network_security_group.host.name
}

resource "azurerm_network_security_rule" "egress_model" {
  name                         = "allow-out-model-api"
  priority                     = 120
  direction                    = "Outbound"
  access                       = "Allow"
  protocol                     = "Tcp"
  source_port_range            = "*"
  destination_port_range       = "443"
  source_address_prefix        = "*"
  destination_address_prefixes = var.model_api_prefixes
  resource_group_name          = azurerm_resource_group.host.name
  network_security_group_name  = azurerm_network_security_group.host.name
}

# Tout le reste d'Internet refusé. Retiré seulement pour installer la VM (egress_locked =
# false, premier apply) : un contrat relu avec la sortie ouverte reste `passive`.
resource "azurerm_network_security_rule" "egress_deny_internet" {
  count                       = var.egress_locked ? 1 : 0
  name                        = "deny-out-internet"
  priority                    = 4000
  direction                   = "Outbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "Internet"
  resource_group_name         = azurerm_resource_group.host.name
  network_security_group_name = azurerm_network_security_group.host.name
}

resource "azurerm_public_ip" "host" {
  name                = "pip-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "host" {
  name                = "nic-${local.name}"
  location            = azurerm_resource_group.host.location
  resource_group_name = azurerm_resource_group.host.name
  tags                = local.tags

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.host.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.host.id
  }
}

resource "azurerm_network_interface_security_group_association" "host" {
  network_interface_id      = azurerm_network_interface.host.id
  network_security_group_id = azurerm_network_security_group.host.id
}

resource "azurerm_linux_virtual_machine" "host" {
  name                  = "vm-${local.name}"
  resource_group_name   = azurerm_resource_group.host.name
  location              = azurerm_resource_group.host.location
  size                  = var.vm_size
  admin_username        = var.admin_username
  network_interface_ids = [azurerm_network_interface.host.id]
  tags                  = local.tags

  # Identité managée : pas de secret sur la VM. La révoquer = retirer ses attributions de
  # rôle (orodruin-kill, depuis le poste de l'opérateur).
  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 32
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Docker seulement, au premier démarrage, sortie encore ouverte. L'image d'Annatar arrive
  # ensuite par `make orodruin-push` (docker save | ssh), sans rouvrir la sortie.
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    set -eu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q docker.io
    usermod -aG docker ${var.admin_username}
    sudo -u ${var.admin_username} mkdir -p /home/${var.admin_username}/runs /home/${var.admin_username}/.annatar
    touch /home/${var.admin_username}/.orodruin-ready
  EOF
  )
}

# ── Droits : agir sur le banc, rien d'autre ───────────────────────────────────────────────
# Les actions exactes que demandent les injecteurs, pas un rôle intégré plus large. La liste
# est celle d'eregion_core/orodruin.py (REQUIRED_ACTIONS) — un test vérifie qu'elles
# restent identiques. Gothmog (G0) démarre, suit et annule une expérience Chaos Studio du
# banc ; c'est l'identité de l'expérience, limitée à sa VM, qui agit sur la VM.
resource "azurerm_role_definition" "injector" {
  name        = "eregion-orodruin-injector-${data.azurerm_resource_group.bench.name}"
  scope       = data.azurerm_resource_group.bench.id
  description = "Orodruin (Eregion O1) : ce que les injecteurs demandent sur le banc, rien de plus."

  permissions {
    actions = [
      "Microsoft.Resources/subscriptions/resourceGroups/read",
      "Microsoft.Compute/virtualMachines/read",
      "Microsoft.Compute/virtualMachines/start/action",
      "Microsoft.Compute/virtualMachines/runCommand/action",
      "Microsoft.Network/networkSecurityGroups/read",
      "Microsoft.Chaos/experiments/read",
      "Microsoft.Chaos/experiments/start/action",
      "Microsoft.Chaos/experiments/cancel/action",
      "Microsoft.Chaos/experiments/executions/read",
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_resource_group.bench.id]
}

resource "azurerm_role_assignment" "bench_injector" {
  scope              = data.azurerm_resource_group.bench.id
  role_definition_id = azurerm_role_definition.injector.role_definition_resource_id
  principal_id       = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

resource "azurerm_role_assignment" "bench_logs_reader" {
  scope                = data.azurerm_log_analytics_workspace.bench.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

# Prouver qu'elle n'a AUCUN droit ailleurs demande de lire les attributions sur tout
# l'abonnement : Azure ne liste que celles que l'appelant peut lire (mesuré le 19/10 — avec
# ses seuls droits, la liste montrait l'attribution du workspace et cachait celle du banc).
# contract_reader lui donne cette lecture et rien d'autre — la seule attribution hors du
# banc que le contrat accepte (eregion_core/orodruin.py, AUTHZ_READ_ONLY).
resource "azurerm_role_definition" "contract_reader" {
  count       = var.contract_reader ? 1 : 0
  name        = "eregion-orodruin-contract-reader"
  scope       = data.azurerm_subscription.current.id
  description = "Orodruin (Eregion O1) : lire ses propres attributions de rôle, pour prouver le contrat."

  permissions {
    actions = [
      "Microsoft.Authorization/roleAssignments/read",
      "Microsoft.Authorization/roleDefinitions/read",
    ]
    not_actions = []
  }

  assignable_scopes = [data.azurerm_subscription.current.id]
}

resource "azurerm_role_assignment" "contract_reader" {
  count              = var.contract_reader ? 1 : 0
  scope              = data.azurerm_subscription.current.id
  role_definition_id = azurerm_role_definition.contract_reader[0].role_definition_resource_id
  principal_id       = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

# ── Le canal des fenêtres d'exercice (B2) vers la watch hébergée — O1, partie C ─────────────
# Un conteneur à Orodruin : son identité y écrit les fenêtres (open_window, close_window),
# celle de Glorfindel (H0) les lit. Entra ID seulement, pas de clé partagée. Détruit avec
# Orodruin : la watch garde ses copies locales, et sans fenêtre un cycle reste « real ».
resource "azurerm_storage_account" "channel" {
  name                            = "storodruin${substr(md5(data.azurerm_subscription.current.subscription_id), 0, 10)}"
  resource_group_name             = azurerm_resource_group.host.name
  location                        = azurerm_resource_group.host.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  allow_nested_items_to_be_public = false
  tags                            = local.tags
}

resource "azurerm_storage_container" "exercises" {
  name                  = "exercises"
  storage_account_id    = azurerm_storage_account.channel.id
  container_access_type = "private"
}

# Portée : le conteneur lui-même — la seule attribution hors du banc que le contrat accepte
# avec la lecture des attributions (EREGION_CHANNEL_SCOPE, eregion_core/orodruin.py).
resource "azurerm_role_assignment" "channel_writer" {
  scope                = azurerm_storage_container.exercises.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

# L'arrêt d'urgence (M-1) ferme les fenêtres encore ouvertes depuis le az login de l'opérateur :
# l'identité d'Orodruin vient d'être révoquée, elle ne peut plus les fermer. L'opérateur = qui
# applique ce module (déjà propriétaire de l'abonnement). Ce conteneur seulement, jamais `watch`.
data "azurerm_client_config" "operator" {}

resource "azurerm_role_assignment" "channel_operator" {
  scope                = azurerm_storage_container.exercises.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = data.azurerm_client_config.operator.object_id
}

resource "azurerm_role_assignment" "channel_watch_reader" {
  count                = var.watch_principal_id != "" ? 1 : 0
  scope                = azurerm_storage_container.exercises.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = var.watch_principal_id
  principal_type       = "ServicePrincipal"
}

# ── Le canal retour (#159) : la watch hébergée parle au run ────────────────────────────────
# Le battement de cœur de la watch et ses détections des VM d'une fenêtre ouverte ou en grâce
# (eregion_core/watch_channel.py). La watch (H0) y écrit, Orodruin le lit : le contrat refuse
# à Orodruin tout rôle d'écriture sur ce conteneur (EREGION_WATCH_CHANNEL_SCOPE), un injecteur
# n'écrit jamais ce que dit la watch. Canal coupé → le run écrit `unknown`, jamais `missed`.
resource "azurerm_storage_container" "watch" {
  name                  = "watch"
  storage_account_id    = azurerm_storage_account.channel.id
  container_access_type = "private"
}

resource "azurerm_role_assignment" "watch_channel_reader" {
  scope                = azurerm_storage_container.watch.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_linux_virtual_machine.host.identity[0].principal_id
}

resource "azurerm_role_assignment" "watch_channel_writer" {
  count                = var.watch_principal_id != "" ? 1 : 0
  scope                = azurerm_storage_container.watch.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.watch_principal_id
  principal_type       = "ServicePrincipal"
}
