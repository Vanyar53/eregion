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

# ── Les journaux du plan de contrôle et d'Entra ID → le workspace du banc (ID1) ──────────
# Deux paramètres de diagnostic qui ne vivent pas dans le groupe du banc : l'un sur
# l'ABONNEMENT (activity_log.tf), l'autre sur le TENANT Entra ID (entra_logs.tf).
# Désactivés par défaut. Les activer est une décision de l'opérateur sur SON abonnement et
# SON tenant : dans terraform.tfvars (ignoré par git, persistant) — jamais dans config.yaml
# (suivi, repo public : un fork qui applique enverrait les journaux de son tenant sans
# l'avoir décidé), ni en `-var` d'une seule commande (le prochain apply sans lui retirerait
# le paramètre). Posés par l'instance canonique seule (workspace Terraform "default") ;
# ailleurs, sans effet, et dit (check "diagnostic_settings_on_the_canonical_instance").
# Commandes, droits, coût, mesures : docs/operations.md, « Les journaux d'activité et
# d'Entra ID au banc (ID1) ».

variable "activity_log_enabled" {
  description = "Journal d'activité de l'abonnement (catégorie Administrative) → le workspace du banc : la table AzureActivity des règles d'AL1. Droit : écrire un paramètre de diagnostic sur l'abonnement (Monitoring Contributor). Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

variable "entra_logs_enabled" {
  description = "Journaux d'Entra ID du tenant (AuditLogs, ServicePrincipalSignInLogs) → le workspace du banc : les tables des règles de C2. Tout le tenant, pas seulement le banc. Droit : rôle d'Entra Administrateur de la sécurité (ou général), pas un rôle Azure. Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

# ── Une identité de test du banc dans Entra ID, inscrite (IDI1, #546) ───────────────────
# Désactivée par défaut ; dans terraform.tfvars, jamais en `-var` d'une seule commande (le prochain
# apply sans lui la détruirait). entra_identity.tf, docs/operations.md.
variable "entra_test_identity_enabled" {
  description = "Une application et son principal de service dans le tenant du banc, mono-tenant, sans secret, inscrits par les deux clés (ses tags Graph eregion-target et eregion-zone, eregion-identities sur le groupe du banc) : la cible des techniques d'identité (R2). Instance canonique seule. Droit : créer une application (Développeur d'applications, ou plus). Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

# ── auditd sur les VM du banc, ses lignes vers le workspace (AUD1, #408) ────────────────
# Désactivé par défaut ; dans terraform.tfvars (persistant), jamais en `-var` d'une seule commande
# (le prochain apply sans lui retirerait l'extension et la facilité). auditd.tf, docs/operations.md.
variable "auditd_enabled" {
  description = "auditd sur les VM du banc (la règle du CIS user_emulation, et root_command : les commandes d'un shell root sous l'auid de connexion), ses lignes par audisp-syslog vers local6, que la DCR envoie à Syslog : la règle auditd-sensitive-root-command de Glorfindel. Défaut false."
  type        = bool
  default     = false
  nullable    = false
}

# G1 : les VM qui reçoivent le bruit bénin (chaos.tf). La source de vérité reste chaos.noise_vms
# du config.yaml ; cette variable ne sert qu'à le remplacer le temps d'un plan — ce que fait
# tests/chaos_noise.tftest.hcl, un local ne se remplaçant pas dans un test. Un second moyen
# d'allumer le bruit, réservé aux tests : jamais dans terraform.tfvars ni par TF_VAR_.
variable "chaos_noise_vms" {
  description = "Remplace chaos.noise_vms du config.yaml (G1) quand elle est donnée ; null (défaut) : le config.yaml."
  type        = list(string)
  default     = null
}
