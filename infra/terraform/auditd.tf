# auditd à la manière du CIS sur les VM du banc, ses lignes vers le workspace (AUD1, #408).
#
# ADM1 et COR1 jugent un `sudo` vers root ; ce qui se fait ensuite dans un shell root n'est pas
# écrit par sudo (COR2 le garde comme limite). auditd le voit. Désactivé par défaut :
# `auditd_enabled = true` dans terraform.tfvars (variables.tf), puis `make celebrimbor-auditd-plan`,
# puis `make celebrimbor-auditd-up YES=1` (docs/operations.md, « auditd au banc (AUD1) »).
#
# Ce que le drapeau pose, et rien d'autre :
#   - sur chaque VM du banc (local.vms : gondolin, bree), l'extension CustomScript qui lance
#     scripts/auditd.sh — auditd, la règle du CIS (`-C euid!=uid -F auid!=unset -S execve -k
#     user_emulation`), celle des commandes d'un shell root (`-F euid=0 -F auid>=1000 -F
#     auid!=unset -S execve -k root_command`), le format ENRICHED, le greffon audisp-syslog vers
#     local6. Une extension, jamais le custom_data : le changer remplacerait la VM ;
#   - la facilité local6 dans la DCR du banc (monitoring.tf), que l'agent Azure Monitor envoie à
#     la table Syslog du workspace.
#
# L'acheminement : audisp-syslog → Syslog, par la DCR qui existe déjà — pas un journal texte
# d'AMA (/var/log/audit/audit.log vers une table *_CL). La même table que lisent ADM1, COR1 et le
# brute force, la même lecture (glorfindel/correlation.py, le KQL des règles) ; ni table à
# définir, ni point de collecte, ni transformation à tenir. Ce que cela coûte : une ligne écrite
# par `logger -p local6.info` arrive au même endroit — elle ajoute une carte, elle n'en efface
# aucune (deux enregistrements pour un événement : une carte, A0). Le journal d'audit de la VM,
# lisible par root seul, garde le reste.
#
# Le retirer : `auditd_enabled = false`, puis le même `make celebrimbor-auditd-up` retire
# l'extension et local6 de la DCR. Supprimer l'extension ne défait rien sur la VM (auditd reste,
# ses règles et le greffon aussi, ses lignes ne sont plus collectées) : les gestes sont dans
# docs/operations.md.
#
# Droits : ceux d'un `make celebrimbor-up` (écrire une extension de VM et la DCR du groupe du
# banc). Lecture côté Glorfindel : aucun droit de plus (Log Analytics Reader sur le workspace).
# Coût, volume, mesures : docs/operations.md, « auditd au banc (AUD1) ».

locals {
  # Les VM du banc qui reçoivent auditd : toutes celles du baseline, ou aucune.
  auditd_vms = { for k, v in local.vms : k => v if var.auditd_enabled }
  # La facilité où audisp-syslog écrit (scripts/auditd.sh, `args = LOG_INFO LOG_LOCAL6`).
  auditd_facility = "local6"
}

resource "azurerm_virtual_machine_extension" "auditd" {
  for_each                   = local.auditd_vms
  name                       = "eregion-auditd"
  virtual_machine_id         = azurerm_linux_virtual_machine.baseline[each.key].id
  publisher                  = "Microsoft.Azure.Extensions"
  type                       = "CustomScript"
  type_handler_version       = "2.1"
  auto_upgrade_minor_version = true
  tags                       = local.common_tags

  # Rien de secret : le script, lisible par qui lit la VM, comme dans le dépôt.
  settings = jsonencode({
    script = base64encode(file("${path.module}/scripts/auditd.sh"))
  })
}
