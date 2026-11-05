# AUD1 (#408) : auditd sur les VM du banc et local6 dans la DCR, planifiés contre de faux azurerm,
# azapi et null — aucun appel à Azure, comme les tests d'ID1 et de G1. La CI le lance à chaque PR
# (ci.yml, job terraform-test, CI4) ; à la main :
#   terraform -chdir=infra/terraform init -backend=false
#   terraform -chdir=infra/terraform test
# Deux cas : le drapeau à false (le défaut), dont le plan ne change rien au banc ; le drapeau à
# true, qui pose l'extension sur chaque VM du banc et local6 dans la DCR, et rien d'autre.
# tests/unit/test_bench_auditd.py tient le même contrat en lisant les fichiers.

mock_provider "azurerm" {}
mock_provider "azapi" {}
mock_provider "null" {}
mock_provider "azuread" {}

variables {
  # La clé jetable du test d'ID1 (sa clé privée n'a jamais été gardée).
  admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJsmbq1cw7yKD96VpcLp0pc+ghC6Shc4ZG5t9jktOyi id1-test"
  # Hermétique face au terraform.tfvars de l'opérateur (qui peut les activer).
  activity_log_enabled        = false
  entra_logs_enabled          = false
  auditd_enabled              = false
  entra_test_identity_enabled = false
  entra_bench_unit_enabled    = false
}

run "off_nothing_on_the_vms_the_dcr_as_always" {
  command = plan

  assert {
    condition     = length(azurerm_virtual_machine_extension.auditd) == 0
    error_message = "l'extension d'auditd est planifiée alors que auditd_enabled est à false"
  }
  assert {
    condition     = toset(azurerm_monitor_data_collection_rule.celebrimbor.data_sources[0].syslog[0].facility_names) == toset(["auth", "authpriv", "syslog", "daemon"])
    error_message = "la DCR du banc collecte d'autres facilités que celles de toujours, drapeau à false"
  }
}

run "on_every_bench_vm_and_local6_nothing_else" {
  command = plan

  variables {
    auditd_enabled = true
  }

  assert {
    condition     = keys(azurerm_virtual_machine_extension.auditd) == keys(azurerm_linux_virtual_machine.baseline)
    error_message = "l'extension d'auditd n'est pas sur chaque VM du banc, et sur elles seules"
  }
  assert {
    condition = alltrue([for k, e in azurerm_virtual_machine_extension.auditd :
    e.publisher == "Microsoft.Azure.Extensions" && e.type == "CustomScript" && e.name == "eregion-auditd"])
    error_message = "l'extension d'auditd n'est pas un CustomScript nommé eregion-auditd"
  }
  assert {
    condition = alltrue([for k, e in azurerm_virtual_machine_extension.auditd :
      strcontains(base64decode(jsondecode(e.settings).script), "-C euid!=uid -F auid!=unset -S execve -k user_emulation")
    && strcontains(base64decode(jsondecode(e.settings).script), "-F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command")])
    error_message = "le script de l'extension ne pose pas les deux règles d'audit (CIS user_emulation, root_command)"
  }
  assert {
    condition = alltrue([for k, e in azurerm_virtual_machine_extension.auditd :
    strcontains(base64decode(jsondecode(e.settings).script), "args = LOG_INFO LOG_LOCAL6")])
    error_message = "le greffon syslog d'auditd n'écrit pas dans local6, la facilité que la DCR collecte"
  }
  assert {
    condition     = toset(azurerm_monitor_data_collection_rule.celebrimbor.data_sources[0].syslog[0].facility_names) == toset(["auth", "authpriv", "syslog", "daemon", "local6"])
    error_message = "la DCR du banc ne collecte pas local6 en plus des facilités de toujours"
  }
  assert {
    condition     = length(azurerm_monitor_diagnostic_setting.activity_log) == 0 && length(azurerm_monitor_aad_diagnostic_setting.entra) == 0
    error_message = "auditd entraîne les paramètres de diagnostic de l'abonnement ou du tenant"
  }
}
