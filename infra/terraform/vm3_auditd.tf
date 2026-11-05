# VM3 (#548) — les règles auditd des paires T1059.004 et T1070.002 : PROPOSÉES, NON APPLIQUÉES.
#
# Pourquoi pas une extension : Azure n'autorise qu'une extension CustomScript par VM Linux, et
# AUD1 la tient (auditd.tf). Les règles de VM3 (volume élevé pour shell_exec) doivent rester sous
# un garde séparé — les câbler dans la même extension ferait tout passer avec auditd_enabled.
#
# Ce que ce fichier porte : la variable d'intention `vm3_auditd_enabled` (variables.tf, défaut
# false) et le local ci-dessous qui la relie au script. Le geste pour l'appliquer est manuel
# (docs/operations.md, « Les règles auditd de VM3 ») : poser scripts/vm3_auditd.sh sur les VM du
# banc où auditd est déjà installé (auditd_enabled, qui fournit local6 → Syslog).
#
# Un vrai câblage Terraform (une extension dédiée sur un autre socle, ou un garde dans auditd.sh
# sans toucher le contrat d'AUD1) est un lot de suite — hors VM3, qui livre les règles de
# détection et la source proposée.
locals {
  # Référence la variable (sinon déclarée sans emploi) et dit l'état de l'intention VM3.
  vm3_auditd_rules_script = "${path.module}/scripts/vm3_auditd.sh"
  vm3_auditd_note = var.vm3_auditd_enabled ? "VM3 auditd rules intended — pose ${local.vm3_auditd_rules_script} on the bench VMs (manual, docs/operations.md)" : "VM3 auditd rules not intended (default)"
}
