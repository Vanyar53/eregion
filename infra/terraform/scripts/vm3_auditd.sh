#!/bin/bash
# VM3 (#548) — les règles auditd des deux paires qui lisent auditd : T1059.004 (un shell depuis
# un répertoire inscriptible) et T1070.002 (une altération de journal sous /var/log).
#
# PROPOSÉ, NON APPLIQUÉ par Terraform. Azure n'autorise qu'une extension CustomScript par VM, et
# AUD1 la tient (infra/terraform/auditd.tf → scripts/auditd.sh) ; y joindre ces règles les ferait
# passer avec auditd_enabled (le volume de shell_exec noierait le signal humain d'AUD1). C'est un
# geste de Jonathan, sur une VM du banc où auditd est déjà posé (auditd_enabled : le greffon
# audisp-syslog vers local6). Le dépôt n'est pas sur la VM : le script y part par Run Command,
# depuis le poste, à la racine du dépôt (docs/operations.md, « Les règles auditd de VM3 ») :
#   az vm run-command invoke -g rg-celebrimbor -n vm-celebrimbor-gondolin \
#     --command-id RunShellScript --scripts @infra/terraform/scripts/vm3_auditd.sh
# Idempotent : relancé, il réécrit le même fichier. Le défaire : retirer le fichier, puis
# `augenrules --load`.
#
# Ce que lisent les règles de Glorfindel (glorfindel/rules/azure/detection_rules.yaml) :
#   - t1070-002-log-tamper : un événement de clé log_tamper dont l'écrivain (exe) n'est pas un
#     démon de journalisation, ni un écrivain connu sur ses seuls fichiers ;
#   - t1059-004-shell-from-world-writable : l'execve d'un shell (clé shell_exec) dont le script
#     est sous /tmp, /dev/shm ou /var/tmp.
# Les colonnes et la forme des lignes sont des HYPOTHÈSES (A0, AUD1), à mesurer au banc.
#
# COÛT (hypothèse) : shell_exec journalise CHAQUE execve de dash/bash — volume élevé. Pour cela
# il reste séparé d'AUD1 et désactivé par défaut. À affiner (filtrer, limiter) après mesure.
set -euo pipefail

if [ ! -x /sbin/audisp-syslog ] && [ ! -x /usr/sbin/audisp-syslog ]; then
  echo "VM3 : audisp-syslog absent — pose d'abord auditd (auditd_enabled, AUD1) avant ce script" >&2
  exit 1
fi

RULES=/etc/audit/rules.d/60-eregion-vm3.rules
cat > "$RULES" <<'EOF'
## VM3 (#548) — Eregion, le banc. Posé par infra/terraform/scripts/vm3_auditd.sh.
## T1070.002 : une altération d'un journal sous /var/log.
##   - une écriture ou un attribut dans le sous-arbre (surveillance du répertoire) ;
-w /var/log -p wa -k log_tamper
##   - la troncature/suppression/renommage d'un fichier existant du sous-arbre (appels système).
-a always,exit -F arch=b64 -F dir=/var/log -F perm=wa -S truncate,ftruncate,unlink,unlinkat,rename,renameat,renameat2 -k log_tamper
-a always,exit -F arch=b32 -F dir=/var/log -F perm=wa -S truncate,ftruncate,unlink,unlinkat,rename,renameat,renameat2 -k log_tamper
## T1059.004 : l'exécution d'un interpréteur shell (la règle retient les scripts sous /tmp,
## /dev/shm, /var/tmp). Volume élevé : chaque execve de dash/bash.
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dash -k shell_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/dash -k shell_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/bash -k shell_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/bash -k shell_exec
EOF
chmod 0640 "$RULES"

# Les règles se chargent dans le noyau sans redémarrer auditd (Ubuntu refuse un `systemctl
# restart auditd` : RefuseManualStop).
augenrules --load

# Dit ce qui est chargé : les deux clés de VM3.
auditctl -l | grep -E 'key=(log_tamper|shell_exec)'
