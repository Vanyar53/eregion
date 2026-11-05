#!/bin/bash
# VM3 (#548) — les règles auditd des deux paires qui lisent auditd : T1059.004 (un shell depuis
# un répertoire inscriptible) et T1070.002 (une altération de journal sous /var/log).
#
# PROPOSÉ, NON APPLIQUÉ par Terraform. Azure n'autorise qu'une extension CustomScript par VM, et
# AUD1 la tient (infra/terraform/auditd.tf → scripts/auditd.sh) : y ajouter ces règles sans le
# gardes séparé ferait tout passer en même temps (le volume de shell_exec noierait le signal
# humain d'AUD1). Ce script est donc un geste de Jonathan, à lancer sur une VM du banc où auditd
# est déjà posé (auditd_enabled, qui installe le greffon audisp-syslog vers local6) :
#   sudo bash vm3_auditd.sh         # pose /etc/audit/rules.d/60-eregion-vm3.rules et recharge
# Idempotent : relancé, il réécrit le même fichier. Le défaire : rm le fichier, puis
# `augenrules --load`. Détails et mesures : docs/operations.md, « Les règles auditd de VM3 ».
#
# Ce que lisent les règles de Glorfindel (glorfindel/rules/azure/detection_rules.yaml) :
#   - t1070-002-log-tamper : une écriture/création/suppression sous /var/log (clé log_tamper) par
#     un comm hors des démons de journalisation ;
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
##   - la création/suppression/renommage d'une entrée du répertoire (surveillance) ;
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

augenrules --load
service auditd restart || systemctl restart auditd

# Dit ce qui est chargé : les deux clés de VM3.
auditctl -l | grep -E 'key=(log_tamper|shell_exec)'
