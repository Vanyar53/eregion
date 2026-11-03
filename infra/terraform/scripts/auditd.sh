#!/bin/bash
# AUD1 (#408) — auditd à la manière du CIS sur une VM du banc, ses lignes vers Syslog.
#
# Posé par l'extension CustomScript d'auditd.tf, seulement quand `auditd_enabled = true`
# (terraform.tfvars ; désactivé par défaut). Idempotent : relancé, il réécrit les mêmes fichiers.
#
# Deux règles d'audit, sous l'identité de connexion (auid) que le noyau garde à travers sudo et su :
#   - celle des benchmarks CIS pour Linux (« actions as another user are always logged ») :
#     un programme exécuté sous un autre utilisateur — sudo, su, un binaire setuid ;
#   - ce que la règle du CIS ne voit pas : après sudo, un shell root a uid = euid = 0, ses commandes
#     n'ont pas euid != uid. La seconde règle écrit chaque exécution en root (euid 0) d'une
#     connexion humaine (auid >= 1000, jamais unset).
# Puis le greffon syslog d'auditd (audisp-syslog) envoie chaque enregistrement à syslog, facilité
# local6, niveau info : rsyslog le passe à l'agent Azure Monitor, que la DCR du banc fait lire
# local6 (monitoring.tf). La règle auditd-sensitive-root-command de Glorfindel les lit.
#
# Ce qui reste des hypothèses, à mesurer au banc avec Jonathan (docs/operations.md, « Les
# hypothèses d'AUD1 », A1–A13) : le paquet du greffon, l'étiquette et la forme des lignes, le
# format ENRICHED transmis au greffon, le débit que journald laisse passer.
#
# Le défaire : retirer /etc/audit/rules.d/50-eregion-aud1.rules, mettre `active = no` dans
# /etc/audit/plugins.d/syslog.conf, puis `augenrules --load` et `service auditd restart`
# (supprimer l'extension ne défait rien sur la VM ; docs/operations.md, « auditd au banc (AUD1) »).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Le verrou de dpkg attendu (les mises à jour automatiques le tiennent parfois au démarrage).
apt-get -o DPkg::Lock::Timeout=300 update -q
# auditd, et audispd-plugins qui porte audisp-syslog sous Ubuntu 22.04 (hypothèse A1).
apt-get -o DPkg::Lock::Timeout=300 install -y -q auditd audispd-plugins

RULES=/etc/audit/rules.d/50-eregion-aud1.rules
cat > "$RULES" <<'EOF'
## AUD1 (#408) — Eregion, le banc. Posé par infra/terraform/scripts/auditd.sh.
## CIS : les actions sous un autre utilisateur (sudo, su, un binaire setuid), sous l'auid de connexion.
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
## Ce que le CIS ne voit pas : les commandes d'un shell root (uid = euid = 0) d'une connexion humaine.
-a always,exit -F arch=b64 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command
-a always,exit -F arch=b32 -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command
EOF
chmod 0640 "$RULES"

# ENRICHED : le nom du compte (AUID="…") écrit à côté de son numéro (hypothèse A6).
CONF=/etc/audit/auditd.conf
if grep -q '^log_format' "$CONF"; then
  sed -i 's/^log_format.*/log_format = ENRICHED/' "$CONF"
else
  echo 'log_format = ENRICHED' >> "$CONF"
fi

# Le greffon syslog : chaque enregistrement vers syslog, local6, info.
PLUGIN=/etc/audit/plugins.d/syslog.conf
if [ ! -x /sbin/audisp-syslog ]; then
  echo "AUD1 : /sbin/audisp-syslog absent — le greffon syslog n'est pas installé (hypothèse A1)" >&2
  exit 1
fi
cat > "$PLUGIN" <<'EOF'
# AUD1 (#408) — posé par infra/terraform/scripts/auditd.sh
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_INFO LOG_LOCAL6
format = string
EOF
chmod 0640 "$PLUGIN"

systemctl enable auditd
augenrules --load
# auditd se redémarre par son script de service (le format et le greffon se relisent au démarrage).
service auditd restart

# Dit ce qui est chargé : les deux clés, quatre règles.
auditctl -l | grep -E 'key=(user_emulation|root_command)'
test "$(auditctl -l | grep -cE 'key=(user_emulation|root_command)')" -eq 4
