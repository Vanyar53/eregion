#!/bin/bash
# Annatar — Privilege escalation simulation (T1548.003)
# Simulates an attacker escalating from a compromised service account to root
# via a misconfigured sudoers wildcard entry.
# Uses logger only — no actual privilege escalation or system modification occurs.
#
# Detection: Syslog auth facility, successful sudo USER=root entries.
# Expected Glorfindel response: isolate_vm (OS-level compromise).

set -euo pipefail

ATTACKER_USER="${1:-svc-backup}"
FAILED_ATTEMPTS="${2:-8}"

echo "[annatar] Simulating privilege escalation (T1548.003) by ${ATTACKER_USER}..."

# Phase 1: Probing — attacker tests which sudo commands are available
for i in $(seq 1 "$FAILED_ATTEMPTS"); do
  pid=$((12000 + i))
  # sudo password prompt rejected (attacker doesn't have the sudoer password)
  logger -p auth.warning "sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1001 euid=0 tty=/dev/pts/1 ruser=${ATTACKER_USER} rhost=  user=${ATTACKER_USER}"
  logger -p auth.warning "sudo[${pid}]:   ${ATTACKER_USER} : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/${ATTACKER_USER} ; USER=root ; COMMAND=/bin/bash"
  sleep 0.05
done

# Phase 2: Discovery — attacker reads /etc/sudoers.d/ and finds a wildcard entry:
#   svc-backup ALL=(root) NOPASSWD: /opt/scripts/backup.sh *
# The wildcard allows arbitrary arguments — attacker appends a shell escape.
sleep 1

pid_esc=$((12000 + FAILED_ATTEMPTS + 1))
pid_sess=$((12000 + FAILED_ATTEMPTS + 2))
pid_cmd1=$((12000 + FAILED_ATTEMPTS + 3))
pid_cmd2=$((12000 + FAILED_ATTEMPTS + 4))

# Escalation: sudo invoked with shell-escape via wildcard (NOPASSWD, no prompt)
logger -p auth.warning "sudo[${pid_esc}]:   ${ATTACKER_USER} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/opt/scripts/backup.sh /dev/null"
logger -p auth.warning "sudo: pam_unix(sudo:session): session opened for user root by ${ATTACKER_USER}(uid=1001)"

# Post-escalation: attacker exercises root access (credential dump, persistence)
logger -p auth.warning "sudo[${pid_cmd1}]:   ${ATTACKER_USER} : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow"
logger -p auth.warning "sudo[${pid_cmd2}]:   ${ATTACKER_USER} : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"

echo "[annatar] PRIVILEGE_ESCALATION_SIMULATED — ${ATTACKER_USER} escalated to root via sudoers wildcard"
