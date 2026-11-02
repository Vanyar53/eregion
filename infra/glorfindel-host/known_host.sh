#!/usr/bin/env bash
# V-32 (SEC7, SEC14): a host key pinned by its fingerprint — the hosted Glorfindel's (H0), and
# Orodruin's.
#
#   HOST_SSH_FINGERPRINT=SHA256:… bash infra/glorfindel-host/known_host.sh <ip> <known_hosts>
#   ORO_SSH_FINGERPRINT=SHA256:… bash infra/glorfindel-host/known_host.sh <ip> <known_hosts> \
#       ORO_SSH_FINGERPRINT required
#
# The third argument names the variable that holds the fingerprint (HOST_SSH_FINGERPRINT by
# default, or ORO_SSH_FINGERPRINT); with « required », its absence refuses — Orodruin's commands
# never fall back to accept-new.
# Run by make before every command that reaches H0 (glorfindel-host-known) or Orodruin
# (orodruin-known). The expected
# fingerprint comes from the operator's environment, never from the repository: read once on
# the host itself (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`, README « SSH »).
#   - With it: the dedicated known_hosts must hold, for <ip>, a key of that fingerprint. Absent,
#     the key the host presents is read (ssh-keyscan) and written only if it has that
#     fingerprint. A key of another fingerprint, recorded or presented, refuses: nothing runs.
#     ssh then connects with StrictHostKeyChecking=yes on that file alone (the Makefile's
#     HOST_SSH_OPTS): a key changed afterwards refuses too.
#   - Without it, for H0: accept-new stays (the key accepted at first contact, a change refused),
#     and this says so on every command. For Orodruin (« required »): refused, nothing runs.
# Exit 0: go on; 1: refused. No secret here, nothing written but that known_hosts.
set -euo pipefail

ip=${1:-}
file=${2:-}
var=${3:-HOST_SSH_FINGERPRINT}
required=${4:-}
case "$var" in
  HOST_SSH_FINGERPRINT | ORO_SSH_FINGERPRINT) ;;
  *) echo "✗ known_host.sh : HOST_SSH_FINGERPRINT ou ORO_SSH_FINGERPRINT, pas « $var »" >&2; exit 1 ;;
esac
want=${!var:-}

[ -n "$ip" ] || exit 0          # no VM: the target says so itself
if [ -z "$want" ]; then
  if [ -n "$required" ]; then
    echo "✗ $var requis : la clé d'hôte de $ip doit être vérifiée par son empreinte — jamais" \
         "accept-new pour ce qui fait agir Orodruin. La lire par Azure (make orodruin-fingerprint)" \
         "et la poser dans ton environnement : rien n'est lancé." >&2
    exit 1
  fi
  echo "⚠ $var absent : la clé d'hôte de $ip est acceptée au premier contact" \
       "(accept-new). La relever sur la VM et la poser : infra/glorfindel-host/README.md, « SSH »." >&2
  exit 0
fi
case "$want" in
  SHA256:?*) ;;
  *) echo "✗ $var : une empreinte SHA256:… (ssh-keygen -lf …), pas « $want » : rien n'est lancé." >&2
     exit 1 ;;
esac
[ -n "$file" ] || { echo "✗ pas de fichier known_hosts" >&2; exit 1; }

# The fingerprint of each key line read on stdin (ssh-keygen -lf - : one line per key).
fingerprints() { ssh-keygen -lf - 2>/dev/null | awk '{print $2}'; }

if [ -s "$file" ]; then
  known=$(ssh-keygen -F "$ip" -f "$file" 2>/dev/null | grep -v '^#' || true)
  if [ -n "$known" ]; then
    if printf '%s\n' "$known" | fingerprints | grep -qxF -- "$want"; then
      exit 0
    fi
    echo "✗ La clé d'hôte enregistrée pour $ip dans $file n'a pas l'empreinte $var :" \
         "rien n'est lancé. VM reconstruite ? Relever sa nouvelle empreinte sur la VM, la poser," \
         "puis retirer $file." >&2
    exit 1
  fi
fi

scanned=$(ssh-keyscan -T 10 -t ed25519 "$ip" 2>/dev/null || true)
match=""
while IFS= read -r line; do
  case "$line" in ''|\#*) continue ;; esac
  if [ "$(printf '%s\n' "$line" | fingerprints)" = "$want" ]; then
    match=$line
    break
  fi
done <<< "$scanned"
if [ -z "$match" ]; then
  echo "✗ La clé d'hôte que présente $ip n'a pas l'empreinte $var (ou l'hôte ne répond" \
       "pas) : rien n'est lancé. Une autre machine à cette adresse ? Relever l'empreinte sur la VM." >&2
  exit 1
fi
mkdir -p "$(dirname "$file")"
umask 077
printf '%s\n' "$match" >> "$file"
echo "  ✓ Clé d'hôte de $ip vérifiée par son empreinte, écrite dans $file" >&2
