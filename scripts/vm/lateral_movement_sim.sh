#!/bin/bash
# Annatar — SSH brute force simulation (T1110.001)
# Injects fake failed SSH attempts into auth.log via logger.
# The attacker IP is external and realistic (known Tor exit node range).
# Detection: Syslog table in Log Analytics (DCR already collects auth facility).

set -euo pipefail

ATTACKER_IP="${1:-185.220.101.1}"
ATTEMPTS="${2:-25}"

echo "[annatar] Simulating SSH brute force from ${ATTACKER_IP} (${ATTEMPTS} attempts)..."

for i in $(seq 1 "$ATTEMPTS"); do
  port=$((40000 + i))
  # Alternate between invalid user and valid username brute force
  if (( i % 3 == 0 )); then
    logger -p auth.warning "sshd[$$]: Failed password for root from ${ATTACKER_IP} port ${port} ssh2"
  elif (( i % 3 == 1 )); then
    logger -p auth.warning "sshd[$$]: Invalid user admin from ${ATTACKER_IP} port ${port}"
    logger -p auth.warning "sshd[$$]: Failed password for invalid user admin from ${ATTACKER_IP} port ${port} ssh2"
  else
    logger -p auth.warning "sshd[$$]: Failed password for annatar from ${ATTACKER_IP} port ${port} ssh2"
  fi
  sleep 0.05
done

echo "[annatar] LATERAL_MOVEMENT_SIMULATED — ${ATTEMPTS} failed SSH attempts from ${ATTACKER_IP}"
