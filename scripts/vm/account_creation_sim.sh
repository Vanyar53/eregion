#!/bin/bash
# Annatar — T1136.001 Local Account Creation simulation
# Creates then immediately removes a test account.
# Also injects via auth facility (logger) to ensure DCR collection —
# DCR collects auth/syslog/daemon but not authpriv (Ubuntu useradd uses authpriv).

set -euo pipefail

USERNAME="testuser-annatar"

# Idempotent cleanup of any leftover from a previous run
userdel -f "${USERNAME}" 2>/dev/null || true

# Create the account (no home dir, no shell)
useradd -M -s /sbin/nologin "${USERNAME}"

# Inject auth-facility events to ensure DCR collection (useradd uses authpriv on Ubuntu)
logger -p auth.notice -t useradd "new group: name=${USERNAME}, GID=2001"
logger -p auth.notice -t useradd "new user: name=${USERNAME}, UID=2001, GID=2001, home=/home/${USERNAME}, shell=/sbin/nologin"

echo "[annatar] T1136.001 — account ${USERNAME} created + auth syslog events injected"

# Immediate cleanup
userdel -f "${USERNAME}"

echo "[annatar] Cleanup complete — ${USERNAME} removed"
