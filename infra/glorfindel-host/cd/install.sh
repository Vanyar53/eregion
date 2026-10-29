#!/bin/bash
# install.sh — on H0, with sudo: the CD's systemd units (H1, #244). Run by
# `make glorfindel-host-cd-install`, after the agent's files are copied to ~/.eregion-cd/.
#
#   sudo bash ~/.eregion-cd/install.sh            install (or update) the units; the timer
#                                                 stays as it was — disabled at the first
#                                                 installation: make glorfindel-host-cd-check,
#                                                 then make glorfindel-host-cd-enable
#   sudo bash ~/.eregion-cd/install.sh --remove   stop and remove them (~/.eregion-cd stays)
set -euo pipefail

die() { echo "✗ $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "à lancer avec sudo"
USER_NAME="${SUDO_USER:-}"
[ -n "$USER_NAME" ] && [ "$USER_NAME" != root ] || die "lancer depuis le compte de H0 avec sudo (SUDO_USER manque)"
USER_HOME=$(getent passwd "$USER_NAME" | cut -d: -f6)
SRC="$USER_HOME/.eregion-cd"
UNITS=/etc/systemd/system

if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now eregion-cd.timer 2>/dev/null || true
  rm -f "$UNITS/eregion-cd.service" "$UNITS/eregion-cd.timer"
  systemctl daemon-reload
  echo "✓ unités du CD retirées ($SRC reste)"
  exit 0
fi

for f in eregion_cd.py deploy.sh notify_discord.py chat_text.py published_image.py cosign \
         eregion-cd.service eregion-cd.timer; do
  [ -f "$SRC/$f" ] || die "$SRC/$f manque : make glorfindel-host-cd-install le copie"
done
# CI3: the CD verifies each release's image with this cosign, pinned by its sha256.
sudo -u "$USER_NAME" python3 "$SRC/published_image.py" install-cosign "$SRC/cosign" >/dev/null \
  || die "$SRC/cosign n'est pas le cosign épinglé (published_image.py, COSIGN_SHA256)"
command -v python3 >/dev/null || die "python3 manque"
id -nG "$USER_NAME" | grep -qw docker || die "$USER_NAME n'est pas dans le groupe docker"
sed -e "s|@USER@|$USER_NAME|g" -e "s|@HOME@|$USER_HOME|g" "$SRC/eregion-cd.service" > "$UNITS/eregion-cd.service"
cp "$SRC/eregion-cd.timer" "$UNITS/eregion-cd.timer"
chmod 644 "$UNITS/eregion-cd.service" "$UNITS/eregion-cd.timer"
systemctl daemon-reload
state=$(systemctl is-enabled eregion-cd.timer 2>/dev/null || true)
echo "✓ unités du CD installées pour $USER_NAME (timer : ${state:-disabled})"
[ "$state" = enabled ] || echo "  ensuite : make glorfindel-host-cd-check (à blanc), puis make glorfindel-host-cd-enable"
