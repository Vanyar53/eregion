#!/bin/bash
# Annatar — Post-scenario cleanup for /mnt/testdata
# Fallback if restore failed or was skipped — removes attack artifacts manually

TARGET="/mnt/testdata"

set -euo pipefail

if [ ! -d "$TARGET" ]; then
  echo "[annatar] WARNING: $TARGET not mounted, nothing to clean"
  exit 0
fi

removed=0
for f in "$TARGET"/enc_*.dat "$TARGET/seed.dat"; do
  [ -f "$f" ] && rm -f "$f" && removed=$((removed + 1))
done

if [ "$removed" -gt 0 ]; then
  echo "[annatar] Cleanup removed $removed file(s)"
else
  echo "[annatar] Nothing to clean — volume already in clean state"
fi
