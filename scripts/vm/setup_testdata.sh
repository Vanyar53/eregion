#!/bin/bash
# Annatar — Pre-scenario setup for /mnt/testdata
# Idempotent: safe to run multiple times, clears residuals from previous runs

TARGET="/mnt/testdata"
MARKER="$TARGET/.annatar_test_marker"

set -euo pipefail

if [ ! -d "$TARGET" ]; then
  echo "[annatar] ERROR: $TARGET not mounted — attach and mount the test data disk first"
  exit 1
fi

# Remove residuals from any previous failed run so we start clean
removed=0
for f in "$TARGET"/enc_*.dat "$TARGET/seed.dat"; do
  [ -f "$f" ] && rm -f "$f" && removed=$((removed + 1))
done
[ "$removed" -gt 0 ] && echo "[annatar] Removed $removed residual file(s) from previous run"

# Ensure the safety marker is present — ransomware_sim.sh refuses to run without it
if [ ! -f "$MARKER" ]; then
  touch "$MARKER"
  echo "[annatar] Created safety marker: $MARKER"
else
  echo "[annatar] Safety marker already present: $MARKER"
fi

echo "[annatar] Setup complete — $(ls "$TARGET" | wc -l) file(s) in $TARGET"
