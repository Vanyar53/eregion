#!/bin/bash
# Annatar — Ransomware simulation script
# Runs ONLY on /mnt/testdata — never touches system files

TARGET="/mnt/testdata"
MARKER="$TARGET/.annatar_test_marker"

set -euo pipefail

if [ ! -d "$TARGET" ]; then
  echo "[annatar] ERROR: $TARGET not found. Is the test data disk mounted?"
  exit 1
fi

if [ ! -f "$MARKER" ]; then
  echo "[annatar] ERROR: Safety marker not found at $MARKER"
  echo "  This script only runs on volumes explicitly prepared for chaos testing."
  echo "  Run: touch $MARKER on the test volume to authorize."
  exit 1
fi

rm -f "$TARGET"/enc_*.dat "$TARGET/seed.dat"

echo "[annatar] Generating test data on $TARGET..."
dd if=/dev/urandom bs=1M count=512 of="$TARGET/seed.dat" 2>/dev/null

echo "[annatar] Starting encryption simulation..."
START=$(date -u +%s)
DURATION=45
END_AT=$((START + DURATION))

# Sustained I/O for at least 45s to ensure AMA captures the spike
i=0
while [ "$(date -u +%s)" -lt "$END_AT" ]; do
  dd if="$TARGET/seed.dat" bs=1M of="$TARGET/enc_$i.dat" conv=fsync 2>/dev/null
  rm -f "$TARGET/enc_$((i-1)).dat" 2>/dev/null
  i=$((i+1))
done
rm -f "$TARGET/seed.dat" "$TARGET/enc_$((i-1)).dat"

END=$(date -u +%s)
echo "[annatar] ENCRYPTION_COMPLETE at $(date -u +%Y-%m-%dT%H:%M:%SZ) (${START}→${END})"
