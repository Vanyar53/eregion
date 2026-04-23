#!/bin/bash
# SecurityChaos — Ransomware simulation script
# Runs ONLY on /mnt/testdata — never touches system files

TARGET="/mnt/testdata"
MARKER="$TARGET/.sechaos_test_marker"

set -euo pipefail

if [ ! -d "$TARGET" ]; then
  echo "[sechaos] ERROR: $TARGET not found. Is the test data disk mounted?"
  exit 1
fi

if [ ! -f "$MARKER" ]; then
  echo "[sechaos] ERROR: Safety marker not found at $MARKER"
  echo "  This script only runs on volumes explicitly prepared for chaos testing."
  echo "  Run: touch $MARKER on the test volume to authorize."
  exit 1
fi

echo "[sechaos] Generating test data on $TARGET..."
for i in $(seq 1 200); do
  dd if=/dev/urandom bs=1K count=512 of="$TARGET/testfile_$i.dat" 2>/dev/null
done

echo "[sechaos] Starting encryption simulation..."
START=$(date -u +%s)

find "$TARGET" -name "testfile_*.dat" | while read -r file; do
  dd if=/dev/urandom bs=1K count=512 of="${file}.enc" 2>/dev/null
  rm -f "$file"
done

END=$(date -u +%s)
echo "[sechaos] ENCRYPTION_COMPLETE at $(date -u +%Y-%m-%dT%H:%M:%SZ) (${START}→${END})"
