#!/bin/bash
# Annatar — Post-restore integrity verification
# Verifies /mnt/testdata is in the expected clean state after OriginalLocation restore

TARGET="/mnt/testdata"
MARKER="$TARGET/.annatar_test_marker"

set -uo pipefail

PASS=0
FAIL=0

check() {
  local desc="$1"
  local result="$2"
  if [ "$result" = "ok" ]; then
    echo "[PASS] $desc"
  else
    echo "[FAIL] $desc — $result"
    FAIL=$((FAIL + 1))
  fi
}

if [ ! -d "$TARGET" ]; then
  echo "[FAIL] $TARGET not mounted"
  exit 1
fi

echo "=== disk diagnostic ==="
lsblk -o NAME,SIZE,MOUNTPOINT,UUID
echo "--- mounted at $TARGET ---"
df -h "$TARGET" 2>/dev/null || echo "(not mounted)"
echo "======================="

# Marker must be present
if [ -f "$MARKER" ]; then
  check "safety marker present" "ok"
else
  check "safety marker present" "missing — disk may not have been restored"
fi

# No encryption artifacts
enc_files=$(find "$TARGET" -maxdepth 1 -name "enc_*.dat" -type f | wc -l)
if [ "$enc_files" -eq 0 ]; then
  check "no enc_*.dat files" "ok"
else
  check "no enc_*.dat files" "$enc_files file(s) found — restore did not clean up attack artifacts"
  echo "  enc file timestamps (to distinguish backup data vs current attack):"
  find "$TARGET" -maxdepth 1 -name "enc_*.dat" -o -name "seed.dat" 2>/dev/null | xargs -I{} stat --format="  %n  mtime=%y" {} 2>/dev/null | head -5
  echo "  disk UUID: $(blkid -s UUID -o value $(df --output=source "$TARGET" | tail -1) 2>/dev/null)"
  echo "  marker mtime: $(stat --format='%y' $MARKER 2>/dev/null)"
fi

seed_file="$TARGET/seed.dat"
if [ ! -f "$seed_file" ]; then
  check "no seed.dat" "ok"
else
  check "no seed.dat" "file found — restore did not clean up attack artifacts"
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "INTEGRITY_PASS"
  exit 0
else
  echo "INTEGRITY_FAIL ($FAIL check(s) failed)"
  exit 1
fi
