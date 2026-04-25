#!/bin/bash
# Annatar — Data exfiltration simulation script
# Transfers synthetic data to a test storage account

STORAGE_SAS_URL="${1:-}"
SIZE_MB="${2:-512}"

set -euo pipefail

if [ -z "$STORAGE_SAS_URL" ]; then
  echo "[annatar] ERROR: Storage SAS URL required as first argument"
  exit 1
fi

echo "[annatar] Starting exfiltration simulation (${SIZE_MB}MB)..."
START=$(date -u +%s)

dd if=/dev/urandom bs=1M count="$SIZE_MB" 2>/dev/null | \
  curl -s -X PUT \
    --data-binary @- \
    -H "x-ms-blob-type: BlockBlob" \
    -H "Content-Type: application/octet-stream" \
    "${STORAGE_SAS_URL}/exfil-${START}.bin"

END=$(date -u +%s)
echo "[annatar] EXFIL_COMPLETE at $(date -u +%Y-%m-%dT%H:%M:%SZ) (${SIZE_MB}MB in $((END-START))s)"
