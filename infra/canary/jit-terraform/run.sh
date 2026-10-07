#!/usr/bin/env bash
# Canary for the just-in-time isolation: re-checks, on the latest azurerm provider, the
# Terraform properties Glorfindel's isolation relies on (measured 2026-10-06 with
# azurerm 4.81.0). Exit 0 = still holds; exit 1 = a property changed (read the output
# before relying on the isolation with that provider version); exit 2 = setup error.
#
# Needs: terraform, az (logged in), ARM_SUBSCRIPTION_ID or AZURE_SUBSCRIPTION_ID.
set -uo pipefail
cd "$(dirname "$0")"
export ARM_SUBSCRIPTION_ID="${ARM_SUBSCRIPTION_ID:-${AZURE_SUBSCRIPTION_ID:-}}"
[ -n "$ARM_SUBSCRIPTION_ID" ] || { echo "ARM_SUBSCRIPTION_ID / AZURE_SUBSCRIPTION_ID not set"; exit 2; }
SUFFIX="${CANARY_SUFFIX:-$(date +%s)}"
RG="rg-eregion-canary-jit-$SUFFIX"
TFV=(-var "suffix=$SUFFIX" -input=false -no-color)
FAILED=0

cleanup() {
  echo "== cleanup"
  terraform destroy -auto-approve "${TFV[@]}" -var nic_tag=v2 >/dev/null 2>&1 \
    || az group delete -n "$RG" --yes --no-wait >/dev/null 2>&1
  rm -rf .terraform terraform.tfstate* .terraform.lock.hcl
}
trap cleanup EXIT

nic_nsg() { az network nic show -g "$RG" -n "$1" --query networkSecurityGroup.id -o tsv | awk -F/ '{print $NF}'; }
expect() {  # expect <label> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1 — got '$2', expected '$3'"; FAILED=1; fi
}
plan_code() { terraform plan -detailed-exitcode "${TFV[@]}" "$@" >/dev/null 2>&1; echo $?; }

echo "== setup (latest azurerm ~> 4.0)"
terraform init -upgrade -input=false -no-color >/dev/null || exit 2
VERSION=$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("provider_selections",{}).get("registry.terraform.io/hashicorp/azurerm","?"))')
echo "   azurerm $VERSION"
terraform apply -auto-approve "${TFV[@]}" >/dev/null || exit 2
Q=nsg-glorfindel-quarantine-canary
az network nsg create -g "$RG" -n "$Q" -o none || exit 2
QID=$(az network nsg show -g "$RG" -n "$Q" --query id -o tsv)
CID=$(az network nsg show -g "$RG" -n nsg-customer --query id -o tsv)

echo "== properties the isolation relies on"
az network nic update -g "$RG" -n nic-with-nsg --network-security-group "$QID" -o none
expect "NSG set outside Terraform on a NIC whose NSG is in code: plan shows no change" "$(plan_code)" 0
az network nic update -g "$RG" -n nic-no-nsg --network-security-group "$QID" -o none
expect "NSG attached outside Terraform to a NIC without one: plan shows no change" "$(plan_code)" 0
terraform apply -auto-approve "${TFV[@]}" -var nic_tag=v2 >/dev/null 2>&1
expect "apply updating the NIC keeps the quarantine NSG (NIC with NSG in code)" "$(nic_nsg nic-with-nsg)" "$Q"
expect "apply updating the NIC keeps the quarantine NSG (NIC without NSG)" "$(nic_nsg nic-no-nsg)" "$Q"
az network nic update -g "$RG" -n nic-with-nsg --network-security-group "$CID" -o none
expect "original NSG put back on release: plan shows no change" "$(plan_code -var nic_tag=v2)" 0

echo "== result: azurerm $VERSION"
if [ "$FAILED" = 0 ]; then echo "PASS — the just-in-time isolation behaves as measured"; exit 0; fi
echo "CHANGED — see docs/design/module-isolation-iac.md before using this provider version"
exit 1
