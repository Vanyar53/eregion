#!/usr/bin/env bash
# Canary for the just-in-time isolation: re-checks, on the latest azurerm provider, the
# Terraform properties Glorfindel's isolation relies on (measured 2026-10-06 with
# azurerm 4.81.0). Exit 0 = still holds; exit 1 = a property changed (read the output
# before relying on the isolation with that provider version); exit 2 = setup error.
#
# Needs: terraform, az (logged in), ARM_SUBSCRIPTION_ID or AZURE_SUBSCRIPTION_ID, and the
# resource group it works in, created once (CANARY_RESOURCE_GROUP, default rg-eregion-canary;
# docs/operations.md, « Le canari azurerm, sans secret »). It never creates nor deletes a group
# (P-04): it creates free resources only, named with its suffix (CANARY_SUFFIX), and deletes
# them at the end, success or not.
# AZURERM_CONSTRAINT picks the provider line (default "~> 4.0"; "~> 5.0", "~> 3.0"…):
# customers run all of them. The stack runs from a temporary copy (no state in the repo).
set -uo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
CONSTRAINT="${AZURERM_CONSTRAINT:-~> 4.0}"
export ARM_SUBSCRIPTION_ID="${ARM_SUBSCRIPTION_ID:-${AZURE_SUBSCRIPTION_ID:-}}"
[ -n "$ARM_SUBSCRIPTION_ID" ] || { echo "ARM_SUBSCRIPTION_ID / AZURE_SUBSCRIPTION_ID not set"; exit 2; }
RG="${CANARY_RESOURCE_GROUP:-rg-eregion-canary}"
SUFFIX="${CANARY_SUFFIX:-$(date +%s)}"
[[ "$SUFFIX" =~ ^[a-z0-9-]{1,40}$ ]] || { echo "CANARY_SUFFIX: 1 to 40 of a-z, 0-9, -"; exit 2; }
# The principal may not register resource providers (Network Contributor on one group): the provider
# must not try. 3.x reads skip_provider_registration; 4.x and 5.x resource_provider_registrations.
case "$CONSTRAINT" in
  *" 3."*|"3."*|*"=3."*) export ARM_SKIP_PROVIDER_REGISTRATION=true ;;
  *) export ARM_RESOURCE_PROVIDER_REGISTRATIONS=none ;;
esac
az group show -n "$RG" -o none >/dev/null 2>&1 \
  || { echo "resource group $RG not found or not readable: create it once (docs/operations.md)"; exit 2; }
WORK="$(mktemp -d)"
cp "$SRC/main.tf" "$WORK/"
sed -i "s/version = \"~> 4.0\"/version = \"$CONSTRAINT\"/" "$WORK/main.tf"
cd "$WORK"
TFV=(-var "suffix=$SUFFIX" -var "resource_group=$RG" -input=false -no-color)
Q="nsg-glorfindel-quarantine-canary-$SUFFIX"
FAILED=0

# This run's resources, found by their tag, NICs first: an NSG or a VNet still in use cannot go.
# The tag is filtered on the client, by equality: az refuses --tag with -g. One list per type,
# by the network commands (Network Contributor's own reads; the suffix is validated above).
# Their errors are left on stderr: a sweep that fails is seen in the job's log.
sweep() {
  local kind ids
  echo "   destroy failed: sweeping this run's resources by their tag"
  for kind in nic nsg vnet; do
    ids=$(az network "$kind" list -g "$RG" --query "[?tags.\"canary-run\"=='$SUFFIX'].id" -o tsv)
    # shellcheck disable=SC2086
    [ -z "$ids" ] || az network "$kind" delete --ids $ids -o none >/dev/null
  done
}

cleanup() {
  echo "== cleanup"
  terraform destroy -auto-approve "${TFV[@]}" -var nic_tag=v2 >/dev/null 2>&1 || sweep
  # Created outside Terraform, as Glorfindel does: never in its state.
  az network nsg delete -g "$RG" -n "$Q" -o none >/dev/null 2>&1
  cd / && rm -rf "$WORK"
}
trap cleanup EXIT
# A cancelled job (SIGINT, SIGTERM) still cleans up.
trap 'exit 130' INT TERM

nic_nsg() { az network nic show -g "$RG" -n "$1" --query networkSecurityGroup.id -o tsv | awk -F/ '{print $NF}'; }
expect() {  # expect <label> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1 — got '$2', expected '$3'"; FAILED=1; fi
}
plan_code() { terraform plan -detailed-exitcode "${TFV[@]}" "$@" >/dev/null 2>&1; echo $?; }

echo "== setup (latest azurerm $CONSTRAINT, group $RG, suffix $SUFFIX)"
terraform init -upgrade -input=false -no-color >/dev/null || exit 2
VERSION=$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("provider_selections",{}).get("registry.terraform.io/hashicorp/azurerm","?"))')
echo "   azurerm $VERSION"
terraform apply -auto-approve "${TFV[@]}" >/dev/null || exit 2
az network nsg create -g "$RG" -n "$Q" --tags purpose=eregion-canary-jit "canary-run=$SUFFIX" -o none || exit 2
QID=$(az network nsg show -g "$RG" -n "$Q" --query id -o tsv)
CID=$(az network nsg show -g "$RG" -n "nsg-customer-$SUFFIX" --query id -o tsv)
WITH="nic-with-nsg-$SUFFIX"
NONE="nic-no-nsg-$SUFFIX"

echo "== properties the isolation relies on"
az network nic update -g "$RG" -n "$WITH" --network-security-group "$QID" -o none
expect "NSG set outside Terraform on a NIC whose NSG is in code: plan shows no change" "$(plan_code)" 0
az network nic update -g "$RG" -n "$NONE" --network-security-group "$QID" -o none
expect "NSG attached outside Terraform to a NIC without one: plan shows no change" "$(plan_code)" 0
# This apply must succeed: if it fails, the two checks below pass without testing
# anything (third review, T16).
terraform apply -auto-approve "${TFV[@]}" -var nic_tag=v2 >/dev/null 2>&1
expect "apply updating the NIC succeeds" "$?" 0
expect "apply updating the NIC keeps the quarantine NSG (NIC with NSG in code)" "$(nic_nsg "$WITH")" "$Q"
expect "apply updating the NIC keeps the quarantine NSG (NIC without NSG)" "$(nic_nsg "$NONE")" "$Q"
az network nic update -g "$RG" -n "$WITH" --network-security-group "$CID" -o none
expect "original NSG put back on release: plan shows no change" "$(plan_code -var nic_tag=v2)" 0

echo "== result: azurerm $VERSION"
if [ "$FAILED" = 0 ]; then echo "PASS — the just-in-time isolation behaves as measured"; exit 0; fi
echo "CHANGED — see docs/design/module-isolation-iac.md before using this provider version"
exit 1
