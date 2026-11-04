#!/usr/bin/env bash
# Canary for the just-in-time isolation: re-checks, on the latest azurerm provider, the
# Terraform properties Glorfindel's isolation relies on (measured 2026-10-06 with
# azurerm 4.81.0). Exit 0 = still holds; exit 1 = a property changed (read the output
# before relying on the isolation with that provider version); exit 2 = setup error;
# exit 3 = inconclusive: a command failed on an error Azure calls transient (429,
# AnotherOperationInProgress, RetryableError…) and no check had failed before it — re-run.
#
# Its logs are public (GitHub Actions, a public repository). A failed terraform says the end
# of its output, an az its stderr, only through redact.py: the canary's identifiers, resource
# ids, GUIDs, tokens, a SAS's signature, a tenant's domain, e-mail addresses and IPs taken out
# first, no workflow command left (::name:: nor ##[name]; CAN1, #501). Nothing else of theirs
# is printed — and nothing at all if the filter fails.
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
WORK="$(mktemp -d)"
OUT="$WORK/.canary-out"
SAY_CONTEXT=check   # what a transient error asks: a re-run (check), nothing more (cleanup)

# A command's output, said through the filter only (redact.py), on stderr: stdout may be a
# $(…) capture. What the filter said is printed on its exits 0 and 3 alone — on any other,
# nothing of it (it may have stopped halfway), its own errors silenced too. Exit 3 = a
# transient error, noted for the verdict.
say() {  # say <label> <file> [redact.py options…]
  local rc=0
  python3 -I "$SRC/redact.py" --label "$1" --context "$SAY_CONTEXT" "${@:3}" < "$2" \
    > "$OUT.said" 2>/dev/null || rc=$?
  case $rc in
    0) cat "$OUT.said" >&2 ;;
    3) cat "$OUT.said" >&2; : > "$WORK/.transient" ;;
    *) echo "   $1: its output withheld (the filter failed)" >&2 ;;
  esac
}
# terraform, its output kept aside; an exit not among <ok> says its end, filtered.
tf() {  # tf "<ok exits>" <terraform args…>
  local ok=" $1 " rc
  shift
  terraform "$@" > "$OUT.tf" 2>&1
  rc=$?
  [[ "$ok" == *" $rc "* ]] || say "terraform $1 failed (exit $rc)" "$OUT.tf" --tail 30 --verdict
  return "$rc"
}
# az, its stderr said through the filter: an Azure error names ids and addresses. Its stdout,
# which the canary captures (an NSG's id), never printed, is left as it is.
az() {
  local rc
  command az "$@" 2> "$OUT.az"
  rc=$?
  if [ "$rc" != 0 ]; then say "az $1 ${2:-} ${3:-} failed (exit $rc)" "$OUT.az" --tail 30 --verdict
  elif [ -s "$OUT.az" ]; then say "az $1 ${2:-} ${3:-} warned" "$OUT.az" --tail 10
  fi
  return "$rc"
}
# A setup step failed: exit 3 if on a transient error, else 2.
setup_failed() {
  if [ -e "$WORK/.transient" ]; then
    echo "INCONCLUSIVE — the setup failed on a transient error (above): re-run this line"; exit 3
  fi
  exit 2
}

if ! az group show -n "$RG" -o none; then
  echo "resource group $RG not found or not readable: create it once (docs/operations.md)"
  code=2
  [ ! -e "$WORK/.transient" ] || code=3
  rm -rf "$WORK"
  exit "$code"
fi
cp "$SRC/main.tf" "$WORK/"
sed -i "s/version = \"~> 4.0\"/version = \"$CONSTRAINT\"/" "$WORK/main.tf"
cd "$WORK"
TFV=(-var "suffix=$SUFFIX" -var "resource_group=$RG" -input=false -no-color)
Q="nsg-glorfindel-quarantine-canary-$SUFFIX"
FAILED=0
CLEAN_FAIL=0     # a check failed before any transient error: a change, not a passing hitch

# This run's resources, found by their tag, NICs first: an NSG or a VNet still in use cannot go.
# The tag is filtered on the client, by equality: az refuses --tag with -g. One list per type,
# by the network commands (Network Contributor's own reads; the suffix is validated above).
# Their errors are said, filtered (az, above): a sweep that fails is seen in the job's log.
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
  # A second signal (the runner's SIGTERM some 7.5 s after its SIGINT) must not cut the cleanup
  # short: ignored from here on. SIGKILL, which follows, cannot be.
  trap '' INT TERM
  # The verdict is said: a transient error here asks for no re-run of the checks.
  SAY_CONTEXT=cleanup
  echo "== cleanup"
  tf 0 destroy -auto-approve "${TFV[@]}" -var nic_tag=v2 || sweep
  # Created outside Terraform, as Glorfindel does: never in its state.
  az network nsg delete -g "$RG" -n "$Q" -o none >/dev/null 2>&1
  cd / && rm -rf "$WORK"
}
trap cleanup EXIT
# A cancelled or timed-out job (SIGINT, then SIGTERM, then SIGKILL) tries to clean up.
trap 'exit 130' INT TERM

nic_nsg() { az network nic show -g "$RG" -n "$1" --query networkSecurityGroup.id -o tsv | awk -F/ '{print $NF}'; }
expect() {  # expect <label> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "  ok   $1"; return; fi
  echo "  FAIL $1 — got '$2', expected '$3'"
  FAILED=1
  [ -e "$WORK/.transient" ] || CLEAN_FAIL=1
}
plan_code() { tf "0 2" plan -detailed-exitcode "${TFV[@]}" "$@"; echo $?; }

echo "== setup (latest azurerm $CONSTRAINT, group $RG, suffix $SUFFIX)"
tf 0 init -upgrade -input=false -no-color || setup_failed
VERSION=$(terraform version -json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("provider_selections",{}).get("registry.terraform.io/hashicorp/azurerm","?"))')
echo "   azurerm $VERSION"
tf 0 apply -auto-approve "${TFV[@]}" || setup_failed
az network nsg create -g "$RG" -n "$Q" --tags purpose=eregion-canary-jit "canary-run=$SUFFIX" -o none || setup_failed
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
tf 0 apply -auto-approve "${TFV[@]}" -var nic_tag=v2
expect "apply updating the NIC succeeds" "$?" 0
expect "apply updating the NIC keeps the quarantine NSG (NIC with NSG in code)" "$(nic_nsg "$WITH")" "$Q"
expect "apply updating the NIC keeps the quarantine NSG (NIC without NSG)" "$(nic_nsg "$NONE")" "$Q"
az network nic update -g "$RG" -n "$WITH" --network-security-group "$CID" -o none
expect "original NSG put back on release: plan shows no change" "$(plan_code -var nic_tag=v2)" 0

echo "== result: azurerm $VERSION"
if [ "$FAILED" = 0 ]; then echo "PASS — the just-in-time isolation behaves as measured"; exit 0; fi
if [ "$CLEAN_FAIL" = 0 ] && [ -e "$WORK/.transient" ]; then
  echo "INCONCLUSIVE — every failed check came after a transient error (above): re-run this line before reading a change"
  exit 3
fi
echo "CHANGED — see docs/design/module-isolation-iac.md before using this provider version"
exit 1
