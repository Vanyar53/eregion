#!/bin/bash
# Annatar — VM start/stop control

RG="annatar"
VM="vm-annatar-victim"

usage() {
  echo "Usage: $0 {start|stop|status}"
  exit 1
}

cmd="${1:-}"
[[ -z "$cmd" ]] && usage

case "$cmd" in
  start)
    echo "Starting $VM..."
    az vm start --resource-group "$RG" --name "$VM"
    echo "Done. Public IP:"
    az vm list-ip-addresses --resource-group "$RG" --name "$VM" \
      --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv
    ;;
  stop)
    echo "Stopping (deallocating) $VM..."
    az vm deallocate --resource-group "$RG" --name "$VM"
    echo "Done — VM deallocated, no compute charges."
    ;;
  status)
    az vm get-instance-view --resource-group "$RG" --name "$VM" \
      --query "instanceView.statuses[1].displayStatus" -o tsv
    ;;
  *)
    usage
    ;;
esac
