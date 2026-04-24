#!/usr/bin/env python3
"""Standalone test for Azure Backup OriginalLocation restore."""

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
latest = rps[0]
vm = compute.virtual_machines.get(rg, vm_name)

print(f"Recovery point : {latest.name} ({getattr(latest.properties, 'recovery_point_time', '?')})")
print(f"VM             : {vm.id}")

storage_id = (
    f"/subscriptions/{sub_id}/resourceGroups/{rg}"
    f"/providers/Microsoft.Storage/storageAccounts/stannatarexfil"
)

print("\nDeallocating VM...")
compute.virtual_machines.begin_deallocate(rg, vm_name).result()
print("VM deallocated.")

token = credential.get_token("https://management.azure.com/.default").token
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
container_enc = container_name.replace(";", "%3B")
item_enc = item_name.replace(";", "%3B")

payload = {
    "properties": {
        "objectType": "IaasVMRestoreRequest",
        "recoveryPointId": latest.name,
        "recoveryType": "OriginalLocation",
        "sourceResourceId": vm.id,
        "storageAccountId": storage_id,
        "region": vm.location,
        "affinityGroup": "",
        "createNewCloudService": False,
        "originalStorageAccountOption": False,
        "skipPreOLRBackup": True,
        "targetVirtualMachineId": None,
        "targetResourceGroupId": None,
    }
}

url = (
    f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}"
    f"/providers/Microsoft.RecoveryServices/vaults/{vault_name}"
    f"/backupFabrics/Azure/protectionContainers/{container_enc}"
    f"/protectedItems/{item_enc}/recoveryPoints/{latest.name}/restore"
    f"?api-version=2021-10-01"
)

r = requests.post(url, json=payload, headers=headers)
print(f"\nResult → {r.status_code}")
if r.status_code in (200, 202):
    print("SUCCESS — restore triggered")
    print(f"AsyncOperation: {r.headers.get('Azure-AsyncOperation', '')}")
    print("Polling (check Azure portal for job status)...")
else:
    print(r.text[:400])
