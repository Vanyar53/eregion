from __future__ import annotations

import time

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from rich.console import Console

console = Console()


class AzureVMExecutor:
    def __init__(self, target: dict):
        self.resource_group = target["resource_group"]
        self.vm_name = target["vm_name"]
        self._credential = DefaultAzureCredential()
        self._subscription_id = target.get("subscription_id") or self._get_subscription_id()
        self._compute = ComputeManagementClient(self._credential, self._subscription_id)

    def get_resource_group_tags(self, rg_name: str) -> dict:
        from azure.mgmt.resource import ResourceManagementClient
        client = ResourceManagementClient(self._credential, self._subscription_id)
        rg = client.resource_groups.get(rg_name)
        return rg.tags or {}

    def run_script(self, script_path: str, params: list[str] | None = None) -> str:
        """Execute a shell script on the VM via Azure Run Command."""
        with open(script_path) as f:
            script_content = f.read()

        console.print(f"  [dim]RunCommand → {self.vm_name} : {script_path}[/dim]")

        poller = self._compute.virtual_machines.begin_run_command(
            self.resource_group,
            self.vm_name,
            {
                "command_id": "RunShellScript",
                "script": [script_content],
                "parameters": [{"name": "arg", "value": p} for p in (params or [])],
            },
        )
        result = poller.result()
        output = result.value[0].message if result.value else ""
        console.print(f"  [dim]{output.strip()[-200:]}[/dim]")
        return output

    def trigger_recovery(self, recovery_config: dict) -> None:
        action = recovery_config.get("action")
        if action == "azure_backup_restore":
            self._trigger_backup_restore(recovery_config)
        else:
            raise ValueError(f"Unsupported recovery action: {action}")

    def _trigger_backup_restore(self, config: dict) -> None:
        """Trigger Azure Backup OriginalLocation restore and poll until completion.

        Stops the VM, replaces disks with the latest restore point, restarts.
        This is the actual RTO: time from trigger to VM back online.
        """
        import requests
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        vault_name = config.get("vault", "rsv-annatar")
        rg = self.resource_group
        container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{self.vm_name}"
        item_name = f"vm;iaasvmcontainerv2;{rg};{self.vm_name}"

        backup_client = RecoveryServicesBackupClient(self._credential, self._subscription_id)

        console.print(f"  [dim]Fetching recovery points from {vault_name}...[/dim]")
        fabric = "Azure"
        rps = list(backup_client.recovery_points.list(vault_name, rg, fabric, container_name, item_name))
        if not rps:
            raise RuntimeError("No recovery points found — run 'az backup protection backup-now' first")

        latest = rps[0]
        rp_time = getattr(latest.properties, "recovery_point_time", "unknown")
        console.print(f"  [dim]Latest recovery point: {latest.name} ({rp_time})[/dim]")

        vm = self._compute.virtual_machines.get(rg, self.vm_name)
        storage_id = (
            f"/subscriptions/{self._subscription_id}/resourceGroups/{rg}"
            f"/providers/Microsoft.Storage/storageAccounts/stannatarexfil"
        )

        console.print("  [dim]Deallocating VM before restore...[/dim]")
        self._compute.virtual_machines.begin_deallocate(rg, self.vm_name).result()

        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vault_name}"
            f"/backupFabrics/Azure/protectionContainers/{container_enc}"
            f"/protectedItems/{item_enc}/recoveryPoints/{latest.name}/restore"
            f"?api-version=2021-10-01"
        )
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

        console.print("  [dim]Triggering restore to original location...[/dim]")
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Restore trigger failed ({r.status_code}): {r.text[:300]}")

        time.sleep(15)
        restore_job = next(
            (j for j in backup_client.backup_jobs.list(vault_name, rg)
             if getattr(j.properties, "operation", "") == "Restore"
             and getattr(j.properties, "status", "") == "InProgress"),
            None,
        )
        if restore_job is None:
            raise RuntimeError("Restore job not found after trigger — check Azure portal")

        console.print(f"  [dim]Tracking job {restore_job.name} (15-30 min expected)...[/dim]")
        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault_name, rg, restore_job.name)
            status = getattr(job.properties, "status", "Unknown")
            console.print(f"  [dim]Still restoring... {elapsed//60}min elapsed — {status}[/dim]")
            if status in ("Completed", "Failed", "Cancelled"):
                break

        if status != "Completed":
            raise RuntimeError(f"Restore job ended with status: {status}")
        console.print("  [green]Restore completed — VM disks replaced with backup state.[/green]")

        console.print("  [dim]Starting VM after restore...[/dim]")
        self._compute.virtual_machines.begin_start(rg, self.vm_name).result()
        console.print("  [dim]VM started.[/dim]")

    def verify_restore_integrity(self, script_path: str = "scripts/verify_restore.sh") -> bool:
        """Run the integrity check script on the VM. Returns True if PASS."""
        output = self.run_script(script_path)
        passed = "INTEGRITY_PASS" in output
        if passed:
            console.print("  [green]Integrity check: PASS[/green]")
        else:
            console.print("  [red]Integrity check: FAIL[/red]")
            console.print(f"  [dim]{output.strip()[-300:]}[/dim]")
        return passed

    def _get_subscription_id(self) -> str:
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(self._credential)
        subs = list(client.subscriptions.list())
        if not subs:
            raise RuntimeError("No Azure subscriptions found")
        return subs[0].subscription_id
