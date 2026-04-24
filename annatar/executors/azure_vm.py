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
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
        from azure.mgmt.recoveryservicesbackup.models import IaasVMRestoreRequest, RestoreRequestResource

        vault_name = config.get("vault", "rsv-annatar")
        rg = self.resource_group
        fabric = "Azure"
        container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{self.vm_name}"
        item_name = f"vm;iaasvmcontainerv2;{rg};{self.vm_name}"

        client = RecoveryServicesBackupClient(self._credential, self._subscription_id)

        console.print(f"  [dim]Fetching recovery points from {vault_name}...[/dim]")
        rps = list(client.recovery_points.list(vault_name, rg, fabric, container_name, item_name))
        if not rps:
            raise RuntimeError("No recovery points found — run 'az backup protection backup-now' first")

        latest = rps[0]
        rp_time = getattr(latest.properties, "recovery_point_time", "unknown")
        console.print(f"  [dim]Latest recovery point: {latest.name} ({rp_time})[/dim]")

        vm = self._compute.virtual_machines.get(rg, self.vm_name)

        restore_req = RestoreRequestResource(
            properties=IaasVMRestoreRequest(
                recovery_point_id=latest.id,
                recovery_type="OriginalLocation",
                source_resource_id=vm.id,
                region=vm.location,
                create_new_cloud_service=False,
                original_storage_account_option="Never",
            )
        )

        console.print("  [dim]Stopping VM and triggering restore to original location...[/dim]")
        poller = client.restores.begin_trigger(
            vault_name, rg, fabric, container_name, item_name, latest.name, restore_req
        )

        console.print("  [dim]Polling restore job (30-60 min expected for full VM restore)...[/dim]")
        elapsed = 0
        while not poller.done():
            time.sleep(60)
            elapsed += 60
            console.print(f"  [dim]Still restoring... {elapsed//60}min elapsed[/dim]")

        poller.result()
        console.print("  [green]Restore completed — VM disks replaced with backup state.[/green]")

    def _get_subscription_id(self) -> str:
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(self._credential)
        subs = list(client.subscriptions.list())
        if not subs:
            raise RuntimeError("No Azure subscriptions found")
        return subs[0].subscription_id
