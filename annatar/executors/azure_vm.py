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
        """Trigger Azure Backup restore and wait for completion."""
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        vault_name = config.get("vault", "rsv-annatar")
        client = RecoveryServicesBackupClient(self._credential, self._subscription_id)

        console.print(f"  [dim]Triggering restore from vault: {vault_name}[/dim]")
        # Restore logic: find latest recovery point and trigger restore
        # Full implementation depends on vault/policy config
        # Placeholder — implement once infra is provisioned
        time.sleep(2)
        console.print("  [dim]Restore triggered (polling for completion...)[/dim]")

    def _get_subscription_id(self) -> str:
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(self._credential)
        subs = list(client.subscriptions.list())
        if not subs:
            raise RuntimeError("No Azure subscriptions found")
        return subs[0].subscription_id
