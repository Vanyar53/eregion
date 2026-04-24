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
        """Trigger Azure Backup OriginalLocation restore via az CLI and poll until completion.

        Stops the VM, replaces disks with the latest restore point, restarts.
        This is the actual RTO: time from trigger to VM back online.
        """
        import json
        import subprocess

        vault_name = config.get("vault", "rsv-annatar")
        rg = self.resource_group
        container_name = f"IaasVMContainer;iaasvmcontainerv2;{rg};{self.vm_name}"
        item_name = f"VM;iaasvmcontainerv2;{rg};{self.vm_name}"

        console.print(f"  [dim]Fetching recovery points from {vault_name}...[/dim]")
        rps_out = subprocess.run(
            ["az", "backup", "recoverypoint", "list",
             "--resource-group", rg, "--vault-name", vault_name,
             "--container-name", container_name, "--item-name", item_name,
             "--output", "json"],
            capture_output=True, text=True, check=True,
        )
        rps = json.loads(rps_out.stdout)
        if not rps:
            raise RuntimeError("No recovery points found — run 'az backup protection backup-now' first")

        latest = rps[0]
        rp_name = latest["name"]
        rp_time = latest.get("properties", {}).get("recoveryPointTime", "unknown")
        console.print(f"  [dim]Latest recovery point: {rp_name} ({rp_time})[/dim]")

        console.print("  [dim]Stopping VM and triggering restore to original location...[/dim]")
        job_out = subprocess.run(
            ["az", "backup", "restore", "restore-disks",
             "--resource-group", rg, "--vault-name", vault_name,
             "--container-name", container_name, "--item-name", item_name,
             "--rp-name", rp_name,
             "--restore-mode", "OriginalLocation",
             "--rehydration-priority", "None",
             "--output", "json"],
            capture_output=True, text=True, check=True,
        )
        job = json.loads(job_out.stdout)
        job_name = job["name"]
        console.print(f"  [dim]Job {job_name} started. Polling (30-60 min expected)...[/dim]")

        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            status_out = subprocess.run(
                ["az", "backup", "job", "show",
                 "--resource-group", rg, "--vault-name", vault_name,
                 "--name", job_name, "--output", "json"],
                capture_output=True, text=True, check=True,
            )
            job_status = json.loads(status_out.stdout).get("properties", {}).get("status", "Unknown")
            console.print(f"  [dim]Still restoring... {elapsed//60}min elapsed — {job_status}[/dim]")
            if job_status in ("Completed", "Failed", "Cancelled"):
                break

        if job_status != "Completed":
            raise RuntimeError(f"Restore job ended with status: {job_status}")
        console.print("  [green]Restore completed — VM disks replaced with backup state.[/green]")

    def _get_subscription_id(self) -> str:
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(self._credential)
        subs = list(client.subscriptions.list())
        if not subs:
            raise RuntimeError("No Azure subscriptions found")
        return subs[0].subscription_id
