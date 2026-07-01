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

    @property
    def resource_id(self) -> str:
        return (
            f"/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.Compute/virtualMachines/{self.vm_name}"
        )

    def get_resource_group_tags(self, rg_name: str) -> dict:
        from azure.mgmt.resource import ResourceManagementClient
        client = ResourceManagementClient(self._credential, self._subscription_id)
        rg = client.resource_groups.get(rg_name)
        return rg.tags or {}

    def _ensure_vm_running(self) -> None:
        iv = self._compute.virtual_machines.get(
            self.resource_group, self.vm_name, expand="instanceView"
        ).instance_view
        statuses = {s.code for s in (iv.statuses or [])}
        if "PowerState/running" not in statuses:
            console.print(f"  [dim]VM not running — starting {self.vm_name}...[/dim]")
            self._compute.virtual_machines.begin_start(self.resource_group, self.vm_name).result()
            console.print("  [dim]VM started.[/dim]")

    def run_script(self, script_path: str, params: list[str] | None = None) -> str:
        """Execute a shell script on the VM via Azure Run Command.

        Retries on Conflict (Run Command extension busy) with exponential backoff.
        """
        self._ensure_vm_running()

        with open(script_path) as f:
            script_content = f.read()

        console.print(f"  [dim]RunCommand → {self.vm_name} : {script_path}[/dim]")

        from azure.core.exceptions import HttpResponseError
        from azure.mgmt.compute.models import RunCommandInput, RunCommandInputParameter

        cmd = RunCommandInput(
            command_id="RunShellScript",
            script=[script_content],
            parameters=[RunCommandInputParameter(name="arg", value=p) for p in (params or [])],
        )

        delays = [15, 30, 60, 90, 120]
        for attempt, delay in enumerate(delays + [None], start=1):
            try:
                poller = self._compute.virtual_machines.begin_run_command(
                    self.resource_group, self.vm_name, cmd,
                )
                result = poller.result()
                output = result.value[0].message if result.value else ""
                console.print(f"  [dim]{output.strip()[-200:]}[/dim]")
                return output
            except HttpResponseError as e:
                if "Conflict" not in str(e) or delay is None:
                    raise
                console.print(
                    f"  [yellow]RunCommand busy (attempt {attempt}/{len(delays)}) "
                    f"— retrying in {delay}s...[/yellow]"
                )
                time.sleep(delay)

        raise RuntimeError("RunCommand failed after all retries")

    def check_preflight(self) -> list[str]:
        """Check VM state before running a scenario. Returns a list of blocking issues."""
        issues = []

        # VM power state
        try:
            iv = self._compute.virtual_machines.get(
                self.resource_group, self.vm_name, expand="instanceView"
            ).instance_view
            statuses = {s.code for s in (iv.statuses or [])}
            if "PowerState/running" not in statuses:
                state = next(
                    (s.code for s in (iv.statuses or []) if s.code.startswith("PowerState/")),
                    "PowerState/unknown",
                )
                issues.append(
                    f"VM '{self.vm_name}' is not running ({state})\n"
                    f"  → az vm start -g {self.resource_group} -n {self.vm_name}"
                )
        except Exception as e:
            issues.append(f"Cannot check VM power state: {e}")

        # Glorfindel isolation — scan NSGs in the resource group for isolation rules
        try:
            from azure.mgmt.network import NetworkManagementClient
            network = NetworkManagementClient(self._credential, self._subscription_id)
            for nsg in network.network_security_groups.list(self.resource_group):
                isolation_rules = [
                    r.name for r in (nsg.security_rules or [])
                    if r.name.startswith("glorfindel-isolation-")
                ]
                if isolation_rules:
                    issues.append(
                        f"VM '{self.vm_name}' is isolated by Glorfindel "
                        f"(NSG '{nsg.name}', {len(isolation_rules)} rule(s))\n"
                        f"  → glorfindel revert {self.resource_id} --yes"
                    )
        except Exception as e:
            console.print(f"  [dim yellow]Preflight NSG check skipped: {e}[/dim yellow]")

        return issues

    def verify_restore_integrity(self, script_path: str = "scripts/vm/verify_restore.sh") -> bool:
        """Run the integrity check script on the VM. Returns True if PASS."""
        output = self.run_script(script_path)
        passed = "INTEGRITY_PASS" in output
        if passed:
            console.print("  [green]Integrity check: PASS[/green]")
        else:
            console.print("  [red]Integrity check: FAIL[/red]")
            console.print(f"  [dim]{output.strip()}[/dim]")
        return passed

    def _get_subscription_id(self) -> str:
        import os
        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not sub_id:
            raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
        return sub_id
