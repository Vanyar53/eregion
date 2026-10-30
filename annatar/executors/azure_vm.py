from __future__ import annotations

import time

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from rich.console import Console

console = Console()


class AzureVMExecutor:
    def __init__(self, target: dict, session=None):
        self.resource_group = target["resource_group"]
        self.vm_name = target["vm_name"]
        self._credential = DefaultAzureCredential()
        self._subscription_id = target.get("subscription_id") or self._get_subscription_id()
        self._compute = ComputeManagementClient(self._credential, self._subscription_id)
        # Orodruin's armed session (eregion_core/orodruin.py): every call that writes on
        # the target is journaled through it first. None → passive, nothing written.
        self._session = session

    @property
    def resource_id(self) -> str:
        return (
            f"/subscriptions/{self._subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.Compute/virtualMachines/{self.vm_name}"
        )

    def get_resource_group_tags(self, rg_name: str) -> dict:
        # Import from the .resources submodule (stable across versions). In
        # azure-mgmt-resource 26.0.0 the top-level `azure.mgmt.resource` no longer
        # re-exports ResourceManagementClient → `from azure.mgmt.resource import ...`
        # breaks. The submodule path works on 25.x and 26.x.
        from azure.mgmt.resource.resources import ResourceManagementClient
        client = ResourceManagementClient(self._credential, self._subscription_id)
        rg = client.resource_groups.get(rg_name)
        return rg.tags or {}

    def get_vm_name(self) -> str:
        """The VM's name as Azure writes it — what a typed name is compared to (DG-b)."""
        vm = self._compute.virtual_machines.get(self.resource_group, self.vm_name)
        return str(vm.name or "")

    def get_vm_tags(self) -> dict:
        """Tags of the target VM — the per-VM chaos authorization (safety/guard.py)."""
        vm = self._compute.virtual_machines.get(self.resource_group, self.vm_name)
        return vm.tags or {}

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
        """Execute a shell script file on the VM via Azure Run Command.

        Retries on Conflict (Run Command extension busy) with exponential backoff.
        """
        self._before_call("run_script", script_path)
        self._ensure_vm_running()

        with open(script_path) as f:
            script_content = f.read()
        return self._run_shell(script_content, script_path, params)

    def run_command(self, command: str, label: str = "command",
                    params: list[str] | None = None) -> str:
        """Execute an inline shell command on the VM via Azure Run Command (R1 atomic adapter).

        Journaled and capped by the Orodruin contract (``_before_call``) exactly like
        ``run_script`` — every write on the target goes through the same gate.
        """
        self._before_call("run_command", label)
        self._ensure_vm_running()
        return self._run_shell(command, label, params)

    def _run_shell(self, script_content: str, label: str,
                   params: list[str] | None = None) -> str:
        """The Run Command call itself, shared by run_script and run_command."""
        console.print(f"  [dim]RunCommand → {self.vm_name} : {label}[/dim]")

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

    def _before_call(self, action: str, detail: str) -> None:
        """The journal precedes the call (O1) — the start of a stopped VM included."""
        from eregion_core.orodruin import Passive
        if self._session is None:
            raise Passive(f"{action} on {self.vm_name}: no armed Orodruin contract")
        self._session.before_call(action, self.resource_id, detail)

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

        # Glorfindel's hold — its isolation or quarantine rules on the NSGs of the VM's NICs and
        # of their subnets, wherever they live (eregion_core/held.py, the rule Orodruin reads
        # too). Unreadable holds the VM: the run waits for a human, never goes on blind.
        from eregion_core import held
        why = held.holding(self.resource_id, self._arm_get)
        if why:
            issues.append(f"VM '{self.vm_name}' is held by Glorfindel ({why})\n"
                          f"  → glorfindel revert {self.resource_id} --yes")
        return issues

    def _arm_get(self, path: str, api: str) -> dict:
        """A read of Azure Resource Manager with this executor's identity."""
        import requests

        from eregion_core.held import safe_path
        token = self._credential.get_token("https://management.azure.com/.default").token
        r = requests.get(f"https://management.azure.com{safe_path(path)}",
                         headers={"Authorization": f"Bearer {token}"},
                         params={"api-version": api}, timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} reading {path.rsplit('/', 1)[-1]}")
        return r.json()

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
