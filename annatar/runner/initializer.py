from __future__ import annotations

import json
import subprocess
from pathlib import Path

from rich.console import Console

console = Console()

TERRAFORM_DIR = Path(__file__).parent.parent.parent / "infra" / "terraform"


class InitRunner:
    def run(
        self,
        auto_approve: bool = False,
        scenario_path: str | None = None,
    ) -> None:
        self._terraform_apply(auto_approve)
        outputs = self._terraform_outputs()
        ws_id = outputs.get("log_analytics_workspace_id")
        console.print(f"\n  [dim]log_analytics_workspace_id: {ws_id}[/dim]")
        console.print(
            "  [dim]Update your scenario YAML with this workspace ID if needed.[/dim]\n"
        )

        if scenario_path:
            self.clean(scenario_path)
        else:
            console.print(
                "  [yellow]Run 'annatar clean <scenario>' to prepare the VM disk.[/yellow]"
            )
            console.print(
                "  [yellow]Then run 'glorfindel snapshot <resource_id> --yes'"
                " to take a clean backup.[/yellow]"
            )

    def clean(self, scenario_path: str) -> None:
        """Reset the VM disk to a clean state before a scenario run."""
        from annatar.runner.parser import ScenarioParser
        from annatar.executors.azure_vm import AzureVMExecutor

        scenario = ScenarioParser().load(scenario_path)
        target = scenario.target
        vm_name = target["vm_name"]

        executor = AzureVMExecutor(target)

        console.print(f"[cyan]->[/cyan] Preparing VM disk ({vm_name})...")
        executor.run_script("scripts/vm/setup_testdata.sh")

        console.print("[cyan]->[/cyan] Verifying disk state...")
        if not executor.verify_restore_integrity():
            raise RuntimeError(
                "Disk not clean after setup — aborting. Check the VM manually."
            )

        console.print(
            "  [green]VM disk ready.[/green]"
            " Run 'glorfindel snapshot <resource_id> --yes'"
            " to capture a clean recovery point."
        )

    # ── Terraform ──────────────────────────────────────────────────────────────

    def _terraform_apply(self, auto_approve: bool) -> None:
        tf = str(TERRAFORM_DIR)
        console.print("[cyan]->[/cyan] terraform init")
        self._run(
            ["terraform", f"-chdir={tf}", "init", "-upgrade", "-input=false"]
        )
        console.print("[cyan]->[/cyan] terraform apply")
        cmd = ["terraform", f"-chdir={tf}", "apply", "-input=false"]
        if auto_approve:
            cmd.append("-auto-approve")
        self._run(cmd, capture=False)

    def _terraform_outputs(self) -> dict:
        tf = str(TERRAFORM_DIR)
        result = self._run(
            ["terraform", f"-chdir={tf}", "output", "-json"], capture=True
        )
        raw = json.loads(result.stdout)
        return {k: v["value"] for k, v in raw.items()}

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _run(
        cmd: list[str], capture: bool = True
    ) -> subprocess.CompletedProcess:
        result = subprocess.run(cmd, capture_output=capture, text=True)
        if result.returncode != 0:
            err = result.stderr.strip() if capture else ""
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{err}")
        return result
