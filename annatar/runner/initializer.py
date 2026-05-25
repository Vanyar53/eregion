from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rich.console import Console

console = Console()

TERRAFORM_DIR = Path(__file__).parent.parent.parent / "infra" / "terraform"


class InitRunner:
    def run(self, auto_approve: bool = False, scenario_path: str | None = None) -> None:
        self._terraform_apply(auto_approve)
        outputs = self._terraform_outputs()
        console.print(f"\n  [dim]log_analytics_workspace_id: {outputs.get('log_analytics_workspace_id')}[/dim]")
        console.print("  [dim]Update your scenario YAML with this workspace ID if needed.[/dim]\n")

        if scenario_path:
            self.snapshot(scenario_path)
        else:
            console.print("  [yellow]Run 'annatar snapshot <scenario>' to prepare the VM and create a clean backup.[/yellow]")

    def snapshot(self, scenario_path: str) -> None:
        """Clean the VM disk and take a fresh on-demand backup."""
        from annatar.runner.parser import ScenarioParser
        from annatar.executors.azure_vm import AzureVMExecutor

        scenario = ScenarioParser().load(scenario_path)
        target = scenario.target
        vault_name = scenario.recovery.get("vault", "rsv-annatar") if scenario.recovery else "rsv-annatar"

        rg = target["resource_group"]
        vm_name = target["vm_name"]
        container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{vm_name}"
        item_name = f"vm;iaasvmcontainerv2;{rg};{vm_name}"

        _, _, backup_client = self._azure_clients()

        existing = list(backup_client.recovery_points.list(vault_name, rg, "Azure", container_name, item_name))
        if existing:
            rp = existing[0]
            rp_time = getattr(rp.properties, "recovery_point_time", "?")
            console.print(f"  [dim]Most recent RP: {rp.name} ({rp_time})[/dim]")
        else:
            console.print("  [dim]No existing recovery points[/dim]")

        executor = AzureVMExecutor(target)

        console.print(f"[cyan]->[/cyan] Preparing VM disk ({vm_name})...")
        executor.run_script("scripts/vm/setup_testdata.sh")

        console.print("[cyan]->[/cyan] Verifying disk state before backup...")
        if not executor.verify_restore_integrity():
            raise RuntimeError("Disk not clean after cleanup — aborting snapshot. Check the VM manually.")

        console.print("[cyan]->[/cyan] Triggering on-demand backup (5-15 min)...")
        self._do_backup(backup_client, rg, vm_name, vault_name, container_name, item_name)

        new_rps = list(backup_client.recovery_points.list(vault_name, rg, "Azure", container_name, item_name))
        if new_rps:
            rp = new_rps[0]
            rp_time = getattr(rp.properties, "recovery_point_time", "?")
            console.print(f"  [dim]New RP: {rp.name} ({rp_time})[/dim]")
        console.print("  [green]Snapshot done — environment ready for next run.[/green]")

    # ── Terraform ──────────────────────────────────────────────────────────────

    def _terraform_apply(self, auto_approve: bool) -> None:
        tf = str(TERRAFORM_DIR)
        console.print("[cyan]->[/cyan] terraform init")
        self._run(["terraform", f"-chdir={tf}", "init", "-upgrade", "-input=false"])
        console.print("[cyan]->[/cyan] terraform apply")
        cmd = ["terraform", f"-chdir={tf}", "apply", "-input=false"]
        if auto_approve:
            cmd.append("-auto-approve")
        self._run(cmd, capture=False)

    def _terraform_outputs(self) -> dict:
        tf = str(TERRAFORM_DIR)
        result = self._run(["terraform", f"-chdir={tf}", "output", "-json"], capture=True)
        raw = json.loads(result.stdout)
        return {k: v["value"] for k, v in raw.items()}

    # ── Backup ─────────────────────────────────────────────────────────────────

    def _do_backup(
        self,
        backup_client,
        rg: str,
        vm_name: str,
        vault_name: str,
        container_name: str,
        item_name: str,
    ) -> None:
        from azure.mgmt.recoveryservicesbackup.models import BackupRequestResource, IaasVMBackupRequest

        expiry = datetime.now(timezone.utc) + timedelta(days=30)
        backup_client.backups.trigger(
            vault_name=vault_name,
            resource_group_name=rg,
            fabric_name="Azure",
            container_name=container_name,
            protected_item_name=item_name,
            parameters=BackupRequestResource(
                properties=IaasVMBackupRequest(
                    backup_type="Full",
                    recovery_point_expiry_time_in_utc=expiry,
                )
            ),
        )

        time.sleep(10)
        job = next(
            (j for j in backup_client.backup_jobs.list(vault_name, rg)
             if getattr(j.properties, "operation", "") == "Backup"
             and getattr(j.properties, "status", "") == "InProgress"),
            None,
        )
        if job is None:
            console.print("  [yellow]Warning: backup job not found — check Azure portal[/yellow]")
            return

        console.print(f"  [dim]Job {job.name} — polling every 60s...[/dim]")
        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault_name, rg, job.name)
            status = getattr(job.properties, "status", "Unknown")
            console.print(f"  [dim]{elapsed // 60}min — {status}[/dim]")
            if status not in ("InProgress", "Unknown"):
                break

        if status not in ("Completed", "CompletedWithWarnings"):
            raise RuntimeError(f"Backup ended with status: {status}")
        console.print("  [green]Backup completed.[/green]")

    # ── Azure clients ──────────────────────────────────────────────────────────

    @staticmethod
    def _azure_clients():
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not sub_id:
            raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
        credential = DefaultAzureCredential()
        backup_client = RecoveryServicesBackupClient(credential, sub_id)
        return credential, sub_id, backup_client

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _run(cmd: list[str], capture: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(cmd, capture_output=capture, text=True)
        if result.returncode != 0:
            err = result.stderr.strip() if capture else ""
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{err}")
        return result
