from __future__ import annotations

import time
from datetime import datetime, timezone

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

        delays = [15, 30, 60]
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

    def trigger_recovery(self, recovery_config: dict, attack_time: float | None = None) -> None:
        action = recovery_config.get("action")
        if action == "azure_backup_restore":
            self._trigger_backup_restore(recovery_config, attack_time)
        else:
            raise ValueError(f"Unsupported recovery action: {action}")

    def _trigger_backup_restore(self, config: dict, attack_time: float | None = None) -> None:
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
            raise RuntimeError("No recovery points found — run 'annatar init' first")

        console.print(f"  [dim]{len(rps)} recovery point(s) available:[/dim]")
        for rp in rps:
            rp_t = getattr(rp.properties, "recovery_point_time", "?")
            tiers = [t.type for t in (getattr(rp.properties, "recovery_point_tier_details", None) or []) if getattr(t, "status", "") == "Valid"]
            tier_str = "+".join(tiers) if tiers else "unknown-tier"
            console.print(f"    [dim]{rp.name}  {rp_t}  [{tier_str}][/dim]")

        def _has_vault_tier(rp) -> bool:
            return any(
                t.type == "HardenedRP" and getattr(t, "status", "") == "Valid"
                for t in (getattr(rp.properties, "recovery_point_tier_details", None) or [])
            )

        if attack_time is not None:
            attack_dt = datetime.fromtimestamp(attack_time, tz=timezone.utc)
            clean_rps = [
                rp for rp in rps
                if getattr(rp.properties, "recovery_point_time", None) is not None
                and rp.properties.recovery_point_time < attack_dt
            ]
            if not clean_rps:
                raise RuntimeError(
                    f"No clean recovery point found before attack time {attack_dt.isoformat()} — "
                    "a backup may have run during the attack. Check the portal and re-run 'annatar init'."
                )
            vaulted = [rp for rp in clean_rps if _has_vault_tier(rp)]
            if not vaulted:
                raise RuntimeError(
                    "No clean recovery point with completed vault transfer found — "
                    "wait for the backup vault transfer to finish before running a test."
                )
            latest = vaulted[0]
        else:
            vaulted = [rp for rp in rps if _has_vault_tier(rp)]
            latest = vaulted[0] if vaulted else rps[0]

        rp_time = getattr(latest.properties, "recovery_point_time", "unknown")
        tiers = [t.type for t in (getattr(latest.properties, "recovery_point_tier_details", None) or []) if getattr(t, "status", "") == "Valid"]
        console.print(f"  [dim]Selected RP: {latest.name}  {rp_time}  [{'+'.join(tiers) if tiers else 'unknown-tier'}][/dim]")

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
        # Collect all data disk LUNs attached to the VM so we can explicitly
        # include them in the restore request. Without this, Azure Backup V1
        # policy OriginalLocation restore silently skips data disks.
        data_luns = [
            d.lun for d in (vm.storage_profile.data_disks or [])
        ]
        console.print(f"  [dim]Data disk LUNs to restore: {data_luns}[/dim]")

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
                "restoreDiskLunList": data_luns,
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

        # Azure Backup V1 does not restore externally-attached data disk content.
        # Hot-attach a disk from a clean snapshot, rsync the state, then detach.
        snapshot_name = config.get("data_disk_snapshot")
        if snapshot_name:
            self._restore_data_disk_from_snapshot(rg, snapshot_name)

        # Azure Backup OriginalLocation restore leaves the previous OS and data disks
        # unattached in the resource group. Clean them up to avoid cost accumulation.
        self._cleanup_orphan_backup_disks(rg)

    def _restore_data_disk_from_snapshot(self, rg: str, snapshot_name: str) -> None:
        """Restore the data disk to clean snapshot state while the VM is running.

        Azure Backup V1 does not restore externally-attached managed disk content.
        We work around this by hot-attaching a disk created from the clean snapshot
        at a temp LUN, then rsyncing the snapshot state onto /mnt/testdata, then
        detaching the temp disk. No disk swap — no boot-time UUID ambiguity.

        Must be called AFTER the VM has started.
        """
        from azure.mgmt.compute.models import DataDisk, ManagedDiskParameters, DiskCreateOptionTypes
        import tempfile, os

        snapshot = self._compute.snapshots.get(rg, snapshot_name)
        location = snapshot.location
        disk_size_gb = snapshot.disk_size_gb

        # Find a free LUN for the temp disk
        vm = self._compute.virtual_machines.get(rg, self.vm_name)
        used_luns = {d.lun for d in (vm.storage_profile.data_disks or [])}
        temp_lun = next(i for i in range(20) if i not in used_luns)

        # Create a disk from the clean snapshot
        temp_disk_name = f"disk-annatar-snap-temp-{int(time.time())}"
        console.print(f"  [dim]Creating temp disk {temp_disk_name} from snapshot {snapshot_name}...[/dim]")
        temp_disk = self._compute.disks.begin_create_or_update(
            rg, temp_disk_name,
            {
                "location": location,
                "sku": {"name": "Premium_LRS"},
                "properties": {
                    "creationData": {"createOption": "Copy", "sourceResourceId": snapshot.id},
                    "diskSizeGB": disk_size_gb,
                },
            },
        ).result()
        console.print(f"  [dim]Temp disk created at LUN {temp_lun}[/dim]")

        # Hot-attach to the running VM
        vm = self._compute.virtual_machines.get(rg, self.vm_name)
        vm.storage_profile.data_disks.append(
            DataDisk(
                lun=temp_lun,
                name=temp_disk_name,
                create_option=DiskCreateOptionTypes.ATTACH,
                managed_disk=ManagedDiskParameters(id=temp_disk.id),
            )
        )
        self._compute.virtual_machines.begin_create_or_update(rg, self.vm_name, vm).result()
        console.print(f"  [dim]Temp disk hot-attached. Running rsync restore...[/dim]")

        # Rsync clean snapshot state onto the data disk from inside the VM.
        # Both disks share the same filesystem UUID (snapshot is a block copy).
        # We find the unmounted one by elimination — it's the newly attached temp disk.
        restore_script = """\
#!/bin/bash
set -uo pipefail
TARGET="/mnt/testdata"
SNAP_MOUNT="/mnt/_annatar_snap_restore"

DATA_DEV=$(findmnt -n -o SOURCE "$TARGET" 2>/dev/null)
if [ -z "$DATA_DEV" ]; then
  echo "[ERROR] $TARGET is not mounted"
  exit 1
fi
DATA_UUID=$(blkid -s UUID -o value "$DATA_DEV")

SNAP_DEV=$(blkid -t "UUID=$DATA_UUID" -o device 2>/dev/null | grep -v "$DATA_DEV" | head -1)
if [ -z "$SNAP_DEV" ]; then
  echo "[ERROR] Could not find snapshot disk (UUID=$DATA_UUID, data=$DATA_DEV)"
  exit 1
fi

echo "[annatar] Mounting snapshot disk $SNAP_DEV (read-only)..."
mkdir -p "$SNAP_MOUNT"
mount -o ro "$SNAP_DEV" "$SNAP_MOUNT"

echo "[annatar] Rsyncing clean state from snapshot to $TARGET..."
rsync -a --delete --exclude=lost+found --exclude='.annatar_test_marker' "$SNAP_MOUNT/" "$TARGET/"
# Preserve the marker (created by setup, not by attack)
[ -f "$SNAP_MOUNT/.annatar_test_marker" ] && cp -p "$SNAP_MOUNT/.annatar_test_marker" "$TARGET/"

umount "$SNAP_MOUNT"
rmdir "$SNAP_MOUNT"
echo "[annatar] DATA_DISK_RESTORED"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, prefix='annatar_restore_') as f:
            f.write(restore_script)
            tmp_path = f.name
        try:
            output = self.run_script(tmp_path)
            if "DATA_DISK_RESTORED" not in output:
                raise RuntimeError(f"Data disk restore script did not complete: {output[-300:]}")
        finally:
            os.unlink(tmp_path)
        console.print(f"  [green]Data disk restored from snapshot via rsync.[/green]")

        # Hot-detach and delete the temp disk
        console.print(f"  [dim]Detaching temp disk...[/dim]")
        vm = self._compute.virtual_machines.get(rg, self.vm_name)
        vm.storage_profile.data_disks = [
            d for d in (vm.storage_profile.data_disks or []) if d.lun != temp_lun
        ]
        self._compute.virtual_machines.begin_create_or_update(rg, self.vm_name, vm).result()
        self._compute.disks.begin_delete(rg, temp_disk_name).result()
        console.print(f"  [dim]Temp disk removed.[/dim]")

    def _cleanup_orphan_backup_disks(self, rg: str) -> None:
        """Delete unattached disks left behind by Azure Backup OriginalLocation restores.

        Each restore creates a renamed copy of the previous OS+data disk. Without cleanup
        these accumulate indefinitely. We identify them by the naming pattern Azure uses
        and confirm they are unattached before deleting.
        """
        vm_prefix = self.vm_name.replace("-", "")
        patterns = (f"{vm_prefix}-datadisk-", f"{vm_prefix}-osdisk-")
        disks = self._compute.disks.list_by_resource_group(rg)
        pollers = []
        for disk in disks:
            if disk.disk_state != "Unattached":
                continue
            name_lower = disk.name.lower()
            if any(name_lower.startswith(p) for p in patterns):
                console.print(f"  [dim]Deleting orphan disk {disk.name}...[/dim]")
                pollers.append(self._compute.disks.begin_delete(rg, disk.name))
        if pollers:
            for p in pollers:
                p.result()
            console.print(f"  [dim]Cleaned up {len(pollers)} orphan backup disk(s).[/dim]")

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
        from azure.mgmt.subscription import SubscriptionClient
        client = SubscriptionClient(self._credential)
        subs = list(client.subscriptions.list())
        if not subs:
            raise RuntimeError("No Azure subscriptions found")
        return subs[0].subscription_id
