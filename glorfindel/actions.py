from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from rich.console import Console

_console = Console()

# Actions Glorfindel peut exécuter seul (réversibles)
AUTONOMOUS_ACTIONS = {
    "isolate_vm",
    "release_isolation",  # inverse of isolate_vm — safe to reverse autonomously
    "revoke_temp_access",
    "snapshot",           # forensic snapshot of current (compromised) state
    "block_suspicious_ip",
}

# Actions nécessitant validation humaine (destructives ou à impact large)
HUMAN_APPROVAL_REQUIRED = {
    "delete_resource",
    "modify_network_rule",
    "escalate_permissions",
    "wipe_storage",
    "restore_from_backup",  # replaces disk content — irreversible without another backup
}


class CloudConnector(ABC):
    """Provider-agnostic interface. Azure now, AWS/GCP later."""

    @abstractmethod
    def isolate_vm(self, resource_id: str) -> dict:
        """Block all inbound/outbound traffic on the VM's NIC. Fully reversible."""
        ...

    @abstractmethod
    def release_isolation(self, resource_id: str) -> dict:
        """Remove the isolation NSG rule applied by isolate_vm."""
        ...

    @abstractmethod
    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict:
        """Add deny rule for this IP on the resource's NSG."""
        ...

    @abstractmethod
    def snapshot(self, resource_id: str, vault: str = "rsv-annatar", wait: bool = True) -> str:
        """Take an on-demand RSV backup snapshot.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately. Use on detection_timeout
        paths to avoid blocking the queue during a long initial backup.
        """
        ...

    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict:
        """Confirm that isolation rules are active on the VM's NSG."""
        ...

    @abstractmethod
    def verify_snapshot(self, snap_id: str) -> dict:
        """Confirm that a snapshot was actually created."""
        ...

    @abstractmethod
    def restore_from_backup(
        self,
        resource_id: str,
        vault: str = "rsv-annatar",
        before_attack_time: str | None = None,
    ) -> dict:
        """Trigger an Azure Backup OriginalLocation restore. Human-approved action.

        before_attack_time: ISO8601 timestamp — selects the most recent recovery point
        that predates the attack, avoiding restoration of a post-attack backup.
        """
        ...

    @abstractmethod
    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        """Confirm that the deny rule for this IP is active on the NSG."""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove the deny rules created by block_suspicious_ip for this IP."""
        ...


class AzureConnector(CloudConnector):
    """Azure implementation of CloudConnector.

    All mutating actions are restricted to resources tagged annatar-test: 'true'
    unless the resource_id is explicitly in an override list.
    """

    ISOLATION_RULE_NAME = "glorfindel-isolation-deny-all"
    ISOLATION_PRIORITY = 100

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._credential = None
        self._subscription_id = None
        self._network = None
        self._compute = None

    def _ensure_clients(self) -> None:
        if self._network is not None:
            return
        import os
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.compute import ComputeManagementClient

        sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
        if not sub_id:
            raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
        self._credential = DefaultAzureCredential()
        self._subscription_id = sub_id
        self._network = NetworkManagementClient(self._credential, self._subscription_id)
        self._compute = ComputeManagementClient(self._credential, self._subscription_id)

    def isolate_vm(self, resource_id: str) -> dict:
        """Apply a deny-all NSG rule (priority 100) to the VM's NSG.

        If existing rules occupy priority 100, they are shifted +100 and saved
        to ~/.glorfindel/isolation/<vm>.json for restoration on release.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        from azure.mgmt.network.models import SecurityRule

        # Shift any existing rules that conflict at ISOLATION_PRIORITY
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used_priorities = {r.priority for r in existing}
        bumped = []
        for r in existing:
            if r.priority == self.ISOLATION_PRIORITY and not r.name.startswith("glorfindel-"):
                new_prio = next(
                    p for p in range(self.ISOLATION_PRIORITY + 100, 4000, 100)
                    if p not in used_priorities
                )
                used_priorities.add(new_prio)
                r.priority = new_prio
                self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
                bumped.append({"name": r.name, "original_priority": self.ISOLATION_PRIORITY})

        from datetime import datetime, timezone
        _save_isolation_state(vm_name, {
            "nsg_rg": nsg_rg,
            "nsg_name": nsg_name,
            "bumped": bumped,
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
        })

        for direction, rule_name in [
            ("Inbound", self.ISOLATION_RULE_NAME),
            ("Outbound", f"{self.ISOLATION_RULE_NAME}-out"),
        ]:
            self._network.security_rules.begin_create_or_update(
                nsg_rg, nsg_name, rule_name,
                SecurityRule(
                    name=rule_name, protocol="*",
                    source_port_range="*", destination_port_range="*",
                    source_address_prefix="*", destination_address_prefix="*",
                    access="Deny", priority=self.ISOLATION_PRIORITY, direction=direction,
                ),
            ).result()

        return {
            "status": "isolated",
            "nsg": f"{nsg_rg}/{nsg_name}",
            "rule": self.ISOLATION_RULE_NAME,
            "resource_id": resource_id,
        }

    def release_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        for rule_name in (self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out"):
            try:
                self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
            except Exception:
                pass

        # Restore bumped rules to their original priorities
        state = _load_isolation_state(vm_name)
        if state:
            for rule_info in state.get("bumped", []):
                r = self._network.security_rules.get(nsg_rg, nsg_name, rule_info["name"])
                r.priority = rule_info["original_priority"]
                self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
        _clear_isolation_state(vm_name)  # always clear — even if state was already absent

        return {"status": "released", "resource_id": resource_id}

    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "block_ip", "ip": ip}
        if not ip:
            raise ValueError("block_suspicious_ip: no IP address provided")

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        from azure.mgmt.network.models import SecurityRule

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used_priorities = {r.priority for r in existing}
        priority = next(p for p in range(200, 4000, 10) if p not in used_priorities)

        rule_name = f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
        for direction in ("Inbound", "Outbound"):
            name = rule_name if direction == "Inbound" else f"{rule_name}-out"
            self._network.security_rules.begin_create_or_update(
                nsg_rg, nsg_name, name,
                SecurityRule(
                    name=name, protocol="*",
                    source_port_range="*", destination_port_range="*",
                    source_address_prefix=ip if direction == "Inbound" else "*",
                    destination_address_prefix="*" if direction == "Inbound" else ip,
                    access="Deny", priority=priority, direction=direction,
                ),
            ).result()

        _save_block_state(vm_name, ip, resource_id)
        return {
            "status": "blocked",
            "ip": ip,
            "nsg": f"{nsg_rg}/{nsg_name}",
            "rule": rule_name,
            "resource_id": resource_id,
        }

    def snapshot(self, resource_id: str, vault: str = "rsv-annatar", wait: bool = True) -> str:
        """Trigger an RSV on-demand backup.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately without polling.
        Use on detection_timeout paths to avoid blocking the queue.
        """
        if self.dry_run:
            return "snap-dry-run-000"

        import time
        import requests
        from datetime import datetime, timezone, timedelta
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        sub = self._subscription_id
        container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{vm_name}"
        item_name = f"vm;iaasvmcontainerv2;{rg};{vm_name}"

        backup_client = RecoveryServicesBackupClient(self._credential, sub)

        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vault}"
            f"/backupFabrics/Azure/protectionContainers/{container_enc}"
            f"/protectedItems/{item_enc}/backup"
            f"?api-version=2021-10-01"
        )
        payload = {
            "properties": {
                "objectType": "IaasVMBackupRequest",
                "recoveryPointExpiryTimeInUTC": expiry,
            }
        }
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Snapshot trigger failed ({r.status_code}): {r.text[:300]}")

        time.sleep(10)
        backup_job = next(
            (j for j in backup_client.backup_jobs.list(vault, rg)
             if getattr(j.properties, "operation", "") == "Backup"
             and getattr(j.properties, "status", "") == "InProgress"),
            None,
        )
        if backup_job is None:
            raise RuntimeError("Backup job not found after trigger")

        snap_id = f"rsv:{vault}/{rg}/{backup_job.name}"
        _console.print(
            f"  [dim]Backup job {backup_job.name} started (5-20 min expected)...[/dim]"
        )
        if not wait:
            return snap_id

        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault, rg, backup_job.name)
            status = getattr(job.properties, "status", "Unknown")
            _console.print(f"  [dim]Backup in progress... {elapsed}s — {status}[/dim]")
            if status in ("Completed", "Failed", "Cancelled"):
                break

        if status != "Completed":
            raise RuntimeError(f"Backup job ended with status: {status}")

        return snap_id

    def verify_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        try:
            self._network.security_rules.get(nsg_rg, nsg_name, self.ISOLATION_RULE_NAME)
            self._network.security_rules.get(nsg_rg, nsg_name, f"{self.ISOLATION_RULE_NAME}-out")
            return {"verified": True, "method": "nsg_check", "nsg": f"{nsg_rg}/{nsg_name}"}
        except Exception as e:
            return {"verified": False, "method": "nsg_check", "error": str(e)}

    def verify_snapshot(self, snap_id: str) -> dict:
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}
        if not snap_id:
            return {"verified": None, "method": "no_snap_id"}

        # RSV on-demand backup: "rsv:{vault}/{rg}/{job_name}"
        if snap_id.startswith("rsv:"):
            try:
                from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
                _, rest = snap_id.split("rsv:", 1)
                vault, rg, job_name = rest.split("/", 2)
                self._ensure_clients()
                backup_client = RecoveryServicesBackupClient(
                    self._credential, self._subscription_id
                )
                job = backup_client.job_details.get(vault, rg, job_name)
                status = getattr(job.properties, "status", "Unknown")
                if status == "Completed":
                    return {"verified": True, "method": "rsv_backup", "job": job_name}
                if status == "InProgress":
                    # Fire-and-forget path: job still running — not a failure
                    return {"verified": None, "method": "rsv_backup", "status": status}
                return {"verified": False, "method": "rsv_backup", "status": status}
            except Exception as e:
                return {"verified": False, "method": "rsv_backup", "error": str(e)}

        # Legacy: Azure Compute disk snapshot by full resource ID
        self._ensure_clients()
        try:
            rg = snap_id.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in snap_id else None
            name = snap_id.split("/")[-1]
            if rg:
                self._compute.snapshots.get(rg, name)
                return {"verified": True, "method": "snapshot_check", "snap_id": snap_id}
            return {"verified": None, "method": "not_implemented", "note": "snap_id is not a full resource ID"}
        except Exception as e:
            return {"verified": False, "method": "snapshot_check", "error": str(e)}

    def restore_from_backup(
        self,
        resource_id: str,
        vault: str = "rsv-annatar",
        before_attack_time: str | None = None,
    ) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "restore_from_backup", "resource_id": resource_id}

        import time
        import requests
        from datetime import datetime, timezone
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        sub = self._subscription_id
        container_name = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{vm_name}"
        item_name = f"vm;iaasvmcontainerv2;{rg};{vm_name}"
        fabric = "Azure"

        backup_client = RecoveryServicesBackupClient(self._credential, sub)

        rps = list(backup_client.recovery_points.list(vault, rg, fabric, container_name, item_name))
        if not rps:
            raise RuntimeError(f"No recovery points in vault {vault}")

        def _has_vault_tier(rp) -> bool:
            return any(
                t.type == "HardenedRP" and getattr(t, "status", "") == "Valid"
                for t in (getattr(rp.properties, "recovery_point_tier_details", None) or [])
            )

        # Select the most recent clean recovery point — must predate the attack
        # to avoid restoring a backup that already contains attack artifacts.
        if before_attack_time:
            attack_dt = datetime.fromisoformat(before_attack_time).astimezone(timezone.utc)
            pre_attack = [
                rp for rp in rps
                if getattr(rp.properties, "recovery_point_time", None) is not None
                and rp.properties.recovery_point_time < attack_dt
            ]
            if not pre_attack:
                raise RuntimeError(
                    f"No recovery point found before attack time {before_attack_time}. "
                    "A backup may have run during the attack. Check the portal."
                )
            candidate_pool = pre_attack
        else:
            candidate_pool = rps

        vaulted = [rp for rp in candidate_pool if _has_vault_tier(rp)]
        latest = vaulted[0] if vaulted else candidate_pool[0]
        rp_time = getattr(latest.properties, "recovery_point_time", "unknown")
        if before_attack_time:
            _console.print(f"  [dim]Using pre-attack recovery point: {rp_time}[/dim]")

        vm = self._compute.virtual_machines.get(rg, vm_name)
        storage_id = (
            f"/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.Storage/storageAccounts/stannatarexfil"
        )

        self._compute.virtual_machines.begin_deallocate(rg, vm_name).result()

        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{rg}/providers/Microsoft.RecoveryServices/vaults/{vault}"
            f"/backupFabrics/Azure/protectionContainers/{container_enc}"
            f"/protectedItems/{item_enc}/recoveryPoints/{latest.name}/restore"
            f"?api-version=2021-10-01"
        )
        data_luns = [d.lun for d in (vm.storage_profile.data_disks or [])]
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

        r = requests.post(url, json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Restore trigger failed ({r.status_code}): {r.text[:300]}")

        time.sleep(15)
        restore_job = next(
            (j for j in backup_client.backup_jobs.list(vault, rg)
             if getattr(j.properties, "operation", "") == "Restore"
             and getattr(j.properties, "status", "") == "InProgress"),
            None,
        )
        if restore_job is None:
            raise RuntimeError("Restore job not found after trigger")

        _console.print(f"  [dim]Tracking job {restore_job.name} (15-30 min expected)...[/dim]")
        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault, rg, restore_job.name)
            status = getattr(job.properties, "status", "Unknown")
            _console.print(f"  [dim]Still restoring... {elapsed // 60}min elapsed — {status}[/dim]")
            if status in ("Completed", "Failed", "Cancelled"):
                break

        if status != "Completed":
            raise RuntimeError(f"Restore ended with status: {status}")

        _console.print("  [dim]Starting VM after restore...[/dim]")
        self._compute.virtual_machines.begin_start(rg, vm_name).result()

        return {
            "status": "restored",
            "recovery_point": latest.name,
            "recovery_point_time": str(rp_time),
            "resource_id": resource_id,
        }

    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}
        if not ip:
            return {"verified": False, "method": "nsg_check", "error": "no IP provided"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        rule_name = f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
        try:
            self._network.security_rules.get(nsg_rg, nsg_name, rule_name)
            return {"verified": True, "method": "nsg_check", "rule": rule_name}
        except Exception as e:
            return {"verified": False, "method": "nsg_check", "error": str(e)}

    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "unblock_ip", "ip": ip}
        if not ip:
            raise ValueError("unblock_ip: no IP address provided")

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        rule_name = f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
        deleted = []
        for name in (rule_name, f"{rule_name}-out"):
            try:
                self._network.security_rules.begin_delete(nsg_rg, nsg_name, name).result()
                deleted.append(name)
            except Exception:
                pass

        _clear_block_state(vm_name, ip)
        return {
            "status": "unblocked" if deleted else "not_found",
            "ip": ip,
            "deleted_rules": deleted,
            "nsg": f"{nsg_rg}/{nsg_name}",
        }

    # ── Audit / readiness checks ───────────────────────────────────────────────

    def check_nsg_access(self, resource_id: str) -> dict:
        """Verify NSG read access — proxy for isolate_vm / block_suspicious_ip readiness."""
        if self.dry_run:
            return {"ok": True, "nsg": "dry_run"}
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            nic_id = self._get_primary_nic_id(rg, vm_name)
            nsg_rg, nsg_name = self._get_nic_nsg(nic_id)
            rules = list(self._network.security_rules.list(nsg_rg, nsg_name))
            return {"ok": True, "nsg": f"{nsg_rg}/{nsg_name}", "rules": len(rules)}
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}

    def check_backup_points(self, resource_id: str, vault: str = "rsv-annatar") -> dict:
        """Verify vault + recent recovery point — restore_from_backup readiness."""
        if self.dry_run:
            return {"ok": True, "vault": vault, "dry_run": True}
        try:
            from datetime import datetime, timezone
            from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            client = RecoveryServicesBackupClient(self._credential, self._subscription_id)
            container = f"iaasvmcontainer;iaasvmcontainerv2;{rg};{vm_name}"
            item = f"vm;iaasvmcontainerv2;{rg};{vm_name}"
            rps = list(client.recovery_points.list(vault, rg, "Azure", container, item))
            if not rps:
                return {
                    "ok": False, "iam": False, "vault": vault,
                    "error": f"No recovery points found for {vm_name} in vault '{vault}'",
                }
            times = [
                getattr(rp.properties, "recovery_point_time", None) for rp in rps
            ]
            latest = max((t for t in times if t), default=None)
            age_h = (
                (datetime.now(timezone.utc) - latest).total_seconds() / 3600
                if latest else 9999.0
            )
            return {
                "ok": True, "vault": vault,
                "points": len(rps), "latest_age_h": round(age_h, 1),
            }
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "vault": vault, "error": str(e)}

    def check_compute_access(self, resource_id: str) -> dict:
        """Verify VM + disk read access — snapshot readiness."""
        if self.dry_run:
            return {"ok": True, "dry_run": True}
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            vm = self._compute.virtual_machines.get(rg, vm_name)
            disks = []
            if vm.storage_profile.os_disk.managed_disk:
                disks.append(vm.storage_profile.os_disk.managed_disk.id.split("/")[-1])
            disks += [
                d.managed_disk.id.split("/")[-1]
                for d in vm.storage_profile.data_disks
                if d.managed_disk
            ]
            return {"ok": True, "vm": vm_name, "disks": disks}
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}

    def _get_primary_nic_id(self, rg: str, vm_name: str) -> str:
        vm = self._compute.virtual_machines.get(rg, vm_name)
        nics = vm.network_profile.network_interfaces
        primary = next((n for n in nics if n.primary), nics[0])
        return primary.id

    def _get_nic_nsg(self, nic_id: str) -> tuple[str, str]:
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)

        # NIC-level NSG (preferred)
        if nic.network_security_group is not None:
            return _parse_nsg_resource_id(nic.network_security_group.id)

        # Fallback: subnet-level NSG
        subnet_id = nic.ip_configurations[0].subnet.id
        # /subscriptions/.../virtualNetworks/<vnet>/subnets/<subnet>
        parts = subnet_id.split("/")
        sub_rg = parts[parts.index("resourceGroups") + 1]
        vnet = parts[parts.index("virtualNetworks") + 1]
        subnet_name = parts[-1]
        subnet = self._network.subnets.get(sub_rg, vnet, subnet_name)
        if subnet.network_security_group is None:
            raise RuntimeError(f"NIC {nic_name} and its subnet have no NSG — cannot isolate VM")
        return _parse_nsg_resource_id(subnet.network_security_group.id)


_ISOLATION_STATE_DIR = Path.home() / ".glorfindel" / "isolation"
_BLOCK_STATE_DIR = Path.home() / ".glorfindel" / "blocks"


def _save_isolation_state(vm_name: str, state: dict) -> None:
    import json
    _ISOLATION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    (_ISOLATION_STATE_DIR / f"{vm_name}.json").write_text(json.dumps(state))


def _load_isolation_state(vm_name: str) -> dict | None:
    import json
    f = _ISOLATION_STATE_DIR / f"{vm_name}.json"
    return json.loads(f.read_text()) if f.exists() else None


def _clear_isolation_state(vm_name: str) -> None:
    f = _ISOLATION_STATE_DIR / f"{vm_name}.json"
    if f.exists():
        f.unlink()


def active_isolations() -> list[dict]:
    """Return all active isolation state files (VMs that Glorfindel has isolated)."""
    import json
    result = []
    for f in _ISOLATION_STATE_DIR.glob("*.json"):
        try:
            state = json.loads(f.read_text())
            if state.get("resource_id"):
                result.append({**state, "vm_name": f.stem})
        except Exception:
            pass
    return result


def _save_block_state(vm_name: str, ip: str, resource_id: str) -> None:
    import json
    from datetime import datetime, timezone
    _BLOCK_STATE_DIR.mkdir(parents=True, exist_ok=True)
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    entries = json.loads(f.read_text()) if f.exists() else []
    if not any(e["ip"] == ip for e in entries):
        entries.append({"ip": ip, "resource_id": resource_id,
                        "blocked_at": datetime.now(timezone.utc).isoformat()})
    f.write_text(json.dumps(entries))


def _clear_block_state(vm_name: str, ip: str) -> None:
    import json
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    if not f.exists():
        return
    entries = [e for e in json.loads(f.read_text()) if e["ip"] != ip]
    if entries:
        f.write_text(json.dumps(entries))
    else:
        f.unlink()


def active_blocks() -> list[dict]:
    """Return all active IP blocks per VM ({vm_name, resource_id, ip, blocked_at})."""
    import json
    result = []
    if not _BLOCK_STATE_DIR.exists():
        return result
    for f in _BLOCK_STATE_DIR.glob("*.json"):
        try:
            for entry in json.loads(f.read_text()):
                result.append({**entry, "vm_name": f.stem})
        except Exception:
            pass
    return result


def _is_iam_error(err: str) -> bool:
    """Return True if the error is an Azure authorization/permission failure."""
    markers = ("AuthorizationFailed", "Forbidden", "403", "does not have authorization")
    return any(m in err for m in markers)


def _parse_vm_resource_id(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
    return parts[rg_idx + 1], parts[-1]


def _parse_nic_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)


def _parse_nsg_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)
