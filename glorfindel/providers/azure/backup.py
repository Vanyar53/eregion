"""Restore points on Azure Backup: on-demand snapshot, its verification, the vault's
recovery points and items, a restore job's status (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.sdk import _backup_item_names, _is_iam_error
from glorfindel.response.ids import _is_backupable_vm, _parse_vm_resource_id
from glorfindel.response.policy import _console


class BackupMixin:
    """Azure Backup: snapshots and recovery points (part of AzureConnector)."""

    def snapshot(
        self, resource_id: str, vault: str = "", wait: bool = True,
        vault_rg: str = "",
    ) -> str:
        """Trigger an RSV on-demand backup.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately without polling.
        The agent always uses it (see CloudConnector.snapshot).
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        if self.dry_run:
            return "snap-dry-run-000"

        self._guard_write("snapshot")
        if not vault:
            from glorfindel.config import NO_VAULT_MSG
            raise RuntimeError(NO_VAULT_MSG)
        import time
        import requests
        from datetime import datetime, timezone, timedelta
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        v_rg = vault_rg or rg
        sub = self._subscription_id

        backup_client = RecoveryServicesBackupClient(self._credential, sub)
        container_name, item_name = self._resolve_backup_item_names(
            backup_client, vault, v_rg, rg, vm_name)

        expiry = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{v_rg}/providers/Microsoft.RecoveryServices/vaults/{vault}"
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
        triggered_at = datetime.now(timezone.utc)
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Snapshot trigger failed ({r.status_code}): {r.text[:300]}")

        backup_job = self._find_backup_job(
            backup_client, vault, v_rg, "Backup", vm_name, triggered_at)
        if backup_job is None:
            raise RuntimeError(f"Backup job for {vm_name} not found after trigger")

        snap_id = f"rsv:{vault}/{v_rg}/{backup_job.name}"
        _console.print(
            f"  [dim]Backup job {backup_job.name} started (5-20 min expected)...[/dim]"
        )
        if not wait:
            return snap_id

        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault, v_rg, backup_job.name)
            status = getattr(job.properties, "status", "Unknown")
            _console.print(f"  [dim]Backup in progress... {elapsed}s — {status}[/dim]")
            if status in ("Completed", "Failed", "Cancelled"):
                break

        if status != "Completed":
            raise RuntimeError(f"Backup job ended with status: {status}")

        return snap_id

    def _resolve_backup_item_names(
        self, client, vault: str, vault_rg: str, vm_rg: str, vm_name: str,
    ) -> tuple[str, str]:
        """The (container, item) names exactly as the vault stores them.

        recovery_points.list is case-SENSITIVE on these names; protected_items.get is
        not. So: ask the vault for the item with the canonical names, then read the
        stored names back from the returned resource id. Falls back to the canonical
        names when the lookup fails (the call that needs them reports the real error).
        """
        container, item = _backup_item_names(vm_rg, vm_name)
        try:
            found = client.protected_items.get(vault, vault_rg, "Azure", container, item)
            parts = (getattr(found, "id", "") or "").split("/")
            low = [p.lower() for p in parts]
            if "protectioncontainers" in low and "protecteditems" in low:
                container = parts[low.index("protectioncontainers") + 1]
                item = parts[low.index("protecteditems") + 1]
        except Exception:
            pass
        return container, item

    def _find_backup_job(
        self, client, vault: str, vault_rg: str, operation: str, vm_name: str,
        triggered_at, attempts: int = 3, delay_s: float = 10.0,
    ):
        """The InProgress job this trigger created, for THIS VM.

        Taking the first InProgress job of the vault cross-wired concurrent jobs: two
        snapshots (watch + CLI + War Room) could each track the other VM's job. Filter
        on the VM (entity_friendly_name) and on a start time not older than the trigger,
        newest first. Jobs show up a few seconds after the trigger: retry a few times.
        """
        import time
        from datetime import timedelta

        not_before = triggered_at - timedelta(minutes=2)  # tolerate clock skew
        for attempt in range(attempts):
            time.sleep(delay_s)
            candidates = []
            for j in client.backup_jobs.list(vault, vault_rg):
                p = getattr(j, "properties", None)
                if p is None:
                    continue
                if getattr(p, "operation", "") != operation:
                    continue
                if getattr(p, "status", "") != "InProgress":
                    continue
                if (getattr(p, "entity_friendly_name", "") or "").lower() != vm_name.lower():
                    continue
                start = getattr(p, "start_time", None)
                if start is not None and start < not_before:
                    continue
                candidates.append((start, j))
            if candidates:
                candidates.sort(key=lambda c: (c[0] is not None, c[0]), reverse=True)
                return candidates[0][1]
        return None

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

    def check_backup_points(
        self, resource_id: str, vault: str = "", vault_rg: str = ""
    ) -> dict:
        """Verify vault + recent recovery point — restore_from_backup readiness.

        vault_rg: the resource group the VAULT lives in. A central backup vault commonly
        protects VMs spread across many resource groups, so the vault's RG ≠ the VM's RG.
        The protected-item CONTAINER is keyed by the VM's RG (fabric naming), but the
        recovery_points / protected_items calls are scoped to the VAULT's RG — passing
        the VM's RG there yields ResourceNotFound on the vault and a false "backup
        missing". Falls back to the VM's RG when empty (sandbox: vault and VM co-located).
        """
        if self.dry_run:
            return {"ok": True, "vault": vault, "dry_run": True}
        # Only a standalone Microsoft.Compute/virtualMachines is an IaaS-VM backup item.
        # An AKS managed cluster (what the AMA heartbeat reports for AKS nodes), a VMSS
        # instance, or any other resource produces the same BMSUserErrorDataSourceObject
        # NotFound as a genuinely unprotected VM — the error can't tell them apart, the
        # resource SHAPE can. Short-circuit so posture/audit don't raise a false gap.
        if not _is_backupable_vm(resource_id):
            return {
                "ok": False, "iam": False, "vault": vault, "not_backupable": True,
                "error": f"{resource_id.split('/')[-1]} is not a standalone IaaS VM "
                         "(AKS cluster / VMSS instance / other) — not a backup item",
            }
        try:
            from datetime import datetime, timezone
            from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

            self._ensure_clients()
            vm_rg, vm_name = _parse_vm_resource_id(resource_id)
            v_rg = vault_rg or vm_rg
            client = RecoveryServicesBackupClient(self._credential, self._subscription_id)
            # Canonical fabric names — CASE MATTERS (see _backup_item_names).
            container, item = _backup_item_names(vm_rg, vm_name)
            rps = list(client.recovery_points.list(vault, v_rg, "Azure", container, item))
            if not rps:
                # No recovery point — but is the VM actually protected? An empty RP
                # list means EITHER "protected, first backup pending" OR "not protected
                # at all". Distinguish via the protected-item status so posture/audit
                # don't cry "not linked to vault" on a freshly-protected VM.
                protected = self._is_protected_item(client, vault, v_rg, container, item)
                if protected:
                    return {
                        "ok": False, "iam": False, "vault": vault,
                        "protected": True, "no_recovery_point": True,
                        "error": (
                            f"{vm_name} is protected in '{vault}' but has no recovery "
                            "point yet (first backup pending)"
                        ),
                    }
                return {
                    "ok": False, "iam": False, "vault": vault, "protected": False,
                    "error": f"{vm_name} not linked to vault '{vault}'",
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

    def _is_protected_item(self, client, vault: str, rg: str, container: str, item: str) -> bool:
        """Return True if the VM is registered as a protected item in the vault.

        Used to tell "protected, first backup pending" (recovery points empty but the
        item exists) from "not protected at all". A 404 / ResourceNotFound means not
        protected; any other error → assume not protected (conservative).
        """
        try:
            client.protected_items.get(vault, rg, "Azure", container, item)
            return True
        except Exception:
            return False

    def list_backup_items(
        self, vault: str = "", resource_group: str = ""
    ) -> list[dict]:
        """List the vault's protected items directly — the backup inventory.

        Source of truth for "do my backups exist?". The RSV knows its protected items
        regardless of VM power state, so this works when an off VM has dropped out of
        the LAW heartbeat (the discovered-asset audit can't see it then — which is
        exactly when you want to confirm backups exist). One paginated
        `backup_protected_items.list` call — the CHEAP leg.

        `last_recovery_point` rides on each item, so freshness comes free. The recovery
        point COUNT does NOT (it needs a per-item recovery_points.list = N slow RSV
        calls, the very thing the discovery/posture decoupling avoids) and is
        deliberately omitted — use check_backup_points(resource_id) for a single VM's
        count when a card is expanded.

        Pure read — no _guard_write, so it runs on read-only (observe-only) credentials.
        An empty list means the vault has no protected items (meaningful: nothing is
        backed up). IAM / vault-not-found surface as a raised exception (the caller
        distinguishes "empty vault" from "can't read vault").
        """
        if self.dry_run:
            return []
        from datetime import datetime, timezone
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient

        self._ensure_clients()
        client = RecoveryServicesBackupClient(self._credential, self._subscription_id)
        # Narrow to IaaS VM items so we don't enumerate file-share / SQL / SAP items.
        fltr = "backupManagementType eq 'AzureIaasVM' and itemType eq 'VM'"
        now = datetime.now(timezone.utc)
        items: list[dict] = []
        for it in client.backup_protected_items.list(vault, resource_group, filter=fltr):
            p = getattr(it, "properties", None)
            if p is None:
                continue
            last_rp = getattr(p, "last_recovery_point", None)
            age_h = round((now - last_rp).total_seconds() / 3600, 1) if last_rp else None
            rid = getattr(p, "virtual_machine_id", None) or getattr(p, "source_resource_id", "")
            items.append({
                "name": getattr(p, "friendly_name", "") or getattr(it, "name", ""),
                "resource_id": rid,
                "protection_state": (
                    getattr(p, "protection_state", None)
                    or getattr(p, "protection_status", "")
                ),
                "latest_recovery_point": last_rp.isoformat() if last_rp else None,
                "latest_age_h": age_h,
            })
        return items

    def restore_job_status(self, vault: str, vault_rg: str, job_name: str) -> str:
        """The vault's status of a restore job, read in the vault's group (central vault ≠
        VM RG). glorfindel/jobs.py reconciles its record with it (moved from there, A1:
        no SDK outside the adapter)."""
        from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
        self._ensure_clients()
        bc = RecoveryServicesBackupClient(self._credential, self._subscription_id)
        j = bc.job_details.get(vault, vault_rg, job_name)
        return getattr(j.properties, "status", "Unknown")
