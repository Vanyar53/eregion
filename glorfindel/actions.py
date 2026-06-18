from __future__ import annotations

import threading
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

_warmed_up = False
_warmup_lock = threading.Lock()


def warm_up_azure_sdk() -> None:
    """Import the Azure SDK once, single-threaded, before any worker threads run.

    The codebase imports azure.* lazily inside methods. When several threads first-import
    azure.core concurrently (audit's 3 parallel checks, or the watch's discovery + poll
    threads), CPython's import system can deadlock (`_ModuleLock` on azure.core.exceptions)
    or expose a half-initialised module ("cannot import name 'Pipeline'"). Doing every
    azure import here, on the calling (main) thread, makes all later in-method imports
    instant cache hits — no concurrent first-import. Idempotent + best-effort.

    Call at watch startup AND at the top of audit.run (before the ThreadPoolExecutor) so
    both the watch process and the War Room API process are covered.
    """
    global _warmed_up
    if _warmed_up:
        return
    with _warmup_lock:
        if _warmed_up:
            return
        try:
            import azure.core.pipeline          # noqa: F401  (the module that races)
            import azure.core.exceptions         # noqa: F401
            from azure.identity import DefaultAzureCredential   # noqa: F401
            from azure.mgmt.network import NetworkManagementClient   # noqa: F401
            from azure.mgmt.network import models               # noqa: F401
            from azure.mgmt.compute import ComputeManagementClient   # noqa: F401
            from azure.mgmt.recoveryservicesbackup import (        # noqa: F401
                RecoveryServicesBackupClient,
            )
            from azure.monitor.query import LogsQueryClient    # noqa: F401
            _warmed_up = True
        except Exception:
            # azure not installed / partial env — real errors surface at actual use.
            pass


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
    def block_suspicious_ip(
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False
    ) -> dict:
        """Add deny rule for this IP. scope="vm" (this VM only) | "subnet" (all VMs).
        replace=True (with scope="subnet"): promote — apply the subnet rule, then drop
        the now-redundant VM-scoped rule (create-then-delete → no protection gap)."""
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
        wait: bool = True,
    ) -> dict:
        """Trigger an Azure Backup OriginalLocation restore. Human-approved action.

        before_attack_time: ISO8601 timestamp — selects the most recent recovery point
        that predates the attack, avoiding restoration of a post-attack backup.
        wait=False: returns after triggering the restore job, without polling.
          VM stays deallocated; caller must start it and emit recovery_complete manually.
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

    def __init__(self, dry_run: bool = False, read_only: bool | None = None):
        import os
        self.dry_run = dry_run
        # read_only: when the SP only has Reader/Log Analytics Reader, write actions
        # cannot run. human_only mode never calls them, so detection-only deployments
        # work on read-only credentials. Declared via GLORFINDEL_READ_ONLY=1 (the
        # operator knows the SP's role; auto-detection isn't reliable without a write).
        if read_only is None:
            read_only = os.environ.get("GLORFINDEL_READ_ONLY", "").lower() in ("1", "true", "yes")
        self.read_only = read_only
        self._credential = None
        self._subscription_id = None
        self._network = None
        self._compute = None
        self._clients_lock = threading.Lock()

    def permission_mode(self) -> str:
        """Return the effective permission regime: 'read_only' or 'read_write'."""
        return "read_only" if self.read_only else "read_write"

    def _guard_write(self, action: str) -> None:
        """Block a mutating action when running on read-only credentials.

        Raised lazily, only when an action is actually attempted — never at init,
        so detection-only (human_only) deployments start cleanly on Reader creds.
        """
        if self.read_only:
            raise PermissionError(
                f"Action '{action}' impossible : credentials lecture seule "
                "(GLORFINDEL_READ_ONLY). Glorfindel détecte et recommande mais ne peut "
                "pas agir. Utilisez un SP avec droits d'écriture pour exécuter les actions."
            )

    def _ensure_clients(self) -> None:
        # Double-checked locking: the lazy SDK import + client creation must be
        # thread-safe. audit.run() and the watch poll threads can call this
        # concurrently; without the lock, simultaneous first-calls trigger parallel
        # imports of azure.core and one thread sees a half-initialised module
        # (ImportError: cannot import name 'Pipeline'). _network is assigned LAST so
        # the lock-free fast path only passes when both clients are fully built.
        if self._network is not None:
            return
        with self._clients_lock:
            if self._network is not None:
                return
            import os
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.compute import ComputeManagementClient

            sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
            if not sub_id:
                raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
            credential = DefaultAzureCredential()
            compute = ComputeManagementClient(credential, sub_id)
            network = NetworkManagementClient(credential, sub_id)
            self._credential = credential
            self._subscription_id = sub_id
            self._compute = compute
            self._network = network  # assign last — gate for the fast path

    def isolate_vm(self, resource_id: str) -> dict:
        """Apply a deny-all NSG rule (priority 100) to the VM's NSG.

        If existing rules occupy priority 100, they are shifted +100 and saved
        to ~/.glorfindel/isolation/<vm>.json for restoration on release.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}

        self._guard_write("isolate_vm")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)

        from azure.mgmt.network.models import SecurityRule

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used_priorities = {r.priority for r in existing}
        in_name, out_name = self._isolation_rule_names(vm_name, nsg_scope)
        bumped = []

        if nsg_scope == "subnet":
            # Shared subnet NSG: a deny any/any would cut EVERY VM. Scope the deny to
            # THIS VM's private IP so only the target is isolated. Use a free priority
            # (don't bump others' rules) so several VMs can be isolated independently.
            vm_ip = self._get_nic_private_ip(nic_id)
            priority = next(
                p for p in range(self.ISOLATION_PRIORITY, 4000)
                if p not in used_priorities
            )
            rules = [
                ("Inbound", in_name, "*", vm_ip),     # deny inbound TO this VM
                ("Outbound", out_name, vm_ip, "*"),   # deny outbound FROM this VM
            ]
        else:
            # NIC-level NSG: scoped to this VM already → a deny any/any is safe.
            # Insist on ISOLATION_PRIORITY, shifting any conflicting non-glorfindel rule.
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
            priority = self.ISOLATION_PRIORITY
            rules = [
                ("Inbound", in_name, "*", "*"),
                ("Outbound", out_name, "*", "*"),
            ]

        for direction, rule_name, src, dst in rules:
            self._network.security_rules.begin_create_or_update(
                nsg_rg, nsg_name, rule_name,
                SecurityRule(
                    name=rule_name, protocol="*",
                    source_port_range="*", destination_port_range="*",
                    source_address_prefix=src, destination_address_prefix=dst,
                    access="Deny", priority=priority, direction=direction,
                ),
            ).result()

        # Persist isolation state ONLY after the deny rules are confirmed on Azure.
        # Writing it earlier left an orphan ~/.glorfindel/isolation/<vm>.json (War Room
        # showing ISOLATED) when the NSG write failed with 403 — no rule, but stale state.
        from datetime import datetime, timezone
        _save_isolation_state(vm_name, {
            "nsg_rg": nsg_rg,
            "nsg_name": nsg_name,
            "nsg_scope": nsg_scope,
            # scoped=True → the rule only affects THIS VM (NIC NSG, or subnet NSG with
            # VM-IP addressing). A future subnet-wide opt-in (any on a shared NSG) would
            # set this False → War Room shows the ⚠ "subnet-wide" blast-radius chip.
            "scoped": True,
            "bumped": bumped,
            "rule_names": [in_name, out_name],
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
        })

        out = {
            "status": "isolated",
            "nsg": f"{nsg_rg}/{nsg_name}",
            "nsg_scope": nsg_scope,
            "scoped": True,
            "rule": in_name,
            "resource_id": resource_id,
        }
        if nsg_scope == "subnet":
            # Now SAFE on a shared subnet NSG: isolation is scoped to this VM's IP,
            # not the whole subnet. Note it so the operator knows it's a shared NSG.
            out["note"] = (
                f"NSG {nsg_rg}/{nsg_name} is subnet-level — isolation scoped to this "
                "VM's private IP only (no impact on other VMs on the subnet)."
            )
        return out

    def release_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._guard_write("release_isolation")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)

        # Delete the rule names this VM could have under either scope (state-stored
        # names + both fixed and VM-suffixed), so cleanup is robust to scope drift.
        state = _load_isolation_state(vm_name)
        names = set((state or {}).get("rule_names", []))
        names.update([
            self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out",
            f"{self.ISOLATION_RULE_NAME}-{vm_name}", f"{self.ISOLATION_RULE_NAME}-{vm_name}-out",
        ])
        for rule_name in names:
            try:
                self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
            except Exception:
                pass

        # Restore bumped rules to their original priorities (NIC-scope only)
        if state:
            for rule_info in state.get("bumped", []):
                r = self._network.security_rules.get(nsg_rg, nsg_name, rule_info["name"])
                r.priority = rule_info["original_priority"]
                self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
        _clear_isolation_state(vm_name)  # always clear — even if state was already absent

        return {"status": "released", "resource_id": resource_id}

    def block_suspicious_ip(
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False
    ) -> dict:
        """Block a suspicious IP.

        scope="vm" (default, autonomous): the rule only affects THIS VM — on a shared
          subnet NSG it is addressed to the VM's private IP; on a NIC NSG it's any/any
          (the NSG already covers only this VM).
        scope="subnet" (deliberate, operator opt-in): one perimeter rule on the SUBNET
          NSG, attacker→any → blocks the IP for EVERY VM on the subnet (incl. future
          ones). scoped=False → War Room shows the ⚠ subnet-wide chip.
        replace=True (promote VM→subnet): apply the subnet rule FIRST, then drop the
          now-redundant VM-scoped rule for this IP. Create-then-delete → no protection
          gap (if the subnet rule fails to apply, the VM rule is left intact).
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "block_ip", "ip": ip, "scope": scope}
        if not ip:
            raise ValueError("block_suspicious_ip: no IP address provided")

        self._guard_write("block_suspicious_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)

        from azure.mgmt.network.models import SecurityRule

        if scope == "subnet":
            # Perimeter block: one any rule on the SUBNET NSG (always the subnet's,
            # even if the NIC has its own NSG). Covers all VMs on the subnet + future.
            nsg_rg, nsg_name = self._get_subnet_nsg(nic_id)
            nsg_scope = "subnet"
            scoped = False
            vm_ip = "*"
            rule_name = self._block_rule_name(ip, vm_name, scope="vm")  # shared (no VM suffix)
        else:
            # VM-scoped block (autonomous default) — only this VM. See _block_rule_name.
            nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)
            scoped = True
            # subnet NSG → address to the VM IP so other VMs aren't touched; nic → any.
            vm_ip = self._get_nic_private_ip(nic_id) if nsg_scope == "subnet" else "*"
            rule_name = self._block_rule_name(ip, vm_name, nsg_scope)

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used_priorities = {r.priority for r in existing}
        priority = next(p for p in range(200, 4000, 10) if p not in used_priorities)

        for direction in ("Inbound", "Outbound"):
            name = rule_name if direction == "Inbound" else f"{rule_name}-out"
            if direction == "Inbound":
                src, dst = ip, vm_ip       # deny attacker → VM (vm scope) / any (subnet)
            else:
                src, dst = vm_ip, ip       # deny VM (vm scope) / any (subnet) → attacker
            self._network.security_rules.begin_create_or_update(
                nsg_rg, nsg_name, name,
                SecurityRule(
                    name=name, protocol="*",
                    source_port_range="*", destination_port_range="*",
                    source_address_prefix=src, destination_address_prefix=dst,
                    access="Deny", priority=priority, direction=direction,
                ),
            ).result()

        promoted_from = None
        if scope == "subnet" and replace:
            # The subnet-wide rule is now in place (created above) → the prior VM-scoped
            # rule for this IP is redundant. Delete it AFTER (create-then-delete → never
            # a protection gap). Target the NSG recorded at block time (faithful), so a
            # NIC-NSG VM-scoped rule is removed from its NIC NSG, not the subnet one.
            prev = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)
            old_rule = (prev or {}).get("rule") or self._block_rule_name(ip, vm_name, "subnet")
            old_nsg = (prev or {}).get("nsg", f"{nsg_rg}/{nsg_name}")
            old_rg, old_name = old_nsg.split("/", 1)
            if old_rule != rule_name:  # don't delete the subnet rule we just created
                for nm in (old_rule, f"{old_rule}-out"):
                    try:
                        self._network.security_rules.begin_delete(old_rg, old_name, nm).result()
                    except Exception:
                        pass
                promoted_from = old_rule
            _clear_block_state(vm_name, ip)  # drop the old entry so the new one is saved

        _save_block_state(
            vm_name, ip, resource_id,
            nsg=f"{nsg_rg}/{nsg_name}", nsg_scope=nsg_scope, rule=rule_name, scoped=scoped,
        )
        out = {
            "status": "blocked",
            "ip": ip,
            "nsg": f"{nsg_rg}/{nsg_name}",
            "nsg_scope": nsg_scope,
            "scoped": scoped,
            "rule": rule_name,
            "resource_id": resource_id,
        }
        if promoted_from:
            out["promoted_from"] = promoted_from   # VM-scoped rule removed after promote
        if scope == "subnet":
            out["note"] = (
                f"NSG {nsg_rg}/{nsg_name} — perimeter block: this IP is denied for ALL "
                "VMs on the subnet (and future ones)."
            )
        elif nsg_scope == "subnet":
            out["note"] = (
                f"NSG {nsg_rg}/{nsg_name} is subnet-level — block scoped to this VM's "
                "private IP only (attacker still reaches other VMs until they detect it)."
            )
        return out

    def snapshot(self, resource_id: str, vault: str = "rsv-annatar", wait: bool = True) -> str:
        """Trigger an RSV on-demand backup.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately without polling.
        Use on detection_timeout paths to avoid blocking the queue.
        """
        if self.dry_run:
            return "snap-dry-run-000"

        self._guard_write("snapshot")
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
        nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)

        in_name, out_name = self._isolation_rule_names(vm_name, nsg_scope)
        try:
            self._network.security_rules.get(nsg_rg, nsg_name, in_name)
            self._network.security_rules.get(nsg_rg, nsg_name, out_name)
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
        wait: bool = True,
    ) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "restore_from_backup", "resource_id": resource_id}

        self._guard_write("restore_from_backup")
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

        if not wait:
            return {
                "status": "restore_triggered",
                "job_name": restore_job.name,
                "vault": vault,
                "rg": rg,
                "recovery_point": latest.name,
                "recovery_point_time": str(rp_time),
                "resource_id": resource_id,
            }

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
        nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)

        rule_name = self._block_rule_name(ip, vm_name, nsg_scope)
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

        self._guard_write("unblock_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)

        # Prefer the NSG recorded at block time (faithful — a subnet-wide block lives
        # on the subnet NSG even if the VM has its own NIC NSG). Fall back to resolving
        # via the NIC for legacy state without a recorded nsg.
        entry = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)
        if entry and entry.get("nsg"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
        else:
            nsg_rg, nsg_name, _ = self._get_nic_nsg(self._get_primary_nic_id(rg, vm_name))

        # Delete every name this block could have under any scope (VM-suffixed,
        # plain/perimeter) so cleanup is robust regardless of how it was created.
        scoped = self._block_rule_name(ip, vm_name, "subnet")
        plain = self._block_rule_name(ip, vm_name, "nic")
        deleted = []
        for name in (scoped, f"{scoped}-out", plain, f"{plain}-out"):
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
            nsg_rg, nsg_name, nsg_scope = self._get_nic_nsg(nic_id)
            rules = list(self._network.security_rules.list(nsg_rg, nsg_name))
            return {
                "ok": True, "nsg": f"{nsg_rg}/{nsg_name}",
                "scope": nsg_scope, "rules": len(rules),
            }
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
                # No recovery point — but is the VM actually protected? An empty RP
                # list means EITHER "protected, first backup pending" OR "not protected
                # at all". Distinguish via the protected-item status so posture/audit
                # don't cry "not linked to vault" on a freshly-protected VM.
                protected = self._is_protected_item(client, vault, rg, container, item)
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
        self, vault: str = "rsv-annatar", resource_group: str = "annatar"
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

    def _isolation_rule_names(self, vm_name: str, scope: str) -> tuple[str, str]:
        """(inbound, outbound) isolation rule names. On a shared subnet NSG the names
        are VM-suffixed so isolating several VMs doesn't clobber each other's rules."""
        if scope == "subnet":
            base = f"{self.ISOLATION_RULE_NAME}-{vm_name}"
            return base, f"{base}-out"
        return self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out"

    def _block_rule_name(self, ip: str, vm_name: str, scope: str) -> str:
        """Base name for a block rule. VM-suffixed on a shared subnet NSG so blocks
        scoped to different VMs (same attacker IP) don't collide."""
        base = f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
        return f"{base}-{vm_name}" if scope == "subnet" else base

    def _get_nic_private_ip(self, nic_id: str) -> str:
        """Primary private IP of a NIC — used to scope isolation on a subnet NSG."""
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        cfgs = nic.ip_configurations or []
        primary = next((c for c in cfgs if getattr(c, "primary", False)), cfgs[0] if cfgs else None)
        ip = getattr(primary, "private_ip_address", None) if primary else None
        if not ip:
            raise RuntimeError(f"NIC {nic_name} has no private IP — cannot scope isolation")
        return ip

    def _get_nic_nsg(self, nic_id: str) -> tuple[str, str, str]:
        """Resolve the NSG governing a NIC. Returns (rg, name, scope).

        scope is "nic" (NSG attached to the NIC — rule affects only this VM) or
        "subnet" (fallback: NSG on the subnet — ⚠ rule affects EVERY VM on the
        subnet, not just this one). Callers acting on the NSG (isolate/block) must
        surface "subnet" so the blast radius is visible — a subnet-level deny-all
        isolates the whole subnet, not the single VM.
        """
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)

        # NIC-level NSG (preferred — scoped to this VM)
        if nic.network_security_group is not None:
            rg, name = _parse_nsg_resource_id(nic.network_security_group.id)
            return rg, name, "nic"

        # Fallback: subnet-level NSG (shared — affects all VMs on the subnet)
        subnet_id = nic.ip_configurations[0].subnet.id
        # /subscriptions/.../virtualNetworks/<vnet>/subnets/<subnet>
        parts = subnet_id.split("/")
        sub_rg = parts[parts.index("resourceGroups") + 1]
        vnet = parts[parts.index("virtualNetworks") + 1]
        subnet_name = parts[-1]
        subnet = self._network.subnets.get(sub_rg, vnet, subnet_name)
        if subnet.network_security_group is None:
            raise RuntimeError(f"NIC {nic_name} and its subnet have no NSG — cannot isolate VM")
        rg, name = _parse_nsg_resource_id(subnet.network_security_group.id)
        return rg, name, "subnet"

    def _get_subnet_nsg(self, nic_id: str) -> tuple[str, str]:
        """Resolve the NSG on the NIC's SUBNET (always the subnet's, ignoring any NIC
        NSG). Used for a deliberate subnet-wide block. Raises if the subnet has no NSG
        (then a subnet-wide block isn't possible without per-NIC propagation)."""
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        subnet_id = nic.ip_configurations[0].subnet.id
        parts = subnet_id.split("/")
        sub_rg = parts[parts.index("resourceGroups") + 1]
        vnet = parts[parts.index("virtualNetworks") + 1]
        subnet_name = parts[-1]
        subnet = self._network.subnets.get(sub_rg, vnet, subnet_name)
        if subnet.network_security_group is None:
            raise RuntimeError(
                f"Subnet {subnet_name} has no NSG — subnet-wide block not available "
                "(NSGs are per-NIC; would require propagating to each NIC)."
            )
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


def _save_block_state(
    vm_name: str, ip: str, resource_id: str,
    nsg: str = "", nsg_scope: str = "", rule: str = "", scoped: bool = True,
) -> None:
    import json
    from datetime import datetime, timezone
    _BLOCK_STATE_DIR.mkdir(parents=True, exist_ok=True)
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    entries = json.loads(f.read_text()) if f.exists() else []
    if not any(e["ip"] == ip for e in entries):
        # Record the NSG + scope so the representation matches Azure reality:
        # nsg_scope="subnet" → rule lives on a shared subnet NSG, "nic" → on the VM NIC.
        # scoped=True → rule only affects THIS VM (NIC, or subnet+VM-IP addressing);
        # False would be a subnet-wide `any` rule → War Room shows the ⚠ blast-radius chip.
        entries.append({
            "ip": ip, "resource_id": resource_id,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "nsg": nsg, "nsg_scope": nsg_scope, "rule": rule, "scoped": scoped,
        })
    f.write_text(json.dumps(entries))


def _load_block_entries(vm_name: str) -> list[dict]:
    """Return the recorded block entries for a VM (empty if none)."""
    import json
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


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
