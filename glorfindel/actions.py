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

    def _put_deny_rule(
        self, nsg_rg: str, nsg_name: str, name: str, direction: str, priority: int,
        *, src=None, srcs=None, dst=None, dsts=None,
    ) -> None:
        """Create/update a Deny security rule. Use srcs/dsts (lists, augmented rule) to
        cover several IPs in one rule; src/dst for a single prefix like '*'."""
        from azure.mgmt.network.models import SecurityRule
        kwargs = dict(
            name=name, protocol="*",
            source_port_range="*", destination_port_range="*",
            access="Deny", priority=priority, direction=direction,
        )
        if srcs is not None:
            kwargs["source_address_prefixes"] = srcs
        else:
            kwargs["source_address_prefix"] = src
        if dsts is not None:
            kwargs["destination_address_prefixes"] = dsts
        else:
            kwargs["destination_address_prefix"] = dst
        self._network.security_rules.begin_create_or_update(
            nsg_rg, nsg_name, name, SecurityRule(**kwargs)
        ).result()

    def isolate_vm(self, resource_id: str) -> dict:
        """Deny all traffic on EVERY NIC of the VM (fully reversible).

        A VM can have several NICs, each behind its own NSG (or its subnet's NSG).
        Isolating only the primary NIC leaves the others open. So we place one deny
        pair per NIC: any/any on a NIC-level NSG (priority 100, bumping conflicts), or
        scoped to all the NIC's private IPs on a shared subnet NSG (free priority, no
        bump → other VMs untouched). State records every placement for release.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}

        self._guard_write("isolate_vm")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        targets = self._get_vm_nic_targets(rg, vm_name)

        placements: list[dict] = []
        assigned: dict[str, set] = {}  # nsg_key → priorities used during THIS call
        for t in targets:
            nsg_rg, nsg_name, scope = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
            in_name, out_name = base, f"{base}-out"
            existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
            used = {r.priority for r in existing} | assigned.get(nsg_key, set())
            bumped: list[dict] = []

            if scope == "subnet":
                ips = t["private_ips"]
                if not ips:
                    raise RuntimeError(
                        f"NIC {t['nic_short']} has no private IP — cannot scope isolation "
                        "on its shared subnet NSG"
                    )
                priority = next(p for p in range(self.ISOLATION_PRIORITY, 4000) if p not in used)
                self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)
                self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst="*")
            else:
                # NIC-level NSG (this VM only) — any/any is safe. Insist on priority 100
                # so the deny wins; shift any conflicting non-glorfindel rule off it.
                for r in existing:
                    if r.priority == self.ISOLATION_PRIORITY and not r.name.startswith("glorfindel-"):
                        new_prio = next(
                            p for p in range(self.ISOLATION_PRIORITY + 100, 4000, 100)
                            if p not in used
                        )
                        used.add(new_prio)
                        r.priority = new_prio
                        self._network.security_rules.begin_create_or_update(
                            nsg_rg, nsg_name, r.name, r).result()
                        bumped.append({"name": r.name, "original_priority": self.ISOLATION_PRIORITY})
                priority = self.ISOLATION_PRIORITY
                self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dst="*")
                self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst="*")

            assigned.setdefault(nsg_key, set()).add(priority)
            placements.append({
                "nic_id": t["nic_id"], "nsg_rg": nsg_rg, "nsg_name": nsg_name,
                "scope": scope, "ips": t["private_ips"], "priority": priority,
                "rule_in": in_name, "rule_out": out_name, "bumped": bumped,
            })

        # Persist state ONLY after every deny rule is confirmed on Azure (a 403 mid-way
        # must not leave an orphan "ISOLATED" state). placements[] drives release/verify;
        # the flat nsg/nsg_scope/rule_names fields keep /api/state + legacy paths working.
        from datetime import datetime, timezone
        first = placements[0]
        _save_isolation_state(vm_name, {
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "scoped": True,
            "placements": placements,
            "nsg_rg": first["nsg_rg"], "nsg_name": first["nsg_name"], "nsg_scope": first["scope"],
            "rule_names": [p["rule_in"] for p in placements] + [p["rule_out"] for p in placements],
        })

        out = {
            "status": "isolated",
            "resource_id": resource_id,
            "scoped": True,
            "nics_covered": len(placements),
            "placements": [
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"]}
                for p in placements
            ],
            # Back-compat summary (first placement)
            "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
            "nsg_scope": first["scope"],
            "rule": first["rule_in"],
        }
        if any(p["scope"] == "subnet" for p in placements):
            out["note"] = (
                "subnet-level NSG involved — isolation scoped to this VM's private IP(s) "
                "only (no impact on other VMs on the subnet)."
            )
        return out

    def release_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._guard_write("release_isolation")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        state = _load_isolation_state(vm_name) or {}

        if state.get("placements"):
            # Multi-NIC: undo each placement on its own NSG (delete rules, restore bumps).
            for p in state["placements"]:
                p_rg, p_name = p["nsg_rg"], p["nsg_name"]
                for rule_name in (p.get("rule_in"), p.get("rule_out")):
                    if rule_name:
                        try:
                            self._network.security_rules.begin_delete(p_rg, p_name, rule_name).result()
                        except Exception:
                            pass
                for rule_info in p.get("bumped", []):
                    try:
                        r = self._network.security_rules.get(p_rg, p_name, rule_info["name"])
                        r.priority = rule_info["original_priority"]
                        self._network.security_rules.begin_create_or_update(p_rg, p_name, r.name, r).result()
                    except Exception:
                        pass
        else:
            # Legacy single-NSG state (isolated before the multi-NIC upgrade) — resolve
            # via the primary NIC and delete both fixed and VM-suffixed rule names.
            nic_id = self._get_primary_nic_id(rg, vm_name)
            nsg_rg, nsg_name, _ = self._get_nic_nsg(nic_id)
            names = set(state.get("rule_names", []))
            names.update([
                self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out",
                f"{self.ISOLATION_RULE_NAME}-{vm_name}", f"{self.ISOLATION_RULE_NAME}-{vm_name}-out",
            ])
            for rule_name in names:
                try:
                    self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
                except Exception:
                    pass
            for rule_info in state.get("bumped", []):
                try:
                    r = self._network.security_rules.get(nsg_rg, nsg_name, rule_info["name"])
                    r.priority = rule_info["original_priority"]
                    self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
                except Exception:
                    pass

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

        if scope == "subnet":
            return self._block_ip_subnet(ip, resource_id, rg, vm_name, replace)
        return self._block_ip_vm(ip, resource_id, rg, vm_name)

    def _block_ip_vm(self, ip: str, resource_id: str, rg: str, vm_name: str) -> dict:
        """VM-scoped block (autonomous default) — deny the attacker IP on EVERY NIC so a
        secondary NIC doesn't leave the attacker a path. One rule per NIC: any↔attacker
        on a NIC NSG, attacker↔(all the NIC's IPs) on a shared subnet NSG."""
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        placements: list[dict] = []
        assigned: dict[str, set] = {}
        for t in targets:
            nsg_rg, nsg_name, scope_t = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            base = self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])
            in_name, out_name = base, f"{base}-out"
            existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
            used = {r.priority for r in existing} | assigned.get(nsg_key, set())
            priority = next(p for p in range(200, 4000, 10) if p not in used)
            if scope_t == "subnet":
                ips = t["private_ips"]
                self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dsts=ips)
                self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst=ip)
            else:
                self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dst="*")
                self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst=ip)
            assigned.setdefault(nsg_key, set()).add(priority)
            placements.append({
                "nsg_rg": nsg_rg, "nsg_name": nsg_name, "scope": scope_t,
                "ips": t["private_ips"], "rule": base,
            })

        first = placements[0]
        _save_block_state(
            vm_name, ip, resource_id,
            nsg=f'{first["nsg_rg"]}/{first["nsg_name"]}', nsg_scope=first["scope"],
            rule=first["rule"], scoped=True, placements=placements,
        )
        out = {
            "status": "blocked", "ip": ip, "scoped": True, "resource_id": resource_id,
            "nics_covered": len(placements),
            "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
            "nsg_scope": first["scope"], "rule": first["rule"],
            "placements": [
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"]}
                for p in placements
            ],
        }
        if any(p["scope"] == "subnet" for p in placements):
            out["note"] = (
                "subnet-level NSG involved — block scoped to this VM's private IP(s) "
                "(attacker still reaches other VMs until they detect it)."
            )
        return out

    def _block_ip_subnet(
        self, ip: str, resource_id: str, rg: str, vm_name: str, replace: bool
    ) -> dict:
        """Perimeter block — one any rule on the SUBNET NSG (covers all VMs on the
        subnet + future). replace=True promotes a prior VM-scoped block: create the
        subnet rule first, then drop the prior per-NIC rules (no protection gap)."""
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_subnet_nsg(nic_id)
        rule_name = self._block_rule_name(ip, vm_name, scope="vm")  # shared (no VM suffix)

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used = {r.priority for r in existing}
        priority = next(p for p in range(200, 4000, 10) if p not in used)
        self._put_deny_rule(nsg_rg, nsg_name, rule_name, "Inbound", priority, src=ip, dst="*")
        self._put_deny_rule(nsg_rg, nsg_name, f"{rule_name}-out", "Outbound", priority, src="*", dst=ip)

        promoted_from = None
        if replace:
            # Subnet rule now in place → drop the prior VM-scoped rules (every NIC).
            prev = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)
            dropped = []
            for pl in (prev or {}).get("placements", []):
                for nm in (pl["rule"], f'{pl["rule"]}-out'):
                    try:
                        self._network.security_rules.begin_delete(pl["nsg_rg"], pl["nsg_name"], nm).result()
                    except Exception:
                        pass
                dropped.append(pl["rule"])
            # Legacy single-rule entry (no placements)
            if prev and prev.get("rule") and not prev.get("placements") and prev["rule"] != rule_name:
                old_rg, old_name = (prev.get("nsg") or f"{nsg_rg}/{nsg_name}").split("/", 1)
                for nm in (prev["rule"], f'{prev["rule"]}-out'):
                    try:
                        self._network.security_rules.begin_delete(old_rg, old_name, nm).result()
                    except Exception:
                        pass
                dropped.append(prev["rule"])
            if prev:
                _clear_block_state(vm_name, ip)
            promoted_from = dropped or None

        _save_block_state(
            vm_name, ip, resource_id,
            nsg=f"{nsg_rg}/{nsg_name}", nsg_scope="subnet", rule=rule_name, scoped=False,
        )
        out = {
            "status": "blocked", "ip": ip, "nsg": f"{nsg_rg}/{nsg_name}",
            "nsg_scope": "subnet", "scoped": False, "rule": rule_name,
            "resource_id": resource_id,
            "note": (
                f"NSG {nsg_rg}/{nsg_name} — perimeter block: this IP is denied for ALL "
                "VMs on the subnet (and future ones)."
            ),
        }
        if promoted_from:
            out["promoted_from"] = promoted_from
        return out

    def _block_rule_prefix(self, ip: str) -> str:
        return f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"

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
        targets = self._get_vm_nic_targets(rg, vm_name)

        # Isolation holds only if EVERY NIC carries a deny pair — a single uncovered NIC
        # is the multi-NIC gap (looks ISOLATED but traffic still flows on the other NIC).
        uncovered: list[str] = []
        for t in targets:
            base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
            if self._rules_present(t["nsg_rg"], t["nsg_name"], [base, f"{base}-out"]):
                continue
            # Legacy fallback: a VM isolated before the multi-NIC upgrade used the old
            # fixed/VM-suffixed names on the primary NIC's NSG.
            legacy_in, legacy_out = self._isolation_rule_names(vm_name, t["scope"])
            if self._rules_present(t["nsg_rg"], t["nsg_name"], [legacy_in, legacy_out]):
                continue
            uncovered.append(t["nic_short"])

        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered}
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    def _rules_present(self, nsg_rg: str, nsg_name: str, names: list[str]) -> bool:
        """True if all named rules exist on the NSG."""
        try:
            for n in names:
                self._network.security_rules.get(nsg_rg, nsg_name, n)
            return True
        except Exception:
            return False

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
        entry = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)

        # Multi-NIC VM block: confirmed only if every placement's rule is present.
        if entry and entry.get("placements"):
            missing = [
                p["rule"] for p in entry["placements"]
                if not self._rules_present(p["nsg_rg"], p["nsg_name"], [p["rule"]])
            ]
            if missing:
                return {"verified": False, "method": "nsg_check", "missing_rules": missing}
            return {"verified": True, "method": "nsg_check",
                    "nics_covered": len(entry["placements"])}

        # Perimeter (subnet) block, or legacy single-rule entry: check the recorded rule.
        if entry and entry.get("nsg") and entry.get("rule"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
            if self._rules_present(nsg_rg, nsg_name, [entry["rule"]]):
                return {"verified": True, "method": "nsg_check", "rule": entry["rule"]}
            return {"verified": False, "method": "nsg_check", "error": "rule not found"}

        # No state — recompute per-NIC names (multi-NIC) and check coverage.
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        uncovered = [
            t["nic_short"] for t in targets
            if not self._rules_present(
                t["nsg_rg"], t["nsg_name"],
                [self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])],
            )
        ]
        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered}
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "unblock_ip", "ip": ip}
        if not ip:
            raise ValueError("unblock_ip: no IP address provided")

        self._guard_write("unblock_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        entry = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)
        deleted: list[str] = []

        def _del(p_rg: str, p_name: str, rule: str) -> None:
            for nm in (rule, f"{rule}-out"):
                try:
                    self._network.security_rules.begin_delete(p_rg, p_name, nm).result()
                    deleted.append(nm)
                except Exception:
                    pass

        # 1) Every per-NIC placement recorded at block time (multi-NIC VM block).
        for p in (entry or {}).get("placements", []):
            _del(p["nsg_rg"], p["nsg_name"], p["rule"])

        # 2) The recorded single rule (perimeter / legacy entry).
        if entry and entry.get("nsg") and entry.get("rule"):
            r_rg, r_name = entry["nsg"].split("/", 1)
            _del(r_rg, r_name, entry["rule"])

        # 3) Belt-and-braces for legacy state without rule names: resolve via the primary
        # NIC and delete the historical VM-suffixed / plain block-rule names.
        if not deleted:
            try:
                nsg_rg, nsg_name, _ = self._get_nic_nsg(self._get_primary_nic_id(rg, vm_name))
                for legacy in (self._block_rule_name(ip, vm_name, "subnet"),
                               self._block_rule_name(ip, vm_name, "nic")):
                    _del(nsg_rg, nsg_name, legacy)
            except Exception:
                pass

        _clear_block_state(vm_name, ip)
        return {
            "status": "unblocked" if deleted else "not_found",
            "ip": ip,
            "deleted_rules": deleted,
        }

    # ── Audit / readiness checks ───────────────────────────────────────────────

    def check_nsg_access(self, resource_id: str) -> dict:
        """Verify NSG read access — proxy for isolate_vm / block_suspicious_ip readiness.

        Enumerates EVERY NIC's governing NSG (`nsgs`), so the War Room shows the full
        multi-NIC NSG picture at rest (not just the primary NIC). `nsg`/`scope` mirror
        the first NIC for back-compat.
        """
        if self.dry_run:
            return {"ok": True, "nsg": "dry_run"}
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            targets = self._get_vm_nic_targets(rg, vm_name)
            nsgs = [
                {
                    "nsg": f'{t["nsg_rg"]}/{t["nsg_name"]}',
                    "nsg_scope": t["scope"],
                    "nic_id": t["nic_id"],
                    "ips": t["private_ips"],
                }
                for t in targets
            ]
            first = targets[0]
            # rule count on the primary NIC's NSG (cheap signal that we can read it)
            rules = list(self._network.security_rules.list(first["nsg_rg"], first["nsg_name"]))
            return {
                "ok": True,
                "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
                "scope": first["scope"],
                "rules": len(rules),
                "nsgs": nsgs,
            }
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}

    def list_nsgs(self) -> list[dict]:
        """Enumerate ALL NSGs as resources — the true network-control inventory.

        The per-VM audit (check_nsg_access) UNDER-counts the inventory: it reports one
        NSG per NIC and so misses (1) a subnet NSG when the NIC also has its own NSG
        (a NIC is governed by BOTH), (2) an NSG on an AKS subnet (the cluster isn't
        audited as a VM), (3) NSGs of powered-off / evicted VMs. Listing NSG resources
        directly gives the complete set, each with its associations (subnets/NICs), its
        rule count, and whether it carries a Glorfindel restriction (a `glorfindel-*`
        rule = an active isolation/block).

        Each NSG also carries `vms` — the resource_ids of the VMs it governs (NIC-level
        OR subnet-level), resolved from one network-interfaces enumeration. The War Room
        uses it to (a) flag NSGs whose VMs aren't monitored (not in the LAW = a coverage
        blind spot) and (b) glow the associated VM card(s) on hover. Read-only.
        """
        if self.dry_run:
            return []
        self._ensure_clients()

        # NIC → VM and subnet → {VMs} maps, so each NSG can be attributed to the VMs it
        # governs (NIC association OR subnet association). One list_all over NICs — best
        # effort: if it fails, NSGs are still listed, just without `vms`.
        nic_to_vm: dict[str, str] = {}
        subnet_to_vms: dict[str, set] = {}
        try:
            for nic in self._network.network_interfaces.list_all():
                vm_id = getattr(getattr(nic, "virtual_machine", None), "id", None)
                if not vm_id:
                    continue
                nic_to_vm[nic.id.lower()] = vm_id
                for cfg in (nic.ip_configurations or []):
                    sub = getattr(getattr(cfg, "subnet", None), "id", None)
                    if sub:
                        subnet_to_vms.setdefault(sub.lower(), set()).add(vm_id)
        except Exception:
            pass

        out: list[dict] = []
        for nsg in self._network.network_security_groups.list_all():
            rg, name = _parse_nsg_resource_id(nsg.id)
            rules = list(nsg.security_rules or [])
            glor = [r for r in rules if (getattr(r, "name", "") or "").startswith("glorfindel-")]
            nic_ids = [n.id for n in (nsg.network_interfaces or [])]
            subnet_ids = [s.id for s in (nsg.subnets or [])]
            vms: set = set()
            for nid in nic_ids:
                vm = nic_to_vm.get(nid.lower())
                if vm:
                    vms.add(vm)
            for sid in subnet_ids:
                vms |= subnet_to_vms.get(sid.lower(), set())
            out.append({
                "nsg": f"{rg}/{name}",
                "id": nsg.id,
                # Associations: a subnet-level NSG has subnets[], a NIC-level NSG has
                # network_interfaces[]. A shared NSG can have both / several.
                "subnets": subnet_ids,
                "nics": nic_ids,
                "vms": sorted(vms),                # VM resource_ids this NSG governs
                "rules": len(rules),
                "restricted": bool(glor),          # carries an active Glorfindel rule
                "glorfindel_rules": len(glor),
            })
        return out

    def check_backup_points(
        self, resource_id: str, vault: str = "rsv-annatar", vault_rg: str = ""
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
            # Canonical fabric names — CASE MATTERS. `recovery_points.list` is
            # case-SENSITIVE on the container/item type prefix (`IaasVMContainer;` / `VM;`),
            # while `protected_items.get` is case-insensitive. Lowercase prefixes made
            # protected_items.get succeed (→ protected=True) but recovery_points.list return
            # EMPTY → a false "first backup pending" on a VM that IS backed up (confirmed on
            # the Celebrimbor bench: az showed the RP, our query missed it on case alone).
            container = f"IaasVMContainer;iaasvmcontainerv2;{vm_rg};{vm_name}"
            item = f"VM;iaasvmcontainerv2;{vm_rg};{vm_name}"
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

    def _get_vm_nic_targets(self, rg: str, vm_name: str) -> list[dict]:
        """Every NIC of the VM with its governing NSG + all private IPs.

        Isolation must cover EVERY NIC: a VM with 2 NICs each behind its own NSG is
        only half-isolated if we touch the primary alone (the real bug). Each target
        becomes one placement — deny any/any on a NIC-level NSG (scope 'nic') or deny
        scoped to ALL the NIC's private IPs on a shared subnet NSG (scope 'subnet').
        """
        vm = self._compute.virtual_machines.get(rg, vm_name)
        targets: list[dict] = []
        for ref in vm.network_profile.network_interfaces:
            nic_id = ref.id
            nsg_rg, nsg_name, scope = self._get_nic_nsg(nic_id)
            targets.append({
                "nic_id": nic_id,
                "nic_short": nic_id.rstrip("/").split("/")[-1],
                "nsg_rg": nsg_rg,
                "nsg_name": nsg_name,
                "scope": scope,
                "private_ips": self._get_nic_private_ips(nic_id),
            })
        return targets

    def _get_nic_private_ips(self, nic_id: str) -> list[str]:
        """All private IPs across a NIC's ipConfigurations (a NIC can have several).

        An NSG applies to the whole NIC, not per ipConfig, so a subnet-scoped deny must
        address every private IP of the NIC or a secondary IP stays reachable.
        """
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        ips = [
            getattr(c, "private_ip_address", None)
            for c in (nic.ip_configurations or [])
        ]
        return [ip for ip in ips if ip]

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
        """Primary private IP of a NIC — used to scope a subnet-wide block to one VM."""
        ips = self._get_nic_private_ips(nic_id)
        if not ips:
            _, nic_name = _parse_nic_resource_id(nic_id)
            raise RuntimeError(f"NIC {nic_name} has no private IP — cannot scope isolation")
        return ips[0]

    def _placement_rule_base(self, prefix: str, vm_name: str, nic_short: str, nic_id: str) -> str:
        """A rule-name base unique per (VM, NIC), within Azure's 80-char rule-name limit.

        Per-NIC uniqueness lets two NICs of the same VM be denied on the same shared
        subnet NSG without clobbering each other. Falls back to a short nic_id hash if
        the readable name would overflow 80 chars (incl. the '-out' suffix)."""
        base = f"{prefix}-{vm_name}-{nic_short}"
        if len(base) + 4 > 80:
            import hashlib
            h = hashlib.sha1(nic_id.encode()).hexdigest()[:8]
            base = f"{prefix}-{vm_name[:40]}-{h}"
        return base

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
    placements: list | None = None,
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
        # placements[] → one rule per NIC (multi-NIC VM block); nsg/rule mirror the first
        # placement for /api/state + legacy display.
        entries.append({
            "ip": ip, "resource_id": resource_id,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "nsg": nsg, "nsg_scope": nsg_scope, "rule": rule, "scoped": scoped,
            "placements": placements or [],
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


def _is_backupable_vm(resource_id: str) -> bool:
    """True only for a standalone Microsoft.Compute/virtualMachines.

    Azure Backup IaaS-VM protects standalone VMs only. NOT a backup item (and the
    VM-oriented checks — backup/NSG/compute — don't apply): a VMSS instance, an AKS
    managed cluster (Microsoft.ContainerService/managedClusters — what the AMA heartbeat
    actually reports for AKS nodes, NOT the VMSS-instance id), or any other resource.
    Allowlisting standalone VMs is more robust than denylisting each non-VM type."""
    low = resource_id.lower()
    return (
        "/providers/microsoft.compute/virtualmachines/" in low
        and "/virtualmachinescalesets/" not in low
    )


def _parse_vm_resource_id(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
    return parts[rg_idx + 1], parts[-1]


def _parse_nic_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)


def _parse_nsg_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)
