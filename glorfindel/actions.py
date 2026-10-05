from __future__ import annotations

import importlib
import json
import os
import tempfile
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


class PartialActionError(RuntimeError):
    """An NSG action landed on some NICs, then failed on the next one.

    The rules already in place are KEPT (partial containment beats none) and recorded
    in state, so release / unblock / reset can remove them later. Before this, a failure
    on NIC n left the rules of NICs 1..n-1 on Azure with no state at all: invisible to
    `glorfindel list`, and out of reach of `reset`.

    Carries the original error's status_code so execute_action still tells an IAM gap
    (403 → write_blocked) from any other failure (action_failed).
    """

    def __init__(self, message: str, *, cause: BaseException, covered: list[str], failed_nic: str):
        super().__init__(message)
        self.cause = cause
        self.status_code = getattr(cause, "status_code", None)
        self.covered = covered
        self.failed_nic = failed_nic


def _first_line(exc: BaseException) -> str:
    """First line of an exception message (Azure SDK errors repeat it on later lines)."""
    text = str(exc).strip()
    return text.splitlines()[0].strip() if text else type(exc).__name__


def _is_not_found(exc: BaseException) -> bool:
    """True when an Azure call failed only because the resource doesn't exist."""
    if getattr(exc, "status_code", None) == 404:
        return True
    try:
        from azure.core.exceptions import ResourceNotFoundError
        if isinstance(exc, ResourceNotFoundError):
            return True
    except ImportError:
        pass
    return "notfound" in str(exc).replace(" ", "").lower()


def _ip_scoped(target: dict) -> bool:
    """True when the deny must be addressed to the VM's own IPs.

    That is the case on any NSG that also governs other NICs: a subnet NSG, or a
    NIC-level NSG shared with other NICs. An any/any deny there would cut off every VM
    behind it. Older target dicts carry no `ip_scoped` key: fall back to the scope.
    """
    return target.get("ip_scoped", target.get("scope") == "subnet")


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

    Each module is imported on its own: one missing optional package (e.g. the
    recovery-services SDK) no longer cancels the warm-up of the modules that ARE
    installed — which is what removes the deadlock window for them.
    """
    global _warmed_up
    if _warmed_up:
        return
    with _warmup_lock:
        if _warmed_up:
            return
        for module in _WARM_UP_MODULES:
            try:
                importlib.import_module(module)
            except Exception:
                # Not installed / partial env — real errors surface at actual use.
                pass
        _warmed_up = True


_WARM_UP_MODULES = (
    "azure.core.pipeline",        # the module that races
    "azure.core.exceptions",
    "azure.identity",
    "azure.mgmt.network",
    "azure.mgmt.network.models",
    "azure.mgmt.compute",
    "azure.mgmt.recoveryservicesbackup",
    "azure.monitor.query",
)


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
    def snapshot(
        self, resource_id: str, vault: str = "rsv-annatar", wait: bool = True,
        vault_rg: str = "",
    ) -> str:
        """Take an on-demand RSV backup snapshot.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately. The agent always uses
        it: a blocking snapshot holds the VM's (serialized) signal queue for the whole
        backup — 4h25 on an initial full backup in a real run.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        ...

    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict:
        """Confirm that isolation rules are active on EVERY NIC of the VM."""
        ...

    def verify_release(self, resource_id: str) -> dict:
        """Confirm that NO isolation rule remains on any NIC of the VM.

        Not `not verify_isolation()`: that is False as soon as ONE NIC is uncovered, so
        its negation would call a VM released while another NIC is still cut off.
        Default for connectors that don't implement it: no claim (verified=None).
        """
        return {"verified": None, "method": "not_implemented"}

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
        staging_storage: str = "",
        vault_rg: str = "",
    ) -> dict:
        """Trigger an Azure Backup OriginalLocation restore. Human-approved action.

        before_attack_time: ISO8601 timestamp — selects the most recent recovery point
        that predates the attack, avoiding restoration of a post-attack backup.
        wait=False: returns after triggering the restore job, without polling.
          VM stays deallocated; caller must start it and emit recovery_complete manually.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
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

    Mutating actions act on the resource_id they are given. Scope control lives
    upstream, not in a tag allowlist: the per-asset autonomy mode (human_only by
    default) decides whether an action runs at all, and GLORFINDEL_READ_ONLY blocks
    every write (_guard_write). A defender limited to resources tagged as test targets
    would not defend production; the `annatar-test` tag gates the RED side only
    (annatar/safety/guard.py).
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
        pair per NIC: any/any on an NSG that governs this VM alone (priority 100,
        bumping conflicts), or scoped to all the NIC's private IPs on an NSG shared with
        other NICs — a subnet NSG or a shared NIC-level NSG (free priority, no bump →
        other VMs untouched). State records every placement for release.

        Partial failure: if a later NIC fails, the denies already in place stay (partial
        containment beats none), are recorded in state with `partial: true`, and a
        PartialActionError is raised. A failure before anything landed raises the
        original error and writes no state (nothing to undo).
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
            placement = {
                "nic_id": t["nic_id"], "nsg_rg": nsg_rg, "nsg_name": nsg_name,
                "scope": scope, "shared_nsg": bool(t.get("shared_nsg", False)),
                "ips": t["private_ips"], "priority": None,
                "rule_in": in_name, "rule_out": out_name,
                "bumped": [],    # customer rules moved off priority 100 (restored on release)
                "applied": [],   # deny rules confirmed by Azure
            }
            try:
                existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
                used = {r.priority for r in existing} | assigned.get(nsg_key, set())
                if _ip_scoped(t):
                    ips = t["private_ips"]
                    if not ips:
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope isolation "
                            "on its shared NSG"
                        )
                    priority = next(p for p in range(self.ISOLATION_PRIORITY, 4000) if p not in used)
                    placement["priority"] = priority
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst="*")
                    placement["applied"].append(out_name)
                else:
                    # NSG governing this VM only — any/any is safe. Insist on priority 100
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
                            # Recorded as soon as Azure confirms the move: if a later step
                            # fails, release still knows to put the customer's rule back.
                            placement["bumped"].append(
                                {"name": r.name, "original_priority": self.ISOLATION_PRIORITY})
                    priority = self.ISOLATION_PRIORITY
                    placement["priority"] = priority
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dst="*")
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst="*")
                    placement["applied"].append(out_name)
            except Exception as exc:
                partial = self._record_partial_isolation(
                    vm_name, resource_id, placements, placement, exc, total=len(targets))
                if partial is None:
                    raise
                raise partial from exc

            assigned.setdefault(nsg_key, set()).add(priority)
            placements.append(placement)

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
        if any(p["shared_nsg"] for p in placements):
            out["note"] = (
                "NSG shared with other NICs involved — isolation scoped to this VM's "
                "private IP(s) only (no impact on the other VMs behind that NSG)."
            )
        return out

    def _record_partial_isolation(
        self, vm_name: str, resource_id: str, done: list[dict], failed: dict,
        exc: BaseException, *, total: int,
    ) -> PartialActionError | None:
        """Persist what a failed isolation left on Azure; build the error to raise.

        Returns None when nothing landed (no state written — the caller re-raises the
        original error, exactly as before). Otherwise writes a `partial` state covering
        every rule still in place, so release / reset can find and remove them.
        """
        # A customer rule moved off priority 100 for a deny that never landed protects
        # nothing: put it back now. If that fails too, keep it in state for release.
        if failed["bumped"] and not failed["applied"]:
            failed["bumped"] = self._restore_bumped(
                failed["nsg_rg"], failed["nsg_name"], failed["bumped"])
        kept = done + ([failed] if failed["applied"] or failed["bumped"] else [])
        if not kept:
            return None

        from datetime import datetime, timezone
        failed_nic = failed["nic_id"].rstrip("/").split("/")[-1]
        covered = [p["nic_id"].rstrip("/").split("/")[-1] for p in done]
        first = kept[0]
        _save_isolation_state(vm_name, {
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "scoped": True,
            "partial": True,
            "failed_nic": failed_nic,
            "error": _first_line(exc)[:300],
            "placements": kept,
            "nsg_rg": first["nsg_rg"], "nsg_name": first["nsg_name"], "nsg_scope": first["scope"],
            "rule_names": [p["rule_in"] for p in kept] + [p["rule_out"] for p in kept],
        })
        return PartialActionError(
            f"Isolation partielle de {vm_name} : {len(done)}/{total} NIC(s) couverte(s), "
            f"échec sur {failed_nic} ({_first_line(exc)}). Les règles déjà posées restent "
            "en place et sont enregistrées — `glorfindel reset` pour les retirer.",
            cause=exc, covered=covered, failed_nic=failed_nic,
        )

    def _delete_rule(self, nsg_rg: str, nsg_name: str, rule_name: str) -> str | None:
        """Delete one security rule. None on success or if it was already gone; else a
        short description of the failure (the rule may still be in place)."""
        try:
            self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
            return None
        except Exception as e:
            if _is_not_found(e):
                return None
            return f"{nsg_rg}/{nsg_name}/{rule_name}: {_first_line(e)[:200]}"

    def _restore_bumped(self, nsg_rg: str, nsg_name: str, bumped: list[dict]) -> list[dict]:
        """Put customer rules back on their original priority. Returns the ones that
        could not be restored (kept in state so a later release can retry)."""
        left: list[dict] = []
        for info in bumped:
            try:
                r = self._network.security_rules.get(nsg_rg, nsg_name, info["name"])
                r.priority = info["original_priority"]
                self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
            except Exception as e:
                if _is_not_found(e):
                    continue  # its owner deleted it meanwhile — nothing to put back
                left.append({**info, "error": _first_line(e)[:200]})
        return left

    def _isolation_names_for_target(self, vm_name: str, t: dict) -> list[str]:
        """Every rule name an isolation of this VM can have left on this NIC's NSG.

        Names are deterministic: the per-(VM, NIC) names of the multi-NIC isolation,
        plus the legacy VM-suffixed names. The legacy FIXED names are only ours to touch
        on an NSG that governs this VM alone — on a shared NSG they could belong to
        another VM's isolation.
        """
        base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
        names = [
            base, f"{base}-out",
            f"{self.ISOLATION_RULE_NAME}-{vm_name}", f"{self.ISOLATION_RULE_NAME}-{vm_name}-out",
        ]
        if not _ip_scoped(t):
            names += [self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out"]
        return names

    def release_isolation(self, resource_id: str) -> dict:
        """Remove every isolation rule of the VM and restore bumped customer rules.

        Failures are no longer swallowed: a rule that could not be deleted keeps the VM
        cut off, so the state is kept for those placements, and the status says
        `release_partial` with the failing rules. `released` means every delete succeeded
        (or the rule was already gone).

        Without recorded placements (legacy state, a lost or corrupt state file, a state
        never written), the rule names are recomputed on every current NIC — the same
        names verify_isolation / verify_release look for.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._guard_write("release_isolation")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        state = _load_isolation_state(vm_name) or {}

        failed: list[str] = []
        remaining: list[dict] = []
        if state.get("placements"):
            # Multi-NIC: undo each placement on its own NSG. Delete our denies first —
            # a customer rule can only go back to priority 100 once ours is gone.
            for p in state["placements"]:
                p_rg, p_name = p["nsg_rg"], p["nsg_name"]
                p_failed = [
                    err for err in (
                        self._delete_rule(p_rg, p_name, name)
                        for name in (p.get("rule_in"), p.get("rule_out")) if name
                    ) if err
                ]
                left = self._restore_bumped(p_rg, p_name, p.get("bumped", []))
                p_failed += [f"{p_rg}/{p_name}/{b['name']} (priorité non restaurée) : {b['error']}"
                             for b in left]
                if p_failed:
                    failed += p_failed
                    # Keep the placement for a retry: its rule names (deleting an absent
                    # rule is a no-op) and only the bumps still to put back.
                    remaining.append({**p, "bumped": left})
        else:
            for t in self._get_vm_nic_targets(rg, vm_name):
                for name in self._isolation_names_for_target(vm_name, t):
                    err = self._delete_rule(t["nsg_rg"], t["nsg_name"], name)
                    if err:
                        failed.append(err)
            # Legacy single-NSG state: recorded rule names + bumps live on the recorded NSG.
            if state.get("nsg_name"):
                l_rg, l_name = state.get("nsg_rg", rg), state["nsg_name"]
                for name in state.get("rule_names", []):
                    err = self._delete_rule(l_rg, l_name, name)
                    if err:
                        failed.append(err)
                left = self._restore_bumped(l_rg, l_name, state.get("bumped", []))
                failed += [f"{l_rg}/{l_name}/{b['name']} (priorité non restaurée) : {b['error']}"
                           for b in left]

        if failed:
            from datetime import datetime, timezone
            _save_isolation_state(vm_name, {
                **state,
                "resource_id": state.get("resource_id") or resource_id,
                "isolated_at": state.get("isolated_at") or datetime.now(timezone.utc).isoformat(),
                "placements": remaining if state.get("placements") else state.get("placements", []),
                "release_failed": failed,
            })
            return {"status": "release_partial", "resource_id": resource_id, "failed": failed}

        _clear_isolation_state(vm_name)
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
        secondary NIC doesn't leave the attacker a path. One rule pair per NIC:
        any↔attacker on an NSG that governs this VM alone, attacker↔(all the NIC's IPs)
        on an NSG shared with other NICs (subnet NSG or shared NIC-level NSG).

        Partial failure: rules already placed stay and are recorded (`partial: true`),
        then PartialActionError is raised — same contract as isolate_vm."""
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        placements: list[dict] = []
        assigned: dict[str, set] = {}
        for t in targets:
            nsg_rg, nsg_name, scope_t = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            base = self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])
            in_name, out_name = base, f"{base}-out"
            placement = {
                "nsg_rg": nsg_rg, "nsg_name": nsg_name, "scope": scope_t,
                "shared_nsg": bool(t.get("shared_nsg", False)),
                "ips": t["private_ips"], "rule": base,
            }
            applied: list[str] = []
            try:
                existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
                used = {r.priority for r in existing} | assigned.get(nsg_key, set())
                priority = next(p for p in range(200, 4000, 10) if p not in used)
                if _ip_scoped(t):
                    ips = t["private_ips"]
                    if not ips:
                        # Same guard as isolate_vm: an empty destination list would make
                        # a rule that matches nothing (or is rejected) — never "blocked".
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope the "
                            "block on its shared NSG"
                        )
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dsts=ips)
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst=ip)
                    applied.append(out_name)
                else:
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dst="*")
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst=ip)
                    applied.append(out_name)
            except Exception as exc:
                kept = placements + ([placement] if applied else [])
                if not kept:
                    raise
                first = kept[0]
                _save_block_state(
                    vm_name, ip, resource_id,
                    nsg=f'{first["nsg_rg"]}/{first["nsg_name"]}', nsg_scope=first["scope"],
                    rule=first["rule"], scoped=True, placements=kept, partial=True,
                )
                failed_nic = t["nic_short"]
                raise PartialActionError(
                    f"Blocage partiel de {ip} sur {vm_name} : {len(placements)}/{len(targets)} "
                    f"NIC(s) couverte(s), échec sur {failed_nic} ({_first_line(exc)}). "
                    "Les règles déjà posées restent en place et sont enregistrées — "
                    f"`glorfindel unblock {ip} <resource_id>` pour les retirer.",
                    cause=exc, covered=[p["rule"] for p in placements], failed_nic=failed_nic,
                ) from exc
            assigned.setdefault(nsg_key, set()).add(priority)
            placements.append(placement)

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
        if any(_ip_scoped(p) or p["shared_nsg"] for p in placements):
            out["note"] = (
                "shared NSG involved (subnet or several NICs) — block scoped to this VM's "
                "private IP(s) (attacker still reaches other VMs until they detect it)."
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

    def snapshot(
        self, resource_id: str, vault: str = "rsv-annatar", wait: bool = True,
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

    def verify_release(self, resource_id: str) -> dict:
        """Confirm that NO NIC still carries an isolation rule of this VM.

        The previous check was `not verify_isolation()`, i.e. "at least one NIC is
        uncovered". A release that failed on one NIC (or on one direction of a single
        NIC) therefore passed as verified while that NIC stayed cut off. A rule whose
        presence can't be read counts as still there: no success claim on an unknown.
        """
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        still: list[str] = []
        unknown: list[str] = []
        for t in self._get_vm_nic_targets(rg, vm_name):
            for name in self._isolation_names_for_target(vm_name, t):
                state = self._rule_state(t["nsg_rg"], t["nsg_name"], name)
                if state == "present":
                    still.append(f'{t["nic_short"]}:{name}')
                elif state == "unknown":
                    unknown.append(f'{t["nic_short"]}:{name}')
        if still or unknown:
            detail = ", ".join(still + [f"{u} (lecture impossible)" for u in unknown])
            return {"verified": False, "method": "nsg_check",
                    "still_isolated": still, "unreadable": unknown,
                    "error": f"isolation toujours présente : {detail}"}
        return {"verified": True, "method": "nsg_check"}

    def _rule_state(self, nsg_rg: str, nsg_name: str, name: str) -> str:
        """'present' | 'absent' | 'unknown' (the read itself failed)."""
        try:
            self._network.security_rules.get(nsg_rg, nsg_name, name)
            return "present"
        except Exception as e:
            return "absent" if _is_not_found(e) else "unknown"

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
        staging_storage: str = "",
        vault_rg: str = "",
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
        # Vault calls are scoped to the VAULT's resource group (a central vault protects
        # VMs across RGs); the container name stays keyed by the VM's RG.
        v_rg = vault_rg or rg
        sub = self._subscription_id
        fabric = "Azure"

        backup_client = RecoveryServicesBackupClient(self._credential, sub)
        # Stored names, not hand-built ones: recovery_points.list is case-sensitive
        # (lowercase prefixes returned an EMPTY list on the Celebrimbor bench → "No
        # recovery points" on a VM that has some).
        container_name, item_name = self._resolve_backup_item_names(
            backup_client, vault, v_rg, rg, vm_name)

        rps = list(backup_client.recovery_points.list(vault, v_rg, fabric, container_name, item_name))
        if not rps:
            raise RuntimeError(f"No recovery points in vault {vault}")

        def _has_vault_tier(rp) -> bool:
            return any(
                t.type == "HardenedRP" and getattr(t, "status", "") == "Valid"
                for t in (getattr(rp.properties, "recovery_point_tier_details", None) or [])
            )

        def _rp_time(rp):
            return getattr(rp.properties, "recovery_point_time", None)

        # Select the most recent clean recovery point — must predate the attack
        # to avoid restoring a backup that already contains attack artifacts.
        if before_attack_time:
            attack_dt = datetime.fromisoformat(before_attack_time).astimezone(timezone.utc)
            pre_attack = [
                rp for rp in rps
                if _rp_time(rp) is not None and _rp_time(rp) < attack_dt
            ]
            if not pre_attack:
                raise RuntimeError(
                    f"No recovery point found before attack time {before_attack_time}. "
                    "A backup may have run during the attack. Check the portal."
                )
            candidate_pool = pre_attack
        else:
            candidate_pool = rps

        # Prefer the immutable vault tier, then the NEWEST point by its timestamp.
        # Taking pool[0] relied on the order Azure happens to list points in.
        pool = [rp for rp in candidate_pool if _has_vault_tier(rp)] or candidate_pool
        timed = [rp for rp in pool if _rp_time(rp) is not None]
        latest = max(timed, key=_rp_time) if timed else pool[0]
        rp_time = _rp_time(latest) or "unknown"
        if before_attack_time:
            _console.print(f"  [dim]Using pre-attack recovery point: {rp_time}[/dim]")

        vm = self._compute.virtual_machines.get(rg, vm_name)
        if not staging_storage:
            raise RuntimeError(
                "Restore needs a staging storage account, and none is configured.\n"
                "  Why: to restore a VM from the immutable vault tier (the copy an "
                "attacker can't have tampered — the one you want after ransomware), "
                "Azure temporarily writes the recovered disks to a scratch storage "
                "account, then attaches them. This is NOT the vault's storage; it's a "
                "throwaway staging area in the same region/subscription.\n"
                "  Fix: set 'restore_staging_storage: <account>' on the "
                "azure_backup_vault backend in glorfindel-config.yaml (any Standard "
                "LRS account in the VM's region works; `make celebrimbor-output` "
                "generates it for the Celebrimbor sandbox)."
            )
        # Staging SA co-located with the VM's RG (Celebrimbor sandbox). A staging SA in a
        # different RG would need its own rg field — refinement (cf. vault cross-RG).
        storage_id = (
            f"/subscriptions/{sub}/resourceGroups/{rg}"
            f"/providers/Microsoft.Storage/storageAccounts/{staging_storage}"
        )

        self._compute.virtual_machines.begin_deallocate(rg, vm_name).result()

        token = self._credential.get_token("https://management.azure.com/.default").token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        container_enc = container_name.replace(";", "%3B")
        item_enc = item_name.replace(";", "%3B")
        url = (
            f"https://management.azure.com/subscriptions/{sub}"
            f"/resourceGroups/{v_rg}/providers/Microsoft.RecoveryServices/vaults/{vault}"
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

        triggered_at = datetime.now(timezone.utc)
        r = requests.post(url, json=payload, headers=headers)
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Restore trigger failed ({r.status_code}): {r.text[:300]}")

        restore_job = self._find_backup_job(
            backup_client, vault, v_rg, "Restore", vm_name, triggered_at, delay_s=15.0)
        if restore_job is None:
            raise RuntimeError(f"Restore job for {vm_name} not found after trigger")

        _console.print(f"  [dim]Tracking job {restore_job.name} (15-30 min expected)...[/dim]")

        if not wait:
            return {
                "status": "restore_triggered",
                "job_name": restore_job.name,
                "vault": vault,
                # `rg` is the resource group job lookups run against (jobs.refresh_job):
                # the VAULT's. The VM's own RG is kept separately.
                "rg": v_rg,
                "vault_rg": v_rg,
                "vm_rg": rg,
                "recovery_point": latest.name,
                "recovery_point_time": str(rp_time),
                "resource_id": resource_id,
            }

        elapsed = 0
        while True:
            time.sleep(60)
            elapsed += 60
            job = backup_client.job_details.get(vault, v_rg, restore_job.name)
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
        """Confirm the block is in place: the inbound AND the outbound rule of every
        placement. Checking only the inbound one let a missing `-out` rule (egress /
        C2 / exfil path still open) pass as verified."""
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}
        if not ip:
            return {"verified": False, "method": "nsg_check", "error": "no IP provided"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        entry = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)

        # Multi-NIC VM block: confirmed only if every placement's rule pair is present.
        if entry and entry.get("placements"):
            missing = [
                name
                for p in entry["placements"]
                for name in (p["rule"], f'{p["rule"]}-out')
                if not self._rules_present(p["nsg_rg"], p["nsg_name"], [name])
            ]
            if missing:
                return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                        "error": f"rules missing: {', '.join(missing)}"}
            return {"verified": True, "method": "nsg_check",
                    "nics_covered": len(entry["placements"])}

        # Perimeter (subnet) block, or legacy single-rule entry: check the recorded pair.
        if entry and entry.get("nsg") and entry.get("rule"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
            pair = [entry["rule"], f'{entry["rule"]}-out']
            missing = [n for n in pair if not self._rules_present(nsg_rg, nsg_name, [n])]
            if not missing:
                return {"verified": True, "method": "nsg_check", "rule": entry["rule"]}
            return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                    "error": f"rules missing: {', '.join(missing)}"}

        # No state — recompute per-NIC names (multi-NIC) and check coverage.
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        uncovered = []
        for t in targets:
            base = self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])
            if not self._rules_present(t["nsg_rg"], t["nsg_name"], [base, f"{base}-out"]):
                uncovered.append(t["nic_short"])
        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered,
                    "error": f"NIC(s) not covered: {', '.join(uncovered)}"}
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove every rule of a block. Delete failures are reported, not swallowed: a
        rule that could not be removed still blocks the IP, so its entry stays in state
        and the status is `unblock_partial`."""
        if self.dry_run:
            return {"status": "dry_run", "action": "unblock_ip", "ip": ip}
        if not ip:
            raise ValueError("unblock_ip: no IP address provided")

        self._guard_write("unblock_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        entry = next((e for e in _load_block_entries(vm_name) if e.get("ip") == ip), None)
        deleted: list[str] = []
        failed: list[str] = []

        def _del(p_rg: str, p_name: str, rule: str) -> None:
            for nm in (rule, f"{rule}-out"):
                err = self._delete_rule(p_rg, p_name, nm)
                if err:
                    failed.append(err)
                else:
                    deleted.append(nm)

        # 1) Every per-NIC placement recorded at block time (multi-NIC VM block).
        for p in (entry or {}).get("placements", []):
            _del(p["nsg_rg"], p["nsg_name"], p["rule"])

        # 2) The recorded single rule (perimeter / legacy entry).
        if entry and entry.get("nsg") and entry.get("rule"):
            r_rg, r_name = entry["nsg"].split("/", 1)
            _del(r_rg, r_name, entry["rule"])

        # 3) Belt-and-braces for legacy state without rule names: resolve via the primary
        # NIC and delete the historical VM-suffixed / plain block-rule names.
        if not deleted and not failed:
            try:
                nsg_rg, nsg_name, _ = self._get_nic_nsg(self._get_primary_nic_id(rg, vm_name))
                for legacy in (self._block_rule_name(ip, vm_name, "subnet"),
                               self._block_rule_name(ip, vm_name, "nic")):
                    _del(nsg_rg, nsg_name, legacy)
            except Exception as e:
                failed.append(f"legacy lookup: {_first_line(e)[:200]}")

        if failed:
            # Keep the entry: the rules that are still there keep blocking the IP, and a
            # retry of unblock / reset must still find them.
            _update_block_entry(vm_name, ip, unblock_failed=failed)
            return {
                "status": "unblock_partial", "ip": ip,
                "deleted_rules": deleted, "failed": failed,
            }
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
            shared = scope == "nic" and self._nsg_is_shared(nsg_rg, nsg_name)
            targets.append({
                "nic_id": nic_id,
                "nic_short": nic_id.rstrip("/").split("/")[-1],
                "nsg_rg": nsg_rg,
                "nsg_name": nsg_name,
                "scope": scope,
                # A NIC-level NSG attached to other NICs (or to a subnet as well) is as
                # shared as a subnet NSG: any/any there would cut off every VM behind it.
                "shared_nsg": shared,
                "ip_scoped": scope == "subnet" or shared,
                "private_ips": self._get_nic_private_ips(nic_id),
            })
        return targets

    def _nsg_is_shared(self, nsg_rg: str, nsg_name: str) -> bool:
        """True if this NSG governs more than one NIC, or a subnet too.

        Azure lets one NSG be attached to several NICs and subnets at once (the common
        "one NSG per tier" layout). Treating such an NSG as "this VM only" put an
        any/any deny on it: an autonomous isolation then cut off every VM sharing it.
        Unreadable association → shared: the IP-scoped placement only ever touches the
        target's own IPs, so it is the safe default.
        """
        try:
            nsg = self._network.network_security_groups.get(nsg_rg, nsg_name)
        except Exception:
            return True
        nics = list(getattr(nsg, "network_interfaces", None) or [])
        subnets = list(getattr(nsg, "subnets", None) or [])
        return len(nics) > 1 or len(subnets) > 0

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


def _atomic_write_text(path: Path, text: str) -> None:
    """Write through a temp file + os.replace.

    A reader (War Room, a concurrent CLI, the watch) never sees a half-written state
    file, and a crash mid-write leaves the previous version intact instead of a
    truncated JSON that would break the next release.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _save_isolation_state(vm_name: str, state: dict) -> None:
    _atomic_write_text(_ISOLATION_STATE_DIR / f"{vm_name}.json", json.dumps(state))


def _load_isolation_state(vm_name: str) -> dict | None:
    """The recorded isolation, or None if absent or unreadable.

    An unreadable file is reported, not raised: release_isolation then recomputes the
    rule names on every NIC (they are deterministic), so a corrupt file can no longer
    make an isolation impossible to lift from the CLI.
    """
    f = _ISOLATION_STATE_DIR / f"{vm_name}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except (OSError, ValueError) as e:
        _console.print(
            f"[yellow]État d'isolation illisible pour {vm_name} ({e}) — traité comme "
            "absent ; les règles sont retrouvées par leur nom sur chaque NIC.[/yellow]"
        )
        return None


def _clear_isolation_state(vm_name: str) -> None:
    f = _ISOLATION_STATE_DIR / f"{vm_name}.json"
    if f.exists():
        f.unlink()


def active_isolations() -> list[dict]:
    """Return all active isolation state files (VMs that Glorfindel has isolated)."""
    result = []
    for f in _ISOLATION_STATE_DIR.glob("*.json"):
        try:
            state = json.loads(f.read_text())
            if state.get("resource_id"):
                result.append({**state, "vm_name": f.stem})
        except Exception:
            pass
    return result


def _merge_placements(old: list[dict], new: list[dict]) -> list[dict]:
    """Union of block placements, keyed by (NSG, rule) — a re-block after a partial
    failure must keep track of the rules of BOTH attempts."""
    seen = {(p.get("nsg_rg"), p.get("nsg_name"), p.get("rule")) for p in new}
    return new + [p for p in old if (p.get("nsg_rg"), p.get("nsg_name"), p.get("rule")) not in seen]


def _save_block_state(
    vm_name: str, ip: str, resource_id: str,
    nsg: str = "", nsg_scope: str = "", rule: str = "", scoped: bool = True,
    placements: list | None = None, partial: bool = False,
) -> None:
    from datetime import datetime, timezone
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    entries = _load_block_entries(vm_name)
    prev = next((e for e in entries if e.get("ip") == ip), None)
    if prev is None:
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
            "partial": partial,
        })
    else:
        # The IP is already recorded (a retry after a partial block, or a block of
        # another scope). Previously this call was silently dropped, so the rules it
        # had just placed were unknown to unblock. Merge instead: every rule in place
        # stays recorded, and a subnet-wide rule becomes the entry's single rule.
        if not scoped:
            prev.update(nsg=nsg, nsg_scope=nsg_scope, rule=rule, scoped=False)
        prev["placements"] = _merge_placements(prev.get("placements") or [], placements or [])
        prev["partial"] = partial
    _atomic_write_text(f, json.dumps(entries))


def _load_block_entries(vm_name: str) -> list[dict]:
    """Return the recorded block entries for a VM (empty if none)."""
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


def _clear_block_state(vm_name: str, ip: str) -> None:
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    if not f.exists():
        return
    entries = [e for e in _load_block_entries(vm_name) if e.get("ip") != ip]
    if entries:
        _atomic_write_text(f, json.dumps(entries))
    else:
        f.unlink()


def _update_block_entry(vm_name: str, ip: str, **fields) -> None:
    """Annotate an existing block entry (e.g. the rules an unblock could not remove)."""
    f = _BLOCK_STATE_DIR / f"{vm_name}.json"
    entries = _load_block_entries(vm_name)
    for e in entries:
        if e.get("ip") == ip:
            e.update(fields)
    if entries:
        _atomic_write_text(f, json.dumps(entries))


def active_blocks() -> list[dict]:
    """Return all active IP blocks per VM ({vm_name, resource_id, ip, blocked_at})."""
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


def _backup_item_names(vm_rg: str, vm_name: str) -> tuple[str, str]:
    """Canonical (container, item) names of an IaaS-VM backup item.

    CASE MATTERS: `recovery_points.list` is case-SENSITIVE on the type prefix
    (`IaasVMContainer;` / `VM;`) while `protected_items.get` is not. Lowercase prefixes
    made protected_items.get succeed but recovery_points.list return EMPTY — a false
    "first backup pending" in posture (commit 8bda989), and "No recovery points" in
    restore, which still built them in lowercase. One builder for every caller.
    """
    return (
        f"IaasVMContainer;iaasvmcontainerv2;{vm_rg};{vm_name}",
        f"VM;iaasvmcontainerv2;{vm_rg};{vm_name}",
    )


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
