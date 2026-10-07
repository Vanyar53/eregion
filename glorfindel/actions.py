from __future__ import annotations

import contextlib
import importlib
import json
import os
import re
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
    # revoke_temp_access: removed 2026-10-06 — announced to the model, never implemented
    # (it ended as a no_op "executed", then notified). Proposed → escalated as unknown.
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


# An Azure error names the lock (ScopeLocked) or the policy at the END of its first
# line: cut at 200 characters, the operator lost what to remove (real run, 2026-10-05).
_ERR_MAX = 600


def isolation_verdict(verification: dict, outcome: dict) -> dict:
    """verify_isolation's result, downgraded when the drain left sessions open.

    The rules only stop NEW connections (measured 2026-10-05): rules in place with an
    attacker's session still open is not a contained VM. Shared by the agent's
    verify_action and the War Room's approve route."""
    drain = (outcome or {}).get("drain") or {}
    if verification.get("verified") is True and drain.get("status") == "unsupported":
        return {
            **verification, "verified": False, "drain": drain,
            "error": ("sessions déjà ouvertes non coupées (" + (drain.get("note") or "OS non pris en charge")
                      + ") : un attaquant connecté garde la main — les couper à la main"),
        }
    if verification.get("verified") is True and drain.get("status") in ("failed", "partial"):
        return {
            **verification, "verified": False,
            "error": (
                f"règles posées, mais les sessions déjà ouvertes n'ont pas été coupées "
                f"({drain.get('error', drain.get('status'))}) — un attaquant connecté "
                "garde la main. Couper à la main : az vm run-command invoke "
                "--command-id RunShellScript --scripts 'ss -K state established'"
            ),
        }
    return verification


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
    # No substring guess: "…was not found" also describes a REFERENCED resource that is
    # missing (re-attaching a deleted customer NSG), which is a failure, not "already
    # gone". The SDK raises ResourceNotFoundError / status 404 for the target itself.
    return False


def _prefix_covers(prefix: str, ip: str) -> bool:
    """Does one NSG address prefix (CIDR, IP, '*', service tag) include this IP?

    Approximations, chosen for the IPs Glorfindel reasons about: `VirtualNetwork` covers
    private addresses (a VM's own IPs are always in it), `Internet` covers public ones.
    Other service tags (Storage, AzureCloud…) name Azure public ranges, never a VM's IP.
    """
    import ipaddress
    p = (prefix or "").strip()
    low = p.lower()
    if low in ("*", "any"):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if low == "virtualnetwork":
        return addr.is_private
    if low == "internet":
        return not addr.is_private
    try:
        return addr in ipaddress.ip_network(p, strict=False)
    except ValueError:
        return False


def _side_covers(rule, side: str, ips: list[str] | None) -> bool:
    """Does the rule's `side` ('source' | 'destination') include one of `ips`?

    ips=None means "any address" (a subnet-wide block has no destination scope).
    Application security groups can't be resolved here: assume they may cover
    (conservative — flag rather than miss a bypass).
    """
    if ips is None:
        return True
    if getattr(rule, f"{side}_application_security_groups", None):
        return True
    single = getattr(rule, f"{side}_address_prefix", None)
    values = ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
    if not values:
        return True
    if ips == "public":
        # Readiness check, attacker not known yet: a rule open to ANY internet source.
        # An allow from a specific address (admin access) is a deliberate trust choice,
        # unlikely to be the attacker — not flagged.
        return any(_prefix_open_to_internet(v) for v in values)
    return any(_prefix_covers(v, ip) for v in values for ip in ips)


def _prefix_open_to_internet(prefix: str) -> bool:
    return (prefix or "").strip().lower() in ("*", "any", "internet", "0.0.0.0/0", "::/0")


# Lot L4 — Glorfindel's own quarantine NSG, attached to a NIC that has none of its own.
QUARANTINE_NSG_PREFIX = "nsg-glorfindel-quarantine"
QUARANTINE_RULE_IN = "glorfindel-quarantine-deny-in"
QUARANTINE_RULE_OUT = "glorfindel-quarantine-deny-out"
# NSGs don't filter the platform addresses (168.63.129.16 DNS, 169.254.169.254 IMDS)
# unless a rule names their service tags: an "isolated" VM still resolved names through
# Azure DNS (a tunnel) and fetched managed-identity tokens from IMDS (measured on the
# bench, 2026-10-07). The VM agent (Run Command, used to cut sessions) talks to the
# WireServer, which these tags don't cover.
QUARANTINE_PLATFORM_RULES = (
    ("glorfindel-quarantine-deny-dns", 110, "AzurePlatformDNS"),
    ("glorfindel-quarantine-deny-imds", 111, "AzurePlatformIMDS"),
)
QUARANTINE_FORENSIC_RULE = "glorfindel-quarantine-forensic-in"


def _is_quarantine_nsg(nsg_id_or_name: str) -> bool:
    name = (nsg_id_or_name or "").rstrip("/").split("/")[-1].lower()
    return name.startswith(QUARANTINE_NSG_PREFIX)


def _same_id(a: str, b: str) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def _enum_text(value) -> str:
    """Lowercase text of an SDK field that may be a plain string or an enum.

    azure-mgmt-network 33 (the Docker image) returns enums: str(SecurityRuleAccess.ALLOW)
    is 'SecurityRuleAccess.ALLOW', so `str(access).lower() != "allow"` skipped EVERY rule
    — the precedence check saw no allow at all in the deployed product, while 30.x (the
    host venv, the tests) returns plain strings (validation run, 2026-10-06)."""
    return str(getattr(value, "value", value) or "").lower()


def _rule_covers_port(rule, port: int) -> bool:
    """Does this rule's destination port range include `port`? (`*`, `22`, `20-30`)"""
    ranges = [getattr(rule, "destination_port_range", None)]
    ranges += list(getattr(rule, "destination_port_ranges", None) or [])
    for pr in ranges:
        pr = str(pr or "").strip()
        if not pr:
            continue
        if pr in ("*", "any", "Any"):
            return True
        try:
            if "-" in pr:
                lo, hi = (int(x) for x in pr.split("-", 1))
                if lo <= port <= hi:
                    return True
            elif int(pr) == port:
                return True
        except ValueError:
            return True       # unreadable range: assume it covers (fail closed)
    return False


def _shadowing_rules(
    rules, priority: int, *, inbound_src: list[str] | None, inbound_dst: list[str] | None,
    outbound_src: list[str] | None, outbound_dst: list[str] | None, port: int | None = None,
) -> list[dict]:
    """Customer ALLOW rules evaluated before a Glorfindel deny placed at `priority`.

    NSG rules run by ascending priority and the first match wins: an allow at a lower
    number than our deny lets its traffic through, deny or not. Found on the Celebrimbor
    bench (2026-10-05): `allow-ssh` (Inbound, *, port 22) sits at priority 100, so every
    IP-scoped isolation (deny at 101+) left SSH open, and every IP block (200+) let an
    SSH brute force continue — while the presence-only verification said verified=True.

    For each direction, a rule shadows the deny when its source AND destination cover
    the deny's source and destination (None = any).

    `port` (a block whose threat port is known, e.g. 22 for an SSH brute force): every
    shadowing allow is still reported, but `threat_port_open` says whether it lets the
    THREAT through (an inbound allow covering that port) or only leaves other ports
    reachable. Without it, a web server's `allow-https` declared every SSH block
    bypassed — the alert operators learn to ignore. Isolation passes no port: any
    allow before the deny defeats it.
    """
    found: list[dict] = []
    for r in rules or []:
        name = getattr(r, "name", "") or ""
        prio = getattr(r, "priority", None)
        if name.startswith("glorfindel-") or not isinstance(prio, int) or prio >= priority:
            continue
        if _enum_text(getattr(r, "access", "")) != "allow":
            continue
        direction = _enum_text(getattr(r, "direction", ""))
        if direction == "inbound":
            src, dst = inbound_src, inbound_dst
        elif direction == "outbound":
            src, dst = outbound_src, outbound_dst
        else:
            continue
        if _side_covers(r, "source", src) and _side_covers(r, "destination", dst):
            found.append({
                "rule": name, "priority": prio, "direction": _enum_text(getattr(r, "direction", "")),
                "ports": getattr(r, "destination_port_range", None)
                or ",".join(getattr(r, "destination_port_ranges", None) or []) or "*",
                "threat_port_open": (
                    port is None or (direction == "inbound" and _rule_covers_port(r, port))),
            })
    return found


def _report_block_shadowing(out: dict, ip: str, shadowed: list[dict]) -> None:
    """Add a block's precedence findings to its outcome: `bypass` when an allow lets
    the threat through, `exposure` when other ports only stay reachable."""
    if not shadowed:
        return
    out["shadowed_by"] = shadowed
    bypass = [x for x in shadowed if x.get("threat_port_open", True)]
    exposure = [x for x in shadowed if not x.get("threat_port_open", True)]
    if bypass:
        out["bypass"] = (f"Blocage de {ip} contourné : " + _describe_shadowing(bypass)
                         + " passe avant le deny de Glorfindel.")
    if exposure:
        out["exposure"] = (f"Port de la menace bloqué ; {ip} atteint encore d'autres ports : "
                           + _describe_shadowing(exposure) + ".")


def _describe_shadowing(found: list[dict]) -> str:
    return ", ".join(
        f"'{f['rule']}' (priorité {f['priority']}, {f['direction']}, ports {f['ports']})" for f in found)


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
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
        threat_port: int | None = None,
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
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        quarantine_on, _ = self._quarantine_settings()

        placements: list[dict] = []
        assigned: dict[str, set] = {}  # nsg_key → priorities used during THIS call
        for t in targets:
            # L4: a NIC with no NSG of its own gets Glorfindel's quarantine NSG — nothing
            # of the customer's touched, nothing evaluated before its deny, untouched by a
            # `terraform apply` (the NIC resource keeps an NSG it doesn't manage). Falls
            # back to the subnet NSG's rules if attaching is refused (Azure Policy, IAM).
            quarantine_error = ""
            if t.get("quarantine") or (quarantine_on and "nic_has_nsg" in t):
                try:
                    placements.append(self._quarantine_placement(t, rg))
                    continue
                except Exception as exc:
                    if not t.get("nsg_name"):
                        failed = {"nic_id": t["nic_id"], "applied": [], "bumped": []}
                        partial = self._record_partial_isolation(
                            vm_name, resource_id, placements, failed, exc, total=len(targets))
                        if partial is None:
                            raise
                        raise partial from exc
                    quarantine_error = _first_line(exc)[:_ERR_MAX]
            if not t.get("nsg_name"):
                raise RuntimeError(
                    f"NIC {t['nic_short']} has no NSG and the quarantine NSG is disabled — "
                    "cannot isolate (enable `isolation.quarantine_nsg` or add an NSG)")
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
            if quarantine_error:
                placement["quarantine_error"] = quarantine_error
            try:
                # Never move a customer rule (a `terraform apply` puts it back, or fails
                # on the priority we took): the deny takes the first free priority. An
                # ALLOW evaluated before it would let its traffic through — then use the
                # NIC's other NSG if it has one: traffic must pass both, a deny in either
                # holds. Plan both before writing anything.
                own = (in_name, out_name)
                plan = self._plan_isolation(t, nsg_rg, nsg_name, _ip_scoped(t), assigned, own)
                alt = t.get("alt_nsg")
                if plan["shadowed"] and alt:
                    alt_plan = self._plan_isolation(t, alt["nsg_rg"], alt["nsg_name"], True, assigned, own)
                    if not alt_plan["shadowed"]:
                        placement.update({
                            "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                            "scope": "subnet", "shared_nsg": False,
                            "moved_from": {"nsg": nsg_key, "because": plan["shadowed"]},
                        })
                        nsg_rg, nsg_name, nsg_key = alt["nsg_rg"], alt["nsg_name"], alt_plan["nsg_key"]
                        plan = alt_plan
                priority = plan["priority"]
                placement["priority"] = priority
                ips = t["private_ips"]
                if plan["ip_scoped"]:
                    if not ips:
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope isolation "
                            "on its shared NSG"
                        )
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst="*")
                    placement["applied"].append(out_name)
                else:
                    # NSG governing this VM only: any/any affects nobody else.
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dst="*")
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst="*")
                    placement["applied"].append(out_name)
                # Still recorded when no alternative was clean: verify escalates on it.
                placement["shadowed_by"] = plan["shadowed"]
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
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"],
                 **({"moved_from": p["moved_from"]["nsg"]} if p.get("moved_from") else {})}
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
        if any(p.get("kind") == "quarantine" for p in placements):
            out["note"] = (
                "Glorfindel's quarantine NSG on the NIC(s) for the time of the isolation — "
                "the customer's own NSG (if any) is left untouched and goes back on release."
            )
        refused = [p["quarantine_error"] for p in placements if p.get("quarantine_error")]
        if refused:
            out["quarantine_refused"] = refused
        shadowed = [s for p in placements for s in p.get("shadowed_by", [])]
        if shadowed:
            out["shadowed_by"] = shadowed
            out["bypass"] = (
                "Isolation contournée : " + _describe_shadowing(shadowed)
                + " passe avant le deny de Glorfindel."
            )
        # The rules only stop NEW connections: measured 2026-10-05, an attacker's SSH
        # session (17 min), an idle one (11 min) and an outbound download all survived
        # the isolation. Cut them from inside, now that nothing can reconnect.
        out["drain"] = self.drain_connections(resource_id)
        # Kept with the isolation: `list` and the War Room must show that sessions were
        # left open, not only the response of the call (validation run, 2026-10-05).
        try:
            _, _vm = _parse_vm_resource_id(resource_id)
            state = _load_isolation_state(_vm)
            if state is not None:
                _save_isolation_state(_vm, {**state, "drain": out["drain"]})
        except Exception:
            pass
        return out

    # Connections a drain must never cut: loopback (local services) and the Azure
    # platform addresses the VM agent, Run Command and IMDS depend on.
    _DRAIN_FILTER = (
        "( not dst 127.0.0.0/8 and not dst [::1] "
        "and not dst 168.63.129.16 and not dst 169.254.169.254 )"
    )

    # What the JIT isolation, the drain and the fallback rules need — checked without
    # writing anything, through Azure's permissions API (L6 readiness).
    REQUIRED_ACTIONS = (
        ("isolate_vm", "Microsoft.Network/networkInterfaces/write"),
        ("isolate_vm", "Microsoft.Network/virtualNetworks/subnets/join/action"),
        ("isolate_vm", "Microsoft.Network/networkSecurityGroups/write"),
        ("isolate_vm", "Microsoft.Network/networkSecurityGroups/join/action"),
        ("isolate_vm", "Microsoft.Compute/virtualMachines/runCommand/action"),
        ("release_isolation", "Microsoft.Network/networkSecurityGroups/join/action"),
        ("block_suspicious_ip", "Microsoft.Network/networkSecurityGroups/securityRules/write"),
        ("block_suspicious_ip", "Microsoft.Network/networkSecurityGroups/securityRules/delete"),
    )

    def _permission_scopes(self, rg: str, vm_name: str) -> dict[str, tuple[str, set]]:
        """Resource group → the (used_by, action) pairs needed THERE (third review, T12).
        Only the VM's and the quarantine's groups were read: a NIC, a VNet or the
        customer's NSG in another group (a central network group is common) failed the
        swap (LinkedAuthorizationFailed on subnets/join) or the release, while the
        readiness said "ready"."""
        scopes: dict[str, tuple[str, set]] = {}

        def need(group: str, used_by: str, action: str) -> None:
            if group:
                scopes.setdefault(group.lower(), (group, set()))[1].add((used_by, action))

        _, q_rg = self._quarantine_settings()
        need(rg, "isolate_vm", "Microsoft.Compute/virtualMachines/runCommand/action")
        for action in ("Microsoft.Network/networkSecurityGroups/write",
                       "Microsoft.Network/networkSecurityGroups/join/action"):
            need(q_rg or rg, "isolate_vm", action)
        for t in self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True):
            nic_rg, nic_name = _parse_nic_resource_id(t["nic_id"])
            need(nic_rg, "isolate_vm", "Microsoft.Network/networkInterfaces/write")
            try:
                nic = self._network.network_interfaces.get(nic_rg, nic_name)
                for ipc in getattr(nic, "ip_configurations", None) or []:
                    sub_id = getattr(getattr(ipc, "subnet", None), "id", "") or ""
                    if "/resourcegroups/" in sub_id.lower():
                        need(_parse_vm_resource_id(sub_id)[0], "isolate_vm",
                             "Microsoft.Network/virtualNetworks/subnets/join/action")
            except Exception:
                pass
            if t.get("own_nsg_id"):        # release puts the customer's NSG back
                need(_parse_nsg_resource_id(t["own_nsg_id"])[0], "release_isolation",
                     "Microsoft.Network/networkSecurityGroups/join/action")
            for v in self._nic_nsg_views(t):
                for action in ("Microsoft.Network/networkSecurityGroups/securityRules/write",
                               "Microsoft.Network/networkSecurityGroups/securityRules/delete"):
                    need(v["nsg_rg"], "block_suspicious_ip", action)
        return scopes

    def check_permissions(self, resource_id: str) -> dict:
        """Which of REQUIRED_ACTIONS Glorfindel's identity holds, each on the resource
        group where it applies (NICs, VNet, quarantine NSG, customer NSG, rule NSGs,
        VM) — read from `Microsoft.Authorization/permissions` (all pages), nothing
        written. Deny assignments, locks and PIM are not evaluated (the API doesn't
        return them)."""
        if self.dry_run:
            return {"ok": True, "missing": [], "dry_run": True}
        import fnmatch
        import requests
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            scopes = self._permission_scopes(rg, vm_name)
            token = self._credential.get_token("https://management.azure.com/.default").token
            missing: list[dict] = []
            for scope_rg, needed in scopes.values():
                url = (f"https://management.azure.com/subscriptions/{self._subscription_id}"
                       f"/resourceGroups/{scope_rg}/providers/Microsoft.Authorization/permissions")
                params: dict | None = {"api-version": "2022-04-01"}
                perms: list = []
                while url:                     # nextLink: a long role list spans pages
                    r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                                     params=params, timeout=20)
                    if not r.ok:
                        return {"ok": False, "error": f"{scope_rg}: HTTP {r.status_code} {r.text[:200]}"}
                    body = r.json()
                    perms += body.get("value") or []
                    url, params = body.get("nextLink"), None

                def allowed(action: str) -> bool:
                    a = action.lower()
                    return any(
                        any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("actions") or []))
                        and not any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("notActions") or []))
                        for p in perms
                    )
                for used_by, action in sorted(needed):
                    if not allowed(action):
                        missing.append({"scope": scope_rg, "action": action, "used_by": used_by})
            return {"ok": True, "missing": missing, "scopes": [g for g, _ in scopes.values()]}
        except Exception as e:
            return {"ok": False, "error": _first_line(e)[:_ERR_MAX]}

    def vm_os(self, resource_id: str) -> str:
        """"linux" / "windows" (lowercase os type of the OS disk), "" if unknown."""
        if self.dry_run:
            return ""
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        vm = self._compute.virtual_machines.get(rg, vm_name)
        return _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", ""))

    def recent_changes(self, resource_uri: str, minutes: int = 60) -> list[str]:
        """Who wrote this resource lately, from the Azure activity log (best effort, a
        few minutes behind). Explains an alert — never used to detect: Azure itself is
        re-read for that."""
        if self.dry_run:
            return []
        try:
            import requests
            from datetime import datetime, timedelta, timezone
            self._ensure_clients()
            since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
            token = self._credential.get_token("https://management.azure.com/.default").token
            url = (f"https://management.azure.com/subscriptions/{self._subscription_id}"
                   "/providers/Microsoft.Insights/eventtypes/management/values")
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20, params={
                "api-version": "2015-04-01",
                "$filter": f"eventTimestamp ge '{since}' and resourceUri eq '{resource_uri}'",
                "$select": "caller,operationName,eventTimestamp,status",
            })
            out = []
            # Glorfindel's own writes are not the answer to "who changed it".
            own = {os.environ.get(k, "").lower() for k in ("AZURE_CLIENT_ID", "GLORFINDEL_AZURE_CLIENT_ID")} - {""}
            for e in (r.json().get("value") or []) if r.ok else []:
                op = (e.get("operationName") or {}).get("localizedValue") or (e.get("operationName") or {}).get("value", "")
                st = (e.get("status") or {}).get("value", "")
                # One line per write: the activity log has Started/Accepted AND Succeeded.
                if st != "Succeeded" or str(e.get("caller", "")).lower() in own:
                    continue
                out.append(f'{str(e.get("eventTimestamp", ""))[11:19]} {e.get("caller", "?")} — {op}')
            return sorted(set(out))[-5:]
        except Exception:
            return []

    def drain_connections(self, resource_id: str) -> dict:
        """Kill the VM's established TCP connections through Run Command (`ss -K`).

        Run Command still works on an isolated VM (platform address, not filtered by
        NSGs) and `ss -K` cut every session in the bench test. Linux only: on Windows
        the outcome says the sessions were not cut. Never raises — the isolation rules
        are in place either way; the outcome tells whether open sessions survive.
        """
        if self.dry_run:
            return {"status": "dry_run"}
        try:
            from azure.mgmt.compute.models import RunCommandInput
            rg, vm_name = _parse_vm_resource_id(resource_id)
            vm = self._compute.virtual_machines.get(rg, vm_name)
            os_type = _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", "") or "")
            if "windows" in os_type.lower():
                return {"status": "unsupported",
                        "note": "Windows : les sessions déjà ouvertes ne sont pas coupées."}
            # The count must fail loudly: `ss … | wc -l` printed 0 when `ss` was missing
            # or refused -H — "nothing left" on an unknown.
            flt = self._DRAIN_FILTER
            for cidr in self._forensic_sources():     # investigation sessions survive
                flt = flt[:-1] + f"and not dst {cidr} )"
            script = [
                f"ss -K state established '{flt}' >/dev/null 2>&1",
                f"if out=$(ss -Htn state established '{flt}' 2>/dev/null); "
                f"then echo \"glorfindel-drain-remaining=$(printf '%s\\n' \"$out\" | grep -c .)\"; "
                f"else echo glorfindel-drain-remaining=error; fi",
            ]
            res = self._compute.virtual_machines.begin_run_command(
                rg, vm_name, RunCommandInput(command_id="RunShellScript", script=script),
            ).result(timeout=300)   # an unresponsive VM agent must not hold the watch worker
            text = " ".join(str(getattr(v, "message", "") or "") for v in (getattr(res, "value", None) or []))
            if "glorfindel-drain-remaining=error" in text:
                return {"status": "failed",
                        "error": "sessions restantes non comptées (`ss` absent ou en erreur)"}
            m = re.search(r"glorfindel-drain-remaining=(\d+)", text)
            if m is None:
                return {"status": "failed", "error": "sortie de Run Command illisible"}
            remaining = int(m.group(1))
            if remaining:
                return {"status": "partial", "remaining": remaining,
                        "error": f"{remaining} connexion(s) encore établie(s) après ss -K"}
            return {"status": "drained"}
        except Exception as e:
            return {"status": "failed", "error": _first_line(e)[:_ERR_MAX]}

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
            return f"{nsg_rg}/{nsg_name}/{rule_name}: {_first_line(e)[:_ERR_MAX]}"

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
                left.append({**info, "error": _first_line(e)[:_ERR_MAX]})
        return left

    def _plan_isolation(self, t: dict, nsg_rg: str, nsg_name: str, ip_scoped: bool,
                        assigned: dict, own: tuple = ()) -> dict:
        """Priority an isolation deny would take on this NSG, and the customer ALLOW
        rules that would be evaluated before it (nothing written). `own`: our rule
        names — a re-application keeps their priority instead of moving them."""
        nsg_key = f"{nsg_rg}/{nsg_name}"
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used = ({r.priority for r in existing if getattr(r, "name", "") not in own}
                | assigned.get(nsg_key, set()))
        priority = next(p for p in range(self.ISOLATION_PRIORITY, 4000) if p not in used)
        ips = t["private_ips"] or None
        shadowed = _shadowing_rules(existing, priority, inbound_src=None, inbound_dst=ips,
                                    outbound_src=ips, outbound_dst=None)
        return {"nsg_key": nsg_key, "priority": priority, "ip_scoped": ip_scoped,
                "shadowed": shadowed}

    def _quarantine_placement(self, t: dict, default_rg: str) -> dict:
        """Put the quarantine NSG on this NIC (JIT); the placement to record.

        A NIC with no NSG gets ours attached (L4). A NIC with its own NSG gets ours IN
        PLACE of it, for the time of the isolation: the customer's NSG and its rules are
        left untouched, and go back on release. Measured on the bench (2026-10-06,
        azurerm 4.81.0): `terraform plan` sees no change and `apply` reverts nothing —
        the NIC resource doesn't hold its NSG, the association only checks that the NIC
        has one. Only a forced replacement of the association, or a Bicep/ARM redeploy
        of the NIC, puts the customer's NSG back (L5 notices). The original is recorded
        in state and, before the swap, as a tag on our NSG — Azure keeps the answer even
        if the local state is lost."""
        q = self._ensure_quarantine_nsg(t.get("location"), default_rg)
        current = t.get("quarantine")
        if current and _same_id(current["nsg_id"], q["nsg_id"]):
            # Already in quarantine (a re-application): the state knows the original;
            # the tag is the fallback, and a tag that can't be read raises — an unknown
            # original must not be recorded as "none".
            original = _recorded_original(t["nic_id"])
            if original is _UNKNOWN:
                original = self._original_from_tags(q, t["nic_id"])
        else:
            original = t.get("own_nsg_id")
            if original:
                self._record_original(q, t["nic_id"], original)
            self._set_nic_nsg(t["nic_id"], q["nsg_id"], expect=original or "")
        return {
            "nic_id": t["nic_id"], "kind": "quarantine", "scope": "quarantine",
            "nsg_rg": q["nsg_rg"], "nsg_name": q["nsg_name"], "nsg_id": q["nsg_id"],
            "original_nsg_id": original,
            "shared_nsg": False, "ips": t["private_ips"], "priority": 100,
            "rule_in": QUARANTINE_RULE_IN, "rule_out": QUARANTINE_RULE_OUT,
            "bumped": [], "applied": ["nic-attach"], "shadowed_by": [],
        }

    @staticmethod
    def _orig_tag(nic_id: str) -> str:
        import hashlib
        return "glorfindel-orig-" + hashlib.sha1(nic_id.rstrip("/").lower().encode()).hexdigest()[:12]

    def _quarantine_tags(self, q: dict) -> dict:
        nsg = self._network.network_security_groups.get(q["nsg_rg"], q["nsg_name"])
        return dict(getattr(nsg, "tags", None) or {})

    def _write_quarantine_tags(self, q: dict, tags: dict) -> None:
        from azure.mgmt.network.models import TagsObject
        self._network.network_security_groups.update_tags(q["nsg_rg"], q["nsg_name"], TagsObject(tags=tags))

    def _record_original(self, q: dict, nic_id: str, original_id: str) -> None:
        """NIC → its own NSG, kept as a tag on our quarantine NSG (not on the NIC: a
        `terraform apply` rewrites the NIC's tags — measured).

        The quarantine NSG is shared by every isolation in the region: the tags are
        rewritten whole, so two isolations at once (N VMs on one rule, the War Room next
        to the watch) erased each other's tag. Read-modify-write under a lock, then read
        back: a tag that didn't land raises, and the NIC is not swapped."""
        key = self._orig_tag(nic_id)
        with _quarantine_lock(q["nsg_id"]):
            tags = self._quarantine_tags(q)
            tags[key] = original_id
            self._write_quarantine_tags(q, tags)
            if self._quarantine_tags(q).get(key) != original_id:
                raise RuntimeError(f"original NSG of {nic_id.rsplit('/', 1)[-1]} not recorded "
                                   "on the quarantine NSG (tag overwritten)")

    def _original_from_tags(self, q: dict, nic_id: str) -> str | None:
        """The NIC's original NSG from our tag; None if the NIC had none. A read error
        RAISES: it used to read as "no original", and the release then left the NIC
        with no NSG at all while verify_release said verified."""
        return self._quarantine_tags(q).get(self._orig_tag(nic_id)) or None

    def _forget_original(self, q: dict, nic_id: str) -> None:
        try:
            with _quarantine_lock(q["nsg_id"]):
                tags = self._quarantine_tags(q)
                if tags.pop(self._orig_tag(nic_id), None) is not None:
                    self._write_quarantine_tags(q, tags)
        except Exception:
            pass     # a stale tag is harmless: it is only read for a NIC carrying our NSG

    def _nic_nsg_id(self, nic_id: str) -> str | None:
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        return getattr(getattr(nic, "network_security_group", None), "id", None)

    def _nic_gone(self, nic_id: str) -> bool:
        """True only when the NIC itself no longer exists (deleted with its VM)."""
        try:
            self._nic_nsg_id(nic_id)
            return False
        except Exception as e:
            return _is_not_found(e)

    def _unquarantine(self, nic_id: str, q: dict, original: str | None) -> None:
        """Put the NIC's own NSG back (or none), only if it still carries OURS, then read
        the NIC back: release is done when the ORIGINAL is on it, not when ours is gone
        (verify_release only checks the latter)."""
        if self._set_nic_nsg(nic_id, original, expect=q["nsg_id"]):
            now = self._nic_nsg_id(nic_id)
            if not _same_id(now or "", original or ""):
                raise RuntimeError(
                    f"NSG d'origine non remis sur {nic_id.rsplit('/', 1)[-1]} : la carte porte "
                    f"{(now or 'aucun NSG').rsplit('/', 1)[-1]} au lieu de "
                    f"{(original or 'aucun NSG').rsplit('/', 1)[-1]}")
        self._forget_original(q, nic_id)

    @staticmethod
    def _nic_nsg_views(t: dict) -> list[dict]:
        """The NIC as seen from each NSG that governs it: its own (or its subnet's when it
        has none), plus its subnet's NSG when it has both. An isolation or a block may
        sit on either — the second one when the first had an ALLOW before our deny."""
        views = [t] if t.get("nsg_name") else []
        alt = t.get("alt_nsg")
        if alt:
            views.append({**t, "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                          "scope": "subnet", "shared_nsg": False, "ip_scoped": True})
        return views

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
        if state:
            # The intent is recorded before Azure is touched: a release cut off midway
            # (War Room timeout, crash) leaves NICs half released — the reassertion
            # must not read that as "removed outside Glorfindel" and isolate again.
            from datetime import datetime, timezone
            _save_isolation_state(vm_name, {**state, "releasing_at": datetime.now(timezone.utc).isoformat()})

        failed: list[str] = []
        remaining: list[dict] = []
        if state.get("placements"):
            # Multi-NIC: undo each placement on its own NSG. Delete our denies first —
            # a customer rule can only go back to priority 100 once ours is gone.
            for p in state["placements"]:
                if p.get("kind") == "quarantine":
                    # Put the NIC's own NSG back (or none) — only if it still carries
                    # OURS; our NSG keeps its deny rules for the next VM.
                    # The state's original wins (None = the NIC had no NSG); the tag
                    # is read only when the state doesn't say. Unknown original, or
                    # an original that didn't come back → the NIC stays in quarantine.
                    try:
                        original = (p["original_nsg_id"] if "original_nsg_id" in p
                                    else self._original_from_tags(p, p["nic_id"]))
                        self._unquarantine(p["nic_id"], p, original)
                    except Exception as exc:
                        if not self._nic_gone(p["nic_id"]):
                            failed.append(f'{p["nic_id"].split("/")[-1]}: NSG de quarantaine '
                                          f"non détaché : {_first_line(exc)[:_ERR_MAX]}")
                            remaining.append(p)
                    continue
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
            for t0 in self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True):
                if t0.get("quarantine"):
                    q = t0["quarantine"]
                    try:
                        self._unquarantine(t0["nic_id"], q, self._original_from_tags(q, t0["nic_id"]))
                    except Exception as exc:
                        failed.append(f'{t0["nic_short"]}: NSG de quarantaine non retiré : '
                                      f"{_first_line(exc)[:_ERR_MAX]}")
                for t in self._nic_nsg_views(t0):
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
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
        threat_port: int | None = None,
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
        threat_port: the port the attack targets, when known (22 for SSH brute force).
          An ALLOW before the deny only defeats the block if it opens that port; other
          ports left reachable are reported as exposure, not as a bypass.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "block_ip", "ip": ip, "scope": scope}
        if not ip:
            raise ValueError("block_suspicious_ip: no IP address provided")

        self._guard_write("block_suspicious_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)

        if scope == "subnet":
            return self._block_ip_subnet(ip, resource_id, rg, vm_name, replace, threat_port)
        return self._block_ip_vm(ip, resource_id, rg, vm_name, threat_port)

    def _plan_block(self, t: dict, ip: str, nsg_rg: str, nsg_name: str, ip_scoped: bool,
                    assigned: dict, threat_port: int | None) -> dict:
        """Priority a block deny would take on this NSG, and the allows before it."""
        nsg_key = f"{nsg_rg}/{nsg_name}"
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used = {r.priority for r in existing} | assigned.get(nsg_key, set())
        priority = next(p for p in range(200, 4000, 10) if p not in used)
        vm_ips = t["private_ips"] or None
        shadowed = _shadowing_rules(existing, priority, inbound_src=[ip], inbound_dst=vm_ips,
                                    outbound_src=vm_ips, outbound_dst=[ip], port=threat_port)
        return {"nsg_key": nsg_key, "priority": priority, "ip_scoped": ip_scoped,
                "shadowed": shadowed,
                "bypassed": [x for x in shadowed if x.get("threat_port_open", True)]}

    def _block_ip_vm(self, ip: str, resource_id: str, rg: str, vm_name: str,
                     threat_port: int | None = None) -> dict:
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
                # Same placement rule as the isolation: no customer rule moved; when an
                # allow before the deny lets the THREAT through on this NSG, the NIC's
                # other NSG (its subnet's) holds the deny instead.
                plan = self._plan_block(t, ip, nsg_rg, nsg_name, _ip_scoped(t), assigned, threat_port)
                alt = t.get("alt_nsg")
                if plan["bypassed"] and alt:
                    alt_plan = self._plan_block(t, ip, alt["nsg_rg"], alt["nsg_name"], True,
                                                assigned, threat_port)
                    if not alt_plan["bypassed"]:
                        placement.update({
                            "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                            "scope": "subnet", "shared_nsg": False,
                            "moved_from": {"nsg": nsg_key, "because": plan["bypassed"]},
                        })
                        nsg_rg, nsg_name, nsg_key = alt["nsg_rg"], alt["nsg_name"], alt_plan["nsg_key"]
                        plan = alt_plan
                priority = plan["priority"]
                if plan["ip_scoped"]:
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
                placement["shadowed_by"] = plan["shadowed"]
            except Exception as exc:
                kept = placements + ([placement] if applied else [])
                if not kept:
                    raise
                first = kept[0]
                _save_block_state(
                    vm_name, ip, resource_id,
                    nsg=f'{first["nsg_rg"]}/{first["nsg_name"]}', nsg_scope=first["scope"],
                    rule=first["rule"], scoped=True, placements=kept, partial=True,
                    threat_port=threat_port,
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
            rule=first["rule"], scoped=True, placements=placements, threat_port=threat_port,
        )
        out = {
            "status": "blocked", "ip": ip, "scoped": True, "resource_id": resource_id,
            "nics_covered": len(placements),
            "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
            "nsg_scope": first["scope"], "rule": first["rule"],
            "placements": [
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"],
                 **({"moved_from": p["moved_from"]["nsg"]} if p.get("moved_from") else {})}
                for p in placements
            ],
        }
        if any(_ip_scoped(p) or p["shared_nsg"] for p in placements):
            out["note"] = (
                "shared NSG involved (subnet or several NICs) — block scoped to this VM's "
                "private IP(s) (attacker still reaches other VMs until they detect it)."
            )
        moved = [p for p in placements if p.get("moved_from")]
        if moved:
            out["note"] = (
                "deny placed on the subnet NSG, scoped to this VM's IP(s): on "
                + ", ".join(p["moved_from"]["nsg"] for p in moved)
                + " an allow is evaluated before it ("
                + _describe_shadowing([s for p in moved for s in p["moved_from"]["because"]])
                + ")."
            )
        _report_block_shadowing(out, ip, [s for p in placements for s in p.get("shadowed_by", [])])
        return out

    def _block_ip_subnet(
        self, ip: str, resource_id: str, rg: str, vm_name: str, replace: bool,
        threat_port: int | None = None,
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
            threat_port=threat_port,
        )
        # Same precedence report as the VM-scoped block (verify fails on it as well).
        shadowed = _shadowing_rules(
            existing, priority, inbound_src=[ip], inbound_dst=None,
            outbound_src=None, outbound_dst=[ip], port=threat_port)
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
        _report_block_shadowing(out, ip, shadowed)
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
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)

        # Isolation holds only if EVERY NIC carries a deny pair — a single uncovered NIC
        # is the multi-NIC gap (looks ISOLATED but traffic still flows on the other NIC).
        uncovered: list[str] = []
        unreadable: list[str] = []
        found: dict[str, tuple] = {}     # nic_id → (nsg_rg, nsg_name, inbound deny name)
        for t0 in targets:
            unknown = False
            # Glorfindel's quarantine NSG on the NIC (L4): holds if its two denies are there.
            q = t0.get("quarantine")
            if q:
                st = self._rules_state(q["nsg_rg"], q["nsg_name"], [QUARANTINE_RULE_IN, QUARANTINE_RULE_OUT])
                if st == "present":
                    found[t0["nic_id"]] = (q["nsg_rg"], q["nsg_name"], QUARANTINE_RULE_IN)
                    continue
                unknown = st == "unknown"
            # The deny may sit on the NIC's own NSG or on its subnet's (placed there when
            # an ALLOW preceded it on the first): either one holds.
            for t in self._nic_nsg_views(t0):
                base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
                # Legacy fallback: a VM isolated before the multi-NIC upgrade used the
                # old fixed/VM-suffixed names on the primary NIC's NSG.
                legacy_in, legacy_out = self._isolation_rule_names(vm_name, t["scope"])
                hit = None
                for pair in ([base, f"{base}-out"], [legacy_in, legacy_out]):
                    st = self._rules_state(t["nsg_rg"], t["nsg_name"], pair)
                    if st == "present":
                        hit = pair[0]
                        break
                    unknown = unknown or st == "unknown"
                if hit:
                    found[t0["nic_id"]] = (t["nsg_rg"], t["nsg_name"], hit)
                    break
            else:
                # Not found: missing for sure, or only unreadable (no claim either way).
                (unreadable if unknown else uncovered).append(t0["nic_short"])

        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered,
                    **({"unreadable_nics": unreadable} if unreadable else {})}
        if unreadable:
            return {"verified": None, "method": "nsg_check", "unreadable_nics": unreadable,
                    "error": "isolation non vérifiable : règles illisibles sur "
                             + ", ".join(unreadable)}

        # Present is not effective: an ALLOW evaluated before the deny still passes its
        # traffic (the bench's allow-ssh at 100 kept SSH open on every "isolated" VM).
        # Every NSG is checked now — a deny no longer forces priority 100 by moving the
        # customer's rules. The check uses the name actually found (a legacy-named
        # isolation used to pass it by finding nothing to compare).
        shadowed, unknown = self._precedence([
            (*found[t["nic_id"]],
             {"inbound_src": None, "inbound_dst": t["private_ips"] or None,
              "outbound_src": t["private_ips"] or None, "outbound_dst": None})
            for t in targets
        ])
        if shadowed:
            return {
                "verified": False, "method": "nsg_check", "shadowed_by": shadowed,
                "error": "isolation contournée : " + _describe_shadowing(shadowed)
                         + " passe avant le deny de Glorfindel",
            }
        if unknown:
            return self._precedence_unknown(unknown, nics_covered=len(targets))
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    def _list_rules(self, cache: dict, nsg_rg: str, nsg_name: str) -> list | None:
        """Security rules of an NSG, listed once per verification. None if unreadable:
        an empty list would read as "nothing precedes our deny" (fail open)."""
        key = (nsg_rg, nsg_name)
        if key not in cache:
            try:
                cache[key] = list(self._network.security_rules.list(nsg_rg, nsg_name))
            except Exception:
                cache[key] = None
        return cache[key]

    def _shadowed_deny(
        self, cache: dict, nsg_rg: str, nsg_name: str, rule_name: str, **scope,
    ) -> list[dict] | None:
        """ALLOW rules evaluated before OUR deny `rule_name` on this NSG (see
        _shadowing_rules). None when that can't be established: the NSG's rules are
        unreadable, or our rule (present per `get`) is missing from the listing."""
        rules = self._list_rules(cache, nsg_rg, nsg_name)
        if rules is None:
            return None
        ours = next((r for r in rules if getattr(r, "name", "") == rule_name), None)
        prio = getattr(ours, "priority", None)
        if not isinstance(prio, int):
            return None
        found = _shadowing_rules(rules, prio, **scope)
        return [{**f, "nsg": f"{nsg_rg}/{nsg_name}"} for f in found]

    def _precedence(self, checks: list[tuple]) -> tuple[list[dict], list[str]]:
        """Run _shadowed_deny over (nsg_rg, nsg_name, rule_name, scope) checks.
        Returns (shadowing allows, NSGs whose precedence could not be established)."""
        cache: dict = {}
        shadowed: list[dict] = []
        unknown: list[str] = []
        for nsg_rg, nsg_name, rule_name, scope in checks:
            found = self._shadowed_deny(cache, nsg_rg, nsg_name, rule_name, **scope)
            if found is None:
                if f"{nsg_rg}/{nsg_name}" not in unknown:
                    unknown.append(f"{nsg_rg}/{nsg_name}")
            else:
                shadowed += found
        return shadowed, unknown

    @staticmethod
    def _precedence_unknown(unknown: list[str], **extra) -> dict:
        """Rules present but their precedence unreadable: no claim either way."""
        return {
            "verified": None, "method": "nsg_check", "precedence_unknown": unknown, **extra,
            "error": "préséance non vérifiable (règles illisibles sur "
                     + ", ".join(unknown) + ") : les règles sont posées, rien ne garantit "
                     "qu'aucune allow ne passe avant",
        }

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
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        still += [f'{t0["nic_short"]}:{t0["quarantine"]["nsg_name"]} (NSG de quarantaine attaché)'
                  for t0 in targets if t0.get("quarantine")]
        for t in (v for t0 in targets for v in self._nic_nsg_views(t0)):
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
        return self._rules_state(nsg_rg, nsg_name, names) == "present"

    def _rules_state(self, nsg_rg: str, nsg_name: str, names: list[str]) -> str:
        """'present' (all there) | 'absent' (one is definitely gone) | 'unknown' (a read
        failed). A read error used to count as "missing": the reassertion then put back
        an isolation that was still in place, and alerted that it had been removed."""
        states = [self._rule_state(nsg_rg, nsg_name, n) for n in names]
        if "absent" in states:
            return "absent"
        return "unknown" if "unknown" in states else "present"

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

        # Before the disks are swapped: the restored disk would otherwise REPLAY the last
        # Run Command at boot (real run, 2026-10-05: ransomware_sim.sh re-encrypted the
        # restored data). An attacker who used Run Command (T1651) gets the same replay.
        neutralize = self._neutralize_run_command(rg, vm_name, vm)

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
                **neutralize,
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
            **neutralize,
        }

    def _neutralize_run_command(self, rg: str, vm_name: str, vm) -> dict:
        """Make a harmless command the VM's last Run Command.

        The guest agent of a restored disk replays the Run Command whose sequence number
        it has not seen yet: the last one in the VM model, i.e. the attacker's (or, on
        the bench, Annatar's attack script). Running a no-op first makes the replay
        harmless. Works on an isolated VM (Run Command goes through the platform
        address 168.63.129.16, which NSGs don't filter — measured 2026-10-05). Needs a
        running VM; on failure the restore still proceeds (recovery first) and the
        result says so, which holds the autonomous release.
        """
        from azure.mgmt.compute.models import RunCommandInput
        os_type = _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", "") or "")
        if "windows" in os_type.lower():
            cmd = RunCommandInput(command_id="RunPowerShellScript",
                                  script=["Write-Output 'glorfindel: run command neutralized'"])
        else:
            cmd = RunCommandInput(command_id="RunShellScript",
                                  script=["echo 'glorfindel: run command neutralized'"])
        try:
            poller = self._compute.virtual_machines.begin_run_command(rg, vm_name, cmd)
            poller.result(timeout=600)
            # result(timeout) returns at the deadline without raising: "neutralized"
            # must mean the harmless command actually finished (third review, T13).
            if not poller.done():
                raise TimeoutError("la commande inoffensive n'a pas terminé en 600 s")
            others = self._replayable_scripts(rg, vm_name)
            if others:
                # Run Command v1 is neutralized, but these replay the same way on a
                # restored disk and Glorfindel can't vouch for them: hold the release.
                return {"run_command_neutralized": False, "replay_vectors": others,
                        "run_command_error": "autres scripts rejouables sur la VM : " + ", ".join(others)}
            return {"run_command_neutralized": True}
        except Exception as e:
            _console.print(
                f"  [yellow]Run Command non neutralisée ({_first_line(e)[:_ERR_MAX]}) — le "
                "disque restauré peut rejouer la dernière commande au démarrage.[/yellow]")
            return {"run_command_neutralized": False,
                    "run_command_error": _first_line(e)[:_ERR_MAX]}

    _SCRIPT_EXTENSIONS = {("microsoft.azure.extensions", "customscript"),
                          ("microsoft.compute", "customscriptextension"),
                          ("microsoft.ostcextensions", "customscriptforlinux")}

    def _replayable_scripts(self, rg: str, vm_name: str) -> list[str]:
        """Script-running extensions (CustomScript) and managed Run Commands (v2,
        `runCommands` resources) on the VM: like Run Command v1, a restored disk can run
        them again at boot. Unreadable → reported as such (no success on an unknown)."""
        found: list[str] = []
        try:
            for ext in self._compute.virtual_machine_extensions.list(rg, vm_name).value or []:
                # azure-mgmt-compute 38 nests publisher/type under `properties` (the
                # top-level `type` is the ARM resource type); older SDKs flattened them
                # as publisher / type_properties_type — read whichever is there.
                d = ext.as_dict() if hasattr(ext, "as_dict") else {}
                props = d.get("properties") or {}
                key = (str(props.get("publisher") or d.get("publisher") or getattr(ext, "publisher", "") or "").lower(),
                       str(props.get("type") or d.get("type_properties_type")
                           or getattr(ext, "type_properties_type", "") or "").lower())
                if key in self._SCRIPT_EXTENSIONS:
                    found.append(f"extension {ext.name}")
        except Exception as e:
            found.append(f"extensions illisibles ({_first_line(e)[:120]})")
        try:
            for rc in self._compute.virtual_machine_run_commands.list_by_virtual_machine(rg, vm_name):
                found.append(f"run command managé {rc.name}")
        except Exception as e:
            found.append(f"run commands managés illisibles ({_first_line(e)[:120]})")
        return found

    def sweep_vm_rules(self, resource_id: str, dry_run: bool = False) -> dict:
        """Azure as the source of truth: remove every glorfindel-* rule that belongs to
        THIS VM on the NSGs of its NICs, with or without local state.

        Ownership comes from the deterministic rule names: the per-(VM, NIC) isolation
        and block names (readable or hashed form) and the legacy VM-suffixed ones; the
        legacy fixed isolation names only on an NSG governing this VM alone. The IP
        segment of a block name anchors the match, so `web` never matches `app-web`.
        Kept: perimeter (subnet-wide) blocks — an operator decision covering every VM —
        and every non-glorfindel rule. Customer rules bumped by an isolation can't be
        put back without state: reported, not guessed.
        """
        if not dry_run:
            self._guard_write("reset")
        self._ensure_clients()
        import hashlib
        import re
        rg, vm_name = _parse_vm_resource_id(resource_id)
        block_re = re.compile(r"^glorfindel-block-\d{1,3}(?:-\d{1,3}){3}(?:-\d{1,2})?-(?P<rest>.+?)(?:-out)?$")
        to_delete: list[tuple[str, str, str]] = []
        kept: list[str] = []
        unreadable: list[str] = []
        seen: set = set()
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        quarantined = [t0 for t0 in targets if t0.get("quarantine")]
        for t in (v for t0 in targets for v in self._nic_nsg_views(t0)):
            nsg_key = (t["nsg_rg"], t["nsg_name"])
            h = hashlib.sha1(t["nic_id"].encode()).hexdigest()[:8]
            owned_rest = {vm_name, f"{vm_name}-{t['nic_short']}", f"{vm_name[:40]}-{h}"}
            iso_names = set(self._isolation_names_for_target(vm_name, t))
            rules = self._list_rules({}, *nsg_key)
            if rules is None:
                # Unreadable: nothing found is not nothing there — keep the local state.
                unreadable.append(f'{t["nsg_rg"]}/{t["nsg_name"]}: règles illisibles')
                continue
            for r in rules:
                name = getattr(r, "name", "") or ""
                if not name.startswith("glorfindel-") or (nsg_key, name) in seen:
                    continue
                seen.add((nsg_key, name))
                m = block_re.match(name)
                if name in iso_names or (m and m.group("rest") in owned_rest):
                    to_delete.append((t["nsg_rg"], t["nsg_name"], name))
                elif m is None and name.startswith("glorfindel-block-"):
                    kept.append(f'{t["nsg_rg"]}/{t["nsg_name"]}/{name}')   # perimeter block
        deleted, failed = [], list(unreadable)
        for t0 in quarantined:
            q = t0["quarantine"]
            original = self._original_from_tags(q, t0["nic_id"])
            label = (f'{t0["nic_short"]}: retirer {q["nsg_name"]}'
                     + (f' (remettre {original.rstrip("/").split("/")[-1]})' if original else ""))
            if dry_run:
                deleted.append(label)
                continue
            try:
                self._unquarantine(t0["nic_id"], q, original)
                deleted.append(label)
            except Exception as exc:
                failed.append(f"{label} : {_first_line(exc)[:_ERR_MAX]}")
        for nsg_rg, nsg_name, name in to_delete:
            if dry_run:
                deleted.append(f"{nsg_rg}/{nsg_name}/{name}")
                continue
            err = self._delete_rule(nsg_rg, nsg_name, name)
            (failed if err else deleted).append(err or f"{nsg_rg}/{nsg_name}/{name}")
        if not dry_run and not failed:
            _clear_isolation_state(vm_name)
            for entry in _load_block_entries(vm_name):
                _clear_block_state(vm_name, entry.get("ip", ""))
        return {
            "status": "dry_run" if dry_run else ("swept_partial" if failed else "swept"),
            "deleted": deleted, "failed": failed, "kept_perimeter": kept,
            "note": "Règles client décalées par une isolation : non restaurées sans état local.",
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
            states = {
                name: self._rule_state(p["nsg_rg"], p["nsg_name"], name)
                for p in entry["placements"]
                for name in (p["rule"], f'{p["rule"]}-out')
            }
            missing = [n for n, st in states.items() if st == "absent"]
            if missing:
                return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                        "error": f"rules missing: {', '.join(missing)}"}
            unread = [n for n, st in states.items() if st == "unknown"]
            if unread:
                return {"verified": None, "method": "nsg_check", "unreadable_rules": unread,
                        "error": "blocage non vérifiable : règles illisibles (" + ", ".join(unread) + ")"}
            port = entry.get("threat_port")
            shadowed, unknown = self._precedence([
                (p["nsg_rg"], p["nsg_name"], p["rule"],
                 {"inbound_src": [ip], "inbound_dst": p.get("ips") or None,
                  "outbound_src": p.get("ips") or None, "outbound_dst": [ip], "port": port})
                for p in entry["placements"]
            ])
            if self._threat_open(shadowed):
                return self._block_bypassed(ip, shadowed)
            if unknown:
                return self._precedence_unknown(unknown, nics_covered=len(entry["placements"]))
            # Threat port blocked; other ports the attacker still reaches are reported.
            return {"verified": True, "method": "nsg_check",
                    "nics_covered": len(entry["placements"]),
                    **({"exposure": shadowed} if shadowed else {})}

        # Perimeter (subnet) block, or legacy single-rule entry: check the recorded pair.
        if entry and entry.get("nsg") and entry.get("rule"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
            pair = [entry["rule"], f'{entry["rule"]}-out']
            states = {n: self._rule_state(nsg_rg, nsg_name, n) for n in pair}
            missing = [n for n, st in states.items() if st == "absent"]
            if not missing and any(st == "unknown" for st in states.values()):
                return {"verified": None, "method": "nsg_check",
                        "unreadable_rules": [n for n, st in states.items() if st == "unknown"],
                        "error": "blocage non vérifiable : règles illisibles"}
            if not missing:
                # A perimeter block has no destination scope: any VM behind the NSG.
                shadowed, unknown = self._precedence([
                    (nsg_rg, nsg_name, entry["rule"],
                     {"inbound_src": [ip], "inbound_dst": None, "outbound_src": None,
                      "outbound_dst": [ip], "port": entry.get("threat_port")})
                ])
                if self._threat_open(shadowed):
                    return self._block_bypassed(ip, shadowed)
                if unknown:
                    return self._precedence_unknown(unknown, rule=entry["rule"])
                return {"verified": True, "method": "nsg_check", "rule": entry["rule"],
                        **({"exposure": shadowed} if shadowed else {})}
            return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                    "error": f"rules missing: {', '.join(missing)}"}

        # No state — recompute per-NIC names (multi-NIC) and check coverage.
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        uncovered = []
        found: dict[str, tuple] = {}
        for t0 in targets:
            base = self._placement_rule_base(prefix, vm_name, t0["nic_short"], t0["nic_id"])
            for t in self._nic_nsg_views(t0):
                if self._rules_present(t["nsg_rg"], t["nsg_name"], [base, f"{base}-out"]):
                    found[t0["nic_id"]] = (t["nsg_rg"], t["nsg_name"], base)
                    break
            else:
                uncovered.append(t0["nic_short"])
        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered,
                    "error": f"NIC(s) not covered: {', '.join(uncovered)}"}
        shadowed, unknown = self._precedence([
            (*found[t["nic_id"]],
             {"inbound_src": [ip], "inbound_dst": t["private_ips"] or None,
              "outbound_src": t["private_ips"] or None, "outbound_dst": [ip]})
            for t in targets
        ])
        if shadowed:
            return self._block_bypassed(ip, shadowed)
        if unknown:
            return self._precedence_unknown(unknown, nics_covered=len(targets))
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    @staticmethod
    def _threat_open(shadowed: list[dict]) -> bool:
        """An allow before the deny lets the threat itself through (not just another
        port). Entries without the flag (no known threat port) count as open."""
        return any(x.get("threat_port_open", True) for x in shadowed)

    @staticmethod
    def _block_bypassed(ip: str, shadowed: list[dict]) -> dict:
        bypass = [x for x in shadowed if x.get("threat_port_open", True)]
        return {
            "verified": False, "method": "nsg_check", "shadowed_by": shadowed,
            "error": f"blocage de {ip} contourné : " + _describe_shadowing(bypass)
                     + " passe avant le deny de Glorfindel",
        }

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
        if entry:
            # Intent first (see release_isolation): an unblock cut off midway is not a
            # block "removed outside Glorfindel" for the reassertion to put back.
            from datetime import datetime, timezone
            _update_block_entry(vm_name, ip, unblocking_at=datetime.now(timezone.utc).isoformat())
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

        # 2) The recorded single rule (perimeter / legacy entry). A VM-scoped entry also
        # mirrors its first placement in nsg/rule: skip it then (deleted in step 1 — the
        # bench run listed every rule twice).
        if entry and entry.get("nsg") and entry.get("rule"):
            r_rg, r_name = entry["nsg"].split("/", 1)
            done = {(p["nsg_rg"], p["nsg_name"], p["rule"]) for p in entry.get("placements", [])}
            if (r_rg, r_name, entry["rule"]) not in done:
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
                failed.append(f"legacy lookup: {_first_line(e)[:_ERR_MAX]}")

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
                "precedence": self._precedence_issues(targets),
            }
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}

    def _precedence_issues(self, targets: list[dict]) -> list[dict]:
        """ALLOW rules that would be evaluated BEFORE the deny Glorfindel would place —
        found at rest, before any incident (audit readiness).

        Isolation: only on a shared NSG (a dedicated one gets priority 100). Block: the
        deny starts at 200 on every NSG, and the attacker is unknown yet, so any allow
        that admits SOME internet source to the VM counts (bench: allow-ssh at 100).
        """
        issues: list[dict] = []
        cache: dict = {}
        for t in targets:
            rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
            where = {"nsg": f'{t["nsg_rg"]}/{t["nsg_name"]}', "nic": t["nic_short"]}
            if rules is None:
                issues.append({**where, "unreadable": True})
                continue
            used = {r.priority for r in rules if isinstance(getattr(r, "priority", None), int)}
            ips = t["private_ips"] or None
            if _ip_scoped(t):
                iso = next((p for p in range(self.ISOLATION_PRIORITY, 4000) if p not in used), None)
                if iso is not None:
                    issues += [{**s, **where, "action": "isolate_vm"} for s in _shadowing_rules(
                        rules, iso, inbound_src=None, inbound_dst=ips,
                        outbound_src=ips, outbound_dst=None)]
            blk = next((p for p in range(200, 4000, 10) if p not in used), None)
            if blk is not None:
                issues += [{**s, **where, "action": "block_suspicious_ip"} for s in _shadowing_rules(
                    rules, blk, inbound_src="public", inbound_dst=ips,
                    outbound_src=ips, outbound_dst="public")]
        return issues

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

    def _get_vm_nic_targets(self, rg: str, vm_name: str, allow_no_nsg: bool = False) -> list[dict]:
        """Every NIC of the VM with its governing NSG + all private IPs.

        Isolation must cover EVERY NIC: a VM with 2 NICs each behind its own NSG is
        only half-isolated if we touch the primary alone (the real bug). Each target
        becomes one placement — deny any/any on a NIC-level NSG (scope 'nic') or deny
        scoped to ALL the NIC's private IPs on a shared subnet NSG (scope 'subnet').

        Glorfindel's own quarantine NSG (L4) is not the NIC's NSG: a NIC carrying it is
        described as it is without it (`nic_has_nsg` False, its subnet's NSG as the
        governing one) and the quarantine NSG is reported apart (`quarantine`) — a block
        must not land in an NSG that leaves with the isolation.

        allow_no_nsg: a NIC with no NSG at all (neither its own nor its subnet's) is
        returned with scope 'none' instead of raising — isolation can still attach the
        quarantine NSG to it.
        """
        vm = self._compute.virtual_machines.get(rg, vm_name)
        targets: list[dict] = []
        for ref in vm.network_profile.network_interfaces:
            nic_id = ref.id
            nic_rg, nic_name = _parse_nic_resource_id(nic_id)
            nic = self._network.network_interfaces.get(nic_rg, nic_name)
            own_id = getattr(getattr(nic, "network_security_group", None), "id", None)
            quarantine = None
            if own_id and _is_quarantine_nsg(own_id):
                q_rg, q_name = _parse_nsg_resource_id(own_id)
                quarantine = {"nsg_rg": q_rg, "nsg_name": q_name, "nsg_id": own_id}
                own_id = None
            subnet_nsg = self._subnet_nsg_of(nic)
            alt_nsg = None
            if own_id:
                nsg_rg, nsg_name = _parse_nsg_resource_id(own_id)
                scope = "nic"
                if subnet_nsg and subnet_nsg != (nsg_rg, nsg_name):
                    alt_nsg = {"nsg_rg": subnet_nsg[0], "nsg_name": subnet_nsg[1]}
            elif subnet_nsg:
                (nsg_rg, nsg_name), scope = subnet_nsg, "subnet"
            elif allow_no_nsg:
                nsg_rg, nsg_name, scope = None, None, "none"
            else:
                raise RuntimeError(f"NIC {nic_name} and its subnet have no NSG — cannot isolate VM")
            shared = scope == "nic" and self._nsg_is_shared(nsg_rg, nsg_name)
            ips = [getattr(c, "private_ip_address", None) for c in (getattr(nic, "ip_configurations", None) or [])]
            targets.append({
                "nic_id": nic_id,
                "nic_short": nic_id.rstrip("/").split("/")[-1],
                "nsg_rg": nsg_rg,
                "nsg_name": nsg_name,
                "scope": scope,
                # A NIC-level NSG attached to other NICs (or to a subnet as well) is as
                # shared as a subnet NSG: any/any there would cut off every VM behind it.
                "shared_nsg": shared,
                "ip_scoped": scope in ("subnet", "none") or shared,
                "private_ips": [ip for ip in ips if ip],
                # The subnet's NSG when the NIC also has its own: the other place a deny
                # holds (traffic must pass both).
                "alt_nsg": alt_nsg,
                "nic_has_nsg": bool(own_id),
                "own_nsg_id": own_id,
                "quarantine": quarantine,
                "location": getattr(nic, "location", None),
            })
        return targets

    def _subnet_nsg_of(self, nic) -> tuple[str, str] | None:
        """(rg, name) of the NSG on the NIC's subnet, or None (no NSG, or unreadable)."""
        try:
            subnet_id = nic.ip_configurations[0].subnet.id
            parts = subnet_id.split("/")
            sub_rg = parts[parts.index("resourceGroups") + 1]
            vnet = parts[parts.index("virtualNetworks") + 1]
            subnet = self._network.subnets.get(sub_rg, vnet, parts[-1])
            if subnet.network_security_group is None:
                return None
            return _parse_nsg_resource_id(subnet.network_security_group.id)
        except Exception:
            return None

    # ── L4: Glorfindel's quarantine NSG ─────────────────────────────────────────

    def _quarantine_settings(self) -> tuple[bool, str]:
        """(enabled, resource group) from glorfindel-config.yaml `isolation:` — enabled
        by default; GLORFINDEL_QUARANTINE_NSG=0 turns it off."""
        if os.environ.get("GLORFINDEL_QUARANTINE_NSG", "").strip() in ("0", "false", "no"):
            return False, ""
        try:
            from glorfindel.config import load_glorfindel_config
            iso = load_glorfindel_config().isolation
            return bool(iso.quarantine_nsg), iso.quarantine_rg or ""
        except Exception:
            return True, ""

    def _ensure_quarantine_nsg(self, location: str, default_rg: str) -> dict:
        """Get or create Glorfindel's quarantine NSG for this region: deny-all in and
        out at priority 100, deny to Azure's DNS and IMDS (not filtered otherwise), and
        the operator's forensic sources allowed in (`isolation.forensic_sources`), placed
        before the deny. One per region (a NIC only takes an NSG of its own region and
        subscription), created on first need; an older one gets the missing rules."""
        from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule
        _, cfg_rg = self._quarantine_settings()
        q_rg = cfg_rg or default_rg
        name = f"{QUARANTINE_NSG_PREFIX}-{(location or 'unknown').lower()}"

        def _rule(rule_name: str, direction: str) -> SecurityRule:
            return SecurityRule(
                name=rule_name, priority=100, direction=direction, access="Deny",
                protocol="*", source_address_prefix="*", destination_address_prefix="*",
                source_port_range="*", destination_port_range="*",
                description="Glorfindel — incident quarantine (attached only while a VM is isolated)",
            )
        wanted = {QUARANTINE_RULE_IN: _rule(QUARANTINE_RULE_IN, "Inbound"),
                  QUARANTINE_RULE_OUT: _rule(QUARANTINE_RULE_OUT, "Outbound")}
        for rule_name, priority, tag in QUARANTINE_PLATFORM_RULES:
            wanted[rule_name] = SecurityRule(
                name=rule_name, priority=priority, direction="Outbound", access="Deny",
                protocol="*", source_address_prefix="*", destination_address_prefix=tag,
                source_port_range="*", destination_port_range="*",
                description=f"Glorfindel — quarantine: {tag} is not filtered by a deny-all")
        forensic = self._forensic_sources()
        if forensic:
            wanted[QUARANTINE_FORENSIC_RULE] = SecurityRule(
                name=QUARANTINE_FORENSIC_RULE, priority=90, direction="Inbound", access="Allow",
                protocol="*", source_address_prefixes=forensic, destination_address_prefix="*",
                source_port_range="*", destination_port_range="*",
                description="Glorfindel — quarantine: investigation access (isolation.forensic_sources)")
        try:
            nsg = self._network.network_security_groups.get(q_rg, name)
        except Exception as exc:
            if not _is_not_found(exc):
                raise
            nsg = self._network.network_security_groups.begin_create_or_update(q_rg, name, NetworkSecurityGroup(
                location=location,
                tags={"managed-by": "glorfindel", "purpose": "incident-quarantine"},
                security_rules=list(wanted.values()),
            )).result()
        rules = {getattr(r, "name", ""): r for r in (getattr(nsg, "security_rules", None) or [])}
        for rule_name, rule in wanted.items():
            current = rules.get(rule_name)
            # Missing (someone removed it, or an NSG from before the rule existed), or
            # the forensic sources changed in the config: put it (back) in place.
            if current is None or (rule_name == QUARANTINE_FORENSIC_RULE and sorted(
                    getattr(current, "source_address_prefixes", None) or []) != sorted(forensic)):
                self._network.security_rules.begin_create_or_update(q_rg, name, rule_name, rule).result()
        if not forensic and QUARANTINE_FORENSIC_RULE in rules:
            self._network.security_rules.begin_delete(q_rg, name, QUARANTINE_FORENSIC_RULE).result()
        return {"nsg_rg": q_rg, "nsg_name": name, "nsg_id": nsg.id}

    def _forensic_sources(self) -> list[str]:
        try:
            from glorfindel.config import load_glorfindel_config
            return list(load_glorfindel_config().isolation.forensic_sources)
        except Exception:
            return []

    def _set_nic_nsg(self, nic_id: str, nsg_id: str | None, expect: str | None = None) -> bool:
        """Attach `nsg_id` to the NIC (None: detach). With `expect`, only when the NIC
        currently carries that NSG (never touch an NSG that isn't ours). Returns True
        if the NIC was changed."""
        from azure.mgmt.network.models import NetworkSecurityGroup
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        current = getattr(getattr(nic, "network_security_group", None), "id", None)
        if expect is not None and not _same_id(current or "", expect):
            return False
        nic.network_security_group = NetworkSecurityGroup(id=nsg_id) if nsg_id else None
        self._network.network_interfaces.begin_create_or_update(nic_rg, nic_name, nic).result()
        return True

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


class WrongSubscriptionError(RuntimeError):
    """The target lives in another subscription than the one Glorfindel acts in."""


def _subscription_of(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() == "subscriptions":
            return parts[i + 1]
    return ""


def _same_subscription(method):
    """Refuse to act on (or vouch for) a VM of another subscription (third review, T1).

    The resource ids are reduced to (resource group, name) and every client runs in
    AZURE_SUBSCRIPTION_ID. With a Log Analytics workspace shared by several
    subscriptions, a VM discovered in subscription B was isolated in subscription A —
    on the homonymous VM if one exists. Until clients exist per subscription, the
    action is refused, and the cycle escalates it as action_failed."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.dry_run:
            rid = kwargs.get("resource_id") or next(
                (a for a in args if isinstance(a, str) and a.lower().startswith("/subscriptions/")), "")
            # The subscription the clients run in — read without building them, so the
            # read-only guard and its clear message still come first.
            target = _subscription_of(rid)
            mine = self._subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
            if target and mine and target.lower() != mine.lower():
                raise WrongSubscriptionError(
                    f"{rid.rsplit('/', 1)[-1]} est dans l'abonnement {target}, Glorfindel agit dans "
                    f"{mine} : action refusée (elle viserait une autre VM, ou aucune). "
                    "Agir depuis une instance configurée pour cet abonnement.")
        return method(self, *args, **kwargs)
    return wrapper


def _one_writer(method):
    """Hold the VM's lock for the whole write (see _vm_lock)."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        rid = kwargs.get("resource_id") or next(
            (a for a in args if isinstance(a, str) and a.lower().startswith("/subscriptions/")), "")
        if self.dry_run or not rid:
            return method(self, *args, **kwargs)
        with _vm_lock(rid.rstrip("/").rsplit("/", 1)[-1]):
            return method(self, *args, **kwargs)
    return wrapper


for _name in ("isolate_vm", "release_isolation", "block_suspicious_ip", "unblock_ip", "sweep_vm_rules"):
    setattr(AzureConnector, _name, _one_writer(getattr(AzureConnector, _name)))
for _name in ("isolate_vm", "release_isolation", "verify_isolation", "verify_release",
              "block_suspicious_ip", "unblock_ip", "verify_block_ip", "snapshot",
              "restore_from_backup", "drain_connections", "sweep_vm_rules", "check_permissions"):
    if hasattr(AzureConnector, _name):
        setattr(AzureConnector, _name, _same_subscription(getattr(AzureConnector, _name)))


_ISOLATION_STATE_DIR = Path.home() / ".glorfindel" / "isolation"

_UNKNOWN = object()
_QUARANTINE_LOCKS: dict[str, threading.Lock] = {}
_QUARANTINE_LOCKS_GUARD = threading.Lock()


@contextlib.contextmanager
def _quarantine_lock(nsg_id: str):
    """One writer at a time on a quarantine NSG's tags: a thread lock (workers of one
    watch) plus an flock (the War Room and the CLI are other processes)."""
    import hashlib
    key = nsg_id.rstrip("/").lower()
    with _QUARANTINE_LOCKS_GUARD:
        lock = _QUARANTINE_LOCKS.setdefault(key, threading.Lock())
    with lock:
        lock_dir = _ISOLATION_STATE_DIR.parent / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_dir / f"quarantine-{hashlib.sha1(key.encode()).hexdigest()[:12]}.lock", "a") as fh:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:
                pass
            yield


_VM_LOCKS: dict[str, threading.RLock] = {}
_VM_LOCK_DEPTH = threading.local()


@contextlib.contextmanager
def _vm_lock(vm_name: str):
    """One writer at a time per VM (third review, T2): isolate, release, block, unblock
    and the reassertion. A thread lock (watch workers, reassert loop) plus an flock
    (the War Room and the CLI are other processes). Re-entrant within a thread — the
    reassertion re-isolates while holding it."""
    import hashlib
    key = (vm_name or "").lower()
    with _QUARANTINE_LOCKS_GUARD:
        lock = _VM_LOCKS.setdefault(key, threading.RLock())
    depth = getattr(_VM_LOCK_DEPTH, "d", None)
    if depth is None:
        depth = _VM_LOCK_DEPTH.d = {}
    with lock:
        if depth.get(key):
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        lock_dir = _ISOLATION_STATE_DIR.parent / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_dir / f"vm-{hashlib.sha1(key.encode()).hexdigest()[:12]}.lock", "a") as fh:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:
                pass
            depth[key] = 1
            try:
                yield
            finally:
                depth[key] = 0


def _recorded_original(nic_id: str):
    """The original NSG recorded in local state for this NIC (None = it had none), or
    _UNKNOWN when no state records it."""
    for iso in active_isolations():
        for p in iso.get("placements") or []:
            if p.get("kind") == "quarantine" and _same_id(p.get("nic_id", ""), nic_id) \
                    and "original_nsg_id" in p:
                return p["original_nsg_id"]
    return _UNKNOWN
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
    placements: list | None = None, partial: bool = False, threat_port: int | None = None,
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
            "threat_port": threat_port,
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
        if threat_port is not None:
            prev["threat_port"] = threat_port
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
