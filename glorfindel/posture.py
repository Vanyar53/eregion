"""Proactive posture checks — run after each discovery cycle.

For each discovered VM, verifies Glorfindel can actually defend it:
  backup_linked  : VM registered in the RSV
  backup_recent  : latest recovery point < 48h
  nsg_reachable  : NSG exists + accessible

Gaps escalated as posture_gap. Dedup: pending gap → skip, resolved → re-escalate.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

_STATE_FILE = Path.home() / ".glorfindel" / "posture_state.json"

PostureCheckName = Literal["backup_linked", "backup_recent", "nsg_reachable"]


@dataclass
class PostureGap:
    resource_id: str
    vm_name: str
    check: PostureCheckName
    severity: Literal["critical", "warn"]
    message: str
    fix: str = ""

    @property
    def key(self) -> str:
        return f"{self.vm_name}:{self.check}"


class PostureChecker:
    """Check discovered assets for defensive readiness and escalate gaps."""

    def __init__(
        self,
        glorfindel_cfg,
        connector,
        dry_run: bool = False,
    ) -> None:
        self._cfg = glorfindel_cfg
        self._connector = connector
        self._dry_run = dry_run
        self._lock = threading.Lock()
        self._state: dict[str, dict] = self._load_state()

    # ── Public ────────────────────────────────────────────────────────────────

    def check_and_escalate(self, assets: list) -> list[PostureGap]:
        """Check all assets, escalate new gaps, auto-resolve cleared ones. Returns gaps."""
        all_gaps: list[PostureGap] = []
        checked_vms: set[str] = set()
        for asset in assets:
            if not asset.resource_id:
                continue
            checked_vms.add(asset.name)
            gaps = self._check_asset(asset)
            all_gaps.extend(gaps)
            for gap in gaps:
                self._maybe_escalate(gap)
        # Auto-resolve gaps that no longer exist (e.g. the overnight backup ran →
        # "no recovery point yet" cleared) so the operator doesn't have to ack a
        # posture escalation for a condition that fixed itself.
        self._resolve_cleared_gaps({g.key for g in all_gaps}, checked_vms)
        return all_gaps

    def _resolve_cleared_gaps(self, current_keys: set[str], checked_vms: set[str]) -> None:
        """Resolve escalations for gaps whose CONDITION genuinely cleared this cycle.

        Only resolve a gap if its VM was actually checked and the gap no longer fires.
        A VM that simply dropped out of discovery (powered off > retention → evicted) is
        NOT "the gap cleared" — we just couldn't check it. Resolving on eviction would
        wipe the ack and re-flood a fresh escalation when the VM returns (the Monday-
        morning flood after a weekend off). So we FREEZE gaps for un-checked VMs.
        """
        from glorfindel import escalations
        with self._lock:
            changed = False
            for key, entry in list(self._state.items()):
                # Freeze gaps for VMs not checked this cycle (evicted/offline) — don't
                # touch their ack/pending state.
                if entry.get("vm_name") not in checked_vms:
                    continue
                # Clear both still-pending and acked gaps once the condition is gone,
                # so a future recurrence re-alerts (an acked gap that clears must not
                # stay 'acknowledged' forever and swallow the next real occurrence).
                if entry.get("status") in ("pending", "acknowledged") and key not in current_keys:
                    esc_id = entry.get("escalation_id", "")
                    if esc_id and not self._dry_run:
                        try:
                            escalations.resolve(esc_id)
                        except Exception:
                            pass
                    entry["status"] = "resolved"
                    entry["resolved_at"] = datetime.now(timezone.utc).isoformat()
                    changed = True
            if changed:
                self._save_state()

    def active_gaps(self) -> list[dict]:
        """Return persisted pending gaps (for API exposure)."""
        with self._lock:
            return [
                {"key": k, **v}
                for k, v in self._state.items()
                if v.get("status") == "pending"
            ]

    def _vault_name(self) -> str:
        rsv = self._cfg.backup_vault() if self._cfg else None
        return rsv.vault_name if rsv and rsv.vault_name else ""

    def _vault_rg(self) -> str:
        """The vault's own resource group (central vault ≠ VM RG). Empty → caller
        falls back to the VM's RG (sandbox: vault and VM co-located)."""
        rsv = self._cfg.backup_vault() if self._cfg else None
        return rsv.resource_group if rsv and rsv.resource_group else ""

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_asset(self, asset) -> list[PostureGap]:
        if self._dry_run:
            return []

        # Only standalone VMs get VM-oriented checks. An AKS managed cluster (what the
        # AMA heartbeat reports for AKS nodes), a VMSS instance, or any non-VM asset is
        # not backupable, not NSG-isolatable, not snapshot-able the IaaS way → skip
        # entirely. Otherwise check_backup_points / check_nsg_access fail on it and
        # mint false backup_linked / nsg_reachable gaps that loop (the AKS parasite).
        from glorfindel.actions import _is_backupable_vm
        if not _is_backupable_vm(asset.resource_id):
            return []

        gaps: list[PostureGap] = []
        vault = self._vault_name()
        vault_rg = self._vault_rg()
        rid = asset.resource_id
        vm = asset.name
        rg = _rg(rid)
        # az backup commands target the vault's RG, not the VM's.
        vrg = vault_rg or rg

        if vault:
            try:
                res = self._connector.check_backup_points(rid, vault, vault_rg)
                if not res.get("ok") and res.get("protected"):
                    # Protected, but the first backup hasn't run yet. NOT a "not linked"
                    # critical — restore will be possible once a recovery point exists.
                    gaps.append(PostureGap(
                        resource_id=rid,
                        vm_name=vm,
                        check="backup_recent",
                        severity="warn",
                        message=(
                            f"{vm} protected in '{vault}' but no recovery point yet"
                            " — first backup pending, restore not yet possible"
                        ),
                        fix=(
                            f"az backup protection backup-now "
                            f"-g {vrg} -v {vault} -c {vm} -i {vm}"
                            " --backup-management-type AzureIaasVM"
                        ),
                    ))
                elif not res.get("ok"):
                    gaps.append(PostureGap(
                        resource_id=rid,
                        vm_name=vm,
                        check="backup_linked",
                        severity="critical",
                        message=(
                            f"{vm} not linked to vault '{vault}'"
                            " — restore_from_backup impossible"
                        ),
                        fix=(
                            f"az backup protection enable-for-vm "
                            f"-g {vrg} -v {vault} --vm {vm}"
                            " --policy-name DefaultPolicy"
                        ),
                    ))
                elif res.get("latest_age_h", 0) >= 48:
                    age_h = res["latest_age_h"]
                    gaps.append(PostureGap(
                        resource_id=rid,
                        vm_name=vm,
                        check="backup_recent",
                        severity="warn",
                        message=(
                            f"{vm} last backup {age_h}h ago"
                            " — restore will lose recent data"
                        ),
                        fix=(
                            f"az backup protection backup-now "
                            f"-g {vrg} -v {vault} -c {vm} -i {vm}"
                            " --backup-management-type AzureIaasVM"
                        ),
                    ))
            except Exception:
                pass

        try:
            res = self._connector.check_nsg_access(rid)
            if not res.get("ok"):
                gaps.append(PostureGap(
                    resource_id=rid,
                    vm_name=vm,
                    check="nsg_reachable",
                    severity="critical",
                    message=(
                        f"{vm} has no accessible NSG"
                        " — isolate_vm / block_suspicious_ip impossible"
                    ),
                    fix=(
                        f"Attach an NSG to the VM's NIC"
                        f" in resource group {rg}"
                    ),
                ))
        except Exception:
            pass

        return gaps

    # ── Dedup + escalation ────────────────────────────────────────────────────

    def _maybe_escalate(self, gap: PostureGap) -> None:
        from glorfindel import escalations

        with self._lock:
            entry = self._state.get(gap.key)
            if entry:
                status = entry.get("status")
                esc_id = entry.get("escalation_id", "")
                if status == "pending":
                    if esc_id and _escalation_pending(esc_id):
                        return  # already pending — dedup, don't duplicate
                    # The escalation left pending() while the gap is STILL present:
                    # the operator acked it. Respect that — record the ack in posture
                    # state and stop re-raising. Re-escalating an acked-but-real gap
                    # every cycle (the bug) made `ack` useless on a persistent gap.
                    if not self._dry_run:
                        entry["status"] = "acknowledged"
                        entry["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
                        self._save_state()
                    return
                if status == "acknowledged":
                    return  # acked and condition unchanged — stay quiet
                # status == "resolved": the gap had cleared and now recurs → re-escalate

            if self._dry_run:
                return

            esc_id = escalations.record(
                signal_id=f"posture-{gap.key}",
                resource_id=gap.resource_id,
                action="posture_gap",
                escalation_type="posture_gap",
                reason=gap.message,
                suggested_steps=[gap.fix] if gap.fix else [],
                severity=gap.severity,
            )

            self._state[gap.key] = {
                "escalation_id": esc_id,
                "status": "pending",
                "vm_name": gap.vm_name,
                "check": gap.check,
                "severity": gap.severity,
                "message": gap.message,
                "fix": gap.fix,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }
            self._save_state()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_state(self) -> dict:
        try:
            if _STATE_FILE.exists():
                return json.loads(_STATE_FILE.read_text())
        except Exception:
            pass
        return {}

    def _save_state(self) -> None:
        _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _STATE_FILE.write_text(json.dumps(self._state, indent=2))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rg(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        idx = next(
            i for i, p in enumerate(parts)
            if p.lower() == "resourcegroups"
        )
        return parts[idx + 1]
    except StopIteration:
        return "?"


def _escalation_pending(escalation_id: str) -> bool:
    from glorfindel import escalations
    return any(e.get("id") == escalation_id for e in escalations.pending())
