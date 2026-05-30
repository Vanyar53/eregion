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
        """Check all assets and escalate new gaps. Returns all gaps found."""
        all_gaps: list[PostureGap] = []
        for asset in assets:
            if not asset.resource_id:
                continue
            gaps = self._check_asset(asset)
            all_gaps.extend(gaps)
            for gap in gaps:
                self._maybe_escalate(gap)
        return all_gaps

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

    # ── Checks ────────────────────────────────────────────────────────────────

    def _check_asset(self, asset) -> list[PostureGap]:
        if self._dry_run:
            return []

        gaps: list[PostureGap] = []
        vault = self._vault_name()
        rid = asset.resource_id
        vm = asset.name
        rg = _rg(rid)

        if vault:
            try:
                res = self._connector.check_backup_points(rid, vault)
                if not res.get("ok"):
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
                            f"-g {rg} -v {vault} --vm {vm}"
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
                            f"-g {rg} -v {vault} -c {vm} -i {vm}"
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
            if entry and entry.get("status") == "pending":
                esc_id = entry.get("escalation_id", "")
                if esc_id and _escalation_pending(esc_id):
                    return

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
