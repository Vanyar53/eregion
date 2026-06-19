from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from glorfindel.config import GlorfindelConfig, ActionBackendConfig
from glorfindel.discovery import DiscoveredAsset
from glorfindel.posture import PostureChecker, PostureGap


def _asset(name="vm-test", rid="/subs/s/rg/rg-test/providers/vm/vm-test"):
    return DiscoveredAsset(
        name=name,
        resource_id=rid,
        monitoring_backend="law",
        last_seen="2026-01-01T00:00:00Z",
    )


def _cfg(vault="rsv-test"):
    return GlorfindelConfig(
        action_backends=[
            ActionBackendConfig(
                name="rsv-test",
                type="azure_backup_vault",
                vault_name=vault,
                resource_group="rg-test",
            )
        ]
    )


def _connector(backup_ok=True, backup_age_h=1, nsg_ok=True):
    m = MagicMock()
    if backup_ok:
        m.check_backup_points.return_value = {
            "ok": True, "points": 3, "latest_age_h": backup_age_h
        }
    else:
        m.check_backup_points.return_value = {
            "ok": False, "error": "VM not linked to vault"
        }
    m.check_nsg_access.return_value = (
        {"ok": True, "nsg": "nsg-test", "rules": 5} if nsg_ok
        else {"ok": False, "error": "NSG not found"}
    )
    return m


# ── PostureGap.key ─────────────────────────────────────────────────────────────

def test_gap_key():
    gap = PostureGap(
        resource_id="/r", vm_name="vm-a", check="backup_linked",
        severity="critical", message="msg",
    )
    assert gap.key == "vm-a:backup_linked"


# ── _check_asset ───────────────────────────────────────────────────────────────

def test_no_gaps_when_all_ok(tmp_path):
    checker = PostureChecker(_cfg(), _connector(), dry_run=False)
    checker._state = {}
    gaps = checker._check_asset(_asset())
    assert gaps == []


def test_backup_linked_gap(tmp_path):
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)
    gaps = checker._check_asset(_asset())
    assert any(g.check == "backup_linked" for g in gaps)
    assert any(g.severity == "critical" for g in gaps)


def test_vmss_node_raises_no_backup_gap(tmp_path):
    """A VMSS instance (AKS node) is not an IaaS-VM backup item → check_backup_points
    returns not_backupable → NO backup gap (the bogus 'not linked to vault' that
    looped on Jonathan's cluster)."""
    conn = _connector()
    conn.check_backup_points.return_value = {
        "ok": False, "not_backupable": True, "error": "VMSS instance — not a backup item",
    }
    checker = PostureChecker(_cfg(), conn, dry_run=False)
    checker._state = {}
    gaps = checker._check_asset(_asset(
        name="aks-node-0",
        rid="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute"
            "/virtualMachineScaleSets/aks-pool/virtualMachines/0",
    ))
    assert not any(g.check in ("backup_linked", "backup_recent") for g in gaps)


def test_backup_protected_no_rp_warns_not_critical(tmp_path):
    """Protected VM with no recovery point yet → warn 'first backup pending',
    NOT a critical 'not linked to vault' gap (the bug: elrond was protected, just
    had no backup at discovery)."""
    conn = _connector()
    conn.check_backup_points.return_value = {
        "ok": False, "protected": True, "no_recovery_point": True,
        "vault": "rsv-annatar",
        "error": "vm protected in 'rsv-annatar' but has no recovery point yet",
    }
    checker = PostureChecker(_cfg(), conn, dry_run=False)
    checker._state = {}
    gaps = checker._check_asset(_asset())
    backup_gaps = [g for g in gaps if g.check in ("backup_linked", "backup_recent")]
    assert len(backup_gaps) == 1
    g = backup_gaps[0]
    assert g.check == "backup_recent"        # not "backup_linked"
    assert g.severity == "warn"              # not "critical"
    assert "not linked" not in g.message.lower()
    assert "first backup pending" in g.message.lower()
    assert "backup-now" in g.fix             # not enable-for-vm


def test_backup_stale_gap(tmp_path):
    checker = PostureChecker(_cfg(), _connector(backup_age_h=72), dry_run=False)
    gaps = checker._check_asset(_asset())
    assert any(g.check == "backup_recent" for g in gaps)
    assert any(g.severity == "warn" for g in gaps)


def test_nsg_gap(tmp_path):
    checker = PostureChecker(_cfg(), _connector(nsg_ok=False), dry_run=False)
    gaps = checker._check_asset(_asset())
    assert any(g.check == "nsg_reachable" for g in gaps)
    assert any(g.severity == "critical" for g in gaps)


def test_no_gaps_in_dry_run(tmp_path):
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=True)
    gaps = checker._check_asset(_asset())
    assert gaps == []


def test_asset_without_resource_id_skipped(tmp_path):
    checker = PostureChecker(_cfg(), _connector(), dry_run=False)
    asset = DiscoveredAsset(
        name="vm-noid", resource_id="",
        monitoring_backend="law", last_seen="t",
    )
    gaps = checker.check_and_escalate([asset])
    assert gaps == []


def test_gap_fix_contains_az_command(tmp_path):
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)
    gaps = checker._check_asset(_asset())
    backup_gap = next(g for g in gaps if g.check == "backup_linked")
    assert "az backup" in backup_gap.fix


# ── Dedup logic ────────────────────────────────────────────────────────────────

def test_no_duplicate_escalation(tmp_path):
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)
    checker._state = {}

    with patch("glorfindel.posture._escalation_pending", return_value=True), \
         patch("glorfindel.escalations.record", return_value="esc-1") as mock_rec:
        gap = PostureGap(
            resource_id="/r", vm_name="vm-test", check="backup_linked",
            severity="critical", message="msg",
        )
        # First call — escalate
        checker._state = {}
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 1

        # Second call with same key pending — skip
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 1  # no new escalation


def test_reescalate_when_resolved(tmp_path):
    """A gap that had CLEARED (status 'resolved') and now recurs → re-escalate."""
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)

    with patch("glorfindel.posture._escalation_pending", return_value=False), \
         patch("glorfindel.escalations.record", return_value="esc-2") as mock_rec:
        gap = PostureGap(
            resource_id="/r", vm_name="vm-test", check="backup_linked",
            severity="critical", message="msg",
        )
        # Previously cleared (resolved by _resolve_cleared_gaps), now detected again
        checker._state = {
            gap.key: {"escalation_id": "esc-old", "status": "resolved"}
        }
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 1  # re-escalated — genuine recurrence


def test_acked_persistent_gap_is_not_reescalated(tmp_path):
    """The bug Jonathan hit: ack a still-true gap → it must NOT come back.

    State stays 'pending' (ack only touches the escalation, not posture state) while
    the escalation has left pending(). The checker must read that as 'acknowledged'
    and stop re-raising, not mint a fresh escalation every cycle.
    """
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)
    with patch("glorfindel.posture._escalation_pending", return_value=False), \
         patch("glorfindel.escalations.record", return_value="esc-new") as mock_rec:
        gap = PostureGap(
            resource_id="/r", vm_name="vm-test", check="backup_linked",
            severity="critical", message="msg",
        )
        checker._state = {gap.key: {"escalation_id": "esc-old", "status": "pending"}}
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 0                       # no new escalation
        assert checker._state[gap.key]["status"] == "acknowledged"

        # Subsequent cycles stay quiet too.
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 0


def test_acked_gap_realerts_after_clearing_then_recurring(tmp_path):
    """Acked gap that CLEARS then RECURS must re-alert (ack doesn't mute forever)."""
    checker = PostureChecker(_cfg(), _connector(backup_ok=False), dry_run=False)
    gap = PostureGap(
        resource_id="/r", vm_name="vm-test", check="backup_linked",
        severity="critical", message="msg",
    )
    checker._state = {gap.key: {"escalation_id": "esc-old", "status": "acknowledged"}}

    # Condition cleared (gap not in current set) → state goes 'resolved'.
    checker._resolve_cleared_gaps(current_keys=set())
    assert checker._state[gap.key]["status"] == "resolved"

    # Now it recurs → re-escalate.
    with patch("glorfindel.posture._escalation_pending", return_value=False), \
         patch("glorfindel.escalations.record", return_value="esc-2") as mock_rec:
        checker._maybe_escalate(gap)
        assert mock_rec.call_count == 1


# ── active_gaps ────────────────────────────────────────────────────────────────

def test_active_gaps_returns_only_pending(tmp_path):
    checker = PostureChecker(_cfg(), _connector(), dry_run=True)
    checker._state = {
        "vm-a:backup_linked": {
            "escalation_id": "e1", "status": "pending",
            "vm_name": "vm-a", "check": "backup_linked",
            "severity": "critical", "message": "msg", "fix": "",
            "detected_at": "t",
        },
        "vm-b:nsg_reachable": {
            "escalation_id": "e2", "status": "resolved",
            "vm_name": "vm-b", "check": "nsg_reachable",
            "severity": "critical", "message": "msg", "fix": "",
            "detected_at": "t",
        },
    }
    active = checker.active_gaps()
    assert len(active) == 1
    assert active[0]["vm_name"] == "vm-a"


# ── check_and_escalate integration ────────────────────────────────────────────

def test_check_and_escalate_no_vault_skips_backup(tmp_path):
    cfg_no_vault = GlorfindelConfig()  # no action_backends
    checker = PostureChecker(cfg_no_vault, _connector(backup_ok=False), dry_run=False)
    gaps = checker._check_asset(_asset())
    # No vault configured → backup checks skipped
    assert not any(g.check in ("backup_linked", "backup_recent") for g in gaps)


def test_connector_exception_does_not_raise(tmp_path):
    conn = MagicMock()
    conn.check_backup_points.side_effect = Exception("Azure down")
    conn.check_nsg_access.side_effect = Exception("Azure down")
    checker = PostureChecker(_cfg(), conn, dry_run=False)
    gaps = checker._check_asset(_asset())
    assert gaps == []  # exceptions swallowed gracefully
