from __future__ import annotations

from unittest.mock import MagicMock


from glorfindel.audit import AuditCheck, AuditResult, run


# ── Fixtures ────────────────────────────────────────────────────────────────────

RESOURCE_ID = (
    "/subscriptions/sub-123/resourceGroups/annatar"
    "/providers/Microsoft.Compute/virtualMachines/vm-victim"
)


def _connector(
    nsg=None,
    backup=None,
    compute=None,
    dry_run=False,
):
    c = MagicMock()
    c.dry_run = dry_run
    c.check_nsg_access.return_value = nsg or {"ok": True, "nsg": "annatar/nsg-vm", "rules": 3}
    c.check_backup_points.return_value = backup or {
        "ok": True, "vault": "rsv-annatar", "points": 5, "latest_age_h": 12.0
    }
    c.check_compute_access.return_value = compute or {
        "ok": True, "vm": "vm-victim", "disks": ["osdisk", "datadisk"]
    }
    return c


# ── AuditResult ─────────────────────────────────────────────────────────────────

def test_result_ready_all_ok():
    r = AuditResult(RESOURCE_ID, "2026-01-01T00:00:00+00:00", [
        AuditCheck("a", "n", "ok", "fine"),
        AuditCheck("b", "n", "ok", "fine"),
    ])
    assert r.ready is True


def test_result_not_ready_on_fail():
    r = AuditResult(RESOURCE_ID, "2026-01-01T00:00:00+00:00", [
        AuditCheck("a", "n", "ok", "fine"),
        AuditCheck("b", "n", "fail", "broken"),
    ])
    assert r.ready is False


def test_result_ready_with_warn():
    r = AuditResult(RESOURCE_ID, "2026-01-01T00:00:00+00:00", [
        AuditCheck("a", "n", "warn", "stale backup"),
    ])
    assert r.ready is True


def test_result_to_dict():
    r = AuditResult(RESOURCE_ID, "2026-01-01T00:00:00+00:00", [
        AuditCheck("isolate_vm", "NSG access", "ok", "ok message"),
    ])
    d = r.to_dict()
    assert d["ready"] is True
    assert len(d["checks"]) == 1
    assert d["checks"][0]["status"] == "ok"


# ── run() ────────────────────────────────────────────────────────────────────────

def test_run_dry_run_returns_skip():
    c = _connector(dry_run=True)
    result = run(RESOURCE_ID, c)
    assert len(result.checks) == 1
    assert result.checks[0].status == "skip"
    c.check_nsg_access.assert_not_called()


def test_run_all_ok():
    result = run(RESOURCE_ID, _connector())
    assert result.ready is True
    assert len(result.checks) == 3
    statuses = {c.name: c.status for c in result.checks}
    assert statuses["NSG access"] == "ok"
    assert statuses["Backup vault"] == "ok"
    assert statuses["Compute access"] == "ok"


def test_run_nsg_fail_iam():
    c = _connector(nsg={"ok": False, "iam": True, "error": "AuthorizationFailed"})
    result = run(RESOURCE_ID, c)
    assert not result.ready
    nsg_check = next(ch for ch in result.checks if ch.name == "NSG access")
    assert nsg_check.status == "fail"
    assert "IAM" in nsg_check.message
    assert "Network Contributor" in nsg_check.fix


def test_run_nsg_fail_no_nsg():
    c = _connector(nsg={"ok": False, "iam": False, "error": "NIC has no NSG"})
    result = run(RESOURCE_ID, c)
    nsg_check = next(ch for ch in result.checks if ch.name == "NSG access")
    assert nsg_check.status == "fail"
    assert "no NSG" in nsg_check.message.lower() or "not found" in nsg_check.message.lower()


def test_run_backup_fail_iam():
    c = _connector(backup={"ok": False, "iam": True, "vault": "rsv-annatar", "error": "403 Forbidden"})
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "fail"
    assert "IAM" in bk.message
    assert "Backup Contributor" in bk.fix


def test_run_backup_fail_not_configured():
    c = _connector(backup={"ok": False, "iam": False, "vault": "rsv-annatar", "error": "No recovery points"})
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "fail"
    assert "enable-for-vm" in bk.fix


def test_run_backup_warn_stale():
    c = _connector(backup={"ok": True, "vault": "rsv-annatar", "points": 2, "latest_age_h": 52.0})
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "warn"
    assert result.ready is True  # warn does not block readiness
    assert "backup-now" in bk.fix


def test_run_compute_fail_iam():
    c = _connector(compute={"ok": False, "iam": True, "error": "AuthorizationFailed"})
    result = run(RESOURCE_ID, c)
    cp = next(ch for ch in result.checks if ch.name == "Compute access")
    assert cp.status == "fail"
    assert "Virtual Machine Contributor" in cp.fix


def test_run_compute_fail_not_found():
    c = _connector(compute={"ok": False, "iam": False, "error": "ResourceNotFound"})
    result = run(RESOURCE_ID, c)
    cp = next(ch for ch in result.checks if ch.name == "Compute access")
    assert cp.status == "fail"
    assert "az vm show" in cp.fix


# ── _is_iam_error helper ─────────────────────────────────────────────────────────

def test_is_iam_error_detection():
    from glorfindel.actions import _is_iam_error
    assert _is_iam_error("AuthorizationFailed: client does not have authorization")
    assert _is_iam_error("403 Forbidden")
    assert _is_iam_error("does not have authorization to perform action")
    assert not _is_iam_error("ResourceNotFound: The Resource 'Microsoft.Compute/vm' was not found")
    assert not _is_iam_error("Invalid resource ID format")
