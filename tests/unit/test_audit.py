from __future__ import annotations

from unittest.mock import MagicMock


from glorfindel.audit import AuditCheck, AuditResult
from glorfindel.audit import run as _audit_run


def run(resource_id, connector, vault="rsv-test", **kw):
    """audit.run with a vault: there is no default vault any more (third review)."""
    return _audit_run(resource_id, connector, vault=vault, **kw)


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
    result = run(RESOURCE_ID, _connector(), staging_storage="ststaging")
    assert result.ready is True
    assert len(result.checks) == 4
    statuses = {c.name: c.status for c in result.checks}
    assert statuses["NSG access"] == "ok"
    assert statuses["Backup vault"] == "ok"
    assert statuses["Compute access"] == "ok"
    assert statuses["Restore staging"] == "ok"


def test_run_staging_missing_warns_but_stays_ready():
    """No staging SA → a readiness WARN (educational), not a fail: detection/isolation
    still work, only restore would stop. ready stays True (warn ≠ fail)."""
    result = run(RESOURCE_ID, _connector())  # no staging_storage
    staging = next(c for c in result.checks if c.name == "Restore staging")
    assert staging.status == "warn"
    assert staging.action == "restore_from_backup"
    assert "restore_staging_storage" in staging.fix
    assert result.ready is True  # warn does not break readiness


def test_nsg_check_exposes_structured_nsg_and_scope():
    """NSG check carries nsg + nsg_scope in `data` (no message parsing for War Room)."""
    c = _connector(nsg={"ok": True, "nsg": "annatar/subnet-nsg", "scope": "subnet", "rules": 4})
    result = run(RESOURCE_ID, c)
    nsg = next(ch for ch in result.checks if ch.name == "NSG access")
    assert nsg.data["nsg"] == "annatar/subnet-nsg"
    assert nsg.data["nsg_scope"] == "subnet"
    # survives to_dict (what /api/audit serialises)
    d = next(ch for ch in result.to_dict()["checks"] if ch["name"] == "NSG access")
    assert d["data"]["nsg_scope"] == "subnet"


def test_nsg_check_exposes_all_nics_multi_nsg():
    """The NSG check surfaces every NIC's NSG in data.nsgs (multi-NIC at rest)."""
    c = _connector(nsg={
        "ok": True, "nsg": "rg1/nsg-a", "scope": "nic", "rules": 3,
        "nsgs": [
            {"nsg": "rg1/nsg-a", "nsg_scope": "nic", "nic_id": "nic-a", "ips": []},
            {"nsg": "rg2/nsg-b", "nsg_scope": "subnet", "nic_id": "nic-b", "ips": ["10.0.1.7"]},
        ],
    })
    result = run(RESOURCE_ID, c)
    nsg = next(ch for ch in result.checks if ch.name == "NSG access")
    assert [n["nsg"] for n in nsg.data["nsgs"]] == ["rg1/nsg-a", "rg2/nsg-b"]
    assert nsg.data["nsg"] == "rg1/nsg-a"   # back-compat primary
    assert "+1 more NIC" in nsg.message


def test_run_threads_vault_rg_to_backup_check():
    """run(vault_rg=...) reaches check_backup_points — central vault ≠ VM RG."""
    c = _connector()
    run(RESOURCE_ID, c, vault="central-vault", vault_rg="backup-rg")
    c.check_backup_points.assert_called_once_with(
        RESOURCE_ID, "central-vault", "backup-rg")


def test_backup_check_exposes_structured_points_protected():
    """Backup check carries points + protected in `data` (the 'combien')."""
    c = _connector(backup={"ok": True, "vault": "rsv-annatar", "points": 7, "latest_age_h": 3.0})
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.data["points"] == 7
    assert bk.data["protected"] is True


def test_run_checks_run_concurrently():
    """The 3 Azure checks run in parallel — total time ≈ slowest, not the sum.

    Each connector check sleeps 0.3s; sequential would be ~0.9s, parallel ~0.3s.
    Also asserts order is preserved (NSG, Backup, Compute) despite parallelism.
    """
    import time

    def _slow(result):
        def _fn(*args, **kwargs):
            time.sleep(0.3)
            return result
        return _fn

    c = MagicMock()
    c.dry_run = False
    c.read_only = False
    c.check_nsg_access.side_effect = _slow({"ok": True, "nsg": "rg/nsg", "rules": 3})
    c.check_backup_points.side_effect = _slow(
        {"ok": True, "vault": "rsv-annatar", "points": 5, "latest_age_h": 12.0})
    c.check_compute_access.side_effect = _slow(
        {"ok": True, "vm": "vm", "disks": ["osdisk"]})

    # Pre-warm the Azure SDK import so it isn't counted in the concurrency timing
    # (audit.run calls warm_up_azure_sdk() before the ThreadPool; idempotent).
    from glorfindel.actions import warm_up_azure_sdk
    warm_up_azure_sdk()

    t0 = time.monotonic()
    result = run(RESOURCE_ID, c)
    elapsed = time.monotonic() - t0

    assert elapsed < 0.7, f"checks not concurrent — took {elapsed:.2f}s (sum would be ~0.9s)"
    assert [ch.name for ch in result.checks] == [
        "NSG access", "Backup vault", "Compute access", "Restore staging"]


def test_nsg_transient_sdk_error_not_labelled_no_nsg():
    """An SDK import-race error must be reported as transient, not 'attach an NSG'."""
    c = _connector(nsg={
        "ok": False, "iam": False,
        "error": "cannot import name 'Pipeline' from 'azure.core.pipeline'",
    })
    result = run(RESOURCE_ID, c)
    nsg = next(ch for ch in result.checks if ch.name == "NSG access")
    assert nsg.status == "warn"
    assert "transient" in nsg.message.lower()
    assert "Attach an NSG" not in nsg.fix


def test_nsg_genuine_absence_still_says_attach():
    """A real 'no NSG' error keeps the actionable attach-NSG guidance."""
    c = _connector(nsg={
        "ok": False, "iam": False,
        "error": "NIC vm-x and its subnet have no NSG — cannot isolate VM",
    })
    result = run(RESOURCE_ID, c)
    nsg = next(ch for ch in result.checks if ch.name == "NSG access")
    assert nsg.status == "fail"
    assert "Attach an NSG" in nsg.fix


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


def test_run_backup_protected_no_recovery_point_warns_not_fails():
    """Protected VM with no RP yet → warn 'first backup pending', NOT fail 'not configured'."""
    c = _connector(backup={
        "ok": False, "iam": False, "vault": "rsv-annatar", "protected": True,
        "no_recovery_point": True,
        "error": "vm protected in 'rsv-annatar' but has no recovery point yet",
    })
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "warn"
    assert "first backup pending" in bk.message.lower()
    assert "backup-now" in bk.fix          # trigger first backup
    assert "enable-for-vm" not in bk.fix   # NOT the "not linked" guidance


def test_backup_check_vmss_instance_skipped_not_failed():
    """A VMSS instance (AKS node) → backup check is 'skip', not a fail with enable-for-vm."""
    c = _connector(backup={"ok": False, "not_backupable": True, "vault": "rsv-annatar",
                           "error": "VMSS instance"})
    result = run(RESOURCE_ID, c)
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "skip"
    assert "enable-for-vm" not in bk.fix
    assert bk.data.get("not_backupable") is True
    assert result.ready is True  # skip doesn't block readiness


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


# ── Échantillonnage Perf (troisième passe, T6 / L14) ─────────────────────────────

class _PerfDet:
    def __init__(self, rows):
        self.rows = rows

    def run_query(self, query, timespan=None):
        return self.rows


def test_perf_sampling_fine_coarse_and_missing():
    """The ransomware rule never fired at Azure's default 60-s sampling, and is blind
    without the counter — both silent. The audit says which mode the VM is in."""
    from glorfindel.audit import _check_perf_sampling
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    fine = _check_perf_sampling(rid, "ws", _PerfDet([{"n": 361, "step": 10, "gaps": 360}]))
    assert fine.status == "ok" and "fin" in fine.message
    coarse = _check_perf_sampling(rid, "ws", _PerfDet([{"n": 61, "step": 60, "gaps": 60}]))
    assert coarse.status == "warn" and "grossier" in coarse.message
    missing = _check_perf_sampling(rid, "ws", _PerfDet([]))
    assert missing.status == "warn" and "aveugle" in missing.message and missing.fix




# ── P4 : la couverture de détection d'une VM (septième passe) ────────────────────

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


class _Rule:
    def __init__(self, name, query, *, auto_apply=True, resource_id="", enabled=True, ttp="T0000"):
        self.name, self.query, self.auto_apply = name, query, auto_apply
        self.resource_id, self.enabled, self.ttp = resource_id, enabled, ttp


_SHIPPED = [
    _Rule("ransomware-disk-write", "let samples = Perf | where CounterName == 'Disk Write Bytes/sec'"),
    _Rule("ssh-brute-force", "Syslog | where Facility == 'auth'"),
    _Rule("data-exfiltration-blob", "StorageBlobLogs // chunked uploads | where OperationName == 'PutBlob'"),
]


def test_perf_sampling_does_not_read_a_cadence_from_the_boot_batch():
    """Measured on the bench (15/10): the agent's first upload after a boot sends 6 samples
    under one timestamp. The step read ~0 s and the check claimed the fine mode."""
    from glorfindel.audit import _check_perf_sampling
    boot = _check_perf_sampling(_RID, "ws", _PerfDet([{"n": 6, "step": None, "gaps": 0}]))
    assert boot.status == "warn" and "pas encore mesurable" in boot.message
    assert boot.data == {"present": True, "samples": 6, "step_s": None}
    # The batch, then samples the agent sent with gaps of 25, 20, 10, 20 s (measured): the
    # query keeps the smallest gap between single-sample seconds — 10 s, the real cadence.
    later = _check_perf_sampling(_RID, "ws", _PerfDet([{"n": 10, "step": 10, "gaps": 3}]))
    assert later.status == "ok" and later.data["step_s"] == 10


def test_perf_sampling_says_whether_the_counter_is_present():
    from glorfindel.audit import _check_perf_sampling
    assert _check_perf_sampling(_RID, "ws", _PerfDet([{"n": 361, "step": 10, "gaps": 360}])).data == {
        "present": True, "samples": 361, "step_s": 10}
    assert _check_perf_sampling(_RID, "ws", _PerfDet([])).data == {"present": False}


class _Boom:
    def run_query(self, query, timespan=None):
        raise RuntimeError("LAW unreachable")


def test_syslog_present_missing_and_unreadable():
    from glorfindel.audit import _check_syslog
    seen = _check_syslog(_RID, "ws", _PerfDet([{"n": 42, "facilities": "auth, authpriv"}]))
    assert seen.status == "ok" and seen.data["present"] is True and "authpriv" in seen.message
    none = _check_syslog(_RID, "ws", _PerfDet([{"n": 0, "facilities": ""}]))
    assert none.status == "warn" and none.data == {"present": False} and "aveugles" in none.message and none.fix
    assert _check_syslog(_RID, "ws", _Boom()).data == {"present": None}


def test_rule_table_is_the_first_table_the_query_names():
    from glorfindel.audit import rule_table
    assert [rule_table(r.query) for r in _SHIPPED] == ["Perf", "Syslog", "StorageBlobLogs"]
    assert rule_table("nothing here") == ""


def test_shipped_rules_read_a_known_table():
    """Every shipped rule maps to a table the coverage knows — a new one would show as « ? »."""
    from glorfindel.audit import _load_rules, rule_table
    rules, _ = _load_rules()
    assert rules and all(rule_table(r.query) for r in rules)


def test_coverage_says_what_each_rule_can_see():
    from glorfindel.audit import rule_coverage
    cov = rule_coverage(_SHIPPED, _RID, {"perf": False, "syslog": True}, {})
    assert {r["name"]: r["state"] for r in cov} == {
        "ransomware-disk-write": "blind", "ssh-brute-force": "covered", "data-exfiltration-blob": "not_vm"}
    unknown = rule_coverage(_SHIPPED[:1], _RID, {"perf": None, "syslog": None}, {})
    assert unknown[0]["state"] == "unknown"


def test_coverage_errors_exclusions_disabled_and_other_vms():
    from glorfindel.audit import rule_coverage
    rules = [*_SHIPPED,
             _Rule("off", "Syslog | x", enabled=False),
             _Rule("pinned-elsewhere", "Syslog | x", auto_apply=False, resource_id=_RID + "-other"),
             _Rule("pinned-here", "Syslog | x", auto_apply=False, resource_id=_RID.upper())]
    status = {"ssh-brute-force": {"last_error": "Forbidden"}}
    cov = {r["name"]: r for r in rule_coverage(
        rules, _RID, {"perf": True, "syslog": True}, status,
        is_excluded=lambda vm, rule: vm == "vm" and rule == "ransomware-disk-write")}
    assert cov["ransomware-disk-write"]["state"] == "excluded"
    assert cov["ssh-brute-force"]["state"] == "error" and cov["ssh-brute-force"]["error"] == "Forbidden"
    assert cov["off"]["state"] == "disabled"
    assert "pinned-elsewhere" not in cov and cov["pinned-here"]["state"] == "covered"


def test_coverage_check_flags_a_blind_vm(monkeypatch):
    """P4: a VM the rules can't see no longer looks normal on its card."""
    from glorfindel import audit
    from glorfindel.audit import AuditCheck
    monkeypatch.setattr(audit, "_load_rules", lambda: (_SHIPPED, None))
    monkeypatch.setattr("glorfindel.detection_rules._load_status", lambda: {})
    perf = AuditCheck("detection", "Disk write sampling", "warn", "", data={"present": False})
    syslog = AuditCheck("detection", "Syslog", "ok", "", data={"present": True})
    blind = audit._check_rule_coverage(_RID, [perf, syslog])
    assert blind.status == "warn" and "ransomware-disk-write (Perf) aveugle" in blind.message
    assert [r["state"] for r in blind.data["rules"]] == ["blind", "covered", "not_vm"]
    perf.data["present"] = True
    assert audit._check_rule_coverage(_RID, [perf, syslog]).status == "ok"
    monkeypatch.setattr(audit, "_load_rules", lambda: ([], None))
    assert audit._check_rule_coverage(_RID, [perf, syslog]).status == "warn"


def test_audit_run_adds_the_detection_group_only_with_a_workspace(monkeypatch):
    from glorfindel import audit
    monkeypatch.setattr("glorfindel.detectors.detector_for",
                        lambda kind, workspace_id: _PerfDet([{"n": 361, "step": 10, "gaps": 360, "facilities": "auth"}]))
    monkeypatch.setattr(audit, "_load_rules", lambda: (_SHIPPED, None))
    with_ws = audit.run(RESOURCE_ID, _connector(), workspace_id="ws")
    det = [c.name for c in with_ws.checks if c.action == "detection"]
    assert det == ["Disk write sampling", "Syslog", "Detection rules"]
    without = audit.run(RESOURCE_ID, _connector(), workspace_id="")
    assert not [c for c in without.checks if c.action == "detection"]

def test_no_vault_configured_is_a_clear_failure():
    """The retired "rsv-annatar" default sent restores to a vault that no longer exists."""
    result = _audit_run(RESOURCE_ID, _connector())
    bk = next(ch for ch in result.checks if ch.name == "Backup vault")
    assert bk.status == "fail" and "Aucun coffre" in bk.message
