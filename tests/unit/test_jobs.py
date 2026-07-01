"""Tests for glorfindel/jobs.py — async job state management."""
from __future__ import annotations

from unittest.mock import MagicMock
from pathlib import Path

import pytest


@pytest.fixture()
def jobs_dir(tmp_path, monkeypatch):
    """Redirect _JOBS_DIR to a temp directory."""
    import glorfindel.jobs as _jobs
    monkeypatch.setattr(_jobs, "_JOBS_DIR", tmp_path / ".glorfindel" / "active_jobs")
    return tmp_path / ".glorfindel" / "active_jobs"


_RESOURCE_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
_VM_NAME = "vm"


def test_get_job_returns_none_when_no_file(jobs_dir):
    from glorfindel.jobs import get_job
    assert get_job(_VM_NAME) is None


def test_save_and_get_job_roundtrip(jobs_dir):
    from glorfindel.jobs import save_job, get_job
    job = {"job_id": "test-123", "type": "snapshot", "status": "InProgress"}
    save_job(_VM_NAME, job)
    assert get_job(_VM_NAME) == job


def test_clear_job_removes_file(jobs_dir):
    from glorfindel.jobs import save_job, get_job, clear_job
    save_job(_VM_NAME, {"job_id": "test-123"})
    clear_job(_VM_NAME)
    assert get_job(_VM_NAME) is None


def test_clear_job_noop_when_no_file(jobs_dir):
    from glorfindel.jobs import clear_job
    clear_job(_VM_NAME)  # must not raise


def test_all_jobs_empty_when_dir_missing(tmp_path, monkeypatch):
    import glorfindel.jobs as _jobs
    monkeypatch.setattr(_jobs, "_JOBS_DIR", tmp_path / "nonexistent")
    from glorfindel.jobs import all_jobs
    assert all_jobs() == []


def test_all_jobs_returns_all(jobs_dir):
    from glorfindel.jobs import save_job, all_jobs
    save_job("vm1", {"job_id": "a"})
    save_job("vm2", {"job_id": "b"})
    result = all_jobs()
    ids = {j["job_id"] for j in result}
    assert ids == {"a", "b"}


def test_start_snapshot_calls_connector_wait_false(jobs_dir):
    from glorfindel.jobs import start_snapshot, get_job
    connector = MagicMock()
    connector.snapshot.return_value = "rsv:vault/rg/job123"

    job = start_snapshot(_RESOURCE_ID, connector, vault="rsv-annatar")

    connector.snapshot.assert_called_once_with(_RESOURCE_ID, vault="rsv-annatar", wait=False)
    assert job["type"] == "snapshot"
    assert job["status"] == "InProgress"
    assert job["snap_id"] == "rsv:vault/rg/job123"
    assert job["resource_id"] == _RESOURCE_ID

    stored = get_job(_VM_NAME)
    assert stored == job


def test_start_restore_calls_connector_wait_false(jobs_dir):
    from glorfindel.jobs import start_restore, get_job
    connector = MagicMock()
    connector.restore_from_backup.return_value = {
        "status": "restore_triggered",
        "job_name": "restore-job-abc",
        "vault": "rsv-annatar",
        "rg": "rg",
        "recovery_point": "rp-001",
        "recovery_point_time": "2026-06-08T10:00:00Z",
    }

    job = start_restore(_RESOURCE_ID, connector, vault="rsv-annatar",
                        before_attack_time="2026-06-08T09:00:00Z",
                        staging_storage="ststaging")

    connector.restore_from_backup.assert_called_once_with(
        _RESOURCE_ID, vault="rsv-annatar", before_attack_time="2026-06-08T09:00:00Z",
        wait=False, staging_storage="ststaging",
    )
    assert job["type"] == "restore"
    assert job["status"] == "InProgress"
    assert job["restore_job_name"] == "restore-job-abc"
    assert job["rg"] == "rg"

    stored = get_job(_VM_NAME)
    assert stored == job


def test_start_restore_writes_last_restore_at(tmp_path, monkeypatch):
    """start_restore must write ~/.glorfindel/recovery/<vm>.json with last_restore_at."""
    import glorfindel.jobs as _jobs
    monkeypatch.setattr(_jobs, "_JOBS_DIR", tmp_path / "active_jobs")
    monkeypatch.setattr(_jobs, "_RECOVERY_DIR", tmp_path / "recovery")
    from glorfindel.jobs import start_restore, get_last_restore

    connector = MagicMock()
    connector.restore_from_backup.return_value = {
        "status": "restore_triggered",
        "job_name": "restore-job-abc",
        "vault": "rsv-annatar",
        "rg": "rg",
        "recovery_point": "rp-001",
        "recovery_point_time": "2026-06-09T10:00:00Z",
    }
    start_restore(_RESOURCE_ID, connector, vault="rsv-annatar")
    rec = get_last_restore(_VM_NAME)
    assert rec is not None
    assert "last_restore_at" in rec
    assert rec["resource_id"] == _RESOURCE_ID


def test_get_last_restore_returns_none_when_no_file(tmp_path, monkeypatch):
    import glorfindel.jobs as _jobs
    monkeypatch.setattr(_jobs, "_RECOVERY_DIR", tmp_path / "recovery")
    from glorfindel.jobs import get_last_restore
    assert get_last_restore(_VM_NAME) is None


def test_get_last_restore_returns_none_when_older_than_one_hour(tmp_path, monkeypatch):
    import glorfindel.jobs as _jobs
    monkeypatch.setattr(_jobs, "_RECOVERY_DIR", tmp_path / "recovery")
    from glorfindel.jobs import get_last_restore
    import json
    from datetime import datetime, timezone, timedelta

    (tmp_path / "recovery").mkdir(parents=True)
    old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    (tmp_path / "recovery" / f"{_VM_NAME}.json").write_text(json.dumps({
        "last_restore_at": old_time,
        "resource_id": _RESOURCE_ID,
    }))
    assert get_last_restore(_VM_NAME) is None


def test_start_snapshot_job_id_contains_vm_name(jobs_dir):
    from glorfindel.jobs import start_snapshot
    connector = MagicMock()
    connector.snapshot.return_value = "rsv:v/r/j"
    job = start_snapshot(_RESOURCE_ID, connector)
    assert _VM_NAME in job["job_id"]
    assert job["job_id"].startswith("snapshot-")


# ── refresh_job ────────────────────────────────────────────────────────────────

def _hours_ago(h: float) -> str:
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()


def test_refresh_job_snapshot_completed(jobs_dir):
    from glorfindel.jobs import refresh_job
    conn = MagicMock()
    conn.verify_snapshot.return_value = {"verified": True}
    job = {"type": "snapshot", "status": "InProgress", "snap_id": "x"}
    refresh_job(job, conn)
    assert job["status"] == "Completed"
    assert job["completed_at"]


def test_refresh_job_snapshot_failed_carries_error(jobs_dir):
    from glorfindel.jobs import refresh_job
    conn = MagicMock()
    conn.verify_snapshot.return_value = {"verified": False, "error": "boom"}
    job = {"type": "snapshot", "status": "InProgress", "snap_id": "x"}
    refresh_job(job, conn)
    assert job["status"] == "Failed"
    assert job["error"] == "boom"


def test_refresh_job_noop_on_terminal(jobs_dir):
    from glorfindel.jobs import refresh_job
    conn = MagicMock()
    job = {"type": "snapshot", "status": "Completed"}
    refresh_job(job, conn)
    conn.verify_snapshot.assert_not_called()
    assert job["status"] == "Completed"


# ── reconcile_jobs ─────────────────────────────────────────────────────────────

def test_reconcile_marks_old_job_stale_without_connector(jobs_dir):
    """The core zombie fix: an InProgress job past the staleness threshold is moved to a
    terminal 'Stale' state deterministically — no Azure needed (the 2026-06-14 snapshot
    that sat InProgress for 10 days because nobody opened the jobs view)."""
    from glorfindel.jobs import save_job, reconcile_jobs, get_job
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "InProgress", "started_at": _hours_ago(240)})
    changed = reconcile_jobs(connector=None)
    assert len(changed) == 1
    assert get_job("vm")["status"] == "Stale"
    assert "lost" in get_job("vm")["error"]


def test_reconcile_leaves_fresh_job_inprogress(jobs_dir):
    from glorfindel.jobs import save_job, reconcile_jobs, get_job
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "InProgress", "started_at": _hours_ago(1)})
    assert reconcile_jobs(connector=None) == []
    assert get_job("vm")["status"] == "InProgress"


def test_reconcile_polls_azure_and_completes(jobs_dir):
    from glorfindel.jobs import save_job, reconcile_jobs, get_job
    conn = MagicMock()
    conn.verify_snapshot.return_value = {"verified": True}
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "InProgress", "started_at": _hours_ago(1), "snap_id": "x"})
    reconcile_jobs(connector=conn)
    assert get_job("vm")["status"] == "Completed"


def test_reconcile_ignores_terminal_jobs(jobs_dir):
    from glorfindel.jobs import save_job, reconcile_jobs
    conn = MagicMock()
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "Completed", "started_at": _hours_ago(240)})
    assert reconcile_jobs(connector=conn) == []
    conn.verify_snapshot.assert_not_called()


def test_reconcile_unparseable_started_is_stale(jobs_dir):
    from glorfindel.jobs import save_job, reconcile_jobs, get_job
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "InProgress", "started_at": "not-a-date"})
    reconcile_jobs(connector=None)
    assert get_job("vm")["status"] == "Stale"


def test_reconcile_azure_error_falls_through_to_staleness(jobs_dir):
    """A failing Azure poll must not crash reconciliation; an old job still gets the
    deterministic Stale fallback."""
    from glorfindel.jobs import save_job, reconcile_jobs, get_job
    conn = MagicMock()
    conn.verify_snapshot.side_effect = RuntimeError("azure down")
    save_job("vm", {"resource_id": _RESOURCE_ID, "type": "snapshot",
                    "status": "InProgress", "started_at": _hours_ago(240), "snap_id": "x"})
    reconcile_jobs(connector=conn)
    assert get_job("vm")["status"] == "Stale"
