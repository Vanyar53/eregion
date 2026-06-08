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

    job = start_restore(_RESOURCE_ID, connector, vault="rsv-annatar", before_attack_time="2026-06-08T09:00:00Z")

    connector.restore_from_backup.assert_called_once_with(
        _RESOURCE_ID, vault="rsv-annatar", before_attack_time="2026-06-08T09:00:00Z", wait=False
    )
    assert job["type"] == "restore"
    assert job["status"] == "InProgress"
    assert job["restore_job_name"] == "restore-job-abc"
    assert job["rg"] == "rg"

    stored = get_job(_VM_NAME)
    assert stored == job


def test_start_snapshot_job_id_contains_vm_name(jobs_dir):
    from glorfindel.jobs import start_snapshot
    connector = MagicMock()
    connector.snapshot.return_value = "rsv:v/r/j"
    job = start_snapshot(_RESOURCE_ID, connector)
    assert _VM_NAME in job["job_id"]
    assert job["job_id"].startswith("snapshot-")
