"""Persistent state for long-running Azure backup/restore jobs.

Jobs are persisted in ~/.glorfindel/active_jobs/<vm>.json so their status
is readable by both the CLI and the War Room API without coupling.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_JOBS_DIR = Path.home() / ".glorfindel" / "active_jobs"


def _path(vm_name: str) -> Path:
    _JOBS_DIR.mkdir(parents=True, exist_ok=True)
    return _JOBS_DIR / f"{vm_name}.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def save_job(vm_name: str, job: dict) -> None:
    _path(vm_name).write_text(json.dumps(job, default=str))


def get_job(vm_name: str) -> dict | None:
    p = _path(vm_name)
    return json.loads(p.read_text()) if p.exists() else None


def clear_job(vm_name: str) -> None:
    p = _path(vm_name)
    if p.exists():
        p.unlink()


def all_jobs() -> list[dict]:
    if not _JOBS_DIR.exists():
        return []
    result = []
    for f in _JOBS_DIR.glob("*.json"):
        try:
            result.append(json.loads(f.read_text()))
        except Exception:
            pass
    return result


def start_snapshot(resource_id: str, connector, vault: str = "rsv-annatar") -> dict:
    """Trigger a non-blocking RSV backup. Returns job metadata immediately."""
    vm_name = resource_id.split("/")[-1]
    snap_id = connector.snapshot(resource_id, vault=vault, wait=False)
    job = {
        "job_id": f"snapshot-{vm_name}-{_now()}",
        "type": "snapshot",
        "resource_id": resource_id,
        "vault": vault,
        "snap_id": snap_id,
        "status": "InProgress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }
    save_job(vm_name, job)
    return job


def start_restore(
    resource_id: str,
    connector,
    vault: str = "rsv-annatar",
    before_attack_time: str | None = None,
) -> dict:
    """Trigger a non-blocking restore. Blocks only on VM deallocation (~1-2 min).

    Post-restore: VM stays deallocated until started manually.
    Use 'az vm start' + 'glorfindel release' or the War Room after job completes.
    """
    vm_name = resource_id.split("/")[-1]
    result = connector.restore_from_backup(
        resource_id, vault=vault, before_attack_time=before_attack_time, wait=False
    )
    job = {
        "job_id": f"restore-{vm_name}-{_now()}",
        "type": "restore",
        "resource_id": resource_id,
        "vault": vault,
        "restore_job_name": result.get("job_name"),
        "rg": result.get("rg"),
        "recovery_point": result.get("recovery_point"),
        "recovery_point_time": str(result.get("recovery_point_time", "")),
        "status": "InProgress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }
    save_job(vm_name, job)
    return job
