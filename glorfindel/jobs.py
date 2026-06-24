"""Persistent state for long-running Azure backup/restore jobs.

Jobs are persisted in ~/.glorfindel/active_jobs/<vm>.json so their status
is readable by both the CLI and the War Room API without coupling.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_JOBS_DIR = Path.home() / ".glorfindel" / "active_jobs"
_RECOVERY_DIR = Path.home() / ".glorfindel" / "recovery"

# A snapshot is usually minutes; a restore / post-restore full backup tops out around
# a few hours. A job still InProgress past this is dead — the process died, or the Azure
# job record is gone — and the local file must stop claiming "InProgress" forever (a real
# snapshot sat InProgress for 10 days because nobody opened the jobs view to --refresh it).
_STALE_AGE_H = 24.0


def get_last_restore(vm_name: str) -> dict | None:
    """Return last restore metadata if triggered within 60 minutes, else None."""
    p = _RECOVERY_DIR / f"{vm_name}.json"
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        restore_time = datetime.fromisoformat(data["last_restore_at"])
        age_s = (datetime.now(timezone.utc) - restore_time).total_seconds()
        return data if age_s < 3600 else None
    except Exception:
        return None


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


def refresh_job(job: dict, connector) -> dict:
    """Poll Azure for an InProgress job's real status and update it in place.

    Single source of truth for the CLI (`jobs --refresh`), the API (`?refresh=true`) and
    the watch-loop reconciliation — previously duplicated, and the API copy handled only
    snapshots (a restore never reconciled there). No-op on a terminal job. Returns the
    (possibly mutated) job; the caller persists it if the status changed.
    """
    if job.get("status") != "InProgress":
        return job
    now = datetime.now(timezone.utc).isoformat()
    jtype = job.get("type")
    if jtype == "snapshot":
        result = connector.verify_snapshot(job.get("snap_id", ""))
        verified = result.get("verified")
        if verified is True:
            job.update({"status": "Completed", "completed_at": now})
        elif verified is False:
            job.update({"status": "Failed", "completed_at": now,
                        "error": result.get("error", result.get("status", "unknown"))})
    elif jtype == "restore":
        restore_job_name = job.get("restore_job_name")
        vault = job.get("vault", "rsv-annatar")
        rg = job.get("rg", "")
        if restore_job_name and rg:
            from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
            connector._ensure_clients()
            bc = RecoveryServicesBackupClient(connector._credential, connector._subscription_id)
            j = bc.job_details.get(vault, rg, restore_job_name)
            az_status = getattr(j.properties, "status", "Unknown")
            if az_status == "Completed":
                job.update({"status": "Completed", "completed_at": now})
            elif az_status in ("Failed", "Cancelled"):
                job.update({"status": "Failed", "completed_at": now, "error": az_status})
    return job


def reconcile_jobs(connector=None, max_age_h: float = _STALE_AGE_H) -> list[dict]:
    """Move InProgress jobs to a terminal state so the local file stops lying.

    Two layers: (1) with a connector, poll Azure (refresh_job) → Completed/Failed; (2) a
    deterministic fallback — a job still InProgress past max_age_h is marked 'Stale'
    (no Azure needed), for jobs Azure can't resolve (record gone, poll error) or when no
    connector is available. The on-demand `jobs --refresh` only ran when an operator
    looked; nobody looking is exactly how a job lingers forever. Called each watch cycle.

    Returns the jobs whose status changed (for logging).
    """
    changed: list[dict] = []
    now = datetime.now(timezone.utc)
    for job in all_jobs():
        if job.get("status") != "InProgress":
            continue
        before = job.get("status")
        if connector is not None:
            try:
                refresh_job(job, connector)
            except Exception:
                pass  # Azure unreachable → fall through to the staleness guard
        if job.get("status") == "InProgress":
            try:
                age_h = (now - datetime.fromisoformat(job["started_at"])).total_seconds() / 3600
            except (KeyError, ValueError, TypeError):
                age_h = max_age_h + 1.0  # unparseable start → treat as stale
            if age_h > max_age_h:
                job.update({
                    "status": "Stale",
                    "completed_at": now.isoformat(),
                    "error": f"no terminal state after {age_h:.0f}h — job lost, re-verify manually",
                })
        if job.get("status") != before:
            vm = job.get("resource_id", "").rsplit("/", 1)[-1] or job.get("job_id", "job")
            save_job(vm, job)
            changed.append(job)
    return changed


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
    _RECOVERY_DIR.mkdir(parents=True, exist_ok=True)
    (_RECOVERY_DIR / f"{vm_name}.json").write_text(json.dumps({
        "last_restore_at": datetime.now(timezone.utc).isoformat(),
        "resource_id": resource_id,
    }))
    return job
