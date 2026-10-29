"""Persistent state for long-running Azure backup/restore jobs.

Jobs are persisted in ~/.glorfindel/active_jobs/<vm>.json so their status
is readable by both the CLI and the console's API without coupling.
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


def _atomic_write(path: Path, text: str) -> None:
    """Same contract as actions._atomic_write_text: readers never see a torn file."""
    from glorfindel.actions import _atomic_write_text
    _atomic_write_text(path, text)


def save_job(vm_name: str, job: dict) -> None:
    _atomic_write(_path(vm_name), json.dumps(job, default=str))


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
        vault = job.get("vault", "")
        # Job lookups run in the VAULT's resource group (central vault ≠ VM RG).
        rg = job.get("vault_rg") or job.get("rg", "")
        if restore_job_name and rg:
            az_status = connector.restore_job_status(vault, rg, restore_job_name)
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


def record_snapshot_job(
    resource_id: str, snap_id: str, vault: str, vault_rg: str = "",
    *, overwrite_running: bool = True,
) -> dict | None:
    """Persist a snapshot job so the CLI, the console and the watch reconciler see it.

    overwrite_running=False (the agent's autonomous snapshot): keep a job that is still
    InProgress for this VM — there is one job file per VM, and overwriting a running
    restore's record would lose its tracking. Returns the job written, or None.
    """
    vm_name = resource_id.split("/")[-1]
    if not overwrite_running:
        current = get_job(vm_name)
        if current and current.get("status") == "InProgress":
            return None
    job = {
        "job_id": f"snapshot-{vm_name}-{_now()}",
        "type": "snapshot",
        "resource_id": resource_id,
        "vault": vault,
        "vault_rg": vault_rg,
        "snap_id": snap_id,
        "status": "InProgress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }
    save_job(vm_name, job)
    return job


def start_snapshot(
    resource_id: str, connector, vault: str = "", vault_rg: str = "",
) -> dict:
    """Trigger a non-blocking RSV backup. Returns job metadata immediately."""
    snap_id = connector.snapshot(resource_id, vault=vault, wait=False, vault_rg=vault_rg)
    return record_snapshot_job(resource_id, snap_id, vault, vault_rg)


def start_restore(
    resource_id: str,
    connector,
    vault: str = "",
    before_attack_time: str | None = None,
    staging_storage: str = "",
    vault_rg: str = "",
) -> dict:
    """Trigger a non-blocking restore. Blocks only on VM deallocation (~1-2 min).

    Post-restore: VM stays deallocated until started manually.
    Use 'az vm start' + 'glorfindel release' or the console after job completes.
    """
    vm_name = resource_id.split("/")[-1]
    result = connector.restore_from_backup(
        resource_id, vault=vault, before_attack_time=before_attack_time,
        wait=False, staging_storage=staging_storage, vault_rg=vault_rg,
    )
    job = {
        "job_id": f"restore-{vm_name}-{_now()}",
        "type": "restore",
        "resource_id": resource_id,
        "vault": vault,
        "restore_job_name": result.get("job_name"),
        "rg": result.get("rg"),
        "vault_rg": result.get("vault_rg") or vault_rg,
        "recovery_point": result.get("recovery_point"),
        "recovery_point_time": str(result.get("recovery_point_time", "")),
        "recovery_point_vault_tier": bool(result.get("recovery_point_vault_tier")),
        "before_attack_time": before_attack_time,
        "status": "InProgress",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
    }
    save_job(vm_name, job)
    _atomic_write(_RECOVERY_DIR / f"{vm_name}.json", json.dumps({
        "last_restore_at": datetime.now(timezone.utc).isoformat(),
        "resource_id": resource_id,
    }))
    return job


# ── One restore at a time per VM (SEC4c) ───────────────────────────────────────
# Two restores of one VM — two forms in Discord, a double click, two tabs of the console, the
# TUI — would each deallocate it and swap its disks. A restore claims the VM before it starts
# (a file, under a file lock), holds the claim while it runs, and is refused while another one
# claims it or its job is still InProgress.
#
# SEC7: the claim is held by an flock on its file for as long as the restore runs — a `--wait`
# restore of a large disk lasts hours, and writes no job file. The system releases the lock when
# the process dies: a claim no process holds any more is one left behind, still refusing for
# _CLAIM_MAX_AGE_S after it was taken (its restore may still run on Azure), and said with its
# path, its expiry and what to check before removing it. Each claim carries its own token:
# leaving, a restore removes its own claim only.
_CLAIM_MAX_AGE_S = 2 * 3600       # a claim left by a process that died stops holding the VM


class RestoreBusy(RuntimeError):
    """Another restore of this VM is in progress."""


def _claim_held(path: Path) -> bool | None:
    """Is the claim's file locked by a live process? None when it cannot be known (no flock
    here, the file unreadable): then only its age counts."""
    try:
        import fcntl
    except ImportError:
        return None
    try:
        with open(path, "rb") as fh:
            try:
                fcntl.flock(fh, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fh, fcntl.LOCK_UN)
            return False
    except OSError:
        return None


def restore_in_progress(vm_name: str) -> str:
    """Why a restore of `vm_name` is in progress, or ""."""
    import time
    try:
        job = get_job(vm_name)
    except (OSError, ValueError):
        job = None
    if job and job.get("type") == "restore" and job.get("status") == "InProgress":
        return (f"un restore de {vm_name} est en cours (job {job.get('restore_job_name') or job.get('job_id')}, "
                f"lancé le {job.get('started_at', '?')}) — `glorfindel jobs {vm_name} --refresh`")
    claim = _JOBS_DIR / f"{vm_name}.restore-claim"
    try:
        taken = claim.stat().st_mtime
    except OSError:
        return ""
    age = time.time() - taken
    held = _claim_held(claim)
    if held:
        return f"un restore de {vm_name} est en train de partir ou en cours (depuis {int(age)} s, son processus vit)"
    if age < _CLAIM_MAX_AGE_S:
        expires = datetime.fromtimestamp(taken + _CLAIM_MAX_AGE_S, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if held is False:
            return (f"un restore de {vm_name} a été lancé il y a {int(age)} s par un processus qui s'est arrêté : "
                    f"sa réclamation, {claim}, tient jusqu'à {expires}. Avant de la retirer, vérifier qu'aucun "
                    f"restore ne tourne encore sur Azure (le coffre, ses jobs : `az backup job list "
                    f"--status InProgress`) et que la VM n'est pas en cours d'échange de disques")
        return f"un restore de {vm_name} est en train de partir (depuis {int(age)} s ; réclamation {claim}, jusqu'à {expires})"
    return ""


class restore_claim:
    """`with restore_claim(vm):` — the VM claimed for one restore, or RestoreBusy."""

    def __init__(self, vm_name: str) -> None:
        self.vm_name = vm_name
        self.path = _JOBS_DIR / f"{vm_name}.restore-claim"
        self._fh = None
        self._token = ""

    def __enter__(self):
        import os
        import secrets
        import socket
        from glorfindel.response.locks import _file_lock
        _JOBS_DIR.mkdir(parents=True, exist_ok=True)
        with _file_lock(_JOBS_DIR / f"{self.vm_name}.restore.lock"):
            busy = restore_in_progress(self.vm_name)
            if busy:
                raise RestoreBusy(busy)
            self._token = f"{_now()} {socket.gethostname()} {os.getpid()} {secrets.token_hex(8)}"
            # Opened in place, never replaced: the lock lives on this file for the restore's
            # length; a claim left behind (no holder) is the same file, taken over.
            fh = open(self.path, "a+")
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:
                pass
            except BlockingIOError:
                fh.close()
                raise RestoreBusy(f"un restore de {self.vm_name} est en cours (sa réclamation est tenue)")
            fh.seek(0)
            fh.truncate()
            fh.write(self._token + "\n")
            fh.flush()
            os.utime(self.path)
            self._fh = fh
        return self

    def __exit__(self, *exc) -> bool:
        try:
            if self._read_token() == self._token:
                self.path.unlink()
        except OSError:
            pass
        finally:
            if self._fh is not None:
                self._fh.close()          # the lock goes with it
                self._fh = None
        return False

    def _read_token(self) -> str:
        try:
            return self.path.read_text().strip()
        except OSError:
            return ""
