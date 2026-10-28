"""One writer at a time: per VM, and per quarantine NSG — a thread lock plus an flock
shared with the War Room and the CLI (moved from actions.py, A1).
"""
from __future__ import annotations

import contextlib
import threading

from glorfindel.response.ids import _parse_nsg_resource_id
from glorfindel.response.state import _ISOLATION_STATE_DIR


_QUARANTINE_LOCKS: dict[str, threading.Lock] = {}
_QUARANTINE_LOCKS_GUARD = threading.Lock()


@contextlib.contextmanager
def _quarantine_lock(nsg_id: str, timeout: float | None = None):
    """One writer at a time on a quarantine NSG (its creation, its tags): a thread lock
    (workers of one watch) plus an flock (the War Room and the CLI are other processes).
    Keyed `<rg>/<name>`, whether given an id or that pair. `timeout`: give up with
    TimeoutError after that many seconds (as _vm_lock)."""
    import hashlib
    ref = nsg_id.rstrip("/")
    key = ("/".join(_parse_nsg_resource_id(ref)) if "/providers/" in ref.lower() else ref).lower()
    with _QUARANTINE_LOCKS_GUARD:
        lock = _QUARANTINE_LOCKS.setdefault(key, threading.Lock())
    if not lock.acquire(timeout=-1 if timeout is None else timeout):
        raise TimeoutError(f"quarantine NSG {key} busy")
    try:
        lock_dir = _ISOLATION_STATE_DIR.parent / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_dir / f"quarantine-{hashlib.sha1(key.encode()).hexdigest()[:12]}.lock", "a") as fh:
            try:
                import fcntl
                import time as _time
                if timeout is None:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                else:
                    deadline = _time.monotonic() + timeout
                    while True:
                        try:
                            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if _time.monotonic() >= deadline:
                                raise TimeoutError(f"quarantine NSG {key} busy (another process)")
                            _time.sleep(0.2)
            except ImportError:
                pass
            yield
    finally:
        lock.release()


_VM_LOCKS: dict[str, threading.RLock] = {}
_VM_LOCK_DEPTH = threading.local()


@contextlib.contextmanager
def _vm_lock(vm_name: str, timeout: float | None = None):
    """One writer at a time per VM (third review, T2): isolate, release, block, unblock
    and the reassertion. A thread lock (watch workers, reassert loop) plus an flock
    (the War Room and the CLI are other processes). Re-entrant within a thread — the
    reassertion re-isolates while holding it.

    `timeout` (background tasks): give up after that many seconds with TimeoutError
    instead of waiting behind a write that can last minutes (a session cut through Run
    Command) — fourth review, Q10/Q12. Writers keep waiting: they must serialise."""
    import hashlib
    key = (vm_name or "").lower()
    with _QUARANTINE_LOCKS_GUARD:
        lock = _VM_LOCKS.setdefault(key, threading.RLock())
    depth = getattr(_VM_LOCK_DEPTH, "d", None)
    if depth is None:
        depth = _VM_LOCK_DEPTH.d = {}
    if not lock.acquire(timeout=-1 if timeout is None else timeout):
        raise TimeoutError(f"VM {vm_name} busy (another write in progress)")
    try:
        if depth.get(key):
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        lock_dir = _ISOLATION_STATE_DIR.parent / "locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_dir / f"vm-{hashlib.sha1(key.encode()).hexdigest()[:12]}.lock", "a") as fh:
            try:
                import fcntl
                import time as _time
                if timeout is None:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                else:
                    deadline = _time.monotonic() + timeout
                    while True:
                        try:
                            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except BlockingIOError:
                            if _time.monotonic() >= deadline:
                                raise TimeoutError(f"VM {vm_name} busy (another process is writing)")
                            _time.sleep(0.2)
            except ImportError:
                pass
            depth[key] = 1
            try:
                yield
            finally:
                depth[key] = 0
    finally:
        lock.release()


_FILE_LOCKS: dict[str, threading.RLock] = {}
_FILE_LOCK_DEPTH = threading.local()


@contextlib.contextmanager
def _file_lock(lock_file):
    """One read-modify-write at a time of a file the watch, the console, the bot and the
    CLI all write (the escalations store — SEC3, V-10): a thread lock plus an flock on
    `lock_file`, as _vm_lock. Re-entrant within a thread. Writers wait: they must
    serialise, and each holds it for one rewrite of a local file."""
    from pathlib import Path
    path = Path(lock_file)
    key = str(path)
    with _QUARANTINE_LOCKS_GUARD:
        lock = _FILE_LOCKS.setdefault(key, threading.RLock())
    depth = getattr(_FILE_LOCK_DEPTH, "d", None)
    if depth is None:
        depth = _FILE_LOCK_DEPTH.d = {}
    with lock:
        if depth.get(key):
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with open(path, "a") as fh:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:
                pass
            depth[key] = 1
            try:
                yield
            finally:
                depth[key] = 0
