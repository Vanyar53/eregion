"""The locks across processes (L27): the watch, the War Room and the CLI are separate
processes; only the flock part of `_vm_lock` / `_quarantine_lock` keeps them apart. The
invariant machine runs threads of one process — this is the other half."""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="flock: POSIX only")

_WORKER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from glorfindel import actions
    home, kind, name, log, hold = Path(sys.argv[1]), sys.argv[2], sys.argv[3], Path(sys.argv[4]), float(sys.argv[5])
    actions._ISOLATION_STATE_DIR = home / "isolation"
    lock = actions._vm_lock(name) if kind == "vm" else actions._quarantine_lock(name)
    with lock:
        with log.open("a") as fh:
            fh.write(f"in {time.monotonic():.6f}\\n")
        time.sleep(hold)
        with log.open("a") as fh:
            fh.write(f"out {time.monotonic():.6f}\\n")
""")


def _run_workers(tmp_path: Path, kind: str, name: str, n: int = 4, hold: float = 0.15) -> list[str]:
    log = tmp_path / f"{kind}.log"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(tmp_path), kind, name, str(log), str(hold)],
                              env=env) for _ in range(n)]
    for p in procs:
        assert p.wait(timeout=60) == 0
    return log.read_text().split()[0::2]


@pytest.mark.parametrize("kind,name", [("vm", "web"), ("quarantine", "rg-sec/nsg-glorfindel-quarantine-westeurope")])
def test_one_process_at_a_time(tmp_path, kind, name):
    """Four processes take the same lock: their critical sections never overlap — every
    `in` is followed by its own `out` before the next `in`."""
    marks = _run_workers(tmp_path, kind, name)
    assert marks == ["in", "out"] * 4, marks


def test_the_vm_lock_is_by_name_whatever_the_case(tmp_path):
    """The canonical id and Log Analytics' lowercase id reach the same lock."""
    log = tmp_path / "vm.log"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(tmp_path), "vm", vm, str(log), "0.15"], env=env)
             for vm in ("Db--01", "db--01", "DB--01")]
    for p in procs:
        assert p.wait(timeout=60) == 0
    assert log.read_text().split()[0::2] == ["in", "out"] * 3


def test_a_background_task_gives_up_on_a_lock_held_by_another_process(tmp_path):
    """The reassertion waits a bounded time (timeout) behind a write in another process,
    then lets it be — it doesn't queue behind a release that can take minutes."""
    from glorfindel import actions
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    holder = subprocess.Popen([sys.executable, "-c", _WORKER, str(tmp_path), "vm", "web",
                               str(tmp_path / "h.log"), "3"], env=env)
    try:
        deadline = time.monotonic() + 30
        while not (tmp_path / "h.log").exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.05)
        old = actions._ISOLATION_STATE_DIR
        actions._ISOLATION_STATE_DIR = tmp_path / "isolation"
        try:
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                with actions._vm_lock("web", timeout=0.5):
                    pass
            assert time.monotonic() - started < 2.5
        finally:
            actions._ISOLATION_STATE_DIR = old
    finally:
        holder.wait(timeout=60)
