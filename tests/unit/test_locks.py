"""The locks across processes (L27): the watch, the War Room and the CLI are separate
processes; only the flock part of `_vm_lock` / `_quarantine_lock` keeps them apart. The
invariant machine runs threads of one process — this is the other half."""
from __future__ import annotations

import json
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


# ── SEC3 (V-10): the escalations store, written by several processes ──────────────────

_STORE_WRITER = textwrap.dedent("""
    import sys
    from pathlib import Path
    from glorfindel import escalations
    store, me, n = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    escalations._STORE = store
    for i in range(n):
        cid = escalations.record(signal_id=f"{me}-{i}", resource_id=f"/subscriptions/s/vm/{me}-{i}",
                                 action="isolate_vm", escalation_type="mode_hold", reason="r")
        if i % 3 == 0:
            escalations.resolve(cid, note="done")
        elif i % 3 == 1:
            escalations.set_verdict(cid, "right")
""")

_STORE_READER = textwrap.dedent("""
    import json, sys
    from pathlib import Path
    store, stop, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    reads = bad = 0
    while not stop.exists():
        try:
            text = store.read_text()
        except FileNotFoundError:
            continue
        reads += 1
        for line in text.splitlines():
            try:
                json.loads(line)
            except ValueError:
                bad += 1
        if text and not text.endswith("\\n"):
            bad += 1
    out.write_text(json.dumps({"reads": reads, "bad": bad}))
""")


def measure_store(tmp_path: Path, writers: int = 6, cards: int = 50) -> dict:
    """`writers` processes each record `cards` cards (one VM each), resolving a third and
    judging a third, while a reader reads the store in a loop: what is lost, what was read
    half-written. The writer imports `glorfindel.escalations` from PYTHONPATH — pointed at
    an older checkout, it measures that version (SEC3's report: before and after)."""
    store = tmp_path / "escalations.jsonl"
    stop, out = tmp_path / "stop", tmp_path / "reader.json"
    env = {**os.environ, "PYTHONPATH": os.environ.get("SEC3_STORE_PYTHONPATH")
           or str(Path(__file__).resolve().parents[2])}
    reader = subprocess.Popen([sys.executable, "-c", _STORE_READER, str(store), str(stop), str(out)], env=env)
    procs = [subprocess.Popen([sys.executable, "-c", _STORE_WRITER, str(store), f"w{k}", str(cards)], env=env)
             for k in range(writers)]
    try:
        codes = [p.wait(timeout=120) for p in procs]
    finally:
        stop.touch()
        reader.wait(timeout=60)
    entries = []
    for line in store.read_text().splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            pass
    by_id = {e["signal_id"]: e for e in entries}
    want = {f"w{k}-{i}" for k in range(writers) for i in range(cards)}
    resolved = {s for s in want if int(s.rsplit("-", 1)[1]) % 3 == 0}
    judged = {s for s in want if int(s.rsplit("-", 1)[1]) % 3 == 1}
    return {
        "codes": codes, "written": writers * cards, "lost": len(want - set(by_id)),
        "duplicated": len(entries) - len(by_id),
        "resolve_lost": len({s for s in resolved if s in by_id and by_id[s]["status"] != "resolved"}),
        "verdict_lost": len({s for s in judged if s in by_id and by_id[s].get("verdict") != "right"}),
        **json.loads(out.read_text()),
    }


def test_concurrent_writers_lose_no_card_and_no_reader_sees_half_a_store(tmp_path):
    """Lab L-12 measured 76 cards lost out of 301 concurrent writes, and a truncated read:
    each write read the store, changed it, and wrote it back over the others'. Under the
    store's lock, rewritten whole: nothing lost, nothing read half-written."""
    got = measure_store(tmp_path)
    assert got["codes"] == [0] * 6
    assert got["reads"] > 0
    assert {k: got[k] for k in ("lost", "duplicated", "resolve_lost", "verdict_lost", "bad")} == {
        "lost": 0, "duplicated": 0, "resolve_lost": 0, "verdict_lost": 0, "bad": 0}, got


_FILE_HOLDER = textwrap.dedent("""
    import sys, time
    from pathlib import Path
    from glorfindel.response.locks import _file_lock
    lock_file, ready, hold = Path(sys.argv[1]), Path(sys.argv[2]), float(sys.argv[3])
    with _file_lock(lock_file):
        ready.write_text("in")
        time.sleep(hold)
""")


def test_the_store_lock_gives_up_within_its_timeout(tmp_path):
    """`_file_lock(timeout=…)` (I3F, #292), what the invariant machine's scheduler takes it
    with: behind another process's flock, or another thread of this one, it raises
    TimeoutError within its bound and holds nothing — the lock is free again after."""
    import threading
    from glorfindel.response.locks import _file_lock
    lock_file = tmp_path / "escalations.jsonl.lock"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    holder = subprocess.Popen([sys.executable, "-c", _FILE_HOLDER, str(lock_file),
                               str(tmp_path / "ready"), "3"], env=env)
    try:
        deadline = time.monotonic() + 30
        while not (tmp_path / "ready").exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.05)
        for timeout in (0, 0.5):
            started = time.monotonic()
            with pytest.raises(TimeoutError):
                with _file_lock(lock_file, timeout=timeout):
                    pass
            assert time.monotonic() - started < 2.5
    finally:
        holder.wait(timeout=60)
    with _file_lock(lock_file, timeout=0):          # the other process gone: free, nothing held here
        pass

    taken, release = threading.Event(), threading.Event()

    def hold():
        with _file_lock(lock_file):
            taken.set()
            release.wait(10)

    th = threading.Thread(target=hold)
    th.start()
    try:
        assert taken.wait(10)
        with pytest.raises(TimeoutError):
            with _file_lock(lock_file, timeout=0):
                pass
    finally:
        release.set()
        th.join(10)
    with _file_lock(lock_file, timeout=0):
        with _file_lock(lock_file, timeout=0):      # re-entrant within a thread
            pass
