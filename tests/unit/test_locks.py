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


class _ReadMidWrite:
    """A file being written, a reader reading the store (`look`) at several cuts of each write — a
    quarter, a half, three quarters, and one character before its end: never only on a line's edge,
    where a store rewritten in place would read as the one before (CI6e, review: two cards of one
    length, cut at the half, read whole). The moments a reader in another process may fall on."""

    def __init__(self, f, look):
        self._f, self._look = f, look

    def write(self, text):
        cuts = sorted({c for c in (len(text) // 4, len(text) // 2, 3 * len(text) // 4, len(text) - 1)
                       if 0 < c < len(text)})
        done, n = 0, 0
        for cut in cuts:
            n += self._f.write(text[done:cut])
            self._f.flush()
            self._look()
            done = cut
        return n + self._f.write(text[done:])

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._f.__exit__(*exc)

    def __getattr__(self, name):
        return getattr(self._f, name)


def test_a_concurrent_reader_mid_write_reads_the_store_whole_never_half(monkeypatch):
    """CI6e (#553, M1223, M1224): the race above reads half a store only at times. Here the reader
    reads at the worst moments, at every write: a quarter, a half, three quarters of it done, and
    all but its last character. The store is rewritten whole, through a temporary file — the reader
    reads it as it was, whole: never a store cut short (rewritten in place, M1223), nor half a line
    (a card appended, M1224). The two cards differ in length: no cut falls on the first's end."""
    import builtins
    import io
    from glorfindel import escalations
    store = escalations._STORE                       # the conftest's: in this test's tmp_path
    escalations.record(signal_id="s-1", resource_id="/subscriptions/s/vm/a", action="isolate_vm",
                       escalation_type="mode_hold", reason="r")
    before, seen, real_open = store.read_text(), [], io.open

    def opening(file, mode="r", *args, **kwargs):
        f = real_open(file, mode, *args, **kwargs)
        here = isinstance(file, int) or str(file).startswith(str(store.parent))
        return _ReadMidWrite(f, lambda: seen.append(store.read_text())) if here and set(mode) & set("wa") else f
    with monkeypatch.context() as m:
        m.setattr(io, "open", opening)               # Path.open, os.fdopen
        m.setattr(builtins, "open", opening)         # open()
        escalations.record(signal_id="s-2", resource_id="/subscriptions/s/vm/b-of-another-length",
                           action="isolate_vm", escalation_type="mode_hold", reason="r, said at more length")
    after = store.read_text()
    assert seen, "no write of the store went through open: nothing was read mid-write"
    assert after.startswith(before) and len(after.splitlines()) == 2
    assert len(seen) >= 4 and len(after) != 2 * len(before)
    assert all(text in (before, after) for text in seen), seen


_HOLDER_UNTIL = textwrap.dedent("""
    import fcntl, sys, time
    from pathlib import Path
    lock_file, ready, stop = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    with open(lock_file, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        ready.write_text("in")
        deadline = time.monotonic() + 60
        while not stop.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
""")


def _waits_for_another_process(tmp_path: Path, lock_file: Path, write) -> None:
    """Another process holds `lock_file`'s flock (as any version of the code takes it: flock on
    the file): `write`, in a thread of this one, waits — and goes through once it lets go."""
    import threading
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    ready, stop = tmp_path / "held", tmp_path / "let-go"
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER_UNTIL, str(lock_file), str(ready), str(stop)],
                              env=env)
    done = threading.Event()
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.05)
        threading.Thread(target=lambda: (write(), done.set()), daemon=True).start()
        assert not done.wait(0.6), "written while another process held the lock"
    finally:
        stop.touch()
        assert holder.wait(timeout=60) == 0
    assert done.wait(30), "never written once the other process let go"


def test_the_incident_registry_waits_for_another_process_s_write(tmp_path):
    """CI6e (#553, M2915): the race below loses an incident between two processes only at times.
    Here, every time: while another process holds the registry's flock, a write of this one waits —
    its thread lock alone would let it through."""
    from glorfindel.incidents import IncidentRegistry
    path = tmp_path / "incidents.jsonl"
    reg = IncidentRegistry(path=path, ttl_s=3600)
    _waits_for_another_process(tmp_path, path.with_name(path.name + ".lock"),
                               lambda: reg.get_or_create("/subscriptions/s/vm/a", ttp="T1486"))
    assert reg.get_active("/subscriptions/s/vm/a") is not None


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


# ── SEC4b: the proposed rules' store, written by several processes ────────────────────

_PROPOSALS_WRITER = textwrap.dedent("""
    import sys
    from pathlib import Path
    from glorfindel import proposed_rules
    store, me, n, base = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
    proposed_rules._STORE = store
    for i in range(n):
        pid = proposed_rules.record(
            run_id=f"{me}-{i}", ttp="T1486", resource_id=f"/subscriptions/s/vm/{me}-{i}",
            rule_name=f"rule-{me}-{i}", source="azure_monitor", workspace_id="", query="Perf",
            interval_s=60, explanation="e", confidence=0.5, analysis="a")
        if i % 3 == 0:
            proposed_rules.reject(pid)
        elif i % 3 == 1:
            proposed_rules.approve(pid, base)
""")


def measure_proposals(tmp_path: Path, writers: int = 4, proposals: int = 15) -> dict:
    """`writers` processes each record `proposals` proposals, rejecting a third and approving
    a third, while a reader reads the store in a loop: what is lost, what was read
    half-written. PYTHONPATH from SEC4B_STORE_PYTHONPATH measures another checkout (before
    and after, in SEC4b's report). Their HOME is the test's: approve writes the client's
    layer there."""
    store = tmp_path / "proposed_rules.jsonl"
    stop, out = tmp_path / "stop", tmp_path / "reader.json"
    root = Path(__file__).resolve().parents[2]
    (tmp_path / "home").mkdir()
    env = {**os.environ, "HOME": str(tmp_path / "home"),
           "PYTHONPATH": os.environ.get("SEC4B_STORE_PYTHONPATH") or str(root)}
    base = str(root / "rules" / "azure" / "detection_rules.yaml")
    reader = subprocess.Popen([sys.executable, "-c", _STORE_READER, str(store), str(stop), str(out)],
                              env=env, cwd=tmp_path)
    procs = [subprocess.Popen([sys.executable, "-c", _PROPOSALS_WRITER, str(store), f"w{k}", str(proposals), base],
                              env=env, cwd=tmp_path) for k in range(writers)]
    try:
        codes = [p.wait(timeout=300) for p in procs]
    finally:
        stop.touch()
        reader.wait(timeout=60)
    entries = []
    for line in store.read_text().splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            pass
    by_run = {e["run_id"]: e for e in entries}
    want = {f"w{k}-{i}" for k in range(writers) for i in range(proposals)}

    def status_lost(mod: int, status: str) -> int:
        return len({r for r in want if int(r.rsplit("-", 1)[1]) % 3 == mod and r in by_run
                    and by_run[r]["status"] != status})
    return {"codes": codes, "written": writers * proposals, "lost": len(want - set(by_run)),
            "duplicated": len(entries) - len(by_run), "reject_lost": status_lost(0, "rejected"),
            "approve_lost": status_lost(1, "approved"), **json.loads(out.read_text())}


def test_concurrent_proposals_lose_none_and_no_reader_sees_half_a_store(tmp_path):
    """record appended, approve and reject read the whole store and wrote it back over the
    others' (as the escalations before SEC3, V-10). Under the store's lock, rewritten
    whole: nothing lost, nothing read half-written."""
    got = measure_proposals(tmp_path)
    assert got["codes"] == [0] * 4
    assert got["reads"] > 0
    assert {k: got[k] for k in ("lost", "duplicated", "reject_lost", "approve_lost", "bad")} == {
        "lost": 0, "duplicated": 0, "reject_lost": 0, "approve_lost": 0, "bad": 0}, got


# ── SEC13 (V-10): the incident registry, written by the watch and `glorfindel respond` ──

_INCIDENTS_WRITER = textwrap.dedent("""
    import sys
    from pathlib import Path
    from glorfindel.incidents import IncidentRegistry
    path, me, n = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    reg = IncidentRegistry(path=path, ttl_s=3600)
    for i in range(n):
        inc = reg.get_or_create(f"/subscriptions/s/vm/{me}-{i}", ttp="T1486")
        reg.record_action(inc.incident_id, "snapshot", "ok")
        if i % 2 == 0:
            reg.resolve(inc.incident_id)
""")


def measure_incidents(tmp_path: Path, writers: int = 2, incidents: int = 60) -> dict:
    """`writers` processes — the watch and `glorfindel respond` are two — each open
    `incidents` incidents (one VM each), record an action on each and resolve one in two,
    while a reader reads the registry in a loop: what is lost, what was read half-written.
    PYTHONPATH from SEC13_INCIDENTS_PYTHONPATH measures another checkout (before and after)."""
    path = tmp_path / "incidents.jsonl"
    stop, out = tmp_path / "stop", tmp_path / "reader.json"
    env = {**os.environ, "PYTHONPATH": os.environ.get("SEC13_INCIDENTS_PYTHONPATH")
           or str(Path(__file__).resolve().parents[2])}
    reader = subprocess.Popen([sys.executable, "-c", _STORE_READER, str(path), str(stop), str(out)], env=env)
    procs = [subprocess.Popen([sys.executable, "-c", _INCIDENTS_WRITER, str(path), f"w{k}", str(incidents)],
                              env=env) for k in range(writers)]
    try:
        codes = [p.wait(timeout=180) for p in procs]
    finally:
        stop.touch()
        reader.wait(timeout=60)
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    by_vm = {r["resource_id"].rsplit("/", 1)[-1]: r for r in rows}
    want = {f"w{k}-{i}" for k in range(writers) for i in range(incidents)}
    return {
        "codes": codes, "lost": len(want - set(by_vm)), "duplicated": len(rows) - len(by_vm),
        "action_lost": len({v for v in want if v in by_vm and not by_vm[v]["actions_taken"]}),
        "resolve_lost": len({v for v in want if int(v.rsplit("-", 1)[1]) % 2 == 0 and v in by_vm
                             and by_vm[v]["state"] != "resolved"}),
        "mode": oct(path.stat().st_mode & 0o777),
        **json.loads(out.read_text()),
    }


def test_two_processes_lose_no_incident_and_no_reader_sees_half_a_registry(tmp_path):
    """The watch and `glorfindel respond` each hold an IncidentRegistry on the same file: its
    thread lock kept their own threads apart, never the two processes — each rewrite read the
    file, changed it and wrote it back over the other's, in place. Under the registry's flock,
    rewritten whole (temporary file, 0600): nothing lost, nothing read half-written."""
    got = measure_incidents(tmp_path)
    assert got["codes"] == [0, 0]
    assert got["reads"] > 0
    assert {k: got[k] for k in ("lost", "duplicated", "action_lost", "resolve_lost", "bad", "mode")} == {
        "lost": 0, "duplicated": 0, "action_lost": 0, "resolve_lost": 0, "bad": 0, "mode": "0o600"}, got


# ── I11g (#508): the readiness file, written by the watch and the console ─────────────

_READINESS_WRITER = textwrap.dedent("""
    import sys
    from pathlib import Path
    from glorfindel import readiness
    readiness._STATE_FILE, me, n = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    for i in range(n):
        readiness.record_quarantine_refusal(f"/subscriptions/s/resourceGroups/rg/providers/"
                                            f"Microsoft.Compute/virtualMachines/{me}-{i}", ["policy"])
""")

# What every version of the readiness lock took: an flock on `readiness.lock`, beside the file.
_READINESS_OLD_HOLDER = textwrap.dedent("""
    import fcntl, sys, time
    from pathlib import Path
    lock_file, ready, hold = Path(sys.argv[1]), Path(sys.argv[2]), float(sys.argv[3])
    with open(lock_file, "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        ready.write_text("in")
        time.sleep(hold)
""")


def test_two_processes_lose_no_readiness_record(tmp_path):
    """The watch (the tracker, an isolation's quarantine refusal) and the console (an activation)
    rewrite the readiness file: each read-modify-write under the shared lock of the local files
    (`_file_lock`, I11g) — nothing lost between two processes."""
    path = tmp_path / "readiness.json"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    procs = [subprocess.Popen([sys.executable, "-c", _READINESS_WRITER, str(path), f"w{k}", "40"], env=env)
             for k in range(2)]
    assert [p.wait(timeout=180) for p in procs] == [0, 0]
    got = {k.rsplit("--", 1)[0] for k, rec in json.loads(path.read_text()).items()   # `<name>--<id hash>`
           if rec.get("quarantine_refused")}
    assert got == {f"w{k}-{i}" for k in range(2) for i in range(40)}, sorted(got)


def test_the_readiness_lock_is_the_file_every_version_took(tmp_path, monkeypatch):
    """`readiness.lock` beside `readiness.json`, as before I11g: a console of the version before,
    holding it, keeps a newer watch's write waiting until it lets go — never two writers at once
    during an upgrade, one of each version."""
    from glorfindel import readiness
    monkeypatch.setattr(readiness, "_STATE_FILE", tmp_path / "readiness.json")
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    holder = subprocess.Popen([sys.executable, "-c", _READINESS_OLD_HOLDER, str(tmp_path / "readiness.lock"),
                               str(tmp_path / "ready"), "1.5"], env=env)
    try:
        deadline = time.monotonic() + 30
        while not (tmp_path / "ready").exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.05)
        started = time.monotonic()
        readiness.record_quarantine_refusal("/subscriptions/s/resourceGroups/rg/providers/"
                                            "Microsoft.Compute/virtualMachines/web", ["policy"])
        assert time.monotonic() - started > 0.8, "written while the other version held readiness.lock"
    finally:
        holder.wait(timeout=60)
