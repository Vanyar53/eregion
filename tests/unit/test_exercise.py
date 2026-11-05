"""B2 (storage side): an injector's exercise window labels what Glorfindel sees on its
targets `exercise`, in the memory and on the card; the observation report leaves exercises
out; an exercise card never absorbs a real detection. Nothing reaches the model yet.
"""
import json
from datetime import datetime, timedelta, timezone

from eregion_core import exercise
from eregion_core.exercise import GRACE_AFTER_S, close_window, open_window, source_of

VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
OTHER = VM.replace("gondolin", "bree")
# Recent: a window whose last moment is PURGE_AFTER_S old is purged when read (H-1).
T0 = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=1)


def _at(minutes: float) -> datetime:
    return T0 + timedelta(minutes=minutes)


def test_a_window_labels_its_target_only_and_ignores_case():
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM], now=T0)
    assert source_of(VM, _at(5)) == ("exercise", "r1")
    assert source_of(VM.upper(), _at(5)) == ("exercise", "r1")
    assert source_of(OTHER, _at(5)) == ("real", "")
    assert source_of(VM, _at(-1)) == ("real", "")


def test_a_closed_window_keeps_a_grace_for_the_detection_lag_then_ends():
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM], now=T0)
    close_window("r1", injector="annatar", now=_at(10))
    grace = GRACE_AFTER_S / 60
    assert source_of(VM, _at(10 + grace - 1)) == ("exercise", "r1")
    assert source_of(VM, _at(10 + grace + 1)) == ("real", "")


def test_a_window_never_closed_lapses_at_its_expiry():
    """An injector that died must not turn every later incident into an exercise."""
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM],
                max_duration_s=3600, now=T0)
    grace = GRACE_AFTER_S / 60
    assert source_of(VM, _at(60 + grace - 1)) == ("exercise", "r1")
    assert source_of(VM, _at(60 + grace + 1)) == ("real", "")
    assert source_of(VM, _at(24 * 60)) == ("real", "")


def test_the_injectors_own_signal_is_an_exercise_by_its_run_id():
    """Whatever its time — but only on a VM the window names (H-1, M223)."""
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM], now=T0)
    assert source_of(VM, None, run_id="r1") == ("exercise", "r1")
    assert source_of(VM, _at(24 * 60), run_id="r1") == ("exercise", "r1")
    assert source_of(OTHER, _at(5), run_id="r1") == ("real", "")
    assert source_of("", None, run_id="r1") == ("unknown", "")
    assert source_of(OTHER, _at(5), run_id="unknown-run") == ("real", "")


def test_unreadable_windows_and_missing_inputs():
    d = exercise.exercises_dir()
    d.mkdir(parents=True)
    (d / "broken.json").write_text("{not json")
    (d / "partial.json").write_text(json.dumps({"run_id": "x"}))
    assert exercise.load_windows() == []
    assert source_of(VM, _at(1)) == ("real", "")
    assert source_of("", _at(1)) == ("unknown", "")
    assert source_of(VM, "not a time") == ("unknown", "")


# ── Glorfindel: the memory and the card carry the source ─────────────────────

class _Memory:
    def __init__(self):
        self.cycles = []

    def store(self, cycle):
        self.cycles.append(cycle)


def _state(resource_id=VM, timestamp=None):
    return {
        "signal": {"signal_id": "rule-account-creation-0123abcd", "resource_id": resource_id,
                   "ttp": "T1136.001", "event": "detection",
                   "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
                   "context": {}},
        "reasoning": "r", "confidence": 0.35, "action": "snapshot", "escalate": True,
        "outcome": {}, "dry_run": False,
    }


def test_store_cycle_records_exercise_or_real(tmp_path, monkeypatch):
    from glorfindel.agent import store_cycle
    monkeypatch.chdir(tmp_path)
    open_window("r1", injector="annatar", kind="technique", experiment="T1136", targets=[VM])
    memory = _Memory()
    store_cycle(_state(VM), memory=memory)
    store_cycle(_state(OTHER), memory=memory)
    assert [(c["source"], c["exercise_run"]) for c in memory.cycles] == [("exercise", "r1"), ("real", "")]


def test_an_exercise_card_never_absorbs_a_real_detection():
    from glorfindel import escalations
    kw = dict(signal_id="s", resource_id=VM, action="snapshot", escalation_type="low_confidence", reason="r")
    exercise_card = escalations.record(**kw, source="exercise", exercise_run="r1")
    real_card = escalations.record(**kw, source="real")
    assert real_card != exercise_card
    assert escalations.record(**kw, source="real") == real_card          # dedup still works
    assert escalations.record(**kw, source="") == real_card              # older cards = real


def test_the_observation_report_leaves_exercises_out():
    from glorfindel import escalations
    kw = dict(signal_id="rule-x-0123abcd", action="isolate_vm", escalation_type="mode_hold", reason="r")
    escalations.record(resource_id=VM, **kw, source="exercise", exercise_run="r1")
    escalations.record(resource_id=OTHER, **kw, source="real")
    r = escalations.observation_report()
    assert r["cards"] == 1 and r["exercises"] == 1
    assert r["disruptive"]["unjudged"] == 1


# ── Annatar: a run opens its window and closes it ─────────────────────────────

def test_an_annatar_run_opens_and_closes_its_window(tmp_path, monkeypatch):
    from unittest.mock import patch

    from annatar.runner.engine import Engine
    from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the target's: the scope names it (SEC11)
    executor = _make_executor()
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    windows = exercise.load_windows()
    assert len(windows) == 1
    w = windows[0]
    assert w["run_id"] == outcome.run_id and w["injector"] == "annatar"
    assert w["targets"] == [executor.resource_id.lower()]
    assert w["end"] is not None


def test_a_refused_target_opens_no_window(tmp_path, monkeypatch):
    from unittest.mock import patch

    from annatar.runner.engine import Engine
    from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor

    monkeypatch.chdir(tmp_path)
    executor = _make_executor(vm_tags={"env": "production"})
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(executor, _make_collector())), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)
    assert exercise.load_windows() == []


def test_the_model_sees_each_past_cycle_s_source_never_the_current_one(tmp_path, monkeypatch):
    """B2 model side: past cycles are tagged [EXERCICE] / [RÉEL] / [source inconnue]; the
    system prompt says an exercise is no precedent; the current signal carries no source."""
    from glorfindel.agent import _SYSTEM_PROMPT, _build_user_message
    monkeypatch.chdir(tmp_path)
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM])
    signal = {"signal_id": "s", "resource_id": VM, "ttp": "T1486", "event": "detection",
              "raw_signal": {}, "context": {}}
    past = [{"summary": "ransomware isolé", "source": "exercise"},
            {"summary": "brute force bloquée", "source": "real"},
            {"summary": "ancien cycle"}]
    msg = _build_user_message(signal, past)
    assert "**Cycle 1** [EXERCICE] : ransomware isolé" in msg
    assert "**Cycle 2** [RÉEL] : brute force bloquée" in msg
    assert "**Cycle 3** [source inconnue] : ancien cycle" in msg
    assert msg.count("[EXERCICE]") == 1        # the current signal is never labelled
    assert "never a precedent for a real" in _SYSTEM_PROMPT


# ── SEC14 (V-20): a window written on the watch's host, bounded by what the watch saw ──────────

import pytest  # noqa: E402


@pytest.fixture
def seen_record(tmp_path, monkeypatch):
    """The watch's real record of the windows it saw (off elsewhere in the tests), in tmp."""
    monkeypatch.setattr(exercise, "seen_path", lambda: tmp_path / "glorfindel" / "exercise_seen.json")
    return tmp_path / "glorfindel" / "exercise_seen.json"


def _write(directory, window):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{window['run_id']}.json").write_text(json.dumps(window))


def _local(rid="r1", start=None, **kw):
    start = start or T0
    return {"run_id": rid, "injector": "annatar", "kind": "technique", "experiment": "T1110.001",
            "targets": [VM.lower()], "start": start.isoformat(), "end": None,
            "expires": (start + timedelta(hours=2)).isoformat(), "destructive": False, **kw}


def test_a_local_window_dated_back_when_first_seen_is_refused(tmp_path, seen_record):
    d = tmp_path / "x"
    _write(d, _local(start=_at(-110)))                    # written now, dated 110 min back
    assert exercise.load_windows(d, now=T0, seen=seen_record) == []
    assert source_of(VM, _at(-100), windows=exercise.load_windows(d, now=T0, seen=seen_record)) == ("real", "")
    # Without the record (as before SEC14), it was believed: the bound is the record's.
    assert [w["run_id"] for w in exercise.load_windows(d, now=T0)] == ["r1"]


def test_a_local_window_seen_open_may_come_again_closed_and_nothing_else(tmp_path, seen_record):
    d = tmp_path / "x"
    _write(d, _local(start=_at(0)))
    assert len(exercise.load_windows(d, now=_at(1), seen=seen_record)) == 1
    _write(d, _local(start=_at(0), end=_at(30).isoformat(), closed_by="annatar"))
    assert len(exercise.load_windows(d, now=_at(31), seen=seen_record)) == 1   # its closure
    assert json.loads(seen_record.read_text())["r1"]["end"] == _at(30).isoformat()
    for rewrite in (_local(start=_at(0), end=_at(45).isoformat()),           # its end moved
                    _local(start=_at(0)),                                     # its end withdrawn
                    _local(start=_at(-60), end=_at(30).isoformat()),          # its start moved
                    _local(start=_at(0), end=_at(30).isoformat(), targets=[VM.lower(), OTHER.lower()])):
        _write(d, rewrite)
        assert exercise.load_windows(d, now=_at(50), seen=seen_record) == [], rewrite


def test_the_first_sight_is_kept_a_long_run_stays_believed(tmp_path, seen_record):
    d = tmp_path / "x"
    _write(d, _local(start=_at(0)))
    assert len(exercise.load_windows(d, now=_at(1), seen=seen_record)) == 1
    assert len(exercise.load_windows(d, now=_at(100), seen=seen_record)) == 1
    assert json.loads(seen_record.read_text())["r1"]["seen"] == _at(1).isoformat()


def test_a_window_the_pull_wrote_down_keeps_the_channels_bound(tmp_path, seen_record):
    """Pulled through the channel, written down by the pull: bounded by its blob's creation, so
    believed when the watch first reads it 90 min later."""
    from eregion_core import exercise_channel
    from tests.unit.fake_container import CRED, URL, FakeContainer
    c, d = FakeContainer(), tmp_path / "x"
    exercise_channel.publish(_local("r1", start=_at(0)), channel=URL, credential=CRED, put=c.put)
    assert exercise_channel.pull(d, channel=URL, credential=CRED, get=c.get, seen=seen_record) == 1
    assert json.loads(seen_record.read_text())["r1"]["channel"] is True
    assert [w["run_id"] for w in exercise.load_windows(d, now=_at(90), seen=seen_record)] == ["r1"]
    # Its copy edited on the host, its channel_created kept: no longer what was pulled.
    w = json.loads((d / "r1.json").read_text())
    _write(d, {**w, "targets": [VM.lower(), OTHER.lower()]})
    assert exercise.load_windows(d, now=_at(91), seen=seen_record) == []


def test_a_channel_created_the_file_carries_alone_proves_nothing(tmp_path, seen_record):
    """SEC14 review: a window written on the host with a « channel_created » of its own is local —
    the pull never wrote it down — and dated back, refused."""
    d = tmp_path / "x"
    _write(d, _local("r1", start=_at(-100), channel_created=_at(-100).isoformat()))
    assert exercise.load_windows(d, now=T0, seen=seen_record) == []
    entry = json.loads(seen_record.read_text())["r1"]
    assert "channel" not in entry and entry["seen"] == T0.isoformat()
    # Without the watch's record (as before the review), it was believed.
    assert [w["run_id"] for w in exercise.load_windows(d, now=T0)] == ["r1"]


def test_an_unreadable_record_believes_no_window(tmp_path, seen_record):
    d = tmp_path / "x"
    _write(d, _local("r1", start=_at(0)))
    _write(d, _local("r2", start=_at(0), channel_created=_at(0).isoformat()))
    seen_record.parent.mkdir(parents=True)
    seen_record.write_text("[not an object]")
    assert exercise.load_windows(d, now=_at(1), seen=seen_record) == []


def test_the_record_is_written_whole_by_one_writer_at_a_time(tmp_path, seen_record):
    """The watch, `glorfindel respond` and the console may read windows at once: a flock, and a
    temporary file of its own, replaced."""
    import threading
    d = tmp_path / "x"
    for i in range(20):
        _write(d, _local(f"r{i}", start=_at(0)))
    errors = []

    def read():
        try:
            exercise.load_windows(d, now=_at(1), seen=seen_record)
        except Exception as e:      # noqa: BLE001
            errors.append(e)
    threads = [threading.Thread(target=read) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert errors == [] and len(json.loads(seen_record.read_text())) == 20
    assert sorted(q.name for q in seen_record.parent.iterdir()) == ["exercise_seen.json",
                                                                     "exercise_seen.json.lock"]


def test_the_watch_writes_down_what_it_saw_in_its_own_state_never_in_runs(tmp_path, seen_record):
    """observe(), the watch's minute: the default directory (the injector's runs/exercises) read,
    the record written beside the watch's state — never where an injector writes."""
    open_window("r1", injector="annatar", kind="technique", experiment="T1110.001", targets=[VM])
    assert [w["run_id"] for w in exercise.observe()] == ["r1"]
    assert "r1" in json.loads(seen_record.read_text())
    assert not list(exercise.exercises_dir().rglob("exercise_seen*"))


def test_the_watch_reads_its_windows_every_minute():
    """glorfindel/cli.py's housekeeping holds the observation, beside the heartbeat."""
    from pathlib import Path
    cli = (Path(__file__).resolve().parents[2] / "glorfindel" / "cli.py").read_text(encoding="utf-8")
    assert "for _task in (_check_ttl, _reconcile_jobs, _reassert, _write_heartbeat, _observe_windows):" in cli
    assert "        _exercise.observe()\n" in cli


_WRITER = """
import json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from eregion_core import exercise
d, reg, name = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
now = datetime.now(timezone.utc)
d.mkdir(parents=True, exist_ok=True)
for i in range(15):
    rid = f"{name}-{i}"
    (d / f"{rid}.json").write_text(json.dumps({"run_id": rid, "targets": [], "start": now.isoformat(),
        "end": None, "expires": (now + timedelta(hours=1)).isoformat()}))
    exercise.load_windows(d, now=now, seen=reg)
"""


def test_the_record_keeps_every_writers_windows_between_processes(tmp_path):
    """Several processes read windows at once (the watch, `glorfindel respond`): none loses
    another's entries — the record is read, changed and written under one flock."""
    import os
    import subprocess
    import sys
    from pathlib import Path
    reg = tmp_path / "glorfindel" / "exercise_seen.json"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    procs = [subprocess.Popen([sys.executable, "-c", _WRITER, str(tmp_path / f"d{n}"), str(reg), f"w{n}"],
                              env=env) for n in range(6)]
    assert [pr.wait(timeout=120) for pr in procs] == [0] * 6
    assert len(json.loads(reg.read_text())) == 6 * 15


_HOLDER = """
import fcntl, sys, time
from pathlib import Path
lock_file, ready, stop = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
with open(lock_file, "a") as fh:
    fcntl.flock(fh, fcntl.LOCK_EX)
    ready.write_text("in")
    deadline = time.monotonic() + 60
    while not stop.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
"""


def test_the_record_waits_for_another_process_s_write(tmp_path):
    """CI6e (#553, M3077): the race above loses an entry between processes only at times. Here,
    every time: while another process holds the record's flock, reading windows here — which
    writes the record — waits, and goes through once it lets go."""
    import os
    import subprocess
    import sys
    import threading
    import time
    from pathlib import Path
    reg = tmp_path / "glorfindel" / "exercise_seen.json"
    reg.parent.mkdir(parents=True)
    d = tmp_path / "x"
    _write(d, _local("r1", start=_at(0)))
    ready, stop = tmp_path / "held", tmp_path / "let-go"
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    holder = subprocess.Popen([sys.executable, "-c", _HOLDER, str(reg.with_name(reg.name + ".lock")),
                               str(ready), str(stop)], env=env)
    done = threading.Event()
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert time.monotonic() < deadline, "the holder never took the lock"
            time.sleep(0.05)
        threading.Thread(target=lambda: (exercise.load_windows(d, now=_at(1), seen=reg), done.set()),
                         daemon=True).start()
        assert not done.wait(0.6), "the record written while another process held its flock"
    finally:
        stop.touch()
        assert holder.wait(timeout=60) == 0
    assert done.wait(30) and "r1" in json.loads(reg.read_text())


# ── SEC14, second review: the transition — a copy pulled before the record existed ─────────────

def _pulled_before(tmp_path, window, *, forged_created=None):
    """A window in the channel, and its copy already on this host as an older version pulled it
    (its channel_created stamped, its file newer than the blob), never written down."""
    from eregion_core import exercise_channel
    from tests.unit.fake_container import CRED, URL, FakeContainer
    c, d = FakeContainer(), tmp_path / "x"
    c.clock = _at(-1)                                   # the blob written as the run opened
    exercise_channel.publish(window, channel=URL, credential=CRED, put=c.put)
    assert exercise_channel.pull(d, channel=URL, credential=CRED, get=c.get) == 1   # no record then
    if forged_created:
        copy = json.loads((d / f"{window['run_id']}.json").read_text())
        _write(d, {**copy, "channel_created": forged_created})
    return c, d, CRED, URL


def test_a_window_open_across_the_upgrade_is_pulled_once_again_then_believed(tmp_path, seen_record):
    from eregion_core import exercise_channel
    c, d, cred, url = _pulled_before(tmp_path, _local("r1", start=_at(0)))
    assert not seen_record.exists()
    gets = len(c.gets)
    assert exercise_channel.pull(d, channel=url, credential=cred, get=c.get, seen=seen_record) == 1
    assert len(c.gets) == gets + 1 and json.loads(seen_record.read_text())["r1"]["channel"] is True
    assert [w["run_id"] for w in exercise.load_windows(d, now=_at(90), seen=seen_record)] == ["r1"]
    # Written down: the next pull downloads it no more.
    assert exercise_channel.pull(d, channel=url, credential=cred, get=c.get, seen=seen_record) == 0
    assert len(c.gets) == gets + 1


def test_a_copy_pulled_again_takes_the_listings_creation_never_its_own(tmp_path, seen_record):
    """The copy on disk said a channel_created of its own (written on the host): the record takes
    the listing's, the one the channel gives."""
    from eregion_core import exercise_channel
    c, d, cred, url = _pulled_before(tmp_path, _local("r1", start=_at(0)), forged_created=_at(-500).isoformat())
    exercise_channel.pull(d, channel=url, credential=cred, get=c.get, seen=seen_record)
    entry = json.loads(seen_record.read_text())["r1"]
    assert entry["seen"] == c.created["r1.json"].isoformat() != _at(-500).isoformat()
    assert json.loads((d / "r1.json").read_text())["channel_created"] == entry["seen"]


def test_a_copy_that_is_not_the_channels_stays_local(tmp_path, seen_record):
    """Rewritten on the host (a target added): rewrite_refusal keeps it as it is, never written
    down — local, and dated back, refused."""
    from eregion_core import exercise_channel
    c, d, cred, url = _pulled_before(tmp_path, _local("r1", start=_at(0)))
    copy = json.loads((d / "r1.json").read_text())
    _write(d, {**copy, "targets": [VM.lower(), OTHER.lower()]})
    assert exercise_channel.pull(d, channel=url, credential=cred, get=c.get, seen=seen_record,
                                 say=lambda *_: None) == 0
    assert not seen_record.exists() or "channel" not in json.loads(seen_record.read_text()).get("r1", {})
    assert exercise.load_windows(d, now=_at(90), seen=seen_record) == []
