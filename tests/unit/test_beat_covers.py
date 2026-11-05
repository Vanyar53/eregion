"""SEC21b (#535): the watch's signed heartbeat says which detections it covers — for each window it
knows, the sorted ``signal_id`` of every detection delivered for it (``covers``) — and a run reads
back, after that heartbeat, every one it covers before it concludes a silence to a miss.

A detection removed from the channel under a true heartbeat (a hand that can write ``watch``) is
``unknown``, said in the console, Orodruin's journal and the run's report, never ``missed``. A
detection published after the heartbeat is admitted. A heartbeat of a watch older than this lot
(no ``covers``) or that leaves the run out (more than MAX_COVERED) proves no miss. A true silence
is still a miss. The local channel of verdicts (SEC18) is unchanged. On the fake container of the
channel (tests/unit/fake_container.py): no network, no Azure, a fake clock, fixed keys. Mutants
M3740–M3749 (scripts/mutants/SEC21b.py) are measured here.
"""
from __future__ import annotations

import json
import time as _time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import eregion_core.watch_channel as wc
import eregion_core.watch_gate as gate
import eregion_core.watch_key as watch_key
from annatar.runner import engine as engine_module
from tests.unit.fake_container import CRED, FakeContainer
from tests.unit.test_signed_detections import (OTHER, REAL_READ_NAMED, RUN, SID, T0, URL, VM, WATCH,
                                               _blob, _Clock, _detection_at, _file, _iso, _Journal,
                                               _signal, _wait, _window)

OTHER_SID = "rule-t1059-004-v1-ef56ab78"   # a detection of the same VM, of another technique


@pytest.fixture
def pinned(monkeypatch):
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(WATCH.public))


def _publisher(c: FakeContainer, windows=None) -> wc.Publisher:
    return wc.Publisher(URL, credential=CRED, put=c.put, signer=WATCH,
                        windows=lambda: windows or [_window()], now=T0 - timedelta(hours=1))


# ── The watch: its heartbeat lists what it covers, signed with the rest ────────────────

def test_the_heartbeat_lists_for_each_window_the_detections_delivered_for_it(pinned):
    """M3740: the heartbeat names, for each window it knows, the detections it delivered — sorted —,
    an empty list for a window with none; all signed under the heartbeat's own domain."""
    c = FakeContainer(URL)
    quiet = "20261104T110000Z"
    pub = _publisher(c, windows=[_window(), _window(run_id=quiet)])
    pub.note(_signal(sid=SID))
    pub.note({**_signal(sid=OTHER_SID), "ttp": "T1059.004"})
    pub.tick(now=T0 + timedelta(minutes=3))
    beat = json.loads(c.body(wc.HEARTBEAT))
    assert beat["windows"] == sorted([RUN, quiet])
    # Both windows cover the VM from T0: each detection delivered for both.
    assert beat[wc.COVERS] == {RUN: sorted([SID, OTHER_SID]), quiet: sorted([SID, OTHER_SID])}
    assert watch_key.verify_beat(beat, WATCH.public) == ""
    assert watch_key.message(watch_key.DOMAIN_BEAT, beat).startswith(b"eregion.watch-beat/1\n")
    assert b'"covers":' in watch_key.message(watch_key.DOMAIN_BEAT, beat)


def test_a_window_without_detection_is_listed_empty():
    c = FakeContainer(URL)
    _publisher(c).tick(now=T0 + timedelta(minutes=3))
    assert json.loads(c.body(wc.HEARTBEAT))[wc.COVERS] == {RUN: []}


def test_the_heartbeat_covers_only_what_was_delivered():
    """A detection whose write failed is not covered — and no heartbeat goes while it waits."""
    c = FakeContainer(URL)
    c.refused.add(_blob())
    pub = _publisher(c)
    pub.note(_signal())
    pub.tick(now=T0 + timedelta(minutes=3))
    assert wc.HEARTBEAT not in c.blobs
    c.refused.clear()
    pub.tick(now=T0 + timedelta(minutes=4))
    assert json.loads(c.body(wc.HEARTBEAT))[wc.COVERS] == {RUN: [SID]}


def test_covers_changed_after_the_signature_never_holds(pinned):
    """A hand that removes a detection cannot also remove it from the heartbeat: signed."""
    c = FakeContainer(URL)
    pub = _publisher(c)
    pub.note(_signal())
    pub.tick(now=T0 + timedelta(minutes=3))
    beat = json.loads(c.body(wc.HEARTBEAT))
    assert watch_key.verify_beat({**beat, wc.COVERS: {RUN: []}}, WATCH.public).startswith(
        "its signature does not hold")
    assert watch_key.verify_beat({k: v for k, v in beat.items() if k != wc.COVERS}, WATCH.public).startswith(
        "its signature does not hold")


@pytest.mark.parametrize("n, listed", [(wc.MAX_COVERED, True), (wc.MAX_COVERED + 1, False)],
                         ids=["at-the-bound", "beyond-the-bound"])
def test_a_window_beyond_the_bound_is_left_out(n, listed):
    """M3741: MAX_COVERED detections listed; one more and the window is left out of ``covers`` —
    its run then cannot conclude to a miss — while ``windows`` still names it."""
    assert wc.MAX_COVERED == 256
    c = FakeContainer(URL)
    pub = _publisher(c)
    for i in range(n):
        pub.note(_signal(sid=f"rule-many-{i:04d}"))
    pub.tick(now=T0 + timedelta(minutes=3))
    beat = json.loads(c.body(wc.HEARTBEAT))
    assert beat["windows"] == [RUN]
    assert (RUN in beat[wc.COVERS]) is listed
    if listed:
        assert len(beat[wc.COVERS][RUN]) == n


def test_the_local_channel_s_heartbeat_keeps_its_exact_fields(tmp_path):
    """SEC18 unchanged: the local channel's heartbeat holds exactly BEAT_FIELDS — no ``covers``."""
    d = tmp_path / "verdicts"
    d.mkdir()
    v = wc.LocalVerdicts(d, windows=lambda: [_window()])
    v.note(_signal())
    v.tick(now=T0 + timedelta(minutes=3))
    assert set(json.loads((d / wc.HEARTBEAT).read_text())) == set(wc.BEAT_FIELDS)


# ── The reader's comparison ───────────────────────────────────────────────────────────

def _record(sid):
    return {"signal_id": sid}


def test_every_detection_covered_read_back_proves_nothing_missing():
    assert wc.uncovered({wc.COVERS: {RUN: [SID]}}, RUN, [_record(SID)]) == ("", [], 0)
    assert wc.uncovered({wc.COVERS: {RUN: []}}, RUN, []) == ("", [], 0)


def test_a_detection_published_after_the_heartbeat_is_admitted():
    """M3743: read but not listed — delivered after the heartbeat: nothing missing."""
    assert wc.uncovered({wc.COVERS: {RUN: [SID]}}, RUN, [_record(SID), _record(OTHER_SID)]) == ("", [], 0)


def test_a_covered_detection_absent_is_said_with_its_blob():
    why, missing, total = wc.uncovered({wc.COVERS: {RUN: [OTHER_SID, SID]}}, RUN, [_record(OTHER_SID)])
    assert "1 of the 2 detection(s) the watch's heartbeat covers" in why and "absent from the channel" in why
    assert missing == [_blob()] and total == 1


def test_the_missing_said_are_bounded_and_all_counted():
    listed = [f"rule-gone-{i:03d}" for i in range(wc.MAX_MISSING + 5)]
    why, missing, total = wc.uncovered({wc.COVERS: {RUN: listed}}, RUN, [])
    assert len(missing) == wc.MAX_MISSING and total == wc.MAX_MISSING + 5
    assert f"{wc.MAX_MISSING + 5} of the {wc.MAX_MISSING + 5}" in why


def test_a_heartbeat_without_covers_proves_no_miss_and_says_the_gesture():
    """M3744: a watch older than this injector — the reason and the gesture."""
    why, missing, _ = wc.uncovered({"at": "x", "windows": [RUN]}, RUN, [])
    assert why == wc.NOT_COVERING and "update Glorfindel" in why and missing == []


def test_a_heartbeat_that_leaves_the_run_out_proves_no_miss():
    """M3745: more than MAX_COVERED — the run absent from ``covers``, never read as « none »."""
    why, _, _ = wc.uncovered({wc.COVERS: {"another-run": []}}, RUN, [])
    assert f"more than {wc.MAX_COVERED}" in why


@pytest.mark.parametrize("covers", [["not", "a", "map"], {RUN: "rule-x"}, {RUN: [1, 2]}],
                         ids=["not-an-object", "not-a-list", "not-signals"])
def test_covers_of_another_shape_proves_no_miss(covers):
    assert wc.uncovered({wc.COVERS: covers}, RUN, [])[0]


def test_a_signal_id_said_is_a_plain_name():
    """What the heartbeat names is said as a blob name, never an escape sequence."""
    _, missing, _ = wc.uncovered({wc.COVERS: {RUN: ["rule-\x1b[2J"]}}, RUN, [])
    assert missing == [f"{wc.DETECTIONS}/{RUN}/rule-??2J.json"]


# ── The run, end to end on the fake container ─────────────────────────────────────────

@pytest.fixture
def run(monkeypatch, pinned):
    """A run on Orodruin: its return channel the fake container, read through the real reader;
    the gate's real proof; a fake clock. ``beat(covers=..., signer=WATCH, **over)`` makes the
    channel's heartbeat — written now, by a watch up for a day, that knows the run — and its
    ``covers`` (None: a watch older than this lot)."""
    c = FakeContainer(URL)
    clock = _Clock(_time.time())
    monkeypatch.setattr(engine_module, "time", clock)
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)
    monkeypatch.setattr(wc, "read_named",
                        lambda run_id, **_: REAL_READ_NAMED(run_id, channel=URL, credential=CRED, get=c.get))
    monkeypatch.setattr(gate, "channel_beat", lambda: gate.Beat(gate.CHANNEL, datetime.fromtimestamp(clock.now, timezone.utc)))
    monkeypatch.setitem(gate.READERS, "proof", watch_key.proof)
    reads = []

    def beat(covers=None, signer=WATCH, before=None, over=None):
        def read(**_):
            if before is not None:
                before()
            reads.append("heartbeat")
            now = datetime.fromtimestamp(clock.now, timezone.utc)
            body = {"at": now.isoformat(), "since": _iso(clock.now - 86400), "windows": [RUN],
                    "perimeter": ""}
            if covers is not None:
                body[wc.COVERS] = covers
            return {**watch_key.sign_beat(body, signer, now), **(over or {})}
        monkeypatch.setattr(wc, "read_heartbeat", read)
    return SimpleNamespace(container=c, clock=clock, beat=beat, reads=reads)


def _other(seen: float) -> dict:
    """A signed detection of the same VM, another technique: never the run's own."""
    body = {"event": "detection", "signal_id": OTHER_SID, "ttp": "T1059.004", "resource_id": VM,
            "detected_at": _iso(seen), "rule": "t1059-004-v1", "watch_run_id": "watch-t1059-x",
            "exercise_run": RUN}
    return watch_key.sign_detection(body, WATCH)


def test_a_true_silence_is_still_a_miss(run):
    """Nothing covered, nothing filed: a miss, detection_missed emitted (#159)."""
    run.beat(covers={RUN: []})
    engine, emitted = _wait(run.clock.now - 30)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]
    assert engine._detection_missing == []


def test_a_silence_beside_a_detection_of_another_technique_covered_is_a_miss(run):
    attack = run.clock.now - 30
    _file(run.container, _blob(sid=OTHER_SID), _other(attack + 5))
    run.beat(covers={RUN: [OTHER_SID]})
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_a_covered_detection_removed_is_unknown_and_said_in_the_console_and_the_journal(run, capsys):
    """M3742, M3748: the watch delivered the run's detection, its heartbeat covers it, a hand on the
    channel removed it — unknown, never missed (no detection_missed: no rule proposed); the blob
    missing said in the console and in Orodruin's journal, once."""
    attack = run.clock.now - 30
    _file(run.container, _blob(sid=OTHER_SID), _other(attack + 5))   # what is left
    run.beat(covers={RUN: sorted([SID, OTHER_SID])})
    journal = _Journal()
    engine, emitted = _wait(attack, session=journal)
    assert engine._detection_result == "unknown" and emitted == []
    assert engine._detection_missing == [_blob()] and engine._detection_missing_total == 1
    assert journal.lines == [("detection_missing", f"{_blob()}: covered by the watch's heartbeat, absent")]
    out = " ".join(capsys.readouterr().out.split())
    assert out.count("A detection the watch's heartbeat covers is missing") == 1
    assert "Detection not measured" in out and "1 of the 2 detection(s)" in out and "No detection_missed" in out


def test_a_detection_published_after_the_heartbeat_is_admitted_and_the_silence_a_miss(run):
    """M3743: a detection of another technique the heartbeat does not list (delivered after it) —
    read, not covered: admitted, the run's silence still a miss."""
    attack = run.clock.now - 30
    run.beat(covers={RUN: []})
    _file(run.container, _blob(sid=OTHER_SID), _other(attack + 40))
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_the_detections_are_read_after_the_heartbeat(run):
    """M3746: the watch delivers a detection then beats, between two reads of the run — read in
    this order (the heartbeat, then the detections), the run reads back all the heartbeat covers:
    a miss. Read the other way round, it would miss the detection the heartbeat covers."""
    attack = run.clock.now - 30
    run.beat(covers={RUN: [OTHER_SID]},
             before=lambda: _file(run.container, _blob(sid=OTHER_SID), _other(attack + 40)))
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_a_watch_older_than_this_lot_proves_no_miss_and_says_the_gesture(run, capsys):
    """M3744: its heartbeat signed (SEC19), no ``covers`` — unknown, the reason and the gesture."""
    run.beat(covers=None)
    engine, emitted = _wait(run.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
    out = " ".join(capsys.readouterr().out.split())
    assert "does not say which detections it covers" in out and "update Glorfindel" in out


def test_a_watch_older_than_this_lot_still_gives_a_detection(run):
    """The passage touches only the miss: a vouched detection of the run is « detected »."""
    attack = run.clock.now - 150
    _file(run.container, _blob(), _detection_at(attack + 60))
    run.beat(covers=None)
    engine, _ = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 60.0)


def test_a_detection_read_back_counts_even_when_another_covered_is_missing(run):
    """Positive evidence stands: the run's own detection read, another covered one removed."""
    attack = run.clock.now - 150
    _file(run.container, _blob(), _detection_at(attack + 60))
    run.beat(covers={RUN: sorted([SID, OTHER_SID])})
    engine, _ = _wait(attack)
    assert engine._detection_result == "detected"


def test_a_run_beyond_the_bound_proves_no_miss_and_it_is_said(run, capsys):
    """M3745: the heartbeat leaves the run out (more than MAX_COVERED) — unknown, said."""
    run.beat(covers={})
    engine, emitted = _wait(run.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
    assert f"more than {wc.MAX_COVERED}" in " ".join(capsys.readouterr().out.split())


def test_covers_rewritten_by_a_hand_never_proves_a_miss(run, capsys):
    """The detection removed and the heartbeat's ``covers`` emptied: its signature fails — unknown."""
    run.beat(covers={RUN: [SID]}, over={wc.COVERS: {RUN: []}})
    engine, emitted = _wait(run.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
    assert "its signature does not hold" in capsys.readouterr().out


def test_a_heartbeat_of_another_key_listing_nothing_never_proves_a_miss(run):
    run.beat(covers={RUN: []}, signer=OTHER)
    engine, emitted = _wait(run.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []


def test_the_missing_are_bounded_in_the_run(run):
    run.beat(covers={RUN: [f"rule-gone-{i:03d}" for i in range(30)]})
    journal = _Journal()
    engine, emitted = _wait(run.clock.now - 30, session=journal)
    assert engine._detection_result == "unknown" and emitted == []
    assert len(engine._detection_missing) == wc.MAX_MISSING and engine._detection_missing_total == 30
    assert len(journal.lines) == wc.MAX_MISSING


# ── In the run's report ───────────────────────────────────────────────────────────────

def _covering_wait(run, removed: bool, monkeypatch):
    """The run's wait, its heartbeat covering the run's detection (``removed``: and none filed).
    The gate before the run reads the conftest's stand-in, as SEC21's report tests do."""
    monkeypatch.setitem(gate.READERS, "proof", lambda body, record=True: "")
    real = engine_module.Engine._wait_and_emit_feedback

    def wait(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        def read(**_):
            now = datetime.fromtimestamp(run.clock.now, timezone.utc)
            return watch_key.sign_beat({"at": now.isoformat(), "since": _iso(run.clock.now - 86400),
                                        "windows": [run_id], "perimeter": "",
                                        wc.COVERS: {run_id: [SID] if removed else []}}, WATCH, now)
        with patch.object(wc, "read_heartbeat", read):
            return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)
    return wait


def test_a_missing_detection_is_written_in_the_atomic_run_s_report(run, tmp_path, monkeypatch, capsys):
    """M3749: the run's report keeps what is missing (``metrics.detection_missing``), its
    detection unknown — and Annatar prints it with the run."""
    from annatar.runner.report import RunReport
    from tests.unit.test_annatar_atomic import ATOMIC_YAML, _atomic_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the atomic target's (SEC11)
    engine = engine_module.Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(engine_module.Engine, "_wait_and_emit_feedback", _covering_wait(run, True, monkeypatch)):
        outcome = engine.run(ATOMIC_YAML, skip_confirm=True)
    assert outcome.detection == "unknown"
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    assert report["metrics"]["detection"] == "unknown"
    assert len(report["metrics"]["detection_missing"]) == 1 and report["metrics"]["detection_missing_total"] == 1
    assert report["metrics"]["detection_missing"][0].endswith(f"/{SID}.json")
    capsys.readouterr()
    RunReport(**report).render()
    out = " ".join(capsys.readouterr().out.split())
    assert "Missing from the return channel: 1" in out and f"/{SID}.json" in out


def test_a_missing_detection_is_written_in_a_local_script_run_s_report(run, tmp_path, monkeypatch):
    from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the target's (SEC11)
    engine = engine_module.Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_make_executor(), _make_collector())), \
         patch.object(engine_module.Engine, "_wait_and_emit_feedback", _covering_wait(run, True, monkeypatch)):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    assert outcome.detection == "unknown"
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    assert report["metrics"]["detection_missing"][0].endswith(f"/{SID}.json")


def test_a_true_silence_leaves_no_missing_in_the_report(run, tmp_path, monkeypatch):
    from tests.unit.test_annatar_atomic import ATOMIC_YAML, _atomic_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")
    engine = engine_module.Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(engine_module.Engine, "_wait_and_emit_feedback", _covering_wait(run, False, monkeypatch)):
        outcome = engine.run(ATOMIC_YAML, skip_confirm=True)
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    assert outcome.detection == "missed" and "detection_missing" not in report["metrics"]
