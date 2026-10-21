"""#157 — the real detection latency of a run, and only this run's detections count.

A detection counts for a run when it is of the run's technique, on its resource (compared
without case: Log Analytics writes ``_ResourceId`` in lower case, Annatar emits ARM's
casing — measured on the bench, 20/10) and seen at or after the attack. Its latency is
measured from the run's ``attack_time``, the same way on both paths of the wait (the run's
own ``runs/<run_id>_debug.jsonl`` and the RulePoller's ``watch-*`` files), and written in
``runs/<run_id>.json``. No Azure, no LLM (mocked executor, a throwaway HOME, a fake clock).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from annatar.runner import engine as engine_module
from annatar.runner.detection import (
    detection_latency,
    detection_time,
    has_timeout,
    read_records,
    same_resource,
)
from annatar.runner.engine import Engine
from tests.unit.test_annatar_atomic import ATOMIC_YAML, _atomic_executor
from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor

# What Annatar emits (ARM's casing, `resource_id` of AzureVMExecutor) …
ANNATAR_RID = (
    "/subscriptions/sub-123/resourceGroups/rg-celebrimbor"
    "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
# … and what the watch writes (Log Analytics' `_ResourceId`, lower case).
WATCH_RID = ANNATAR_RID.lower()
TTP = "T1136.001"


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _rulepoller_record(seen: float, rid: str = WATCH_RID, ttp: str = TTP) -> dict:
    """A line of a `watch-*_debug.jsonl` — the shape of H0's (run 20261020T121319Z)."""
    return {
        "timestamp": _iso(seen + 10.6),  # written after the decision
        "signal": {
            "event": "detection", "ttp": ttp, "timestamp": _iso(seen), "resource_id": rid,
            "context": {"rule_name": "t1136-001-local-account-creation-linux-v1",
                        "run_id": "watch-t1136-001-local-account-creation-linux-v1-x"},
        },
    }


def _poll_record(attack_time: float, after_s: float, emitted_s: float = 63.0,
                 rid: str = ANNATAR_RID) -> dict:
    """A line of the run's own `runs/<run_id>_debug.jsonl`: Glorfindel resolved the run's
    attack_started — its `timestamp` is the attack_started emission, not the detection."""
    return {
        "timestamp": _iso(attack_time + after_s + 8),
        "signal": {
            "event": "detection", "ttp": TTP, "resource_id": rid,
            "timestamp": _iso(attack_time + emitted_s),
            "raw_signal": {"attack_time": attack_time, "detection_time_s": after_s},
        },
    }


# ── The pure rule ─────────────────────────────────────────────────────────────────────

def test_resource_compared_without_case():
    """The bench's bug: the watch's lower-case id never matched Annatar's (M98)."""
    assert same_resource(ANNATAR_RID, WATCH_RID)
    assert not same_resource(ANNATAR_RID, WATCH_RID.replace("gondolin", "other"))
    assert not same_resource("", "")  # no resource named is no match


def test_latency_counts_a_lower_case_watch_record():
    attack = 1_000_000.0
    assert detection_latency([_rulepoller_record(attack + 117.5)], TTP, ANNATAR_RID, attack) == 117.5
    # and the other way round
    rec = _rulepoller_record(attack + 30, rid=ANNATAR_RID)
    assert detection_latency([rec], TTP, WATCH_RID, attack) == 30.0


def test_a_detection_before_the_attack_never_counts():
    """Same VM, same technique, but seen before the attack: an earlier run's (M99)."""
    attack = 1_000_000.0
    earlier = _rulepoller_record(attack - 120)
    assert detection_latency([earlier], TTP, ANNATAR_RID, attack) is None
    # the run's own detection still counts beside it, with its own latency
    assert detection_latency([earlier, _rulepoller_record(attack + 45)],
                             TTP, ANNATAR_RID, attack) == 45.0


def test_a_detection_at_the_attack_second_counts_as_zero():
    attack = 1_000_000.0
    assert detection_latency([_rulepoller_record(attack)], TTP, ANNATAR_RID, attack) == 0.0


def test_a_detection_of_unknown_time_does_not_count():
    """It cannot be shown to come after the attack."""
    attack = 1_000_000.0
    for stamp in (None, "", "not a date"):
        rec = _rulepoller_record(attack + 10)
        rec["signal"]["timestamp"] = stamp
        assert detection_latency([rec], TTP, ANNATAR_RID, attack) is None


def test_other_technique_or_other_event_does_not_count():
    attack = 1_000_000.0
    assert detection_latency([_rulepoller_record(attack + 5, ttp="T1041")],
                             TTP, ANNATAR_RID, attack) is None
    rec = _rulepoller_record(attack + 5)
    rec["signal"]["event"] = "detection_timeout"
    assert detection_latency([rec], TTP, ANNATAR_RID, attack) is None
    assert detection_latency([{}, {"signal": "x"}, "junk"], TTP, ANNATAR_RID, attack) is None


def test_the_earliest_detection_gives_the_latency():
    attack = 1_000_000.0
    recs = [_rulepoller_record(attack + 200), _rulepoller_record(attack + 117.5)]
    assert detection_latency(recs, TTP, ANNATAR_RID, attack) == 117.5


def test_the_poll_path_is_measured_from_attack_time_not_the_signal_timestamp():
    """attack_started leaves ~63 s after the command on the atomic path; the poll's record
    keeps that timestamp. The latency is detection_time_s from attack_time (M100)."""
    attack = 1_000_000.0
    rec = _poll_record(attack, after_s=118, emitted_s=63)
    assert detection_time(rec["signal"]) == attack + 118
    assert detection_latency([rec], TTP, ANNATAR_RID, attack) == 118.0


def test_naive_timestamp_is_read_as_utc():
    sig = {"timestamp": "2026-10-20T12:15:58.894353"}
    assert detection_time(sig) == datetime(2026, 10, 20, 12, 15, 58, 894353,
                                           tzinfo=timezone.utc).timestamp()


def test_read_records_skips_bad_lines(tmp_path):
    f = tmp_path / "x_debug.jsonl"
    f.write_text('{"signal": {"event": "detection_timeout"}}\n\nnot json\n[1]\n')
    recs = read_records(f)
    assert recs == [{"signal": {"event": "detection_timeout"}}]
    assert has_timeout(recs)
    assert read_records(tmp_path / "missing.jsonl") == []


# ── _check_watch_files: the RulePoller path ───────────────────────────────────────────

def test_watch_files_find_the_bench_record_with_annatar_casing(tmp_path):
    """The bench record (lower-case id) is found from Annatar's id — before, None."""
    runs = tmp_path / "runs"
    runs.mkdir()
    # 12:14:01.41 → 12:15:58.89: the reference measured by hand on run 20261020T121319Z.
    attack = datetime(2026, 10, 20, 12, 14, 1, 410000, tzinfo=timezone.utc).timestamp()
    rec = _rulepoller_record(attack)
    rec["signal"]["timestamp"] = "2026-10-20T12:15:58.894353+00:00"
    (runs / "watch-t1136-001-local-account-creation-linux-v1-20261020T121559Z_debug.jsonl"
     ).write_text(json.dumps(rec) + "\n")
    # mtime is now, after the attack; the record's own time decides
    assert Engine._check_watch_files(TTP, ANNATAR_RID, attack, runs_dir=runs) == 117.5


def test_watch_files_ignore_an_earlier_detection_in_a_fresh_file(tmp_path):
    """The file is fresh (another cycle appended after the attack) but its detection of
    this technique on this VM came before the attack: not this run's (M99)."""
    runs = tmp_path / "runs"
    runs.mkdir()
    import time as _time
    attack = _time.time() - 60
    (runs / "watch-old-rule-x_debug.jsonl").write_text(
        json.dumps(_rulepoller_record(attack - 300)) + "\n")
    assert Engine._check_watch_files(TTP, ANNATAR_RID, attack, runs_dir=runs) is None


# ── _wait_and_emit_feedback: both paths, same latency, same filter ───────────────────

class _Clock:
    """A fake clock for the engine module: sleep advances time (the wait never blocks)."""

    def __init__(self, start: float):
        self.now = start

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.now += s


@pytest.fixture
def waiting(tmp_path, monkeypatch):
    """chdir to tmp, a throwaway HOME with a fresh watch heartbeat, a fake clock."""
    import time as _time

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    clock = _Clock(_time.time())
    monkeypatch.setattr(engine_module, "time", clock)
    hb = tmp_path / "home" / ".glorfindel" / "watch_heartbeat"
    hb.parent.mkdir(parents=True)
    hb.write_text(_iso(clock.now))
    (tmp_path / "runs").mkdir()
    return SimpleNamespace(runs=tmp_path / "runs", clock=clock)


def _wait(attack_time: float, run_id: str = "rid"):
    engine = Engine()
    emitted = []
    scenario = SimpleNamespace(mitre=TTP, detection={}, detection_hints={})
    emitter = SimpleNamespace(resource_id=ANNATAR_RID, emit=lambda **k: emitted.append(k["event"]))
    engine._wait_and_emit_feedback(run_id, emitter, scenario, 600.0, attack_time)
    return engine, emitted


def test_wait_poll_path_records_the_latency(waiting):
    attack = waiting.clock.now - 150
    (waiting.runs / "rid_debug.jsonl").write_text(json.dumps(_poll_record(attack, 118)) + "\n")
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 118.0)
    assert emitted == []


def test_wait_rulepoller_path_records_the_same_latency(waiting):
    attack = waiting.clock.now - 150
    (waiting.runs / "watch-rule-x_debug.jsonl").write_text(
        json.dumps(_rulepoller_record(attack + 118)) + "\n")
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 118.0)
    assert emitted == []


def test_wait_an_earlier_detection_is_a_miss(waiting):
    """Only an earlier detection on the VM and technique: the run is missed, and
    detection_missed is emitted — never 'detected' on another run's detection (M99)."""
    attack = waiting.clock.now - 30
    (waiting.runs / "watch-rule-x_debug.jsonl").write_text(
        json.dumps(_rulepoller_record(attack - 200)) + "\n")
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed"
    assert engine._detection_latency_s is None
    assert emitted == ["detection_missed"]


def test_wait_timeout_in_the_run_file_is_a_miss(waiting):
    attack = waiting.clock.now - 30
    (waiting.runs / "rid_debug.jsonl").write_text(
        json.dumps({"signal": {"event": "detection_timeout", "ttp": TTP}}) + "\n")
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed"
    assert emitted == ["detection_missed"]


# ── The latency is written in runs/<run_id>.json, on both run paths ──────────────────

def _detect_at(after_s: float, seen: dict):
    """A stand-in for the wait: the watch writes a RulePoller detection `after_s` after
    the run's attack_time, then the real wait runs (with a heartbeat, it finds it at once)."""
    real = Engine._wait_and_emit_feedback

    def fake(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        seen["attack_time"] = attack_time
        Path("runs", "watch-rule-x_debug.jsonl").write_text(
            json.dumps(_rulepoller_record(attack_time + after_s, ttp=scenario.mitre)) + "\n")
        return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)

    return fake


def _report(tmp_path):
    return json.loads(next((tmp_path / "runs").glob("2*.json")).read_text())


def _attack_started(tmp_path) -> dict:
    f = next((tmp_path / "runs").glob("2*_signals.jsonl"))
    return next(json.loads(x) for x in f.read_text().splitlines()
                if x.strip() and json.loads(x)["event"] == "attack_started")


def _home(tmp_path, monkeypatch):
    import time as _time

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    hb = tmp_path / "home" / ".glorfindel" / "watch_heartbeat"
    hb.parent.mkdir(parents=True)
    hb.write_text(_iso(_time.time()))


def test_atomic_run_writes_the_latency_in_the_run(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    seen: dict = {}
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(Engine, "_wait_and_emit_feedback", _detect_at(117.5, seen)):
        outcome = engine.run(ATOMIC_YAML, skip_confirm=True)

    assert (outcome.detection, outcome.detection_latency_s) == ("detected", 117.5)
    metrics = _report(tmp_path)["metrics"]
    assert (metrics["detection"], metrics["detection_latency_s"]) == ("detected", 117.5)
    # the wait was given the run's T0 — the attack_time attack_started carries
    assert seen["attack_time"] == _attack_started(tmp_path)["raw_signal"]["attack_time"]
    # and the report keeps it: the campaign report on H0 bounds the run's decision with it (#167)
    assert metrics["attack_time"] == seen["attack_time"]


def test_local_script_run_writes_the_latency_in_the_run(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    seen: dict = {}
    engine = Engine()
    with patch.object(engine, "_get_executor_collector",
                      return_value=(_make_executor(), _make_collector())), \
         patch.object(Engine, "_wait_and_emit_feedback", _detect_at(84.0, seen)):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)

    assert (outcome.detection, outcome.detection_latency_s) == ("detected", 84.0)
    metrics = _report(tmp_path)["metrics"]
    assert (metrics["detection"], metrics["detection_latency_s"]) == ("detected", 84.0)
    assert seen["attack_time"] == _attack_started(tmp_path)["raw_signal"]["attack_time"]
    assert metrics["attack_time"] == seen["attack_time"]  # #167


def test_unmeasured_run_records_no_latency(tmp_path, monkeypatch):
    """No watch (the wait patched out): detection unknown, latency null in the run."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        outcome = engine.run(ATOMIC_YAML, skip_confirm=True)
    assert outcome.detection_latency_s is None
    metrics = _report(tmp_path)["metrics"]
    assert metrics["detection"] == "unknown" and metrics["detection_latency_s"] is None
