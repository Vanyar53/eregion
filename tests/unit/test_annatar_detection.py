"""#157 — the real detection latency of a run, and only this run's detections count.

A detection counts for a run when it is of the run's technique, on its resource (compared
without case: Log Analytics writes ``_ResourceId`` in lower case, Annatar emits ARM's
casing — measured on the bench, 20/10) and seen at or after the attack. Its latency is
measured from the run's ``attack_time``, and written in ``runs/annatar/<run_id>.json``. A run
learns of its detection through the return channel only (#159): the watch's files are not the
red's to read (SEC18) — no channel, the detection is not measured. No Azure, no LLM (mocked
executor, a throwaway HOME, a fake clock, a fake channel).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
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


# ── _wait_and_emit_feedback: the return channel only (SEC18) ──────────────────────────

class _Clock:
    """A fake clock for the engine module: sleep advances time (the wait never blocks)."""

    def __init__(self, start: float):
        self.now = start

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.now += s


def _channel_detection(seen: float, ttp: str = TTP) -> dict:
    """A detection as the hosted watch delivers it on the return channel (watch_channel.Publisher)."""
    return {"event": "detection", "ttp": ttp, "resource_id": WATCH_RID, "detected_at": _iso(seen)}


@pytest.fixture
def waiting(tmp_path, monkeypatch, signed_channel):
    """chdir to tmp, a fake clock, a return channel whose heartbeat is fresh and whose
    detections are ``channel.detections``, signed by the watch's key the injector pins (SEC21) —
    ``channel.raw`` holds ``(signal, body)`` filed as they are, signed or not — and the watch's
    files on this host, which the run must never read (SEC18)."""
    import time as _time

    from eregion_core import watch_channel

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    clock = _Clock(_time.time())
    monkeypatch.setattr(engine_module, "time", clock)
    channel = SimpleNamespace(detections=[], raw=[], heartbeat=None, signed=signed_channel)
    monkeypatch.setenv(watch_channel.CHANNEL_ENV, "https://account.blob.core.windows.net/watch")
    monkeypatch.setattr(watch_channel, "read_named", lambda run_id, **k: [
        signed_channel.sign(d, run_id, n) for n, d in enumerate(channel.detections)] + list(channel.raw))
    monkeypatch.setattr(watch_channel, "read_heartbeat", lambda **k: channel.heartbeat or {
        "at": _iso(clock.now), "since": _iso(clock.now - 86400), "windows": ["rid"]})
    watch = tmp_path / "runs" / "glorfindel"
    watch.mkdir(parents=True)
    return SimpleNamespace(runs=watch, clock=clock, channel=channel)


def _wait(attack_time: float, run_id: str = "rid"):
    engine = Engine()
    emitted = []
    scenario = SimpleNamespace(mitre=TTP, detection={}, detection_hints={})
    emitter = SimpleNamespace(resource_id=ANNATAR_RID, emit=lambda **k: emitted.append(k["event"]))
    engine._wait_and_emit_feedback(run_id, emitter, scenario, 600.0, attack_time)
    return engine, emitted


def test_wait_the_channel_path_records_the_latency(waiting):
    attack = waiting.clock.now - 150
    waiting.channel.detections = [_channel_detection(attack + 118)]
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 118.0)
    assert emitted == []


def test_wait_an_earlier_detection_is_a_miss(waiting):
    """Only an earlier detection on the VM and technique, and a heartbeat that vouches for the
    wait: the run is missed, and detection_missed is emitted — never 'detected' on another run's
    detection (M99)."""
    attack = waiting.clock.now - 30
    waiting.channel.detections = [_channel_detection(attack - 200)]
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed"
    assert engine._detection_latency_s is None
    assert emitted == ["detection_missed"]


def test_wait_never_reads_the_watchs_files(waiting):
    """SEC18 (N-05): the watch's own cycles on this host — a detection of this run in its file
    and in a RulePoller file — are not the red's to read: the channel says nothing, its heartbeat
    vouches, the run is missed."""
    attack = waiting.clock.now - 150
    (waiting.runs / "rid_debug.jsonl").write_text(json.dumps(_poll_record(attack, 118)) + "\n")
    (waiting.runs / "watch-rule-x_debug.jsonl").write_text(json.dumps(_rulepoller_record(attack + 118)) + "\n")
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_without_a_return_channel_the_detection_is_not_measured(waiting, monkeypatch, capsys):
    """SEC18: no channel — even with a live local watch and its files beside — the run's
    detection is unknown, said, never a miss: no detection_missed."""
    from eregion_core import watch_channel
    monkeypatch.delenv(watch_channel.CHANNEL_ENV)
    attack = waiting.clock.now - 150
    (waiting.runs / "rid_debug.jsonl").write_text(json.dumps(_poll_record(attack, 118)) + "\n")
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s, emitted) == ("unknown", None, [])
    out = " ".join(capsys.readouterr().out.split())
    assert "no return channel" in out and "not Annatar's to read (SEC18)" in out


# ── The latency is written in runs/annatar/<run_id>.json, on both run paths ──────────

def _detect_at(after_s: float, seen: dict):
    """A stand-in for the wait: the return channel carries the watch's detection `after_s`
    after the run's attack_time, then the real wait runs (it finds it at once)."""
    from eregion_core import watch_channel, watch_gate, watch_key
    real = Engine._wait_and_emit_feedback
    signer = watch_key.Signer(bytes(range(32)))   # SEC21: the watch's key, a fixed seed

    def fake(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        seen["attack_time"] = attack_time
        found = [("rule-1", watch_key.sign_detection(
            {**_channel_detection(attack_time + after_s, ttp=scenario.mitre),
             "signal_id": "rule-1", "exercise_run": run_id}, signer))]
        with patch.dict("os.environ", {watch_channel.CHANNEL_ENV: "https://account.blob.core.windows.net/watch",
                                       watch_key.KEY_ENV: watch_key.public_text(signer.public)}), \
             patch.object(watch_gate, "channel_beat",
                          lambda: watch_gate.Beat(watch_gate.CHANNEL, datetime.now(timezone.utc))), \
             patch.object(watch_channel, "read_named", lambda rid, **k: found):
            return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)

    return fake


def _report(tmp_path):
    return json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())


def _attack_started(tmp_path) -> dict:
    f = next((tmp_path / "runs" / "annatar").glob("2*_signals.jsonl"))
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


# SEC11 (R-19): the bench's scope names its subscription (Scope.for_bench reads it) — the one of
# this file's targets; conftest removes the operator's.
@pytest.fixture(autouse=True)
def _bench_subscription(monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")


@pytest.mark.parametrize("trap", ["fifo", "link"])
def test_the_watchs_file_is_read_as_the_watch_reads_runs(tmp_path, trap):
    """SEC16 (#438): Annatar reads the watch's debug file as the watch reads runs/ — a pipe never
    blocks the run (``[]`` at once), a link is never followed, even to a file of the right shape."""
    import os
    import threading
    from annatar.runner.detection import read_records
    f = tmp_path / "r1_debug.jsonl"
    if trap == "fifo":
        os.mkfifo(f)
    else:
        (tmp_path / "elsewhere.jsonl").write_text(json.dumps({"signal": {"event": "detection"}}) + "\n")
        f.symlink_to(tmp_path / "elsewhere.jsonl")
    box = []
    t = threading.Thread(target=lambda: box.append(read_records(f)), daemon=True)
    t.start()
    t.join(5.0)
    if t.is_alive():                                 # a red test fails, never hangs: release it
        os.close(os.open(f, os.O_WRONLY | os.O_NONBLOCK))
        t.join(2.0)
        pytest.fail("the read blocked")
    assert box == [[]]
