"""SEC18 (N-05, #455): the local channel of verdicts, ``runs/verdicts/``.

Written by the watch alone, read-only to the red: a run's verdict, its fields exactly
``VERDICT_FIELDS``; read by a run only without a storage channel, as an input it does not trust.
No Azure, no model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from eregion_core import exercise, runs_layout
from eregion_core import watch_channel as wc

VM = "/subscriptions/sub-123/resourcegroups/rg-celebrimbor/providers/microsoft.compute/virtualmachines/vm-a"
NOW = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)


def _verdict(**over) -> dict:
    doc = {"run_id": "R1", "technique": "T1136.001", "verdict": "detected",
           "detected_at": (NOW + timedelta(seconds=90)).isoformat(), "rule": "rule-1",
           "latency_s": 90.0, "target": VM}
    doc.update(over)
    return doc


@pytest.fixture
def verdicts(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(wc.CHANNEL_ENV, raising=False)
    d = runs_layout.dir_of(runs_layout.VERDICTS)
    d.mkdir(parents=True)
    return d


def test_a_verdict_holds_its_fields_and_nothing_else(verdicts):
    """M3321, M3322: a field more, or fewer, is refused at the write; a heartbeat likewise."""
    wc.write_local(verdicts, "detections/R1/a.json", _verdict())
    assert set(json.loads((verdicts / "detections" / "R1" / "a.json").read_text())) == set(wc.VERDICT_FIELDS)
    for bad in (_verdict(note="x"), {k: v for k, v in _verdict().items() if k != "rule"},
                _verdict(verdict="maybe"), _verdict(target="vm-a")):
        with pytest.raises(ValueError):
            wc.write_local(verdicts, "detections/R1/b.json", bad)
    assert not (verdicts / "detections" / "R1" / "b.json").exists()
    with pytest.raises(ValueError):
        wc.write_local(verdicts, wc.HEARTBEAT, {"at": NOW.isoformat(), "since": NOW.isoformat(),
                                                "windows": [], "perimeter": "", "more": 1})


def test_the_watch_writes_the_verdict_of_a_covered_run_only(verdicts, monkeypatch):
    """M3323: the Publisher's rule, as verdicts — only for a window that covers the VM; what the
    detection carried beyond the list never reaches the file."""
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: True)
    window = {"run_id": "R1", "injector": "annatar", "kind": "technique", "experiment": "T1136.001",
              "targets": [VM], "start": NOW.isoformat(), "end": None,
              "expires": (NOW + timedelta(hours=2)).isoformat()}
    pub = wc.LocalVerdicts(verdicts, windows=lambda: [window], now=NOW - timedelta(minutes=1))
    pub.note({"event": "detection", "signal_id": "watch-rule-1-x", "ttp": "T1136.001", "resource_id": VM,
              "timestamp": (NOW + timedelta(seconds=90)).isoformat(), "extra": "kept out",
              "context": {"rule_name": "rule-1", "attribution": "asset"}})
    pub.tick(now=NOW + timedelta(seconds=100))
    [path] = list((verdicts / "detections" / "R1").glob("*.json"))
    doc = json.loads(path.read_text())
    assert set(doc) == set(wc.VERDICT_FIELDS) and doc["latency_s"] == 90.0 and doc["rule"] == "rule-1"
    assert "watch-rule-1-x" not in path.name                      # its name says nothing of the watch's own
    assert set(json.loads((verdicts / wc.HEARTBEAT).read_text())) == set(wc.BEAT_FIELDS)
    assert wc.local_detections("R1")[0]["ttp"] == "T1136.001"


def test_a_forged_verdict_or_another_runs_is_ignored_and_said(verdicts, capsys):
    """M3324, M3325: a file of another shape, or that names another run, read by the run: never
    taken, said once."""
    d = verdicts / "detections" / "R1"
    d.mkdir(parents=True)
    (d / "good.json").write_text(json.dumps(_verdict()))
    (d / "more.json").write_text(json.dumps(_verdict(note="x")))
    (d / "other.json").write_text(json.dumps(_verdict(run_id="R2")))
    got = wc.local_detections("R1")
    assert len(got) == 1 and got[0]["detected_at"] == _verdict()["detected_at"]
    wc.local_detections("R1")
    out = capsys.readouterr().out
    assert out.count("more.json") == 1 and out.count("other.json") == 1 and "another run" in out


def test_the_storage_channel_keeps_the_priority(verdicts, monkeypatch):
    """M3326: a storage channel set, the local one is never read; with neither, no source."""
    wc.write_local(verdicts, wc.HEARTBEAT, {"at": NOW.isoformat(), "since": NOW.isoformat(),
                                            "windows": ["R1"], "perimeter": ""})
    assert wc.source() == wc.LOCAL
    monkeypatch.setenv(wc.CHANNEL_ENV, "https://account.blob.core.windows.net/watch")
    assert wc.source() == wc.STORAGE
    with patch.object(wc, "local_heartbeat", side_effect=AssertionError("local read")), \
         patch.object(wc, "_get", return_value=b'{"at": "x"}'):
        assert wc.read_heartbeat() == {"at": "x"}
    monkeypatch.delenv(wc.CHANNEL_ENV)
    (verdicts / wc.HEARTBEAT).unlink()
    assert wc.source() == ""


def test_a_local_run_finds_its_verdict_through_the_local_channel(verdicts, monkeypatch):
    """M3327, M3328: an Annatar run on a workstation, no storage channel — the watch's local
    verdict gives its detection and its latency, measured from the run's own T0."""
    from types import SimpleNamespace

    from annatar.runner import engine as engine_module
    from annatar.runner.engine import Engine

    attack = datetime.now(timezone.utc) - timedelta(seconds=150)
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: True)
    window = {"run_id": "R1", "injector": "annatar", "kind": "technique", "experiment": "T1136.001",
              "targets": [VM], "start": (attack - timedelta(seconds=5)).isoformat(), "end": None,
              "expires": (attack + timedelta(hours=1)).isoformat()}
    pub = wc.LocalVerdicts(verdicts, windows=lambda: [window], now=attack - timedelta(minutes=5))
    pub.note({"event": "detection", "signal_id": "s1", "ttp": "T1136.001", "resource_id": VM,
              "timestamp": (attack + timedelta(seconds=117.5)).isoformat(),
              "context": {"rule_name": "rule-1", "attribution": "asset"}})
    pub.tick()
    monkeypatch.setattr(engine_module.time, "sleep", lambda s: None)
    engine = Engine()
    scenario = SimpleNamespace(mitre="T1136.001", detection={}, detection_hints={})
    emitted = []
    emitter = SimpleNamespace(resource_id=VM, emit=lambda **k: emitted.append(k["event"]))
    engine._wait_and_emit_feedback("R1", emitter, scenario, 600.0, attack.timestamp())
    assert (engine._detection_result, engine._detection_latency_s, emitted) == ("detected", 117.5, [])


def test_a_local_miss_needs_the_local_heartbeat_to_vouch(verdicts, monkeypatch):
    """M3329: no verdict, and a heartbeat written after the wait by a watch up since before the
    attack, that knows the run's window: a miss, detection_missed emitted."""
    from types import SimpleNamespace

    from annatar.runner import engine as engine_module
    from annatar.runner.engine import Engine

    class Clock:
        now = datetime.now(timezone.utc).timestamp()

        def time(self):
            return self.now

        def sleep(self, s):
            self.now += s
            at = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
            wc.write_local(verdicts, wc.HEARTBEAT, {"at": at, "since": "2026-11-01T00:00:00+00:00",
                                                    "windows": ["R1"], "perimeter": ""})
    clock = Clock()
    clock.sleep(0)
    monkeypatch.setattr(engine_module, "time", clock)
    engine = Engine()
    scenario = SimpleNamespace(mitre="T1136.001", detection={}, detection_hints={})
    emitted = []
    emitter = SimpleNamespace(resource_id=VM, emit=lambda **k: emitted.append(k["event"]))
    engine._wait_and_emit_feedback("R1", emitter, scenario, 60.0, clock.now - 30)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_the_local_channel_starts_only_without_a_storage_channel(verdicts, monkeypatch):
    """M3329: a storage channel set, the watch writes no local verdict — it keeps the priority."""
    monkeypatch.setenv(wc.CHANNEL_ENV, "https://account.blob.core.windows.net/watch")
    assert wc.start_local(verdicts) is None


def test_the_poll_of_a_runs_attack_started_gives_its_verdict(verdicts, monkeypatch):
    """The first way a local watch detects a run: its attack_started resolved by the rule — its
    time the attack's plus the delay; one the watch could not tie to the VM gives none."""
    monkeypatch.setattr(exercise, "_enrollment_check", lambda rid: True)
    window = {"run_id": "R1", "injector": "annatar", "kind": "technique", "experiment": "T1136.001",
              "targets": [VM], "start": NOW.isoformat(), "end": None,
              "expires": (NOW + timedelta(hours=1)).isoformat()}
    pub = wc.LocalVerdicts(verdicts, windows=lambda: [window], now=NOW - timedelta(minutes=1))
    resolved = {"event": "detection", "signal_id": "R1_attack_started", "ttp": "T1136.001", "resource_id": VM,
                "timestamp": NOW.isoformat(), "context": {"run_id": "R1"},
                "raw_signal": {"attack_time": (NOW + timedelta(seconds=10)).timestamp(), "detection_time_s": 50}}
    pub.note_poll({**resolved, "context": {"run_id": "R1", "attribution": "unattributed"}})
    pub.note_poll(resolved)
    pub.tick(now=NOW + timedelta(seconds=90))
    [got] = wc.local_detections("R1")
    assert got["detected_at"] == (NOW + timedelta(seconds=60)).isoformat() and got["rule"] == "poll"
