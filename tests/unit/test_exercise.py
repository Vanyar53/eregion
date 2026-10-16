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
T0 = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)


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
    close_window("r1", now=_at(10))
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
    open_window("r1", injector="annatar", kind="technique", experiment="T1486", targets=[VM], now=T0)
    assert source_of("", None, run_id="r1") == ("exercise", "r1")
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
