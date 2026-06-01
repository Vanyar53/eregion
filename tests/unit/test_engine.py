from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

from annatar.runner.engine import Engine
from annatar.signals.emitter import SignalEmitter

_SCENARIOS = Path(__file__).parent.parent.parent / "annatar" / "scenarios" / "azure"
EXFIL_YAML = str(_SCENARIOS / "data-exfiltration.yaml")
RANSOMWARE_YAML = str(_SCENARIOS / "ransomware-vm.yaml")
LATERAL_YAML = str(_SCENARIOS / "lateral-movement.yaml")


def test_parse_duration_seconds():
    assert Engine._parse_duration("300s") == 300.0


def test_parse_duration_minutes():
    assert Engine._parse_duration("10m") == 600.0


def test_parse_duration_hours():
    assert Engine._parse_duration("2h") == 7200.0


def test_parse_duration_plain():
    assert Engine._parse_duration("120") == 120.0


# ── Signal emission integration ───────────────────────────────────────────────

RESOURCE_ID = (
    "/subscriptions/sub-123/resourceGroups/annatar"
    "/providers/Microsoft.Compute/virtualMachines/vm-annatar-victim"
)


def _make_executor(tags=None):
    executor = MagicMock()
    executor.get_resource_group_tags.return_value = tags or {"annatar-test": "true"}
    executor.resource_id = RESOURCE_ID
    executor.run_script.return_value = "INTEGRITY_PASS"
    executor.verify_restore_integrity.return_value = True
    executor.check_preflight.return_value = []
    return executor


def _make_collector():
    return MagicMock()


def test_engine_emits_attack_started_exfil(tmp_path, monkeypatch):
    """data-exfiltration: Annatar emits attack_started — Glorfindel owns detection."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1
    signals = [json.loads(ln) for ln in files[0].read_text().strip().splitlines() if ln.strip()]
    signal = next(s for s in signals if s["event"] == "attack_started")
    assert signal["ttp"] == "T1041"
    assert signal["severity"] == "high"
    assert signal["provider"] == "azure"
    assert signal["resource_type"] == "vm"
    assert signal["resource_id"] == RESOURCE_ID
    assert "attack_time" in signal["raw_signal"]
    assert "detection_timeout_s" in signal["raw_signal"]
    # detection_query removed — Glorfindel resolves via detection_rules.yaml by TTP


def test_engine_emits_attack_started_ransomware(tmp_path, monkeypatch):
    """ransomware-vm: Annatar emits attack_started — detection and RTO owned by Glorfindel."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    signals = [json.loads(ln) for ln in files[0].read_text().strip().splitlines() if ln.strip()]
    signal = next(s for s in signals if s["event"] == "attack_started")
    assert signal["ttp"] == "T1486"
    raw = signal["raw_signal"]
    assert "attack_time" in raw
    assert "detection_timeout_s" in raw
    # detection_source/workspace_id removed — Glorfindel resolves via detection_rules.yaml


def test_engine_aborts_if_precheck_fails(tmp_path, monkeypatch):
    """Pre-run integrity check failure → engine aborts, no signals emitted."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    executor.verify_restore_integrity.return_value = False
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert files == []


def test_engine_aborts_if_preflight_fails(tmp_path, monkeypatch):
    """Preflight issue (VM stopped or isolated) → engine aborts before setup."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    executor.check_preflight.return_value = [
        "VM 'vm-annatar-victim' is not running (PowerState/deallocated)\n"
        "  → az vm start -g annatar -n vm-annatar-victim"
    ]
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert files == []
    executor.run_script.assert_not_called()


def test_engine_skip_preflight_bypasses_check(tmp_path, monkeypatch):
    """--skip-preflight lets the run proceed even if the VM would fail the check."""
    monkeypatch.chdir(tmp_path)
    engine = Engine(skip_preflight=True)
    executor = _make_executor()
    executor.check_preflight.return_value = ["VM is not running"]
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)), \
         patch.object(engine, "_wait_and_emit_feedback"):
        engine.run(EXFIL_YAML, skip_confirm=True)

    executor.check_preflight.assert_not_called()
    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1


# ── RulePoller watch-file detection ──────────────────────────────────────────

def test_check_watch_files_finds_matching_detection(tmp_path):
    """_check_watch_files returns 'detection' when a watch file has a match."""
    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-sudo-privilege-escalation-20260601T134025Z_debug.jsonl"
    rec = {
        "signal": {
            "event": "detection",
            "ttp": "T1548.003",
            "resource_id": RESOURCE_ID,
        }
    }
    watch_file.write_text(json.dumps(rec) + "\n")

    engine = Engine()
    result = engine._check_watch_files(
        "T1548.003", RESOURCE_ID, since=0.0, runs_dir=runs
    )
    assert result == "detection"


def test_check_watch_files_ignores_wrong_ttp(tmp_path):
    """_check_watch_files ignores files whose TTP does not match."""
    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-something-20260601T000000Z_debug.jsonl"
    rec = {
        "signal": {
            "event": "detection",
            "ttp": "T1041",
            "resource_id": RESOURCE_ID,
        }
    }
    watch_file.write_text(json.dumps(rec) + "\n")

    engine = Engine()
    result = engine._check_watch_files(
        "T1548.003", RESOURCE_ID, since=0.0, runs_dir=runs
    )
    assert result is None


def test_check_watch_files_ignores_old_files(tmp_path):
    """_check_watch_files ignores files older than since."""
    runs = tmp_path / "runs"
    runs.mkdir()
    watch_file = runs / "watch-old-20260101T000000Z_debug.jsonl"
    rec = {
        "signal": {
            "event": "detection",
            "ttp": "T1548.003",
            "resource_id": RESOURCE_ID,
        }
    }
    watch_file.write_text(json.dumps(rec) + "\n")

    import time as _time
    engine = Engine()
    result = engine._check_watch_files(
        "T1548.003", RESOURCE_ID, since=_time.time() + 10, runs_dir=runs
    )
    assert result is None


# ── Block watcher ─────────────────────────────────────────────────────────────

def test_watch_blocks_emits_attack_adapted(tmp_path):
    """_watch_blocks emits attack_adapted when a source IP appears in blocks."""
    emitter = SignalEmitter(
        run_id="test-block-watch",
        scenario_name="test",
        scenario_mitre="T1110.001",
        target={"type": "azure_vm", "resource_group": "rg", "vm_name": "vm"},
        resource_id="/sub/123/vm",
        runs_dir=tmp_path / "runs",
    )
    blocks_file = tmp_path / "blocks.json"
    stop_event = threading.Event()
    engine = Engine()

    t = threading.Thread(
        target=engine._watch_blocks,
        args=(["185.220.101.1"], emitter, stop_event, blocks_file, 0.05),
    )
    t.start()

    # Write block after a short delay — watcher should pick it up
    import time
    time.sleep(0.02)
    blocks_file.write_text(json.dumps([{"ip": "185.220.101.1"}]))
    time.sleep(0.2)
    stop_event.set()
    t.join(timeout=2.0)

    signals_file = tmp_path / "runs" / "test-block-watch_signals.jsonl"
    signals = [json.loads(ln) for ln in signals_file.read_text().strip().splitlines()]
    adapted = [s for s in signals if s["event"] == "attack_adapted"]
    assert len(adapted) == 1
    assert adapted[0]["raw_signal"]["blocked_ip"] == "185.220.101.1"
    assert adapted[0]["raw_signal"]["reason"] == "source_ip_blocked_by_defender"


def test_watch_blocks_no_duplicate_emit(tmp_path):
    """_watch_blocks emits attack_adapted only once per blocked IP."""
    import time

    emitter = SignalEmitter(
        run_id="test-no-dup",
        scenario_name="test",
        scenario_mitre="T1110.001",
        target={"type": "azure_vm", "resource_group": "rg", "vm_name": "vm"},
        resource_id="/sub/123/vm",
        runs_dir=tmp_path / "runs",
    )
    blocks_file = tmp_path / "blocks.json"
    blocks_file.write_text(json.dumps([{"ip": "185.220.101.1"}]))

    stop_event = threading.Event()
    engine = Engine()

    t = threading.Thread(
        target=engine._watch_blocks,
        args=(["185.220.101.1"], emitter, stop_event, blocks_file, 0.05),
    )
    t.start()
    time.sleep(0.3)
    stop_event.set()
    t.join(timeout=2.0)

    signals_file = tmp_path / "runs" / "test-no-dup_signals.jsonl"
    signals = [json.loads(ln) for ln in signals_file.read_text().strip().splitlines()]
    adapted = [s for s in signals if s["event"] == "attack_adapted"]
    assert len(adapted) == 1


def test_watch_blocks_ignores_unrelated_ips(tmp_path):
    """_watch_blocks does not emit for IPs not in source_ips."""
    import time

    emitter = SignalEmitter(
        run_id="test-unrelated",
        scenario_name="test",
        scenario_mitre="T1110.001",
        target={"type": "azure_vm", "resource_group": "rg", "vm_name": "vm"},
        resource_id="/sub/123/vm",
        runs_dir=tmp_path / "runs",
    )
    blocks_file = tmp_path / "blocks.json"
    blocks_file.write_text(json.dumps([{"ip": "10.0.0.1"}]))

    stop_event = threading.Event()
    engine = Engine()

    t = threading.Thread(
        target=engine._watch_blocks,
        args=(["185.220.101.1"], emitter, stop_event, blocks_file, 0.05),
    )
    t.start()
    time.sleep(0.2)
    stop_event.set()
    t.join(timeout=2.0)

    runs_dir = tmp_path / "runs"
    assert not runs_dir.exists() or not any(runs_dir.glob("*_signals.jsonl"))
