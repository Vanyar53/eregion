from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from annatar.runner.engine import Engine

_SCENARIOS = Path(__file__).parent.parent.parent / "scenarios" / "azure"
EXFIL_YAML = str(_SCENARIOS / "data-exfiltration.yaml")
RANSOMWARE_YAML = str(_SCENARIOS / "ransomware-vm.yaml")


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
    return executor


def _make_collector(detection_time=42.0, heartbeat_time=None):
    collector = MagicMock()
    collector.poll_alert.return_value = detection_time
    collector.wait_for_heartbeat.return_value = heartbeat_time
    return collector


def test_engine_emits_detection_signal_exfil(tmp_path, monkeypatch):
    """data-exfiltration: detection only, no recovery — one signal emitted."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector(detection_time=30.0)

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(EXFIL_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    signal = json.loads(lines[0])
    assert signal["event"] == "detection"
    assert signal["ttp"] == "T1041"
    assert signal["severity"] == "high"
    assert signal["provider"] == "azure"
    assert signal["resource_type"] == "vm"
    assert signal["resource_id"] == RESOURCE_ID
    assert signal["raw_signal"]["detection_time_s"] == 30
    assert signal["raw_signal"]["passed"] is True


def test_engine_emits_detection_timeout_signal(tmp_path, monkeypatch):
    """Detection timeout → detection_timeout event emitted."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector(detection_time=None)

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(EXFIL_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "detection_timeout"


def test_engine_emits_detection_only(tmp_path, monkeypatch):
    """ransomware-vm: Annatar emits detection only — recovery is Glorfindel's."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector(detection_time=10.0)

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "detection"


def test_engine_aborts_if_precheck_fails(tmp_path, monkeypatch):
    """Pre-run integrity check failure → engine aborts, no signals emitted."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    executor.verify_restore_integrity.return_value = False
    collector = _make_collector(detection_time=10.0)

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert files == []
