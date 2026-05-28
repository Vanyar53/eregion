from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from annatar.runner.engine import Engine

_SCENARIOS = Path(__file__).parent.parent.parent / "annatar" / "scenarios" / "azure"
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

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(EXFIL_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    signal = json.loads(lines[0])
    assert signal["event"] == "attack_started"
    assert signal["ttp"] == "T1041"
    assert signal["severity"] == "high"
    assert signal["provider"] == "azure"
    assert signal["resource_type"] == "vm"
    assert signal["resource_id"] == RESOURCE_ID
    assert "attack_time" in signal["raw_signal"]
    assert "detection_query" in signal["raw_signal"]
    assert "detection_timeout_s" in signal["raw_signal"]


def test_engine_emits_attack_started_ransomware(tmp_path, monkeypatch):
    """ransomware-vm: Annatar emits attack_started — detection and RTO owned by Glorfindel."""
    monkeypatch.chdir(tmp_path)
    engine = Engine()
    executor = _make_executor()
    collector = _make_collector()

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(RANSOMWARE_YAML, skip_confirm=True)

    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    lines = files[0].read_text().strip().splitlines()
    assert len(lines) == 1
    signal = json.loads(lines[0])
    assert signal["event"] == "attack_started"
    assert signal["ttp"] == "T1486"
    raw = signal["raw_signal"]
    assert raw["detection_source"] == "azure_monitor"
    assert raw["log_analytics_workspace_id"] == "b451c51a-1cd0-4125-ac70-6aaf2c1dc209"


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

    with patch.object(engine, "_get_executor_collector", return_value=(executor, collector)):
        engine.run(EXFIL_YAML, skip_confirm=True)

    executor.check_preflight.assert_not_called()
    files = list((tmp_path / "runs").glob("*_signals.jsonl"))
    assert len(files) == 1
