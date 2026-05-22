from __future__ import annotations

import json
from pathlib import Path

import pytest

from annatar.signals.schema import Signal, severity_for_ttp
from annatar.signals.emitter import SignalEmitter, _provider, _resource_type


# ── severity_for_ttp ──────────────────────────────────────────────────────────

def test_severity_known_ttps():
    assert severity_for_ttp("T1486") == "critical"
    assert severity_for_ttp("T1041") == "high"
    assert severity_for_ttp("T1055") == "medium"


def test_severity_unknown_ttp_defaults_to_medium():
    assert severity_for_ttp("T9999") == "medium"
    assert severity_for_ttp("") == "medium"


# ── _provider / _resource_type ────────────────────────────────────────────────

def test_provider_mapping():
    assert _provider({"type": "azure_vm"}) == "azure"
    assert _provider({"type": "aws_ec2"}) == "aws"
    assert _provider({"type": "gcp_instance"}) == "gcp"
    assert _provider({"type": "unknown_type"}) == "unknown"
    assert _provider({}) == "unknown"


def test_resource_type_mapping():
    assert _resource_type({"type": "azure_vm"}) == "vm"
    assert _resource_type({"type": "azure_storage"}) == "storage"
    assert _resource_type({"type": "azure_network"}) == "network"
    assert _resource_type({}) == "unknown"


# ── SignalEmitter ─────────────────────────────────────────────────────────────

TARGET = {
    "type": "azure_vm",
    "resource_group": "rg-test",
    "vm_name": "vm-test",
}

RESOURCE_ID = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"


def test_emit_writes_jsonl(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    emitter = SignalEmitter(
        run_id="20260101T000000Z",
        scenario_name="azure-ransomware-vm",
        scenario_mitre="T1486",
        target=TARGET,
        resource_id=RESOURCE_ID,
    )
    signal = emitter.emit(
        event="detection",
        raw_signal={"detection_time_s": 42, "passed": True},
        metrics={"detection_s": 42},
    )

    signals_path = tmp_path / "runs" / "20260101T000000Z_signals.jsonl"
    assert signals_path.exists()
    lines = signals_path.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["signal_id"] == "20260101T000000Z_detection"
    assert data["ttp"] == "T1486"
    assert data["severity"] == "critical"
    assert data["provider"] == "azure"
    assert data["resource_type"] == "vm"
    assert data["resource_id"] == RESOURCE_ID
    assert data["event"] == "detection"
    assert data["raw_signal"]["detection_time_s"] == 42
    assert data["context"]["run_id"] == "20260101T000000Z"
    assert data["context"]["scenario"] == "azure-ransomware-vm"


def test_emit_multiple_events_append(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    emitter = SignalEmitter(
        run_id="20260101T000000Z",
        scenario_name="azure-ransomware-vm",
        scenario_mitre="T1486",
        target=TARGET,
        resource_id=RESOURCE_ID,
    )
    emitter.emit(event="detection")
    emitter.emit(event="recovery_complete")

    signals_path = tmp_path / "runs" / "20260101T000000Z_signals.jsonl"
    lines = signals_path.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event"] == "detection"
    assert json.loads(lines[1])["event"] == "recovery_complete"


def test_emit_returns_signal_object(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    emitter = SignalEmitter(
        run_id="20260101T000000Z",
        scenario_name="azure-data-exfiltration",
        scenario_mitre="T1041",
        target=TARGET,
        resource_id=RESOURCE_ID,
    )
    signal = emitter.emit(event="detection")
    assert isinstance(signal, Signal)
    assert signal.severity == "high"
    assert signal.ttp == "T1041"
