from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from annatar.signals.schema import Signal
from glorfindel.actions import (
    AUTONOMOUS_ACTIONS,
    HUMAN_APPROVAL_REQUIRED,
    _parse_vm_resource_id,
)
from glorfindel.signals import load_signals


# ── actions ───────────────────────────────────────────────────────────────────

def test_autonomous_and_destructive_sets_are_disjoint():
    assert AUTONOMOUS_ACTIONS.isdisjoint(HUMAN_APPROVAL_REQUIRED)


def test_isolate_vm_in_autonomous():
    assert "isolate_vm" in AUTONOMOUS_ACTIONS


def test_delete_resource_requires_human():
    assert "delete_resource" in HUMAN_APPROVAL_REQUIRED


def test_parse_vm_resource_id():
    resource_id = (
        "/subscriptions/sub-123/resourceGroups/rg-test"
        "/providers/Microsoft.Compute/virtualMachines/vm-test"
    )
    rg, vm = _parse_vm_resource_id(resource_id)
    assert rg == "rg-test"
    assert vm == "vm-test"


def test_azure_connector_dry_run_isolate(tmp_path):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.isolate_vm("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
    assert result["status"] == "dry_run"
    assert result["action"] == "isolate_vm"


def test_azure_connector_dry_run_release(tmp_path):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.release_isolation("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
    assert result["status"] == "dry_run"


# ── signals loader ────────────────────────────────────────────────────────────

_SAMPLE_SIGNAL = Signal(
    signal_id="20260101T000000Z_detection",
    timestamp="2026-01-01T00:00:00+00:00",
    provider="azure",
    resource_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
    resource_type="vm",
    ttp="T1486",
    severity="critical",
    event="detection",
    raw_signal={"detection_time_s": 42},
    context={"run_id": "20260101T000000Z"},
)


def test_load_signals_from_jsonl(tmp_path):
    path = tmp_path / "signals.jsonl"
    path.write_text(json.dumps(asdict(_SAMPLE_SIGNAL)) + "\n")

    signals = load_signals(path)
    assert len(signals) == 1
    assert signals[0].ttp == "T1486"
    assert signals[0].severity == "critical"
    assert signals[0].event == "detection"


def test_load_signals_multiple(tmp_path):
    path = tmp_path / "signals.jsonl"
    lines = [
        json.dumps(asdict(_SAMPLE_SIGNAL)),
        json.dumps({**asdict(_SAMPLE_SIGNAL), "signal_id": "x_recovery", "event": "recovery_complete"}),
    ]
    path.write_text("\n".join(lines) + "\n")

    signals = load_signals(path)
    assert len(signals) == 2
    assert signals[1].event == "recovery_complete"


# ── agent routing logic ───────────────────────────────────────────────────────

def test_route_autonomous_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "isolate_vm",
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.9,
        "reversible": True,
        "explanation": "",
        "escalation_reason": "",
        "outcome": None,
    }
    assert _route_after_decide(state) == "execute_action"


def test_route_escalates_destructive_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "delete_resource",  # destructive — must escalate regardless
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.9,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "",
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_route_escalates_when_llm_requests():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": True,
        "action": "isolate_vm",  # autonomous, but LLM flagged uncertainty
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.4,
        "reversible": True,
        "explanation": "",
        "escalation_reason": "Confidence too low for autonomous action",
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_route_escalates_unknown_proposed_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "revoke_service_principal_tokens",  # unknown — LLM proposed it
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.85,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "Revoke all tokens for the compromised SP — not in known action set",
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_escalate_to_human_marks_proposed_action_type():
    from glorfindel.agent import escalate_to_human

    state = {
        "escalate": False,
        "action": "revoke_service_principal_tokens",
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.85,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "Revoke all tokens for the compromised SP",
        "outcome": None,
    }
    result = escalate_to_human(state)
    assert result["outcome"]["escalation_type"] == "proposed_action"
    assert result["outcome"]["action_pending"] == "revoke_service_principal_tokens"


# ── memory ────────────────────────────────────────────────────────────────────

def test_memory_store_and_retrieve(tmp_path):
    from glorfindel.memory import CycleMemory

    mem = CycleMemory(path=tmp_path / "cycles")
    assert mem.count() == 0

    mem.store({
        "signal_id": "test_001",
        "ttp": "T1486",
        "severity": "critical",
        "resource_type": "vm",
        "event": "detection",
        "reasoning": "Ransomware detected — isolated VM",
        "action": "isolate_vm",
        "outcome": "isolated",
    })
    assert mem.count() == 1

    results = mem.retrieve_similar(
        {"ttp": "T1486", "severity": "critical", "resource_type": "vm", "event": "detection"},
        n=3,
    )
    assert len(results) == 1
    assert results[0]["action"] == "isolate_vm"


def test_memory_retrieve_empty_returns_empty_list(tmp_path):
    from glorfindel.memory import CycleMemory

    mem = CycleMemory(path=tmp_path / "cycles")
    results = mem.retrieve_similar({"ttp": "T1486"}, n=3)
    assert results == []
