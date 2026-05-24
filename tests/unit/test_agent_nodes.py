"""
Tests for the 6 LangGraph nodes in glorfindel/agent.py.

No Azure API calls, no Claude API calls — all external dependencies are mocked.
Each test exercises one node function in isolation, then three integration tests
exercise the full compiled graph with a mocked Anthropic client.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from glorfindel.actions import AzureConnector
from glorfindel.memory import CycleMemory


# ── Helpers ───────────────────────────────────────────────────────────────────

_RESOURCE_ID = (
    "/subscriptions/s/resourceGroups/rg"
    "/providers/Microsoft.Compute/virtualMachines/vm"
)


def _state(**overrides) -> dict:
    """Return a minimal valid GlorfindelState."""
    base = {
        "signal": {
            "signal_id": "run001_detection",
            "resource_id": _RESOURCE_ID,
            "resource_type": "vm",
            "ttp": "T1486",
            "severity": "critical",
            "event": "detection",
            "raw_signal": {"detection_time_s": 50},
            "context": {"run_id": "run001"},
        },
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": "",
        "escalate": False,
        "escalation_reason": "",
        "outcome": None,
    }
    base.update(overrides)
    return base


def _mock_llm_response(action: str, escalate: bool = False, escalation_reason: str = "") -> MagicMock:
    """Build a mock Anthropic response that calls the security_decision tool."""
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "security_decision"
    tool_block.input = {
        "reasoning": f"Identified threat. Action: {action}.",
        "confidence": 0.95,
        "action": action,
        "reversible": True,
        "explanation": f"Executing {action}.",
        "escalate": escalate,
        "escalation_reason": escalation_reason,
    }
    mock_response = MagicMock()
    mock_response.content = [tool_block]
    return mock_response


@pytest.fixture()
def dry_connector():
    return AzureConnector(dry_run=True)


@pytest.fixture()
def tmp_memory(tmp_path):
    return CycleMemory(path=tmp_path / "cycles")


# ── poll_detection ─────────────────────────────────────────────────────────────

def test_poll_detection_noop_for_detection_event():
    from glorfindel.agent import poll_detection
    state = _state()  # event="detection"
    result = poll_detection(state)
    assert result["signal"]["event"] == "detection"


def test_poll_detection_noop_for_recovery_complete():
    from glorfindel.agent import poll_detection
    state = _state()
    state["signal"]["event"] = "recovery_complete"
    result = poll_detection(state)
    assert result["signal"]["event"] == "recovery_complete"


def test_poll_detection_updates_event_to_detection_on_alert():
    from glorfindel.agent import poll_detection
    state = _state()
    state["signal"]["event"] = "attack_started"
    state["signal"]["raw_signal"] = {
        "detection_source": "azure_monitor",
        "detection_query": "Syslog | ...",
        "detection_timeout_s": 300,
        "attack_time": 1000.0,
        "log_analytics_workspace_id": "ws-123",
    }
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (60.0, {"SourceIP": "185.220.101.1", "FailedAttempts": "34"})

    with patch("glorfindel.detectors.detector_for", return_value=mock_detector):
        result = poll_detection(state)

    assert result["signal"]["event"] == "detection"
    assert result["signal"]["raw_signal"]["detection_time_s"] == 60.0
    assert result["signal"]["raw_signal"]["detected_data"]["SourceIP"] == "185.220.101.1"


def test_poll_detection_updates_event_to_timeout_on_no_alert():
    from glorfindel.agent import poll_detection
    state = _state()
    state["signal"]["event"] = "attack_started"
    state["signal"]["raw_signal"] = {
        "detection_source": "azure_monitor",
        "detection_query": "...",
        "detection_timeout_s": 10,
        "attack_time": 1000.0,
        "log_analytics_workspace_id": "ws-123",
    }
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None  # timed out

    with patch("glorfindel.detectors.detector_for", return_value=mock_detector):
        result = poll_detection(state)

    assert result["signal"]["event"] == "detection_timeout"


def test_poll_detection_unknown_source_falls_back_to_timeout():
    from glorfindel.agent import poll_detection
    state = _state()
    state["signal"]["event"] = "attack_started"
    state["signal"]["raw_signal"] = {
        "detection_source": "unknown_siem",
        "detection_timeout_s": 10,
        "attack_time": 1000.0,
    }
    with patch("glorfindel.detectors.detector_for", side_effect=ValueError("unknown source")):
        result = poll_detection(state)

    assert result["signal"]["event"] == "detection_timeout"


# ── load_context ──────────────────────────────────────────────────────────────

def test_load_context_retrieves_past_cycles(tmp_path):
    from glorfindel.agent import load_context
    mem = CycleMemory(path=tmp_path / "cycles")
    mem.store({
        "signal_id": "prev_001",
        "ttp": "T1486",
        "severity": "critical",
        "resource_type": "vm",
        "event": "detection",
        "reasoning": "Isolated VM after ransomware",
        "action": "isolate_vm",
        "outcome": "isolated",
    })

    result = load_context(_state(), memory=mem)

    assert len(result["past_cycles"]) == 1
    assert result["past_cycles"][0]["action"] == "isolate_vm"


def test_load_context_empty_memory_returns_empty_list(tmp_path):
    from glorfindel.agent import load_context
    mem = CycleMemory(path=tmp_path / "cycles")
    result = load_context(_state(), memory=mem)
    assert result["past_cycles"] == []


def test_load_context_does_not_mutate_other_state_fields(tmp_path):
    from glorfindel.agent import load_context
    mem = CycleMemory(path=tmp_path / "cycles")
    state = _state()
    state["reasoning"] = "preserved"
    result = load_context(state, memory=mem)
    assert result["reasoning"] == "preserved"


# ── execute_action ────────────────────────────────────────────────────────────

def test_execute_action_isolate_vm():
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated"}
    state = _state(action="isolate_vm")

    result = execute_action(state, connector=connector)

    connector.isolate_vm.assert_called_once_with(_RESOURCE_ID)
    assert result["outcome"]["status"] == "isolated"
    assert result["outcome"]["executed"] is True


def test_execute_action_release_isolation():
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.release_isolation.return_value = {"status": "released"}
    state = _state(action="release_isolation")

    result = execute_action(state, connector=connector)

    connector.release_isolation.assert_called_once_with(_RESOURCE_ID)
    assert result["outcome"]["status"] == "released"


def test_execute_action_block_ip_uses_source_ip_first():
    """SourceIP (brute force) takes priority over DestIP_s (exfil)."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.block_suspicious_ip.return_value = {"status": "blocked"}
    state = _state(action="block_suspicious_ip")
    state["signal"]["raw_signal"] = {
        "detected_data": {"SourceIP": "185.220.101.1", "DestIP_s": "10.0.0.5"},
    }

    execute_action(state, connector=connector)

    connector.block_suspicious_ip.assert_called_once_with("185.220.101.1", _RESOURCE_ID)


def test_execute_action_block_ip_falls_back_to_dest_ip():
    """Falls back to DestIP_s when SourceIP is absent."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.block_suspicious_ip.return_value = {"status": "blocked"}
    state = _state(action="block_suspicious_ip")
    state["signal"]["raw_signal"] = {
        "detected_data": {"DestIP_s": "203.0.113.5"},
    }

    execute_action(state, connector=connector)

    connector.block_suspicious_ip.assert_called_once_with("203.0.113.5", _RESOURCE_ID)


def test_execute_action_snapshot_returns_snapshot_id():
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.snapshot.return_value = "snap-20260524-001"
    state = _state(action="snapshot")

    result = execute_action(state, connector=connector)

    connector.snapshot.assert_called_once_with(_RESOURCE_ID)
    assert result["outcome"]["snapshot_id"] == "snap-20260524-001"


def test_execute_action_unknown_is_noop():
    from glorfindel.agent import execute_action
    connector = MagicMock()
    state = _state(action="proposed_custom_action")

    result = execute_action(state, connector=connector)

    connector.isolate_vm.assert_not_called()
    connector.block_suspicious_ip.assert_not_called()
    assert result["outcome"]["status"] == "no_op"
    assert result["outcome"]["action"] == "proposed_custom_action"


def test_execute_action_records_action_s():
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated"}
    result = execute_action(_state(action="isolate_vm"), connector=connector)
    assert "action_s" in result["outcome"]
    assert isinstance(result["outcome"]["action_s"], int)


# ── verify_action ─────────────────────────────────────────────────────────────

def test_verify_action_isolate_vm_success():
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_isolation.return_value = {"verified": True, "method": "nsg_check"}
    state = _state(action="isolate_vm")
    state["outcome"] = {"status": "isolated", "executed": True}

    result = verify_action(state, connector=connector)

    assert result["outcome"]["verified"] is True
    assert result["escalate"] is False


def test_verify_action_isolate_vm_failure_sets_escalate():
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_isolation.return_value = {"verified": False, "error": "rule missing"}
    state = _state(action="isolate_vm")
    state["outcome"] = {"status": "isolated", "executed": True}

    result = verify_action(state, connector=connector)

    assert result["outcome"]["verified"] is False
    assert result["escalate"] is True
    assert result["escalation_reason"] != ""


def test_verify_action_release_isolation_success_when_rules_gone():
    """release_isolation is verified when verify_isolation reports no rules (verified=False)."""
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_isolation.return_value = {"verified": False, "method": "nsg_check"}
    state = _state(action="release_isolation")
    state["outcome"] = {"status": "released", "executed": True}

    result = verify_action(state, connector=connector)

    # not False = True: no isolation = successful release
    assert result["outcome"]["verified"] is True
    assert result["escalate"] is False


def test_verify_action_release_isolation_failure_when_rules_still_present():
    """release_isolation fails when isolation rules are still active."""
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_isolation.return_value = {"verified": True, "method": "nsg_check"}
    state = _state(action="release_isolation")
    state["outcome"] = {"status": "released", "executed": True}

    result = verify_action(state, connector=connector)

    # not True = False: still isolated = failed release
    assert result["outcome"]["verified"] is False
    assert result["escalate"] is True


def test_verify_action_block_suspicious_ip_extracts_source_ip():
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_block_ip.return_value = {"verified": True, "method": "nsg_rule_check"}
    state = _state(action="block_suspicious_ip")
    state["signal"]["raw_signal"] = {"detected_data": {"SourceIP": "185.220.101.1"}}
    state["outcome"] = {"status": "blocked", "executed": True}

    result = verify_action(state, connector=connector)

    connector.verify_block_ip.assert_called_once_with("185.220.101.1", _RESOURCE_ID)
    assert result["outcome"]["verified"] is True


def test_verify_action_dry_run_short_circuits():
    """dry_run outcome skips all verification and returns verified=None."""
    from glorfindel.agent import verify_action
    connector = MagicMock()
    state = _state(action="isolate_vm")
    state["outcome"] = {"status": "dry_run"}

    result = verify_action(state, connector=connector)

    connector.verify_isolation.assert_not_called()
    assert result["outcome"]["verified"] is None
    assert result["escalate"] is False


# ── store_cycle ───────────────────────────────────────────────────────────────

def _ready_state_for_store(**sig_overrides) -> dict:
    state = _state()
    state["action"] = "isolate_vm"
    state["reasoning"] = "Ransomware detected — isolating VM."
    state["confidence"] = 0.95
    state["escalate"] = False
    state["escalation_reason"] = ""
    state["outcome"] = {"status": "isolated", "verified": True, "action_s": 9}
    state["signal"].update(sig_overrides)
    return state


def test_store_cycle_writes_debug_jsonl(tmp_path, monkeypatch, tmp_memory):
    from glorfindel.agent import store_cycle
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()

    store_cycle(_ready_state_for_store(), memory=tmp_memory)

    debug_file = tmp_path / "runs" / "run001_debug.jsonl"
    assert debug_file.exists()
    record = json.loads(debug_file.read_text())
    assert record["action"] == "isolate_vm"
    assert record["confidence"] == 0.95
    assert record["signal"]["ttp"] == "T1486"


def test_store_cycle_appends_on_multiple_calls(tmp_path, monkeypatch, tmp_memory):
    from glorfindel.agent import store_cycle
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()

    store_cycle(_ready_state_for_store(), memory=tmp_memory)
    store_cycle(_ready_state_for_store(action="release_isolation"), memory=tmp_memory)

    debug_file = tmp_path / "runs" / "run001_debug.jsonl"
    lines = debug_file.read_text().strip().splitlines()
    assert len(lines) == 2


def test_store_cycle_no_jsonl_without_run_id(tmp_path, monkeypatch, tmp_memory):
    from glorfindel.agent import store_cycle
    monkeypatch.chdir(tmp_path)

    state = _ready_state_for_store()
    state["signal"]["context"] = {}  # no run_id

    store_cycle(state, memory=tmp_memory)

    runs_dir = tmp_path / "runs"
    if runs_dir.exists():
        assert list(runs_dir.glob("*_debug.jsonl")) == []


def test_store_cycle_persists_to_memory(tmp_path, monkeypatch, tmp_memory):
    from glorfindel.agent import store_cycle
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()

    assert tmp_memory.count() == 0
    store_cycle(_ready_state_for_store(), memory=tmp_memory)
    assert tmp_memory.count() == 1


# ── Graph integration (LLM mocked) ───────────────────────────────────────────

def _build(tmp_path, tmp_memory, dry_connector):
    from glorfindel.agent import _build_graph
    (tmp_path / "runs").mkdir(exist_ok=True)
    return _build_graph(tmp_memory, dry_connector, "claude-test")


def _initial(event: str, ttp: str = "T1486", raw: dict | None = None) -> dict:
    return {
        "signal": {
            "signal_id": f"run001_{event}",
            "resource_id": _RESOURCE_ID,
            "resource_type": "vm",
            "ttp": ttp,
            "severity": "critical",
            "event": event,
            "raw_signal": raw or {},
            "context": {"run_id": "run001"},
        },
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": "",
        "escalate": False,
        "escalation_reason": "",
        "outcome": None,
    }


def test_graph_detection_isolate_vm(tmp_path, monkeypatch, dry_connector, tmp_memory):
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = _mock_llm_response("isolate_vm")
        final = graph.invoke(_initial("detection", raw={"detection_time_s": 50}))

    assert final["action"] == "isolate_vm"
    assert final["outcome"]["status"] == "dry_run"
    assert final["escalate"] is False
    assert tmp_memory.count() == 1


def test_graph_detection_timeout_takes_snapshot_and_escalates(tmp_path, monkeypatch, dry_connector, tmp_memory):
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = _mock_llm_response(
            "snapshot", escalate=True, escalation_reason="IDS gap — T1486 missed"
        )
        final = graph.invoke(_initial("detection_timeout"))

    assert final["action"] == "snapshot"
    assert final["outcome"]["status"] == "escalated"
    # snapshot is autonomous but LLM set escalate=True → low_confidence escalation type
    assert final["outcome"]["escalation_type"] == "low_confidence"
    assert tmp_memory.count() == 1


def test_graph_recovery_complete_releases_isolation(tmp_path, monkeypatch, dry_connector, tmp_memory):
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = _mock_llm_response("release_isolation")
        final = graph.invoke(_initial(
            "recovery_complete",
            raw={"recovery_point_time": "2026-05-24T10:00:00Z", "restore_time_s": 1220},
        ))

    assert final["action"] == "release_isolation"
    assert final["outcome"]["status"] == "dry_run"
    assert final["escalate"] is False
    assert tmp_memory.count() == 1


def test_graph_destructive_action_always_escalates(tmp_path, monkeypatch, dry_connector, tmp_memory):
    """LLM proposes restore_from_backup — must escalate even if escalate=False in response."""
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = _mock_llm_response(
            "restore_from_backup", escalate=False  # LLM forgot to escalate — routing must catch it
        )
        final = graph.invoke(_initial("recovery_failed"))

    assert final["outcome"]["status"] == "escalated"
    assert final["outcome"]["escalation_type"] == "destructive_action"
    assert tmp_memory.count() == 1


def test_graph_proposed_action_escalates(tmp_path, monkeypatch, dry_connector, tmp_memory):
    """Unknown action proposed by LLM must always be escalated."""
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("anthropic.Anthropic") as mock_cls:
        mock_cls.return_value.messages.create.return_value = _mock_llm_response(
            "revoke_managed_identity", escalate=False,
            escalation_reason="Revoke MSI to stop exfil",
        )
        final = graph.invoke(_initial("detection", raw={"detection_time_s": 30}))

    assert final["outcome"]["status"] == "escalated"
    assert final["outcome"]["escalation_type"] == "proposed_action"
    assert tmp_memory.count() == 1
