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
        "incident": None,
        "dry_run": False,
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


def _mock_llm_response(
    action: str,
    escalate: bool = False,
    escalation_reason: str = "",
    confidence: float = 0.95,
) -> MagicMock:
    """Build a mock LiteLLM response (OpenAI format) that calls the security_decision tool."""
    import json
    arguments = json.dumps({
        "reasoning": f"Identified threat. Action: {action}.",
        "confidence": confidence,
        "action": action,
        "reversible": True,
        "explanation": f"Executing {action}.",
        "escalate": escalate,
        "escalation_reason": escalation_reason,
        "suggested_steps": ["Check VM state", "Restore if needed"] if escalate else [],
    })
    tool_call = MagicMock()
    tool_call.function.arguments = arguments

    message = MagicMock()
    message.tool_calls = [tool_call]

    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=message)]
    return mock_response


@pytest.fixture()
def dry_connector():
    return AzureConnector(dry_run=True)


@pytest.fixture()
def tmp_memory(tmp_path):
    return CycleMemory(path=tmp_path / "cycles")


@pytest.fixture()
def tmp_incidents(tmp_path):
    from glorfindel.incidents import IncidentRegistry
    return IncidentRegistry(path=tmp_path / "incidents.jsonl")


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


# ── _find_rule_for_ttp / resolve_attack_started ───────────────────────────────

def test_find_rule_for_ttp_with_glorfindel_cfg_resolves_workspace_id(tmp_path):
    """Bug fix: _find_rule_for_ttp must pass glorfindel_cfg to load_rules so
    workspace_id is resolved from the backend config for auto_apply rules."""
    import yaml
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig
    from glorfindel.detection_rules import load_rules

    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text(yaml.dump({
        "rules": [{
            "name": "test-rule",
            "ttp": "T1548.003",
            "query": "Syslog | where ...",
            "monitoring_backends": ["law-annatar"],
            "assets": ["auto"],
        }]
    }))

    cfg = GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-annatar", type="azure_monitor", workspace_id="ws-test-123")
    ])
    rules = load_rules(rules_file, glorfindel_cfg=cfg)

    assert len(rules) == 1
    assert rules[0].workspace_id == "ws-test-123"


def test_find_rule_for_ttp_without_glorfindel_cfg_has_empty_workspace_id(tmp_path):
    """Without glorfindel_cfg, auto_apply rules get empty workspace_id (the bug)."""
    import yaml
    from glorfindel.detection_rules import load_rules

    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text(yaml.dump({
        "rules": [{
            "name": "test-rule",
            "ttp": "T1548.003",
            "query": "Syslog | where ...",
            "monitoring_backends": ["law-annatar"],
            "assets": ["auto"],
        }]
    }))

    rules = load_rules(rules_file, glorfindel_cfg=None)
    assert len(rules) == 1
    assert rules[0].workspace_id == ""  # empty without cfg — the bug


def test_resolve_attack_started_passes_glorfindel_cfg_to_find_rule(tmp_path):
    """resolve_attack_started must call _find_rule_for_ttp with glorfindel_cfg
    so auto_apply rules get a workspace_id and detection doesn't timeout."""
    from glorfindel.agent import resolve_attack_started
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig
    from glorfindel.detection_rules import DetectionRule

    signal = {
        "ttp": "T1548.003",
        "raw_signal": {
            "detection_timeout_s": 1,
            "attack_time": 0.0,
        },
    }
    cfg = GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-annatar", type="azure_monitor", workspace_id="ws-resolved")
    ])
    rule = DetectionRule(
        name="test", source="azure_monitor", workspace_id="ws-resolved",
        query="Syslog | where ...", ttp="T1548.003", resource_id="",
    )

    captured_cfg = {}

    def fake_find_rule(ttp, glorfindel_cfg=None):
        captured_cfg["cfg"] = glorfindel_cfg
        return rule

    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None  # timeout — we just want to check cfg

    with patch("glorfindel.agent._find_rule_for_ttp", side_effect=fake_find_rule), \
         patch("glorfindel.agent.load_glorfindel_config", return_value=cfg), \
         patch("glorfindel.detectors.detector_for", return_value=mock_detector):
        resolve_attack_started(signal)

    assert captured_cfg.get("cfg") is cfg, (
        "_find_rule_for_ttp must receive glorfindel_cfg from load_glorfindel_config()"
    )


# ── load_context ──────────────────────────────────────────────────────────────

def test_load_context_retrieves_past_cycles(tmp_path, tmp_incidents):
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

    result = load_context(_state(), memory=mem, incidents=tmp_incidents)

    assert len(result["past_cycles"]) == 1
    assert result["past_cycles"][0]["action"] == "isolate_vm"


def test_load_context_empty_memory_returns_empty_list(tmp_path, tmp_incidents):
    from glorfindel.agent import load_context
    mem = CycleMemory(path=tmp_path / "cycles")
    result = load_context(_state(), memory=mem, incidents=tmp_incidents)
    assert result["past_cycles"] == []


def test_load_context_does_not_mutate_other_state_fields(tmp_path, tmp_incidents):
    from glorfindel.agent import load_context
    mem = CycleMemory(path=tmp_path / "cycles")
    state = _state()
    state["reasoning"] = "preserved"
    result = load_context(state, memory=mem, incidents=tmp_incidents)
    assert result["reasoning"] == "preserved"


# ── execute_action ────────────────────────────────────────────────────────────

def test_execute_action_isolate_vm(tmp_incidents):
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated"}
    state = _state(action="isolate_vm")

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.isolate_vm.assert_called_once_with(_RESOURCE_ID)
    assert result["outcome"]["status"] == "isolated"
    assert result["outcome"]["executed"] is True


def test_execute_action_release_isolation(tmp_incidents):
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.release_isolation.return_value = {"status": "released"}
    state = _state(action="release_isolation")

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.release_isolation.assert_called_once_with(_RESOURCE_ID)
    assert result["outcome"]["status"] == "released"


def test_execute_action_block_ip_uses_source_ip_first(tmp_incidents):
    """SourceIP (brute force) takes priority over DestIP_s (exfil)."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.block_suspicious_ip.return_value = {"status": "blocked"}
    state = _state(action="block_suspicious_ip")
    state["signal"]["raw_signal"] = {
        "detected_data": {"SourceIP": "185.220.101.1", "DestIP_s": "10.0.0.5"},
    }

    execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.block_suspicious_ip.assert_called_once_with("185.220.101.1", _RESOURCE_ID)


def test_execute_action_block_ip_falls_back_to_dest_ip(tmp_incidents):
    """Falls back to DestIP_s when SourceIP is absent."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.block_suspicious_ip.return_value = {"status": "blocked"}
    state = _state(action="block_suspicious_ip")
    state["signal"]["raw_signal"] = {
        "detected_data": {"DestIP_s": "203.0.113.5"},
    }

    execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.block_suspicious_ip.assert_called_once_with("203.0.113.5", _RESOURCE_ID)


def test_execute_action_snapshot_returns_snapshot_id(tmp_incidents):
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.snapshot.return_value = "snap-20260524-001"
    state = _state(action="snapshot")  # event="detection" → wait=True

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.snapshot.assert_called_once_with(_RESOURCE_ID, wait=True)
    assert result["outcome"]["snapshot_id"] == "snap-20260524-001"


def test_execute_action_snapshot_fire_and_forget_on_detection_timeout(tmp_incidents):
    """On detection_timeout, snapshot() must be called with wait=False to avoid blocking."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.snapshot.return_value = "rsv:rsv-annatar/rg/job123"
    state = _state(action="snapshot")
    state["signal"]["event"] = "detection_timeout"

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.snapshot.assert_called_once_with(_RESOURCE_ID, wait=False)
    assert result["outcome"]["snapshot_id"] == "rsv:rsv-annatar/rg/job123"


def test_execute_action_unknown_is_noop(tmp_incidents):
    from glorfindel.agent import execute_action
    connector = MagicMock()
    state = _state(action="proposed_custom_action")

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.isolate_vm.assert_not_called()
    connector.block_suspicious_ip.assert_not_called()
    assert result["outcome"]["status"] == "no_op"
    assert result["outcome"]["action"] == "proposed_custom_action"


def test_execute_action_records_action_s(tmp_incidents):
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated"}
    result = execute_action(_state(action="isolate_vm"), connector=connector, incidents=tmp_incidents)
    assert "action_s" in result["outcome"]
    assert isinstance(result["outcome"]["action_s"], int)


# ── execute_action — investigative_context propagation ───────────────────────

def test_execute_action_stores_investigative_context_in_incident(tmp_incidents):
    """investigative_context from raw_signal must be stored in the incident action record."""
    from glorfindel.agent import execute_action

    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated", "nsg": "rg/nsg", "rule": "r"}
    state = _state(action="isolate_vm")
    state["signal"]["raw_signal"] = {
        "detected_data": {"SourceIP": "1.2.3.4"},
        "investigative_context": {
            "successful_auth_from_ip": [{"TimeGenerated": "2026-06-01", "Computer": "vm1"}]
        },
    }
    # Pre-create incident and wire its ID into state["incident"]
    inc = tmp_incidents.get_or_create(resource_id=_RESOURCE_ID, ttp="T1110.001")
    state["incident"] = {"incident_id": inc.incident_id}

    execute_action(state, connector=connector, incidents=tmp_incidents)

    updated = tmp_incidents.get_active(_RESOURCE_ID)
    assert updated is not None
    action_record = updated.actions_taken[-1]
    assert action_record["action"] == "isolate_vm"
    inv = action_record.get("investigative_context", {})
    assert "successful_auth_from_ip" in inv
    assert len(inv["successful_auth_from_ip"]) == 1


def test_execute_action_no_investigative_context_omits_key(tmp_incidents):
    """When no investigative_context, the key must be absent from the action record."""
    from glorfindel.agent import execute_action

    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated", "nsg": "rg/nsg", "rule": "r"}
    state = _state(action="isolate_vm")
    state["signal"]["raw_signal"] = {}
    inc = tmp_incidents.get_or_create(resource_id=_RESOURCE_ID, ttp="T1548.003")
    state["incident"] = {"incident_id": inc.incident_id}

    execute_action(state, connector=connector, incidents=tmp_incidents)

    updated = tmp_incidents.get_active(_RESOURCE_ID)
    action_record = updated.actions_taken[-1]
    assert "investigative_context" not in action_record


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


# ── escalate_to_human ─────────────────────────────────────────────────────────

def test_escalate_to_human_dry_run_skips_record():
    """dry_run=True must not write to the escalations file."""
    from glorfindel.agent import escalate_to_human
    from glorfindel import escalations as esc_module

    state = _state(action="restore_from_backup")
    state["dry_run"] = True
    state["escalation_reason"] = "needs human approval"

    with patch.object(esc_module, "record") as mock_record:
        escalate_to_human(state)

    mock_record.assert_not_called()


def test_escalate_to_human_real_run_records():
    """dry_run=False must persist the escalation."""
    from glorfindel.agent import escalate_to_human
    from glorfindel import escalations as esc_module

    state = _state(action="restore_from_backup")
    state["dry_run"] = False
    state["escalation_reason"] = "needs human approval"

    with patch.object(esc_module, "record") as mock_record:
        escalate_to_human(state)

    mock_record.assert_called_once()


def test_escalate_to_human_snapshot_appends_cli_step():
    """snapshot escalation must include the exact CLI command in suggested_steps."""
    from glorfindel.agent import escalate_to_human
    from glorfindel import escalations as esc_module

    state = _state(action="snapshot")
    state["dry_run"] = False
    state["escalation_reason"] = "confidence too low"
    state["suggested_steps"] = ["/etc/passwd", "check authorized_keys"]

    with patch.object(esc_module, "record") as mock_record:
        escalate_to_human(state)

    _, kwargs = mock_record.call_args
    steps = kwargs.get("suggested_steps", [])
    assert any("glorfindel snapshot" in s and _RESOURCE_ID in s for s in steps)


def test_escalate_to_human_non_snapshot_no_cli_step():
    """restore_from_backup escalation must NOT inject the snapshot CLI command."""
    from glorfindel.agent import escalate_to_human
    from glorfindel import escalations as esc_module

    state = _state(action="restore_from_backup")
    state["dry_run"] = False
    state["escalation_reason"] = "destructive action"
    state["suggested_steps"] = ["Check backup points"]

    with patch.object(esc_module, "record") as mock_record:
        escalate_to_human(state)

    _, kwargs = mock_record.call_args
    steps = kwargs.get("suggested_steps", [])
    assert not any("glorfindel snapshot" in s for s in steps)


# ── escalations.record — dedup ────────────────────────────────────────────────

def test_escalation_record_dedup_returns_existing_id():
    """Second record() call with same action+resource_id+type returns first id."""
    from glorfindel.escalations import record

    id1 = record("sig1", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason A")
    id2 = record("sig2", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason B")
    assert id1 == id2


def test_escalation_record_dedup_different_action_not_deduped():
    """Different action → two distinct escalations created."""
    from glorfindel.escalations import record, pending

    record("sig1", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason")
    record("sig2", "/sub/rg/vm1", "snapshot", "low_confidence", "reason")
    assert len(pending()) == 2


def test_escalation_record_dedup_different_resource_not_deduped():
    """Different resource_id → two distinct escalations created."""
    from glorfindel.escalations import record, pending

    record("sig1", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason")
    record("sig2", "/sub/rg/vm2", "restore_from_backup", "destructive_action", "reason")
    assert len(pending()) == 2


def test_escalation_record_dedup_after_resolve_creates_new():
    """After resolving, a new record() for same action+resource creates a fresh escalation."""
    from glorfindel.escalations import record, resolve, pending

    id1 = record("sig1", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason")
    resolve(id1)
    id2 = record("sig2", "/sub/rg/vm1", "restore_from_backup", "destructive_action", "reason")
    assert id1 != id2
    assert len(pending()) == 1


def test_restore_resolves_escalation_case_insensitive():
    """resolve_by_resource() matches resource_id case-insensitively (Azure ARM IDs)."""
    from glorfindel.escalations import record, resolve_by_resource, pending

    rid_upper = "/subscriptions/abc/resourceGroups/Annatar/providers/Microsoft.Compute/virtualMachines/vm1"
    rid_lower = rid_upper.lower()

    record("sig1", rid_upper, "restore_from_backup", "destructive_action", "ransomware detected")
    assert len(pending()) == 1

    count = resolve_by_resource(rid_lower, "restore_from_backup")
    assert count == 1
    assert len(pending()) == 0


# ── decide — confidence gate ──────────────────────────────────────────────────

def test_decide_confidence_gate_forces_escalation():
    """Low confidence + autonomous action → escalate forced even if LLM said False."""
    from glorfindel.agent import decide

    state = _state()
    with patch("litellm.completion",
               return_value=_mock_llm_response("isolate_vm", escalate=False, confidence=0.5)):
        result = decide(state, model="claude-test")

    assert result["escalate"] is True
    assert "50%" in result["escalation_reason"]
    assert "Low confidence" in result["escalation_reason"]


def test_decide_confidence_gate_above_threshold_no_override():
    """Confidence above threshold → LLM decision respected, no forced escalation."""
    from glorfindel.agent import decide

    state = _state()
    with patch("litellm.completion",
               return_value=_mock_llm_response("isolate_vm", escalate=False, confidence=0.8)):
        result = decide(state, model="claude-test")

    assert result["escalate"] is False


def test_decide_confidence_gate_non_autonomous_not_overridden():
    """Low confidence on a non-autonomous action (human-required) is not overridden."""
    from glorfindel.agent import decide

    state = _state()
    with patch("litellm.completion",
               return_value=_mock_llm_response("restore_from_backup", escalate=False, confidence=0.4)):
        result = decide(state, model="claude-test")

    # restore_from_backup is not in AUTONOMOUS_ACTIONS — gate does not apply
    assert result["escalate"] is False


def test_decide_confidence_gate_env_threshold(monkeypatch):
    """GLORFINDEL_CONFIDENCE_THRESHOLD env var changes the gate threshold."""
    from glorfindel.agent import decide

    monkeypatch.setenv("GLORFINDEL_CONFIDENCE_THRESHOLD", "0.9")
    state = _state()
    # confidence=0.85 is above default 0.7 but below custom 0.9
    with patch("litellm.completion",
               return_value=_mock_llm_response("isolate_vm", escalate=False, confidence=0.85)):
        result = decide(state, model="claude-test")

    assert result["escalate"] is True
    assert "85%" in result["escalation_reason"]


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
        "incident": None,
        "dry_run": False,
        "reasoning": "",
        "confidence": 0.0,
        "action": "",
        "reversible": True,
        "explanation": "",
        "escalate": False,
        "escalation_reason": "",
        "suggested_steps": [],
        "outcome": None,
    }


def test_graph_detection_isolate_vm(tmp_path, monkeypatch, dry_connector, tmp_memory):
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response("isolate_vm")
        final = graph.invoke(_initial("detection", raw={"detection_time_s": 50}))

    assert final["action"] == "isolate_vm"
    assert final["outcome"]["status"] == "dry_run"
    assert final["escalate"] is False
    assert tmp_memory.count() == 1


def test_graph_detection_timeout_takes_snapshot_and_escalates(tmp_path, monkeypatch, dry_connector, tmp_memory):
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response(
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

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response("release_isolation")
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

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response(
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

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response(
            "revoke_managed_identity", escalate=False,
            escalation_reason="Revoke MSI to stop exfil",
        )
        final = graph.invoke(_initial("detection", raw={"detection_time_s": 30}))

    assert final["outcome"]["status"] == "escalated"
    assert final["outcome"]["escalation_type"] == "proposed_action"
    assert tmp_memory.count() == 1


# ── T1548.003 — Sudo privilege escalation ─────────────────────────────────────

_T1548_SYSLOG = (
    "sudo[12011]:   svc-backup : TTY=pts/1 ; PWD=/tmp ;"
    " USER=root ; COMMAND=/opt/scripts/backup.sh /dev/null"
)


def test_execute_action_isolate_vm_on_t1548_signal(tmp_incidents):
    """T1548 detection has no external IP — isolate_vm called, block_suspicious_ip never."""
    from glorfindel.agent import execute_action
    connector = MagicMock()
    connector.isolate_vm.return_value = {"status": "isolated"}
    state = _state(action="isolate_vm")
    state["signal"]["ttp"] = "T1548.003"
    state["signal"]["raw_signal"] = {
        "detection_time_s": 40,
        "detected_data": {"SyslogMessage": _T1548_SYSLOG},
    }

    result = execute_action(state, connector=connector, incidents=tmp_incidents)

    connector.isolate_vm.assert_called_once_with(_RESOURCE_ID)
    connector.block_suspicious_ip.assert_not_called()
    assert result["outcome"]["status"] == "isolated"


def test_graph_t1548_detection_isolates_vm(tmp_path, monkeypatch, dry_connector, tmp_memory):
    """Full graph: T1548 sudo escalation → isolate_vm, autonomous, verified, stored."""
    monkeypatch.chdir(tmp_path)
    graph = _build(tmp_path, tmp_memory, dry_connector)

    with patch("litellm.completion") as mock_cls:
        mock_cls.return_value = _mock_llm_response("isolate_vm")
        final = graph.invoke(_initial(
            "detection",
            ttp="T1548.003",
            raw={
                "detection_time_s": 40,
                "detected_data": {"SyslogMessage": _T1548_SYSLOG},
            },
        ))

    assert final["action"] == "isolate_vm"
    assert final["outcome"]["status"] == "dry_run"
    assert final["escalate"] is False
    assert tmp_memory.count() == 1


# ── investigate node ──────────────────────────────────────────────────────────

from glorfindel.agent import investigate


def _inv_state(event="detection", first_row=None, workspace_id="ws-test", dry_run=False):
    return {
        "signal": {
            "signal_id": "inv-test",
            "event": event,
            "resource_id": _RESOURCE_ID,
            "ttp": "T1486",
            "severity": "critical",
            "raw_signal": {
                "log_analytics_workspace_id": workspace_id,
                "first_result_row": first_row or {},
            },
            "context": {"run_id": "test"},
        },
        "past_cycles": [],
        "incident": None,
        "dry_run": dry_run,
        "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
        "explanation": "", "escalate": False, "escalation_reason": "",
        "suggested_steps": [], "outcome": None,
        "proposed_rule": None, "proposal_id": "",
    }


def test_investigate_skips_non_detection():
    state = _inv_state(event="detection_timeout")
    result = investigate(state)
    assert "investigative_context" not in result["signal"].get("raw_signal", {})


def test_investigate_skips_no_workspace():
    state = _inv_state(workspace_id="")
    result = investigate(state)
    assert "investigative_context" not in result["signal"].get("raw_signal", {})


def test_investigate_resolves_workspace_from_glorfindel_cfg():
    """RulePoller signals have no workspace_id in signal — must fall back to glorfindel_cfg."""
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig

    state = _inv_state(workspace_id="", first_row={"Computer": "vm1", "MaxWrite": 60000000})
    # Simulate no workspace in signal but valid backend in glorfindel_cfg
    cfg = GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-annatar", type="azure_monitor", workspace_id="ws-cfg-123")
    ])
    mock_det = MagicMock()
    mock_det.run_query.return_value = []

    with patch("glorfindel.agent.load_glorfindel_config", return_value=cfg), \
         patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)

    # investigate must have run (investigative_context present)
    ctx = result["signal"]["raw_signal"].get("investigative_context")
    assert ctx is not None, "investigate must run when workspace_id resolved from glorfindel_cfg"
    # detector must have been called with the resolved workspace_id
    from glorfindel.detectors import detector_for as _det_for  # just for reference
    assert mock_det.run_query.called


def test_investigate_skips_dry_run():
    state = _inv_state(first_row={"MaxWrite": 147000000}, dry_run=True)
    result = investigate(state)
    assert "investigative_context" not in result["signal"].get("raw_signal", {})


def test_investigate_disk_write_runs_two_queries():
    state = _inv_state(first_row={"Computer": "vm-test", "MaxWrite": 147000000})
    mock_det = MagicMock()
    mock_det.run_query.return_value = [{"InstanceName": "crypt", "MaxWriteMBs": 140}]
    with patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)
    ctx = result["signal"]["raw_signal"]["investigative_context"]
    assert "top_write_processes" in ctx
    assert "backup_agent_check" in ctx
    assert mock_det.run_query.call_count == 2


def test_investigate_backup_agent_found_appears_in_context():
    state = _inv_state(first_row={"Computer": "vm-test", "MaxWrite": 80000000})
    mock_det = MagicMock()
    mock_det.run_query.side_effect = [
        [{"InstanceName": "crypt", "MaxWriteMBs": 78}],
        [{"InstanceName": "azure-backup", "MaxWriteMBs": 75}],  # backup present
    ]
    with patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)
    ctx = result["signal"]["raw_signal"]["investigative_context"]
    assert any(
        r.get("InstanceName") == "azure-backup"
        for r in ctx["backup_agent_check"]
    )


def test_investigate_brute_force_checks_successful_auth():
    state = _inv_state(first_row={"SourceIP": "185.1.2.3", "FailedAttempts": 47})
    mock_det = MagicMock()
    mock_det.run_query.return_value = []
    with patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)
    ctx = result["signal"]["raw_signal"]["investigative_context"]
    assert "successful_auth_from_ip" in ctx


def test_investigate_priv_esc_runs_root_and_disk_queries():
    syslog = "sudo: user1 : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
    state = _inv_state(first_row={"Computer": "vm-test", "SyslogMessage": syslog})
    mock_det = MagicMock()
    mock_det.run_query.return_value = []
    with patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)
    ctx = result["signal"]["raw_signal"]["investigative_context"]
    assert "root_commands" in ctx
    assert "disk_write_after_escalation" in ctx


def test_investigate_handles_detector_exception():
    state = _inv_state(first_row={"Computer": "vm-test", "MaxWrite": 147000000})
    with patch("glorfindel.detectors.detector_for", side_effect=Exception("Azure down")):
        result = investigate(state)
    # Exception swallowed — context present but empty (LLM sees "no results")
    ctx = result["signal"]["raw_signal"].get("investigative_context", {})
    assert ctx.get("top_write_processes") == []
    assert ctx.get("backup_agent_check") == []


def test_investigate_no_matching_fields_returns_unchanged():
    state = _inv_state(first_row={"Computer": "vm-test", "UnrelatedField": "value"})
    mock_det = MagicMock()
    with patch("glorfindel.detectors.detector_for", return_value=mock_det):
        result = investigate(state)
    assert result["signal"] is state["signal"]
    mock_det.run_query.assert_not_called()


# ── _build_user_message — current_vm_state injection ─────────────────────────


def test_build_user_message_includes_isolation_state_not_isolated(tmp_path):
    """current_vm_state shows NON when no isolation file exists."""
    from glorfindel.agent import _build_user_message
    signal = {
        "resource_id": _RESOURCE_ID,
        "event": "detection",
        "raw_signal": {},
    }
    with patch("pathlib.Path.home", return_value=tmp_path):
        msg = _build_user_message(signal, [])
    assert "État actuel de la VM" in msg
    assert "NON" in msg


def test_build_user_message_includes_isolation_state_isolated(tmp_path):
    """current_vm_state shows OUI when isolation file exists for this VM."""
    import json
    from glorfindel.agent import _build_user_message
    vm_name = _RESOURCE_ID.split("/")[-1]
    iso_dir = tmp_path / ".glorfindel" / "isolation"
    iso_dir.mkdir(parents=True)
    (iso_dir / f"{vm_name}.json").write_text(json.dumps({"resource_id": _RESOURCE_ID}))
    signal = {
        "resource_id": _RESOURCE_ID,
        "event": "detection",
        "raw_signal": {},
    }
    with patch("pathlib.Path.home", return_value=tmp_path):
        msg = _build_user_message(signal, [])
    assert "OUI" in msg


def test_build_user_message_past_cycles_header_warns_about_state_inference(tmp_path):
    """past_cycles header must explicitly warn against inferring current state."""
    from glorfindel.agent import _build_user_message
    signal = {"resource_id": _RESOURCE_ID, "event": "detection", "raw_signal": {}}
    past = [{"summary": "T1486 — isolate_vm confirmed"}]
    with patch("pathlib.Path.home", return_value=tmp_path):
        msg = _build_user_message(signal, past)
    assert "NE PAS inférer état courant" in msg
