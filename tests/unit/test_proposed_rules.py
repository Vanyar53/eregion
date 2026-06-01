from __future__ import annotations

import json

import pytest

from glorfindel.proposed_rules import _append_to_rules_yaml, approve, pending, record, reject


# ── Fixtures ────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _redirect_store(tmp_path, monkeypatch):
    monkeypatch.setattr("glorfindel.proposed_rules._STORE", tmp_path / "proposed_rules.jsonl")


def _sample_proposal(**kwargs) -> str:
    base = dict(
        run_id="20260529T120000Z",
        ttp="T1486",
        resource_id="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        rule_name="ransomware-disk-write-v2",
        source="azure_monitor",
        workspace_id="ws-123",
        query="Perf | where CounterValue > 10000000 | limit 1",
        interval_s=30.0,
        explanation="Lower threshold catches low-intensity encryption",
        confidence=0.85,
        analysis="Original threshold was too high",
    )
    base.update(kwargs)
    return record(**base)


# ── record ───────────────────────────────────────────────────────────────────────

def test_record_creates_file(tmp_path):
    _sample_proposal()
    store = tmp_path / "proposed_rules.jsonl"
    assert store.exists()


def test_record_returns_uuid():
    pid = _sample_proposal()
    assert len(pid) == 36  # UUID format


def test_record_fields(tmp_path):
    _sample_proposal(ttp="T1041", rule_name="exfil-blob-v2")
    store = tmp_path / "proposed_rules.jsonl"
    data = json.loads(store.read_text().strip())
    assert data["ttp"] == "T1041"
    assert data["rule_name"] == "exfil-blob-v2"
    assert data["status"] == "pending"
    assert data["approved_at"] is None


def test_record_multiple(tmp_path):
    _sample_proposal(rule_name="rule-a")
    _sample_proposal(rule_name="rule-b")
    store = tmp_path / "proposed_rules.jsonl"
    lines = [ln for ln in store.read_text().splitlines() if ln.strip()]
    assert len(lines) == 2


# ── pending ──────────────────────────────────────────────────────────────────────

def test_pending_returns_pending_only(tmp_path):
    id1 = _sample_proposal(rule_name="rule-pending")
    id2 = _sample_proposal(rule_name="rule-approved")
    # Manually approve id2 in the store
    store = tmp_path / "proposed_rules.jsonl"
    lines = store.read_text().splitlines()
    updated = []
    for line in lines:
        p = json.loads(line)
        if p["id"] == id2:
            p["status"] = "approved"
        updated.append(json.dumps(p))
    store.write_text("\n".join(updated) + "\n")

    result = pending()
    assert len(result) == 1
    assert result[0]["id"] == id1


def test_pending_empty_store():
    assert pending() == []


# ── approve ───────────────────────────────────────────────────────────────────────

def test_approve_marks_status(tmp_path):
    pid = _sample_proposal()
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")

    proposal = approve(pid, rules_file)
    assert proposal["status"] == "approved"
    assert proposal["approved_at"] is not None


def test_approve_appends_to_rules_yaml(tmp_path):
    pid = _sample_proposal(
        rule_name="test-rule",
        ttp="T1486",
        query="Perf | where CounterValue > 1000000",
    )
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")

    approve(pid, rules_file)

    content = rules_file.read_text()
    assert "test-rule" in content
    assert "T1486" in content
    assert "CounterValue > 1000000" in content
    assert "enabled: true" in content


def test_approve_unknown_id_raises(tmp_path):
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")
    with pytest.raises(ValueError):
        approve("not-a-real-id", rules_file)


def test_approve_already_approved_raises(tmp_path):
    pid = _sample_proposal()
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")
    approve(pid, rules_file)
    with pytest.raises(ValueError):
        approve(pid, rules_file)


def test_approve_removes_from_pending(tmp_path):
    pid = _sample_proposal()
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")

    assert len(pending()) == 1
    approve(pid, rules_file)
    assert pending() == []


# ── reject ───────────────────────────────────────────────────────────────────────

def test_reject_marks_status():
    pid = _sample_proposal()
    proposal = reject(pid)
    assert proposal["status"] == "rejected"


def test_reject_removes_from_pending():
    pid = _sample_proposal()
    assert len(pending()) == 1
    reject(pid)
    assert pending() == []


def test_reject_unknown_id_raises():
    with pytest.raises(ValueError):
        reject("not-a-real-id")


def test_reject_already_approved_raises(tmp_path):
    pid = _sample_proposal()
    rules_file = tmp_path / "detection_rules.yaml"
    rules_file.write_text("rules:\n")
    approve(pid, rules_file)
    with pytest.raises(ValueError):
        reject(pid)


# ── _append_to_rules_yaml ────────────────────────────────────────────────────────

def test_append_indents_multiline_query(tmp_path):
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text("rules:\n")
    proposal = {
        "rule_name": "my-rule",
        "ttp": "T1110",
        "source": "azure_monitor",
        "workspace_id": "ws-x",
        "resource_id": "/subscriptions/s/r/v/vm1",
        "interval_s": 30,
        "explanation": "Better SSH detection",
        "query": "Syslog\n| where Facility == 'auth'\n| limit 1",
    }
    _append_to_rules_yaml(proposal, rules_file)
    content = rules_file.read_text()
    # Each query line should be indented
    assert "      Syslog" in content
    assert "      | where" in content


# ── agent routing: detection_missed goes to propose_detection_rule ───────────────

def test_propose_detection_rule_skips_when_rulepoller_matched_recently(tmp_path, monkeypatch):
    """When RulePoller recently matched the same TTP, propose_detection_rule must return
    without calling the LLM or recording a proposal."""
    from datetime import datetime, timezone
    from unittest.mock import patch
    from glorfindel.agent import propose_detection_rule
    from glorfindel.detection_rules import _save_status

    # Redirect status file so the test has a controlled view of recent matches
    status_path = tmp_path / "rule_status.json"
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", status_path)
    now_iso = datetime.now(timezone.utc).isoformat()
    _save_status({"sudo-rule": {"last_match": now_iso, "ttp": "T1548.003"}})

    state = {
        "signal": {
            "event": "detection_missed",
            "ttp": "T1548.003",
            "resource_id": "/sub/rg/vm1",
            "raw_signal": {"detection_timeout_s": 300},
            "context": {},
        },
        "past_cycles": [], "incident": None, "dry_run": True,
        "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
        "explanation": "", "escalate": False, "escalation_reason": "",
        "suggested_steps": [], "outcome": None, "proposed_rule": None,
        "proposal_id": "",
    }

    with patch("litellm.completion") as mock_llm:
        result = propose_detection_rule(state, model="claude-test")

    mock_llm.assert_not_called()
    # State unchanged — no proposal recorded
    assert pending() == []
    assert result is state


def test_route_after_load_context_detection_missed():
    from glorfindel.agent import _route_after_load_context, GlorfindelState

    state: GlorfindelState = {
        "signal": {"event": "detection_missed", "ttp": "T1486"},
        "past_cycles": [], "incident": None, "dry_run": True,
        "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
        "explanation": "", "escalate": False, "escalation_reason": "",
        "suggested_steps": [], "outcome": None, "proposed_rule": None,
    }
    assert _route_after_load_context(state) == "propose_detection_rule"


def test_route_after_load_context_other_events():
    from glorfindel.agent import _route_after_load_context, GlorfindelState

    for event in ("detection", "detection_timeout", "recovery_complete", "attack_started"):
        state: GlorfindelState = {
            "signal": {"event": event},
            "past_cycles": [], "incident": None, "dry_run": True,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None, "proposed_rule": None,
        }
        assert _route_after_load_context(state) == "poll_detection", f"failed for {event}"
