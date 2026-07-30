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
            "raw_signal": {},
            # detection_timeout_s is in context (Annatar puts metrics there)
            "context": {"run_id": "20260601T130630Z", "detection_timeout_s": 300},
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


# ── gate: existing rule for the TTP → no duplicate authoring ────────────────────

def _missed_state(ttp: str) -> dict:
    return {
        "signal": {
            "event": "detection_missed",
            "ttp": ttp,
            "resource_id": "/sub/rg/vm1",
            "raw_signal": {},
            "context": {"run_id": "20260730T193824Z", "detection_timeout_s": 300},
        },
        "past_cycles": [], "incident": None, "dry_run": True,
        "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
        "explanation": "", "escalate": False, "escalation_reason": "",
        "suggested_steps": [], "outcome": None, "proposed_rule": None,
        "proposal_id": "",
    }


def _fake_rule(name: str, ttp: str, *, enabled: bool = True, workspace_id: str = "ws-1"):
    from glorfindel.detection_rules import DetectionRule

    return DetectionRule(
        name=name, source="azure_monitor", workspace_id=workspace_id,
        query="Syslog | limit 1", ttp=ttp, resource_id="",
        enabled=enabled, expected_latency_s=480,
    )


def test_propose_skips_authoring_when_rule_covers_ttp(monkeypatch):
    """A miss on a TTP an existing rule covers is NOT a rule gap — no LLM call,
    no proposal, and a detection_blocked escalation instead of a duplicate rule."""
    from unittest.mock import patch
    from glorfindel.agent import propose_detection_rule

    monkeypatch.setattr(
        "glorfindel.agent._find_rule_for_ttp",
        lambda ttp, glorfindel_cfg=None: _fake_rule("ssh-brute-force", ttp),
    )

    with patch("glorfindel.agent.author_rule") as mock_author, patch("litellm.completion") as mock_llm:
        result = propose_detection_rule(_missed_state("T1110.001"), model="claude-test")

    mock_author.assert_not_called()
    mock_llm.assert_not_called()
    assert pending() == []
    assert result["action"] == "investigate_detection_gap"
    assert result["escalate"] is True
    assert result["proposed_rule"] is None
    assert result["proposal_id"] == ""
    assert "ssh-brute-force" in result["escalation_reason"]


def test_propose_gate_reports_actions_taken_as_likely_cause(monkeypatch, tmp_path):
    """The leftover isolation that prevented detection must be named in the reason."""
    from glorfindel.agent import propose_detection_rule
    from glorfindel.incidents import IncidentRegistry

    monkeypatch.setattr(
        "glorfindel.agent._find_rule_for_ttp",
        lambda ttp, glorfindel_cfg=None: _fake_rule("data-exfiltration-blob", ttp),
    )
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl", ttl_s=300)
    inc = incidents.get_or_create(resource_id="/sub/rg/vm1", ttp="T1041")
    incidents.record_action(inc.incident_id, "isolate_vm", "success")

    result = propose_detection_rule(
        _missed_state("T1041"), model="claude-test", incidents=incidents
    )

    assert "isolate_vm" in result["escalation_reason"]


def test_propose_gate_flags_rule_bound_to_no_backend(monkeypatch):
    """Rule present but unpollable → say so; authoring another wouldn't fix it."""
    from glorfindel.agent import propose_detection_rule

    monkeypatch.setattr(
        "glorfindel.agent._find_rule_for_ttp",
        lambda ttp, glorfindel_cfg=None: _fake_rule(
            "ssh-brute-force", ttp, enabled=False, workspace_id=""
        ),
    )
    result = propose_detection_rule(_missed_state("T1110.001"), model="claude-test")
    assert "NON pollable" in result["escalation_reason"]


def test_propose_authors_when_no_rule_covers_ttp(monkeypatch):
    """Cold start (no rule for the TTP) keeps the original authoring behaviour."""
    from unittest.mock import patch
    from glorfindel.agent import propose_detection_rule

    monkeypatch.setattr(
        "glorfindel.agent._find_rule_for_ttp", lambda ttp, glorfindel_cfg=None: None
    )
    authored = {
        "rule_name": "new-rule", "source": "azure_monitor", "workspace_id": "ws-1",
        "query": "Syslog | limit 1", "interval_s": 30.0,
        "explanation": "e", "confidence": 0.8, "analysis": "a",
    }
    with patch("glorfindel.agent.author_rule", return_value=authored) as mock_author:
        result = propose_detection_rule(_missed_state("T1070.002"), model="claude-test")

    mock_author.assert_called_once()
    assert result["action"] == "improve_detection"
    assert result["proposed_rule"] == authored


def test_propose_gate_fails_open_on_unreadable_rules(monkeypatch):
    """A broken config must disable the gate, never the purple loop itself."""
    from unittest.mock import patch
    from glorfindel.agent import propose_detection_rule

    def _boom(ttp, glorfindel_cfg=None):
        raise RuntimeError("malformed detection_rules.yaml")

    monkeypatch.setattr("glorfindel.agent._find_rule_for_ttp", _boom)
    authored = {
        "rule_name": "new-rule", "source": "azure_monitor", "workspace_id": "ws-1",
        "query": "Syslog | limit 1", "interval_s": 30.0,
        "explanation": "e", "confidence": 0.8, "analysis": "a",
    }
    with patch("glorfindel.agent.author_rule", return_value=authored):
        result = propose_detection_rule(_missed_state("T1110.001"), model="claude-test")

    assert result["action"] == "improve_detection"


def test_detection_blocked_escalation_type(monkeypatch, tmp_path):
    """escalate_to_human maps the gate's action to its own escalation type."""
    from glorfindel.agent import escalate_to_human

    state = _missed_state("T1110.001")
    state.update({
        "action": "investigate_detection_gap",
        "escalate": True,
        "escalation_reason": "règle existante",
        "dry_run": True,
    })
    out = escalate_to_human(state)
    assert out["outcome"]["escalation_type"] == "detection_blocked"


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
