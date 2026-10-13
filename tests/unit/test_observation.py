"""Observation kit: the operator's verdict on each recommendation, and the report that
measures the false rate of disruptive ones — the number the autonomy decision rests on
(docs/observation.md)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from glorfindel import escalations

VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{}"


def _card(vm="web", action="isolate_vm", kind="mode_hold", signal_id=None, rule="ransomware-disk-write"):
    return escalations.record(
        signal_id=signal_id or f"rule-{rule}-0123abcd", resource_id=VM.format(vm), action=action,
        escalation_type=kind, reason="r", rule_name=rule)


def test_a_verdict_is_kept_on_the_card_independent_of_ack():
    esc = _card()
    escalations.resolve(esc)
    e = escalations.set_verdict(esc, "wrong", note="apt cache")
    assert (e["verdict"], e["verdict_note"], e["status"]) == ("wrong", "apt cache", "resolved")
    assert next(x for x in escalations.all_escalations() if x["id"] == esc)["verdict"] == "wrong"


def test_a_verdict_by_prefix_refuses_what_it_cant_tell_apart():
    esc = _card()
    assert escalations.set_verdict(esc[:8], "right")["id"] == esc
    with pytest.raises(ValueError):
        escalations.set_verdict(esc[:3], "right")          # too short to be safe
    with pytest.raises(ValueError):
        escalations.set_verdict(esc, "maybe")              # not a verdict
    with pytest.raises(KeyError):
        escalations.set_verdict("ffffffffff", "right")


def test_the_rule_of_a_card_is_recorded_or_read_from_its_signal():
    assert escalations.rule_of({"rule_name": "ssh-brute-force"}) == "ssh-brute-force"
    assert escalations.rule_of({"signal_id": "rule-sudo-privilege-escalation-1a2b3c4d"}) == "sudo-privilege-escalation"
    assert escalations.rule_of({"signal_id": "run001_detection"}) == ""


def test_the_report_counts_decisions_once_and_measures_disruptive_false_rate():
    a = _card("web")
    _card("web")                                            # re-fire: same card, occurrences 2
    b = _card("db", action="block_suspicious_ip", rule="ssh-brute-force")
    c = _card("api", action="snapshot", kind="low_confidence", rule="account-creation")
    escalations.record(signal_id="posture-x", resource_id=VM.format("web"), action="backup",
                       escalation_type="posture_gap", reason="r")          # not a decision
    escalations.record(signal_id="reassert-web-1a2b3c4d", resource_id=VM.format("web"),
                       action="isolate_vm", escalation_type="verification_failed", reason="r")
    escalations.set_verdict(a, "right")
    escalations.set_verdict(b, "wrong")
    escalations.set_verdict(c, "unsure")
    r = escalations.observation_report()
    assert r["cards"] == 3 and r["judged"] == 3
    assert r["disruptive"] == {"right": 1, "wrong": 1, "unsure": 0, "unjudged": 0, "false_rate": 0.5}
    assert r["by_rule"]["ssh-brute-force"]["wrong"] == 1
    assert r["by_action"]["snapshot"]["unsure"] == 1


def test_the_report_has_no_rate_before_anything_is_judged_and_honours_since():
    _card()
    r = escalations.observation_report()
    assert r["disruptive"]["false_rate"] is None and r["disruptive"]["unjudged"] == 1
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert escalations.observation_report(future)["cards"] == 0


def test_the_cli_judges_and_reports():
    from glorfindel.cli import cli
    esc = _card()
    res = CliRunner().invoke(cli, ["verdict", esc[:8], "wrong", "--note", "nightly backup"])
    assert res.exit_code == 0, res.output
    res = CliRunner().invoke(cli, ["report", "--since", "all", "--json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["disruptive"]["false_rate"] == 1.0
    res = CliRunner().invoke(cli, ["verdict", "nope00", "right"])
    assert res.exit_code == 1 and "no card" in res.output
    assert CliRunner().invoke(cli, ["report", "--since", "7x"]).exit_code != 0


def test_the_api_judges_and_reports(monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    import glorfindel.api as api
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    client = TestClient(api.app)
    esc = _card()
    assert client.post(f"/api/escalations/{esc}/verdict", json={"verdict": "right"}).json() == {
        "ok": True, "verdict": "right"}
    assert "error" in client.post(f"/api/escalations/{esc}/verdict", json={"verdict": "?"}).json()
    assert client.get("/api/report?since=all").json()["disruptive"]["right"] == 1
    assert "error" in client.get("/api/report?since=soon").json()


def test_a_card_carries_the_rule_of_its_detection():
    """escalate_to_human passes the RulePoller's rule name — the report groups by it."""
    from glorfindel.agent import escalate_to_human
    state = {"signal": {"signal_id": "rule-ssh-brute-force-1a2b3c4d", "resource_id": VM.format("web"),
                        "ttp": "T1110.001", "severity": "high", "event": "detection",
                        "raw_signal": {}, "context": {"run_id": "r", "rule_name": "ssh-brute-force"}},
             "past_cycles": [], "incident": None, "dry_run": False, "reasoning": "", "confidence": 0.9,
             "action": "block_suspicious_ip", "reversible": True, "explanation": "", "escalate": True,
             "escalation_reason": "held", "outcome": None, "mode_hold": True}
    with patch.object(escalations, "record") as rec:
        escalate_to_human(state)
    assert rec.call_args.kwargs["rule_name"] == "ssh-brute-force"
