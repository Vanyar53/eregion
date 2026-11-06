"""B3a (#609) — a deterministic floor in the decision: a brute force that succeeded, then root,
on the same VM, and the decision proposes at least isolate_vm, whatever the model chose.

The harness of H0's CD drew `block_suspicious_ip` one time in three on its paired case (a brute
force after a sudo to root on the same VM), above the gate: the source blocked, the VM where
root was taken left standing. Jonathan's decision (06/11): when the correlation (COR1) confirmed
both on one VM, `decide` raises the action to isolate_vm; the mode still applies (human_only:
nothing runs, the card proposes it), and the card says why. Never in the prompt.

No floor for a brute force alone, a sudo alone, two VMs, or failures the correlation never saw
succeed (neighbouring signals): the model's choice stands.

No Azure call, no model call (the model is patched, dry_run or a recording connector).
Mutants M4375–M4379 (scripts/mutants/B3a.py) are measured here.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from glorfindel import agent
from glorfindel.config import AutonomyConfig
from glorfindel.incidents import IncidentRegistry
from tests.unit.test_dependency_failures import FakeMemory, LogAnalytics, Recorder, _agent, _cards

RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b3a"
OTHER = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b3b"
IP = "185.220.101.5"
SMOKE = Path(__file__).resolve().parents[2] / "scripts" / "llm_smoke.py"


@pytest.fixture(autouse=True)
def hermetic(tmp_path, monkeypatch):
    for var in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "GLORFINDEL_LLM_BASE_URL",
                "GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_LLM_TIMEOUT_S",
                "GLORFINDEL_READ_ONLY", "GLORFINDEL_DECISION_DRAWS", "GLORFINDEL_INCIDENT_TTL_S"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    from eregion_core import llm_call
    monkeypatch.setattr(llm_call, "_AUTO_TOOL_CHOICE", set())
    monkeypatch.setattr(llm_call, "_NO_TEMPERATURE", set())
    import glorfindel.escalations as escalations
    monkeypatch.setattr(escalations, "notify_action", lambda **kw: None)
    monkeypatch.setattr(agent, "CycleMemory", FakeMemory)
    from glorfindel.actions import AzureConnector

    def no_azure(self):
        raise RuntimeError("no Azure client in tests (B3a)")
    monkeypatch.setattr(AzureConnector, "_ensure_clients", no_azure)


def _decision(action: str, confidence: float = 0.9, **fields) -> MagicMock:
    """The model, patched: a security_decision call that answers `action`."""
    call = MagicMock()
    call.function.arguments = json.dumps({
        "reasoning": f"r — {action}", "confidence": confidence, "action": action,
        "reversible": True, "explanation": "e", "escalate": False, "escalation_reason": "",
        "suggested_steps": [], **fields})
    resp = MagicMock()
    resp.choices[0].message.tool_calls = [call]
    resp.usage = None
    return resp


def _brute_force(rid: str = RID, *, succeeded: bool = True, **row_over) -> dict:
    """A RulePoller detection of `ssh-brute-force`; `succeeded`: marked by the correlation
    (COR1), a login from the same address seen after the failures."""
    row = {"Computer": rid.rsplit("/", 1)[-1], "_ResourceId": rid, "SourceIP": IP,
           "FailedAttempts": 47}
    if succeeded:
        row["Correlation"] = "ssh-login-after-brute-force"
        row["SuccessfulLogins"] = [{"account": "alice", "method": "password",
                                    "at": "2026-11-06T10:00:00+00:00"}]
    row.update(row_over)
    return {
        "signal_id": f"rule-ssh-brute-force-{rid[-3:]}", "event": "detection", "ttp": "T1110.001",
        "severity": "critical" if succeeded else "high", "resource_id": rid, "resource_type": "vm",
        "timestamp": "2026-11-06T10:05:00+00:00",
        "context": {"rule_name": "ssh-brute-force", "attribution": "asset",
                    "run_id": "watch-ssh-brute-force-20261106T100500Z"},
        "raw_signal": {"first_result_row": row},
    }


def _sudo(rid: str = RID, **context) -> dict:
    """A RulePoller detection of `sudo-privilege-escalation`: a sudo to a root shell."""
    return {
        "signal_id": f"rule-sudo-privilege-escalation-{rid[-3:]}", "event": "detection",
        "ttp": "T1548.003", "severity": "high", "resource_id": rid, "resource_type": "vm",
        "timestamp": "2026-11-06T10:04:00+00:00",
        "context": {"rule_name": "sudo-privilege-escalation", "attribution": "asset",
                    "run_id": "watch-sudo-privilege-escalation-20261106T100400Z", **context},
        "raw_signal": {"first_result_row": {
            "Computer": rid.rsplit("/", 1)[-1], "_ResourceId": rid, "ProcessName": "sudo",
            "SyslogMessage": "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"}},
    }


def _incident(*confirmed: str, rid: str = RID) -> dict:
    return {"incident_id": "i1", "resource_id": rid, "ttps": ["T1548.003", "T1110.001"],
            "started_at": "", "last_signal_at": "", "actions_taken": [], "signals_count": 2,
            "state": "active", "confirmed": list(confirmed)}


def _decide(signal: dict, resp, incident: dict | None = None, mode: str = "non_disruptive"):
    state = {"signal": signal, "past_cycles": [], "incident": incident, "dry_run": True,
             "telemetry_gaps": []}
    with patch("litellm.completion", return_value=resp) as llm:
        out = agent.decide(state, model="anthropic/claude-test",
                           autonomy=AutonomyConfig(default=mode))
    return out, llm


# ── The floor plays ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("signal,kept", [
    (_brute_force(), agent.ROOT_ELEVATION),           # root first, then the brute force seen succeed
    (_sudo(), agent.LOGIN_AFTER_BRUTE_FORCE),         # the brute force seen succeed, then root
], ids=["brute-force-after-root", "root-after-brute-force"])
def test_a_block_is_raised_to_isolate_vm_and_says_why(signal, kept):
    """The model blocks the source: the decision isolates the VM, alone in non_disruptive —
    every draw floored alike, so the draws agree — and says why."""
    out, llm = _decide(signal, _decision("block_suspicious_ip"), _incident(kept))
    assert out["action"] == "isolate_vm" and out["escalate"] is False, out.get("escalation_reason")
    assert out["floor"].startswith("Plancher déterministe (B3a)")
    assert "'block_suspicious_ip'" in out["floor"]
    assert out["explanation"].startswith(out["floor"])      # the notification says it
    assert [x["action"] for x in out["decision_draws"]] == ["isolate_vm"] * 3
    assert llm.call_count == 3
    if signal["ttp"] == "T1110.001":
        assert IP in out["floor"]


def test_no_action_is_raised_to_isolate_vm():
    out, _ = _decide(_brute_force(), _decision("no_action"), _incident(agent.ROOT_ELEVATION))
    assert out["action"] == "isolate_vm" and out["escalate"] is False
    assert "'no_action'" in out["floor"]


def test_a_model_that_isolates_keeps_its_choice():
    """Already at the floor: nothing raised, nothing claimed — its own words stay."""
    out, _ = _decide(_brute_force(), _decision("isolate_vm"), _incident(agent.ROOT_ELEVATION))
    assert out["action"] == "isolate_vm" and out["escalate"] is False
    assert out["floor"] == "" and out["explanation"] == "e"


def test_the_gates_still_judge_the_isolation():
    """A low confidence holds the raised isolation as it would the model's own: a card that
    proposes isolate_vm, and says the floor."""
    out, _ = _decide(_brute_force(), _decision("block_suspicious_ip", confidence=0.4),
                     _incident(agent.ROOT_ELEVATION))
    assert out["action"] == "isolate_vm" and out["escalate"] is True
    assert out["held_by"] == "confidence"
    assert "Low confidence" in out["escalation_reason"] and "Plancher" in out["escalation_reason"]


# ── No floor: the model's choice stands ─────────────────────────────────────────────────

def test_a_brute_force_alone_keeps_the_models_choice():
    """Seen succeed, but no root on this VM: the block stands."""
    for incident in (None, _incident(), _incident(agent.LOGIN_AFTER_BRUTE_FORCE)):
        out, _ = _decide(_brute_force(), _decision("block_suspicious_ip"), incident)
        assert out["action"] == "block_suspicious_ip" and out["floor"] == ""


def test_a_sudo_alone_keeps_the_models_choice():
    for incident in (None, _incident(), _incident(agent.ROOT_ELEVATION)):
        out, _ = _decide(_sudo(), _decision("snapshot"), incident)
        assert out["action"] == "snapshot" and out["floor"] == ""


def test_neighbouring_signals_the_correlation_never_confirmed_keep_the_models_choice():
    """Failures alone, or logins the correlation could not read, next to a sudo to root: no
    login confirmed — the block stands."""
    unchecked = _brute_force(succeeded=False, LoginCheck={"status": "unchecked", "why": "plafond"})
    for signal in (_brute_force(succeeded=False), unchecked):
        out, _ = _decide(signal, _decision("block_suspicious_ip"), _incident(agent.ROOT_ELEVATION))
        assert out["action"] == "block_suspicious_ip" and out["floor"] == ""
    assert agent.confirmed_facts(_brute_force(succeeded=False)) == []
    assert agent.confirmed_facts(unchecked) == []


def test_two_vms_keep_the_models_choice():
    """Root on another VM: an incident of another resource is never this VM's."""
    out, _ = _decide(_brute_force(), _decision("block_suspicious_ip"),
                     _incident(agent.ROOT_ELEVATION, rid=OTHER))
    assert out["action"] == "block_suspicious_ip" and out["floor"] == ""


def test_what_confirms_nothing():
    """A timeout, an attack_started, an unattributed detection (anchored on a VM it does not
    name): nothing confirmed on this VM."""
    assert agent.confirmed_facts(_sudo()) == [agent.ROOT_ELEVATION]
    assert agent.confirmed_facts(_brute_force()) == [agent.LOGIN_AFTER_BRUTE_FORCE]
    assert agent.confirmed_facts({**_sudo(), "event": "detection_timeout"}) == []
    assert agent.confirmed_facts({**_sudo(), "event": "attack_started"}) == []
    assert agent.confirmed_facts(_sudo(attribution="unattributed")) == []
    out, _ = _decide({**_brute_force(), "event": "detection_timeout"},
                     _decision("block_suspicious_ip"), _incident(agent.ROOT_ELEVATION))
    assert out["floor"] == ""


# ── Through the graph: the incident keeps the facts; the mode applies ────────────────────

def _respond(agent_, signal, resp):
    with patch("litellm.completion", return_value=resp), \
            patch("glorfindel.detectors.detector_for", return_value=LogAnalytics(fail=False)):
        return agent_.respond(signal)


def test_human_only_runs_nothing_and_the_card_proposes_isolate_vm():
    """The sudo, then the brute force seen succeed, on the same VM in human_only: nothing is
    written; the card proposes isolate_vm and says the floor."""
    conn = Recorder()
    agent_ = _agent(conn, autonomy=AutonomyConfig(default="human_only"))
    _respond(agent_, _sudo(), _decision("snapshot"))
    final = _respond(agent_, _brute_force(), _decision("block_suspicious_ip"))
    assert conn.writes() == []
    assert final["action"] == "isolate_vm" and final["escalate"] is True and final["mode_hold"]
    assert sorted(final["incident"]["confirmed"]) == sorted(
        [agent.ROOT_ELEVATION, agent.LOGIN_AFTER_BRUTE_FORCE])
    card = next(c for c in _cards() if c["action"] == "isolate_vm")
    assert card["escalation_type"] == "mode_hold"
    assert "Plancher déterministe (B3a)" in card["reason"]


def test_non_disruptive_isolates_and_the_compromise_card_says_the_floor():
    """Positive control of the same set-up: in non_disruptive the isolation runs, the block
    does not, and the compromise's card (COR1) says why the VM was isolated."""
    conn = Recorder()
    agent_ = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive"))
    _respond(agent_, _sudo(), _decision("no_action"))
    final = _respond(agent_, _brute_force(), _decision("block_suspicious_ip"))
    assert final["action"] == "isolate_vm" and final["escalate"] is False
    assert conn.writes() == ["isolate_vm"]
    card = next(c for c in _cards() if c["escalation_type"] == "account_compromised")
    assert "isolate_vm" in card["reason"] and "Plancher déterministe (B3a)" in card["reason"]


def test_two_vms_through_the_graph_keep_the_models_block():
    """Root on one VM, the brute force seen succeed on another: two incidents, no floor."""
    conn = Recorder()
    agent_ = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive"))
    _respond(agent_, _sudo(OTHER), _decision("no_action"))
    final = _respond(agent_, _brute_force(RID), _decision("block_suspicious_ip"))
    assert final["action"] == "block_suspicious_ip" and final["floor"] == ""
    assert conn.writes() == ["block_suspicious_ip"]


def test_the_registry_keeps_what_was_confirmed(tmp_path):
    """`confirm` adds to the VM's active incident, once; no active incident, nothing; a row
    written before B3a (no `confirmed`) still reads."""
    reg = IncidentRegistry(path=tmp_path / "inc.jsonl")
    assert reg.confirm(RID, [agent.ROOT_ELEVATION]) is None
    reg.get_or_create(RID, "T1548.003")
    reg.confirm(RID, [agent.ROOT_ELEVATION])
    reg.confirm(RID, [agent.ROOT_ELEVATION, agent.LOGIN_AFTER_BRUTE_FORCE])
    assert reg.get_active(RID).confirmed == [agent.ROOT_ELEVATION, agent.LOGIN_AFTER_BRUTE_FORCE]
    assert reg.get_active(OTHER) is None
    row = json.loads((tmp_path / "inc.jsonl").read_text())
    row.pop("confirmed")
    (tmp_path / "inc.jsonl").write_text(json.dumps(row) + "\n")
    assert reg.get_active(RID).confirmed == []


def test_confirm_facts_on_a_resolved_attack_started(tmp_path):
    """respond mode: an attack_started resolved by poll_detection confirms what the
    detection found, after load_context opened the incident."""
    reg = IncidentRegistry(path=tmp_path / "inc.jsonl")
    inc = reg.get_or_create(RID, "T1548.003")
    from dataclasses import asdict
    state = {"signal": _sudo(), "incident": asdict(inc)}
    out = agent.confirm_facts(state, incidents=reg)
    assert out["incident"]["confirmed"] == [agent.ROOT_ELEVATION]
    # Unresolved (still an attack_started), or no incident: unchanged.
    same = {"signal": {**_sudo(), "event": "attack_started"}, "incident": asdict(inc)}
    assert agent.confirm_facts(same, incidents=reg) is same
    alone = {"signal": _sudo(), "incident": None}
    assert agent.confirm_facts(alone, incidents=reg) is alone


# ── The harness (scripts/llm_smoke.py): it runs the whole decide ─────────────────────────

@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("llm_smoke_b3a", SMOKE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _harness_runs(smoke, sc: dict, row: dict, incident: dict | None, runs: int = 3) -> list[str]:
    """The harness's own loop for one case (its `_state`, its call to decide, its judge), the
    model patched to answer block_suspicious_ip every time."""
    verdicts = []
    for _ in range(runs):
        state = smoke._state(sc["ttp"], {"first_result_row": row}, sc.get("past"), incident)
        with patch("litellm.completion", return_value=_decision("block_suspicious_ip")):
            out = agent.decide(state, model="anthropic/claude-test",
                               autonomy_override="non_disruptive")
        good, _ = smoke._judge(sc, out["action"], bool(out.get("escalate")))
        verdicts.append((out["action"], good))
    return verdicts


def test_the_harness_paired_case_as_written_is_neighbouring_signals(smoke):
    """The paired case 2/2 names a sudo in its incident but no login after the brute force
    (failures only, no COR1 mark, no confirmed facts): the floor does not play there."""
    sc = next(s for s in smoke.SCENARIOS if s.get("pair") and s.get("incident"))
    assert "Correlation" not in sc["row"] and "confirmed" not in sc["incident"]
    assert _harness_runs(smoke, sc, sc["row"], sc["incident"]) == [("block_suspicious_ip", False)] * 3


def test_the_harness_case_with_the_correlation_confirmed_passes_three_times_in_three(smoke):
    """The same case, the brute force seen succeed (COR1) and the sudo confirmed on the VM: a
    model that blocks every time still passes 3/3 — the floor runs inside decide."""
    sc = next(s for s in smoke.SCENARIOS if s.get("pair") and s.get("incident"))
    row = {**sc["row"], "Correlation": "ssh-login-after-brute-force",
           "SuccessfulLogins": [{"account": "alice", "method": "password", "at": "x"}]}
    incident = {**sc["incident"], "confirmed": [agent.ROOT_ELEVATION]}
    assert _harness_runs(smoke, sc, row, incident) == [("isolate_vm", True)] * 3
