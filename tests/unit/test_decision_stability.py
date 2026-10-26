"""D-1 — the stability of the decision: the temperature, the agreement of the draws.

The same brute force drew `block_suspicious_ip` at 0.80 on 21/10 and `isolate_vm` at 0.78
on 23/10, with no temperature set anywhere: context or draw, nobody could say.

- The first draw is asked at temperature 0. A model that refuses it (claude-sonnet-5-5,
  the default: « `temperature` is deprecated for this model. », measured 26/10) is asked
  again without it, once for good, and the cycle records the default sampling.
- A disruptive action about to run alone is drawn again, at the model's default sampling,
  and held (`unstable_decision`) unless every draw would have taken it alone.

The cycles go through the real graph where the card matters (G2's set-up: a recording
connector in place of Azure, the model patched). Mutants M191–M202
(scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock, patch

import pytest

from eregion_core import llm_call
from glorfindel.config import AutonomyConfig
from tests.unit.test_dependency_failures import (
    FakeMemory, LogAnalytics, Recorder, _agent, _cards, _debug, _ransomware,
)

REFUSAL = ('litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":'
           '"invalid_request_error","message":"`temperature` is deprecated for this model."}}')


@pytest.fixture(autouse=True)
def hermetic(tmp_path, monkeypatch):
    for var in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "GLORFINDEL_LLM_BASE_URL",
                "GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_LLM_TIMEOUT_S",
                "GLORFINDEL_READ_ONLY", "GLORFINDEL_DECISION_DRAWS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(llm_call, "_AUTO_TOOL_CHOICE", set())
    monkeypatch.setattr(llm_call, "_NO_TEMPERATURE", set())
    import glorfindel.agent as agent
    monkeypatch.setattr(agent, "CycleMemory", FakeMemory)
    # A snapshot needs a vault to go to; the job it records stays out of ~/.glorfindel.
    monkeypatch.setattr(agent, "_backup_vault_target", lambda: ("rsv-d1", "rg"))
    import glorfindel.jobs as jobs
    monkeypatch.setattr(jobs, "record_snapshot_job", lambda *a, **kw: None)
    from glorfindel.actions import AzureConnector

    def no_azure(self):
        raise RuntimeError("no Azure client in tests (D-1)")
    monkeypatch.setattr(AzureConnector, "_ensure_clients", no_azure)


@pytest.fixture()
def notified(monkeypatch):
    sent: list[dict] = []
    import glorfindel.escalations as escalations
    monkeypatch.setattr(escalations, "notify_action", lambda **kw: sent.append(kw))
    return sent


def _llm(action: str, confidence: float = 0.95, escalate: bool = False):
    call = MagicMock()
    call.function.arguments = json.dumps({
        "reasoning": f"{action}.", "confidence": confidence, "action": action,
        "reversible": True, "explanation": f"{action} recommended.", "escalate": escalate,
        "escalation_reason": "asked" if escalate else "", "suggested_steps": [],
    })
    resp = MagicMock()
    resp.choices[0].message.tool_calls = [call]
    resp.usage = None
    return resp


class Model:
    """The provider. The first draw is the one asked at temperature 0; every other call is
    a confirming draw, answered from `others` in turn (the last one repeated). `refuse`:
    the model refuses any temperature, like claude-sonnet-5-5."""

    def __init__(self, first, others=None, refuse: bool = False):
        self.first, self.others, self.refuse = first, list(others or []), refuse
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def completion(self, **kw):
        with self._lock:
            self.calls.append(kw)
            if "temperature" in kw and self.refuse:
                raise RuntimeError(REFUSAL)
            if kw.get("temperature") == 0 or (self.refuse and len(self.asked()) == 1):
                return self.first
            answer = self.others[0] if self.others else self.first
            if isinstance(answer, BaseException):
                if len(self.others) > 1:
                    self.others.pop(0)
                raise answer
            if len(self.others) > 1:
                self.others.pop(0)
            return answer

    def asked(self) -> list[dict]:
        """The calls that reached the model (a refused temperature is not a draw)."""
        return [c for c in self.calls if not ("temperature" in c and self.refuse)]


def _respond(agent, signal, model: Model):
    with patch("litellm.completion", side_effect=model.completion), \
            patch("glorfindel.detectors.detector_for", return_value=LogAnalytics(fail=False)):
        return agent.respond(signal)


def _autonomous(conn):
    return _agent(conn, autonomy=AutonomyConfig(default="non_disruptive"))


# ── 1. The temperature (eregion_core/llm_call.py) ──────────────────────────────

class _Litellm:
    def __init__(self, refuse_temperature=False, refuse_forced=False, error=""):
        self.refuse_temperature, self.refuse_forced, self.error = (
            refuse_temperature, refuse_forced, error)
        self.calls: list[dict] = []

    def completion(self, **kw):
        self.calls.append(kw)
        if self.error:
            raise RuntimeError(self.error)
        if self.refuse_temperature and "temperature" in kw:
            raise RuntimeError(REFUSAL)
        if self.refuse_forced and kw["tool_choice"] != "auto":
            raise RuntimeError('tool_choice: type "tool" and "any" are not supported for this model.')
        return "response"


def test_the_temperature_reaches_a_model_that_accepts_it():
    lm = _Litellm()
    assert llm_call.completion_with_tool(lm, "t", temperature=0.0, model="anthropic/claude-sonnet-4-6") == "response"
    assert lm.calls[0]["temperature"] == 0.0 and len(lm.calls) == 1
    assert llm_call.temperature_refused("anthropic/claude-sonnet-4-6") is False


def test_a_model_refusing_the_temperature_is_asked_again_without_it_and_remembered():
    """claude-sonnet-5-5 (26/10): « `temperature` is deprecated for this model. » — every
    decision failed before the model saw the signal if this refusal escaped."""
    lm = _Litellm(refuse_temperature=True)
    m = "anthropic/claude-sonnet-5-5"
    assert llm_call.completion_with_tool(lm, "t", temperature=0.0, model=m) == "response"
    assert "temperature" in lm.calls[0] and "temperature" not in lm.calls[1]
    assert llm_call.temperature_refused(m) is True
    llm_call.completion_with_tool(lm, "t", temperature=0.0, model=m)
    assert len(lm.calls) == 3 and "temperature" not in lm.calls[2]   # straight without it


def test_both_refusals_of_claude_sonnet_5_5_resolve_in_either_order():
    lm = _Litellm(refuse_temperature=True, refuse_forced=True)
    m = "anthropic/claude-sonnet-5-5"
    assert llm_call.completion_with_tool(lm, "t", temperature=0.0, model=m) == "response"
    assert lm.calls[-1]["tool_choice"] == "auto" and "temperature" not in lm.calls[-1]
    assert llm_call.completion_with_tool(lm, "t", temperature=0.0, model=m) == "response"
    assert len(lm.calls) == 4                              # both remembered: one call


@pytest.mark.parametrize("message", [
    "Unsupported value: 'temperature' does not support 0 with this model.",
    "litellm.UnsupportedParamsError: openai does not support parameters: ['temperature']",
])
def test_the_other_providers_wordings_of_the_refusal_are_read(message):
    assert llm_call._refuses_temperature(RuntimeError(message))


def test_any_other_failure_is_raised_and_the_temperature_kept():
    lm = _Litellm(error="rate limit exceeded")
    with pytest.raises(RuntimeError, match="rate limit"):
        llm_call.completion_with_tool(lm, "t", temperature=0.0, model="m")
    assert len(lm.calls) == 1 and llm_call.temperature_refused("m") is False


def test_no_temperature_asked_none_sent():
    lm = _Litellm()
    llm_call.completion_with_tool(lm, "t", model="m")
    assert "temperature" not in lm.calls[0]


# ── 2. The first draw (glorfindel/agent.py, decide) ────────────────────────────

def test_the_decision_is_asked_at_temperature_zero():
    from glorfindel.agent import decide
    from tests.unit.test_agent_nodes import _state
    model = Model(_llm("snapshot"))
    with patch("litellm.completion", side_effect=model.completion):
        out = decide(_state(), model="anthropic/claude-test", autonomy=AutonomyConfig("non_disruptive"))
    assert [c.get("temperature") for c in model.calls] == [0.0]
    assert out["decision_temperature"] == 0.0 and out["action"] == "snapshot"


def test_a_model_refusing_the_temperature_decides_and_the_cycle_says_default_sampling(notified):
    """The default model refuses 0: the decision is still taken, and the debug line says
    its draw was the provider's default sampling — not a fixed one."""
    conn = Recorder()
    model = Model(_llm("snapshot"), refuse=True)
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert final["action"] == "snapshot" and final["decision_temperature"] is None
    assert conn.writes() == ["snapshot"]
    assert _debug()[-1]["decision_temperature"] is None


# ── 3. The agreement of the draws ─────────────────────────────────────────────

def test_control_every_draw_agrees_the_isolation_runs(notified):
    """Three draws, all isolate above the gate: it runs, as before D-1."""
    conn = Recorder()
    model = Model(_llm("isolate_vm", 0.95), [_llm("isolate_vm", 0.90)])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == ["isolate_vm"] and [n["action"] for n in notified] == ["isolate_vm"]
    assert len(model.calls) == 3 and _cards() == []
    assert [d["action"] for d in final["decision_draws"]] == ["isolate_vm"] * 3
    assert _debug()[-1]["decision_draws"] == final["decision_draws"]


def test_the_confirming_draws_are_asked_at_the_models_default_sampling():
    """The first draw's temperature removes the variance the confirmation is there to
    probe: the confirming draws carry none."""
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [_llm("isolate_vm")])
    _respond(_autonomous(conn), _ransomware(), model)
    assert [c.get("temperature", "default") for c in model.calls] == [0.0, "default", "default"]


def test_a_draw_that_disagrees_holds_the_isolation(notified):
    """The 21/10–23/10 case: the first draw isolates, another blocks the IP."""
    conn = Recorder()
    model = Model(_llm("isolate_vm", 0.78), [_llm("block_suspicious_ip", 0.80), _llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == [] and notified == [] and final["outcome"]["executed"] is False
    assert [c["escalation_type"] for c in _cards()] == ["unstable_decision"]
    assert final["held_by"] == "agreement" and final["action"] == "isolate_vm"
    assert "2 tirage(s) sur 3" in final["escalation_reason"]
    assert "block_suspicious_ip 80%" in final["escalation_reason"]


def test_a_draw_below_the_confidence_threshold_does_not_agree(notified):
    """Same action, but at 0.40 that draw would not have acted alone."""
    conn = Recorder()
    model = Model(_llm("isolate_vm", 0.95), [_llm("isolate_vm", 0.40)])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == [] and final["held_by"] == "agreement"
    assert "isolate_vm 40%, escaladée" in final["escalation_reason"]


def test_a_draw_that_escalates_itself_does_not_agree(notified):
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [_llm("isolate_vm", 0.95, escalate=True)])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == [] and final["held_by"] == "agreement"


def test_a_confirming_draw_that_fails_holds_the_isolation(notified):
    """The provider fails on a confirming draw: the guard fails closed."""
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [ConnectionError("api unreachable"), _llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == [] and final["held_by"] == "agreement"
    assert "appel en échec (api unreachable)" in final["escalation_reason"]
    assert [c["escalation_type"] for c in _cards()] == ["unstable_decision"]


def test_human_only_pays_for_no_other_draw(notified):
    """H0 runs human_only: the action is held by the mode, the model is asked once."""
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [_llm("block_suspicious_ip")])
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="human_only")), _ransomware(), model)
    assert len(model.calls) == 1 and final["decision_draws"] == []
    assert [c["escalation_type"] for c in _cards()] == ["mode_hold"]


def test_a_snapshot_is_not_drawn_again(notified):
    conn = Recorder()
    model = Model(_llm("snapshot"), [_llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert len(model.calls) == 1 and conn.writes() == ["snapshot"] and final["decision_draws"] == []


def test_an_action_already_held_is_not_drawn_again(notified):
    conn = Recorder()
    model = Model(_llm("isolate_vm", 0.30), [_llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert len(model.calls) == 1 and final["held_by"] == "confidence"


def test_more_draws_can_be_asked(monkeypatch, notified):
    monkeypatch.setenv("GLORFINDEL_DECISION_DRAWS", "5")
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [_llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert len(model.calls) == 5 and conn.writes() == ["isolate_vm"]
    assert len(final["decision_draws"]) == 5


@pytest.mark.parametrize("raw", ["abc", "1", "0", "-3", "11", "2.5"])
def test_a_malformed_number_of_draws_holds_every_disruptive_action(monkeypatch, notified, raw):
    """Configuration fails closed, like the confidence threshold (G2). One draw is no
    agreement."""
    monkeypatch.setenv("GLORFINDEL_DECISION_DRAWS", raw)
    conn = Recorder()
    model = Model(_llm("isolate_vm"), [_llm("isolate_vm")])
    final = _respond(_autonomous(conn), _ransomware(), model)
    assert conn.writes() == [] and final["held_by"] == "agreement"
    assert "GLORFINDEL_DECISION_DRAWS" in final["escalation_reason"]
    assert len(model.calls) == 1


@pytest.mark.parametrize("raw, expected", [("", 3), ("2", 2), ("10", 10), (" 4 ", 4),
                                           ("1", 0), ("11", 0), ("abc", 0), ("nan", 0)])
def test_the_number_of_draws_parses(monkeypatch, raw, expected):
    from glorfindel.config import decision_draws
    monkeypatch.setenv("GLORFINDEL_DECISION_DRAWS", raw)
    assert decision_draws() == expected


def test_fewer_draws_than_required_hold_the_action():
    """Draws lost on the way (a confirming draw never answered) are not an agreement."""
    from glorfindel.agent import _apply_agreement_guard
    d = {"action": "isolate_vm", "confidence": 0.9, "escalate": False}
    _apply_agreement_guard(d, [{"action": "isolate_vm", "confidence": 0.9, "escalate": False}], 3)
    assert d["escalate"] is True and d["held_by"] == "agreement"


def test_an_unstable_decision_card_is_approvable_in_one_click():
    """A human judging the card may run the first draw's action, like every held type."""
    from glorfindel import api, escalations
    assert "unstable_decision" in api._APPROVABLE_TYPES
    assert "unstable_decision" in escalations._ESCALATION_LABELS


def test_the_number_of_draws_reaches_the_watchs_container():
    """docker compose passes an explicit list (`x-env`): a value set in .envrc but missing
    from it is ignored by the watch, where decide() runs. Unset, it is passed empty — and
    empty is 3."""
    from pathlib import Path

    import yaml
    compose = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose["x-env"].get("GLORFINDEL_DECISION_DRAWS") == "${GLORFINDEL_DECISION_DRAWS:-}"
    assert "GLORFINDEL_DECISION_DRAWS" in compose["services"]["watch"]["environment"]
