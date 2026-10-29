"""SEC4a (#275) — the decision facing a model, a memory or a line it did not expect.

1. The model's answer is read field by field, for its type: an action that is not text, a
   confidence that is not a number, steps that are not a list — the cycle escalates, it
   never raises. A property (Hypothesis, arbitrary JSON) keeps it so.
2. A characterized detection that a snapshot alone answers leaves a card for a human: the
   snapshot runs, nothing is contained, a human is asked.
3. The memory: every signal, an exercise too, is given real cycles only; a cycle's
   identifier is drawn by the memory — no cycle overwrites another, a replayed one is
   retrieved once.
4. An attack_started from runs/: the row the rule finds is read as the RulePoller reads it
   and must name the line's VM, or the actions aimed at it are held; its moment is
   bounded, or the line is refused.

No Azure call, no model call (the model is patched). Mutants M1240–M1249, M1330–M1339,
M1360–M1364 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import json
import math
import os
import time
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from glorfindel import agent, signal_origin
from glorfindel.config import AutonomyConfig
from glorfindel.memory import CycleMemory
from tests.unit.test_dependency_failures import FakeMemory, Recorder, _agent, _cards

RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-s4"
OTHER = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-other"
SCHEMA = ("reasoning", "confidence", "action", "reversible", "explanation", "escalate",
          "escalation_reason", "suggested_steps")


@pytest.fixture(autouse=True)
def hermetic(tmp_path, monkeypatch):
    for var in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "GLORFINDEL_LLM_BASE_URL",
                "GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_LLM_TIMEOUT_S",
                "GLORFINDEL_READ_ONLY", "GLORFINDEL_DECISION_DRAWS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    from eregion_core import llm_call
    monkeypatch.setattr(llm_call, "_AUTO_TOOL_CHOICE", set())
    monkeypatch.setattr(llm_call, "_NO_TEMPERATURE", set())
    # A snapshot needs a vault to go to; the job it records stays out of ~/.glorfindel.
    monkeypatch.setattr(agent, "_backup_vault_target", lambda: ("rsv-s4", "rg"))
    import glorfindel.jobs as jobs
    monkeypatch.setattr(jobs, "record_snapshot_job", lambda *a, **kw: None)
    import glorfindel.escalations as escalations
    monkeypatch.setattr(escalations, "notify_action", lambda **kw: None)
    monkeypatch.setattr(agent, "CycleMemory", FakeMemory)     # the agent's; the tests of
    # the memory build their own (glorfindel.memory.CycleMemory)
    from glorfindel.actions import AzureConnector

    def no_azure(self):
        raise RuntimeError("no Azure client in tests (SEC4a)")
    monkeypatch.setattr(AzureConnector, "_ensure_clients", no_azure)


def _response(arguments) -> MagicMock:
    """A LiteLLM response whose security_decision call carries `arguments` as given."""
    call = MagicMock()
    call.function.arguments = arguments
    resp = MagicMock()
    resp.choices[0].message.tool_calls = [call]
    resp.usage = None
    return resp


def _decision(**fields) -> MagicMock:
    base = {"reasoning": "r", "confidence": 0.95, "action": "isolate_vm", "reversible": True,
            "explanation": "e", "escalate": False, "escalation_reason": "", "suggested_steps": []}
    return _response(json.dumps({**base, **fields}))


def _detection(row: dict | None = None, **over) -> dict:
    sig = {
        "signal_id": "rule-ransomware-disk-write-0000s4s4", "event": "detection", "ttp": "T1486",
        "severity": "high", "resource_id": RID, "resource_type": "vm",
        "timestamp": "2026-10-28T10:00:00+00:00",
        "context": {"rule_name": "ransomware-disk-write", "attribution": "asset",
                    "run_id": "watch-ransomware-disk-write-20261028T100000Z"},
        "raw_signal": {"first_result_row": row if row is not None else
                       {"Computer": "vm-s4", "_ResourceId": RID, "MaxWrite": 147000000}},
    }
    sig.update(over)
    return sig


def _state(signal: dict) -> dict:
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": True,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "", "outcome": None,
            "telemetry_gaps": []}


def _decide(signal: dict, resp, mode: str = "non_disruptive") -> dict:
    with patch("litellm.completion", return_value=resp):
        return agent.decide(_state(signal), model="anthropic/claude-test",
                            autonomy=AutonomyConfig(default=mode))


# ── 1. The model's answer, read for its type (V-23) ──────────────────────────────────────

@pytest.mark.parametrize("action", [["isolate_vm"], 42, {"name": "isolate_vm"}, True, 0.5])
def test_an_action_that_is_not_text_escalates_and_never_raises(action):
    """Only a text is an action: anything else is unreadable, and the cycle escalates."""
    d, _raw = agent._parse_decision(_decision(action=action))
    assert d["action"] == "" and d["escalate"] is True
    assert "illisible" in d["escalation_reason"]
    final = _decide(_detection(), _decision(action=action))
    assert final["escalate"] is True and final["action"] == ""


@pytest.mark.parametrize("conf", [True, False, [0.9], {"value": 0.9}])
def test_a_confidence_that_is_not_a_number_is_unknown_and_held(conf):
    """Only a number is a confidence (a boolean is none): unknown, held by the gate."""
    d, raw = agent._parse_decision(_decision(action="snapshot", confidence=conf))
    assert raw is None and d["confidence"] == 0.0
    final = _decide(_detection(), _decision(action="snapshot", confidence=conf))
    assert final["escalate"] is True and final["held_by"] == "confidence"
    assert "unknown" in final["escalation_reason"]


def test_a_key_the_model_adds_never_reaches_the_gates():
    """Only the schema's fields are kept from the answer: which gate held a decision is
    the gates' to say, never the model's."""
    final = _decide(_detection(), _decision(escalate=True, escalation_reason="unsure",
                                            held_by="control_plane", autonomy_gate={"x": 1}))
    assert final["escalate"] is True and final["held_by"] == ""
    d, _raw = agent._parse_decision(_decision(held_by="never_block"))
    assert set(d) == set(SCHEMA)


@pytest.mark.parametrize("steps, read", [(5, []), ("check auth.log", ["check auth.log"]),
                                         ({"a": 1}, []), (["a", 2, None], ["a", "2"]), (None, [])])
def test_steps_are_a_list_of_text(steps, read):
    d, _raw = agent._parse_decision(_decision(suggested_steps=steps))
    assert d["suggested_steps"] == read


@pytest.mark.parametrize("args", ["{not json", "[1, 2]", "42", "null", "[" * 100_000, {"action": "snapshot"}],
                         ids=["not-json", "a-list", "a-number", "null", "nested-too-deep", "an-object"])
def test_arguments_that_are_no_object_are_no_decision(args):
    d, _raw = agent._parse_decision(_response(args))
    if isinstance(args, dict):           # a provider handing the object itself: read
        assert d["action"] == "snapshot"
    else:
        assert d["action"] == "" and d["escalate"] is True


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(min_value=-10**30, max_value=10**30)
    | st.floats(allow_nan=True, allow_infinity=True) | st.text(max_size=12),
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(st.text(max_size=6), inner, max_size=3),
    max_leaves=6)
_PLAUSIBLE = {
    "action": st.sampled_from(["isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation",
                               "restore_from_backup", "revoke_temp_access", "", " isolate_vm "]),
    "confidence": st.floats(min_value=0.0, max_value=1.0) | st.sampled_from(["0.9", "nan", "1e999"]),
    "escalate": st.sampled_from([False, True, "false", "true", 0, 1]),
    "suggested_steps": st.lists(st.text(max_size=10), max_size=3),
}
_FIELDS = st.fixed_dictionaries({}, optional={
    k: (_PLAUSIBLE[k] | _JSON) if k in _PLAUSIBLE else _JSON for k in (*SCHEMA, "held_by")})
_ARGUMENTS = st.one_of(_FIELDS.map(json.dumps), _JSON.map(json.dumps), st.text(max_size=40))


@settings(max_examples=int(os.environ.get("GLORFINDEL_SEC4A_EXAMPLES", "150")), deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow])
@given(arguments=_ARGUMENTS)
def test_property_any_answer_is_a_decision_or_an_escalation_never_an_exception(arguments):
    """Whatever JSON the model returns: `decide` returns, every field of its decision has
    its type, and the graph either runs an autonomous action every gate let through, or
    asks a human (an action needing approval, an unknown one, an escalation). The card
    that follows is built without raising either."""
    final = _decide(_detection(), _response(arguments))
    assert isinstance(final["action"], str)
    assert all(isinstance(final[k], str) for k in ("reasoning", "explanation", "escalation_reason"))
    assert isinstance(final["suggested_steps"], list)
    assert all(isinstance(s, str) for s in final["suggested_steps"])
    assert isinstance(final["confidence"], float)
    assert math.isnan(final["confidence"]) or 0.0 <= final["confidence"] <= 1.0
    assert isinstance(final["escalate"], bool)
    # The graph's next step: an action runs alone, or a human is asked.
    if agent._route_after_decide(final) == "execute_action":
        assert not final["escalate"]
        assert final["action"] in agent._EXECUTABLE_ACTIONS
        assert final["confidence"] >= 0.7
        assert final["action"] != "release_isolation"          # on a detection: held
    else:
        card = agent.escalate_to_human(final)                  # dry_run: no record
        assert card["outcome"]["status"] == "escalated"


# ── 2. A snapshot alone leaves a card (V-11) ─────────────────────────────────────────────

def test_a_characterized_detection_a_snapshot_alone_answers_leaves_a_card():
    """The snapshot runs (autonomous, non-disruptive) and a card asks a human whether to
    contain — no action on it: nothing to approve in one click."""
    conn = Recorder()
    agent_ = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive"))
    with patch("litellm.completion", return_value=_decision(action="snapshot")), \
            patch("glorfindel.detectors.detector_for", side_effect=RuntimeError("no LAW")):
        final = agent_.respond(_detection())
    assert conn.writes() == ["snapshot"]
    assert final["escalate"] is False and final["outcome"]["executed"] is True
    cards = _cards()
    assert [c["escalation_type"] for c in cards] == ["uncontained_detection"]
    assert cards[0]["action"] == "" and "snap-1" in cards[0]["reason"]
    assert "instantané" in cards[0]["reason"]


def test_the_floor_holds_whatever_the_mode_of_the_snapshot_and_only_where_it_should():
    det = _detection()
    assert _decide(det, _decision(action="snapshot"))["uncontained"]
    # Escalated already (the model, or a gate): it has its card — no second one.
    assert not _decide(det, _decision(action="snapshot", escalate=True))["uncontained"]
    assert not _decide(det, _decision(action="snapshot"), mode="human_only")["uncontained"]
    # A containment, a timeout, an uncharacterized row: not this floor's.
    assert not _decide(det, _decision(action="block_suspicious_ip"))["uncontained"]
    assert not _decide(_detection(event="detection_timeout"), _decision(action="snapshot"))["uncontained"]
    assert not _decide(_detection({"Computer": "vm-s4", "Foo": "bar"}),
                       _decision(action="snapshot"))["uncontained"]


def test_no_floor_when_a_previous_cycle_already_contains(monkeypatch):
    """A new trigger on a VM already isolated, or from a source already blocked on it: the
    snapshot answers a contained incident — no card saying nothing is contained. Read from
    the state files, never from the past cycles."""
    import glorfindel.actions as actions
    det = _detection({"Computer": "vm-s4", "SourceIP": "203.0.113.7", "FailedAttempts": 40},
                     ttp="T1110.001")
    monkeypatch.setattr(actions, "_load_isolation_state", lambda rid: {"resource_id": rid})
    monkeypatch.setattr(actions, "_load_block_entries", lambda rid: [])
    assert not _decide(_detection(), _decision(action="snapshot"))["uncontained"]
    monkeypatch.setattr(actions, "_load_isolation_state", lambda rid: {"partial": True})
    assert "partielle" in _decide(_detection(), _decision(action="snapshot"))["uncontained"]
    monkeypatch.setattr(actions, "_load_isolation_state", lambda rid: None)
    monkeypatch.setattr(actions, "_load_block_entries", lambda rid: [{"ip": "203.0.113.7"}])
    assert not _decide(det, _decision(action="snapshot"))["uncontained"]
    monkeypatch.setattr(actions, "_load_block_entries", lambda rid: [{"ip": "198.51.100.9"}])
    reason = _decide(det, _decision(action="snapshot"))["uncontained"]
    assert "198.51.100.9" in reason and "pas isolée" in reason


def test_a_snapshot_that_failed_has_its_own_card_only():
    conn = Recorder(outage=True)
    agent_ = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive"))
    with patch("litellm.completion", return_value=_decision(action="snapshot")), \
            patch("glorfindel.detectors.detector_for", side_effect=RuntimeError("no LAW")):
        agent_.respond(_detection())
    assert [c["escalation_type"] for c in _cards()] == ["action_failed"]


# ── 3. The memory (V-12) ─────────────────────────────────────────────────────────────────

def _cycle(source: str, reasoning: str, signal_id: str = "sig-1", action: str = "isolate_vm") -> dict:
    return {"signal_id": signal_id, "run_id": "r", "ttp": "T1486", "severity": "high",
            "resource_type": "vm", "event": "detection", "reasoning": reasoning,
            "action": action, "outcome": "x", "source": source, "confidence": 0.9}


def test_every_signal_is_given_real_cycles_only(tmp_path):
    mem = CycleMemory(path=tmp_path / "cycles")
    for source in ("real", "exercise", "", "unknown"):
        mem.store(_cycle(source, f"cycle {source or 'legacy'}", signal_id=f"s-{source}"))
    sig = {"ttp": "T1486", "severity": "high", "resource_type": "vm", "event": "detection"}
    assert [c["source"] for c in mem.retrieve_similar(sig, n=4)] == ["real"]


def test_an_exercise_is_given_no_exercise_cycle_nor_one_of_unknown_source(tmp_path, monkeypatch):
    """What the model is shown never tells it whether the current signal is an exercise:
    an exercise is given real cycles only, as a real signal is."""
    from glorfindel.incidents import IncidentRegistry
    mem = CycleMemory(path=tmp_path / "cycles")
    mem.store(_cycle("exercise", "an exercise", signal_id="s-x"))
    mem.store(_cycle("", "before sources existed", signal_id="s-l"))
    mem.store(_cycle("real", "a real one", signal_id="s-r"))
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl")
    real = agent.load_context(_state(_detection()), memory=mem, incidents=incidents)
    monkeypatch.setattr(agent, "_cycle_source", lambda s: ("exercise", "run-1"))
    drill = agent.load_context(_state(_detection()), memory=mem, incidents=incidents)
    assert [c["source"] for c in real["past_cycles"]] == ["real"]
    assert [c["source"] for c in drill["past_cycles"]] == ["real"]


def test_no_cycle_overwrites_another_whatever_its_signal_id(tmp_path):
    """The memory draws a cycle's identifier: two cycles under one signal id are two."""
    mem = CycleMemory(path=tmp_path / "cycles")
    mem.store(_cycle("real", "the real precedent", signal_id="sig-1"))
    mem.store({**_cycle("real", "another cycle", signal_id="sig-1"), "run_id": "r2"})
    assert mem.count() == 2
    sig = {"ttp": "T1486", "severity": "high", "resource_type": "vm", "event": "detection"}
    found = mem.retrieve_similar(sig, n=2)
    assert any("the real precedent" in c["summary"] for c in found) and len(found) == 2


def test_a_replayed_cycle_is_retrieved_once(tmp_path):
    """`respond` replayed on the same file (Annatar's signal ids are fixed) stores its
    cycles again: one (signal_id, action, run_id) fills one place, never N."""
    mem = CycleMemory(path=tmp_path / "cycles")
    for _ in range(4):
        mem.store(_cycle("real", "replayed", signal_id="20261028T100000Z_attack_started"))
    mem.store(_cycle("real", "another", signal_id="s-2"))
    sig = {"ttp": "T1486", "severity": "high", "resource_type": "vm", "event": "detection"}
    found = mem.retrieve_similar(sig, n=3)
    assert sorted(c["signal_id"] for c in found) == ["20261028T100000Z_attack_started", "s-2"]


# ── 4. An attack_started: the row names the VM, the moment is bounded ───────────────────

class _Detector:
    """A workspace holding `rows`: the first one `match_row` accepts is the detection."""

    def __init__(self, rows):
        self.rows, self.polled = rows, 0

    def poll_alert(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        self.polled += 1
        return next(((12, r) for r in self.rows if match_row is None or match_row(r)), None)

    def run_query(self, query, timespan=None):      # the investigation: nothing to add
        return []


def _started(**raw) -> dict:
    return {"signal_id": "20261028T100000Z_attack_started", "event": "attack_started",
            "ttp": "T1486", "severity": "critical", "resource_id": RID, "resource_type": "vm",
            "context": {"run_id": "20261028T100000Z"},
            "raw_signal": {"attack_time": time.time() - 90, "detection_timeout_s": 1, **raw}}


def _resolve(signal: dict, rows, owners: dict | None = None) -> tuple[dict, _Detector]:
    det = _Detector(rows)
    rule = MagicMock(source="azure_monitor", query="Perf | where x", workspace_id="ws",
                     expected_latency_s=0)
    rule.name = "ransomware-disk-write"
    with patch("glorfindel.agent._find_rule_for_ttp", return_value=rule), \
            patch("glorfindel.agent.load_glorfindel_config", return_value=None), \
            patch("glorfindel.detectors.detector_for", return_value=det):
        return agent.resolve_attack_started(
            signal, ip_owners=(lambda: owners) if owners is not None else None), det


def test_a_row_naming_the_lines_vm_is_its_detection():
    out, _ = _resolve(_started(), [{"Computer": "vm-s4", "_ResourceId": RID.lower(), "MaxWrite": 9e7}])
    assert out["event"] == "detection" and "attribution" not in out["context"]
    assert _decide(out, _decision())["action"] == "isolate_vm"


def test_a_row_naming_another_vm_is_never_pinned_to_the_lines():
    """The rule found another VM's encryption: the poll keeps looking for this VM's."""
    own = {"Computer": "vm-s4", "MaxWrite": 8e7}
    out, _ = _resolve(_started(), [{"Computer": "vm-other", "_ResourceId": OTHER, "MaxWrite": 9e7}, own])
    assert out["raw_signal"]["detected_data"] == own
    out, _ = _resolve(_started(), [{"_ResourceId": OTHER + "/extensions/x", "MaxWrite": 9e7},
                                   {"Computer": "vm-other.internal", "MaxWrite": 9e7}])
    assert out["event"] == "detection_timeout"


def test_a_row_naming_no_vm_holds_what_is_aimed_at_the_lines():
    """Aggregated by address: the line's VM is a guess — isolation and block held, the
    card says why; a snapshot stays autonomous."""
    out, _ = _resolve(_started(), [{"SourceIP": "203.0.113.7", "FailedAttempts": 40}])
    assert out["context"]["attribution"] == "unattributed"
    assert out["context"]["run_id"] == "20261028T100000Z"
    for action in ("isolate_vm", "block_suspicious_ip"):
        final = _decide(out, _decision(action=action))
        assert final["escalate"] is True and final["held_by"] == "attribution"
        assert "attack_started" in final["escalation_reason"] and "vm-s4" in final["escalation_reason"]
    assert _decide(out, _decision(action="snapshot"))["escalate"] is False


def test_an_exfiltration_row_is_attributed_by_the_private_ip_that_made_the_call():
    """data-exfiltration-blob (T1041) names no VM: its caller's private IP does, as the
    RulePoller reads it — the line's VM made the call, the isolation runs."""
    row = {"CallerIpAddress": "10.0.0.4:52114", "AccountName": "stacct", "PutBlobCount": 40}
    out, _ = _resolve(_started(), [row], owners={"10.0.0.4": RID, "10.0.0.5": OTHER})
    assert out["event"] == "detection" and "attribution" not in out["context"]
    assert _decide(out, _decision())["action"] == "isolate_vm"
    # Another VM's address: never this VM's row. An address no VM holds: unattributed.
    out, _ = _resolve(_started(), [row], owners={"10.0.0.4": OTHER})
    assert out["event"] == "detection_timeout"
    out, _ = _resolve(_started(), [row], owners={})
    assert out["context"]["attribution"] == "unattributed"


def test_a_dotted_host_name_names_its_vm_and_two_homonyms_name_neither():
    out, _ = _resolve(_started(), [{"Computer": "vm-s4.internal.example", "MaxWrite": 9e7}])
    assert out["event"] == "detection" and "attribution" not in out["context"]
    # A sub-resource of the VM (an extension) names the VM.
    out, _ = _resolve(_started(), [{"_ResourceId": RID.lower() + "/extensions/x", "MaxWrite": 9e7}])
    assert out["event"] == "detection" and "attribution" not in out["context"]
    twin = "/subscriptions/s/resourceGroups/rg2/providers/Microsoft.Compute/virtualMachines/vm-s4"
    out, _ = _resolve(_started(), [{"Computer": "vm-s4", "MaxWrite": 9e7}],
                      owners={"10.0.0.4": RID, "10.1.0.4": twin})
    assert out["context"]["attribution"] == "unattributed"
    held = _decide(out, _decision())
    assert held["escalate"] is True and held["held_by"] == "attribution"


def test_respond_reads_the_private_ips_through_its_connector():
    """`glorfindel respond`: the graph hands the connector's private IP map to the poll —
    an exfiltration made from the line's VM is contained there too."""
    class WithIPs(Recorder):
        def private_ip_owners(self):
            return {"10.0.0.4": RID}

    conn = WithIPs()
    row = {"CallerIpAddress": "10.0.0.4:52114", "AccountName": "stacct", "PutBlobCount": 40}
    det = _Detector([row])
    rule = MagicMock(source="azure_monitor", query="StorageBlobLogs | where x", workspace_id="",
                     expected_latency_s=0)
    rule.name = "data-exfiltration-blob"
    with patch("glorfindel.agent._find_rule_for_ttp", return_value=rule), \
            patch("glorfindel.detectors.detector_for", return_value=det), \
            patch("litellm.completion", return_value=_decision()):
        final = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive")).respond(
            {**_started(), "ttp": "T1041"})
    assert final["signal"]["event"] == "detection"
    assert "attribution" not in final["signal"]["context"]
    assert conn.writes() == ["isolate_vm"], final.get("escalation_reason")


def test_the_same_reading_as_the_rulepoller():
    """One way to attribute a row: the RulePoller's routing and an attack_started's."""
    import inspect
    from glorfindel import detection_rules
    assert "RowAttribution" in inspect.getsource(detection_rules.RulePoller._route)
    assert "RowAttribution" in inspect.getsource(agent._row_reader)


def test_a_control_plane_attack_started_is_not_read_for_a_vm():
    """The Activity Log's rows name an NSG, a role: detection only, unchanged (AL1)."""
    det = _Detector([{"OperationNameValue": "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
                      "_ResourceId": "/subscriptions/s/resourceGroups/rg/providers/"
                                     "Microsoft.Network/networkSecurityGroups/nsg"}])
    rule = MagicMock(source="azure_activity", query="AzureActivity | where x", workspace_id="ws",
                     expected_latency_s=0)
    rule.name = "nsg-change-outside-glorfindel"
    with patch("glorfindel.agent._find_rule_for_ttp", return_value=rule), \
            patch("glorfindel.agent.load_glorfindel_config", return_value=None), \
            patch("glorfindel.detectors.detector_for", return_value=det):
        out = agent.resolve_attack_started(_started())
    assert out["event"] == "detection" and "attribution" not in (out.get("context") or {})


@pytest.mark.parametrize("attack_time, refused", [
    (lambda: time.time() - 60, False), (lambda: time.time() + 120, False),
    (lambda: time.time() - 3 * 3600, True), (lambda: time.time() + 3600, True),
    (lambda: "1761000000", True), (lambda: True, True), (lambda: math.nan, True),
    (lambda: math.inf, True), (lambda: None, True), (lambda: 10**400, True),
], ids=["a-minute-ago", "two-minutes-ahead", "three-hours-ago", "an-hour-ahead", "a-text", "a-boolean",
        "nan", "infinite", "null", "too-large"])
def test_the_moment_of_an_attack_started_is_bounded(attack_time, refused):
    """The rule's search starts there: never more than 2 h back, nor 5 min ahead."""
    value = attack_time()
    line = {"signal_id": "s", "event": "attack_started", "resource_id": RID, "ttp": "T1486",
            "raw_signal": {"attack_time": value}, "context": {"run_id": "r1"}}
    adm = signal_origin.admit(line)
    assert (adm.signal is None) is refused, adm.refused
    if refused:
        assert "attack_time" in adm.refused
        with pytest.raises(ValueError, match="attack_time"):
            _resolve(_started(attack_time=value), [{"Computer": "vm-s4", "MaxWrite": 9e7}])
    # Absent: the moment is now — as before.
    assert signal_origin.admit({**line, "raw_signal": {}}).signal is not None


def test_a_refused_moment_never_reaches_the_detection():
    signal = _started(attack_time=time.time() - 86400)
    det = _Detector([{"Computer": "vm-s4", "MaxWrite": 9e7}])
    with patch("glorfindel.detectors.detector_for", return_value=det), pytest.raises(ValueError):
        agent.resolve_attack_started(signal)
    assert det.polled == 0
    # `respond`: the graph's boundary makes it a card, said — never a decision.
    conn = Recorder()
    with patch("glorfindel.detectors.detector_for", return_value=det):
        final = _agent(conn, autonomy=AutonomyConfig(default="non_disruptive")).respond(signal)
    assert final["outcome"]["escalation_type"] == "cycle_failed"
    assert "attack_time" in final["escalation_reason"] and conn.writes() == []
