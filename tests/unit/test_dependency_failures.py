"""G2 — the failures of Glorfindel's dependencies: each one fails closed.

Four dependencies, each failing the way it fails in the field: the model (down, hung,
answering nonsense), the cloud API (unreachable, throttled), the telemetry (Log
Analytics refusing a query) and the configuration (an unreadable glorfindel-config.yaml,
a malformed environment switch). "Fails closed" means, for every one of them: nothing
disruptive runs on its own, a card says what failed, and nothing is claimed done.

The cycles go through the real graph (`GlorfindelAgent.respond`), not a node alone: a
recording connector in place of Azure, the model and Log Analytics patched, every store
redirected (conftest). A positive control per section proves the same set-up does
execute when nothing fails — a test that could never see an execution would prove
nothing. Mutants M151–M158 and M170–M178 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from glorfindel.config import AutonomyConfig

RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-g2"
WRITES = {"isolate_vm", "release_isolation", "block_suspicious_ip", "snapshot"}


# ── Set-up ─────────────────────────────────────────────────────────────────────

class Recorder:
    """Azure in place: every call recorded. `outage`: every call fails like an ARM
    endpoint that can't be reached (the call is recorded first — an attempt counts)."""

    read_only = False
    dry_run = False
    _subscription_id = "s"

    def __init__(self, outage: bool = False) -> None:
        self.calls: list[str] = []
        self.outage = outage

    def _call(self, name: str, result):
        self.calls.append(name)
        if self.outage:
            raise ConnectionError("management.azure.com unreachable (G2 test)")
        return result

    def isolate_vm(self, resource_id):
        return self._call("isolate_vm", {"status": "isolated", "resource_id": resource_id})

    def block_suspicious_ip(self, ip, resource_id, **_kw):
        return self._call("block_suspicious_ip", {"status": "blocked", "ip": ip})

    def release_isolation(self, resource_id):
        return self._call("release_isolation", {"status": "released"})

    def snapshot(self, resource_id, **_kw):
        return self._call("snapshot", "snap-1")

    def verify_isolation(self, resource_id):
        return self._call("verify_isolation", {"verified": True, "method": "nsg"})

    def verify_block_ip(self, ip, resource_id):
        return self._call("verify_block_ip", {"verified": True})

    def verify_release(self, resource_id):
        return self._call("verify_release", {"verified": True})

    def verify_snapshot(self, snapshot_id):
        return self._call("verify_snapshot", {"verified": None})

    def check_permissions(self, resource_id):
        return self._call("check_permissions", {"ok": True, "missing": []})

    # What readiness.assess reads after the rights: without them, the check raised an
    # AttributeError with Azure up as well — the outage test proved nothing (G2 review).
    def vm_os(self, resource_id):
        return self._call("vm_os", "linux")

    def check_nsg_access(self, resource_id):
        return self._call("check_nsg_access", {"ok": True, "nsg": "nsg-g2", "precedence": []})

    def writes(self) -> list[str]:
        return [c for c in self.calls if c in WRITES]


class FakeMemory:
    def __init__(self, path=None) -> None:
        self.stored: list[dict] = []

    def retrieve_similar(self, signal, n=3, *, exercise=False):
        return []

    def store(self, cycle):
        self.stored.append(cycle)


class LogAnalytics:
    """The investigative queries' workspace: `fail` → every query is refused."""

    def __init__(self, fail: bool) -> None:
        self.fail = fail
        self.queries = 0

    def run_query(self, query, timespan=None):
        self.queries += 1
        if self.fail:
            raise RuntimeError("workspace query not successful: PartialError (G2 test)")
        return []


@pytest.fixture(autouse=True)
def hermetic(tmp_path, monkeypatch):
    """No webhook, no bot, no LLM endpoint, no operator switches; runs/ under tmp;
    ChromaDB replaced (the cycles' content is not what G2 measures)."""
    for var in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "GLORFINDEL_LLM_BASE_URL",
                "GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_LLM_TIMEOUT_S",
                "GLORFINDEL_READ_ONLY", "GLORFINDEL_APPROVAL_MAX_AGE_H"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    import glorfindel.agent as agent
    monkeypatch.setattr(agent, "CycleMemory", FakeMemory)
    # Azure's SDK is never built here, even by a mutant that lets a write through.
    from glorfindel.actions import AzureConnector

    def no_azure(self):
        raise RuntimeError("no Azure client in tests (G2)")
    monkeypatch.setattr(AzureConnector, "_ensure_clients", no_azure)


@pytest.fixture()
def notified(monkeypatch):
    """Every 'done' notification of an autonomous action (store_cycle)."""
    sent: list[dict] = []
    import glorfindel.escalations as escalations
    monkeypatch.setattr(escalations, "notify_action", lambda **kw: sent.append(kw))
    return sent


def _llm(action: str, confidence: float = 0.95):
    """A LiteLLM response calling security_decision with a confident action."""
    call = MagicMock()
    call.function.arguments = json.dumps({
        "reasoning": f"Threat confirmed — {action}.", "confidence": confidence,
        "action": action, "reversible": True, "explanation": f"{action} recommended.",
        "escalate": False, "escalation_reason": "", "suggested_steps": [],
    })
    resp = MagicMock()
    resp.choices[0].message.tool_calls = [call]
    resp.usage = None
    return resp


def _ransomware() -> dict:
    """A RulePoller detection: disk writes far above the curated threshold."""
    return {
        "signal_id": "rule-ransomware-disk-write-0000g2g2",
        "event": "detection",
        "ttp": "T1486",
        "severity": "high",
        "resource_id": RID,
        "resource_type": "vm",
        "timestamp": "2026-10-21T10:00:00+00:00",
        "context": {"workspace_id": "ws-g2", "rule_name": "ransomware-disk-write",
                    "run_id": "watch-ransomware-disk-write-20261021T100000Z",
                    "attribution": "asset"},
        "raw_signal": {"first_result_row": {"Computer": "vm-g2", "_ResourceId": RID,
                                            "MaxWrite": 147000000}},
    }


def _agent(connector, *, autonomy=None, mode=None, gate="ready"):
    """The production agent, actions real (dry_run=False) against `connector`.
    gate="ready": the VM's readiness allows its configured mode; gate="real": the
    production readiness gate (reads Azure through the connector)."""
    from glorfindel.agent import GlorfindelAgent
    readiness_gate = (lambda vm, rid, configured: (configured, {})) if gate == "ready" else True
    return GlorfindelAgent(connector=connector, memory_path="unused", incidents_path="incidents.jsonl",
                           model="anthropic/claude-test", dry_run=False, autonomy=autonomy,
                           autonomy_default=mode, readiness_gate=readiness_gate)


def _respond(agent, signal, *, llm, law: LogAnalytics | None = None):
    law = law or LogAnalytics(fail=False)
    side = {"side_effect": llm} if isinstance(llm, BaseException) else {"return_value": llm}
    with patch("litellm.completion", **side), \
            patch("glorfindel.detectors.detector_for", return_value=law):
        return agent.respond(signal)


def _cards() -> list[dict]:
    from glorfindel import escalations
    return escalations.pending()


def _debug() -> list[dict]:
    path = Path("runs") / "watch-ransomware-disk-write-20261021T100000Z_debug.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def _assert_closed(final, connector, notified, card_type):
    """Fails closed: nothing written, nothing announced done, one card of this type."""
    assert connector.writes() == [], f"a write was attempted: {connector.calls}"
    assert notified == []
    assert final["outcome"]["executed"] is False
    assert [c["escalation_type"] for c in _cards()] == [card_type]


# ── Positive control ──────────────────────────────────────────────────────────

def test_control_with_every_dependency_up_the_isolation_runs(notified):
    """The same set-up executes when nothing fails: the closed results below are the
    failures' doing, not the harness's."""
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"))
    assert conn.writes() == ["isolate_vm"]
    assert final["outcome"]["executed"] is True and final["outcome"]["verified"] is True
    assert [n["action"] for n in notified] == ["isolate_vm"]
    assert _cards() == []


# ── 1. The model ──────────────────────────────────────────────────────────────

def test_model_down_fails_closed_as_cycle_failed(notified):
    """Provider unreachable after the retries: the detection becomes a card, the debug
    line says why, nothing runs."""
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=ConnectionError("api.anthropic.com unreachable"))
    _assert_closed(final, conn, notified, "cycle_failed")
    assert "unreachable" in _debug()[-1]["cycle_error"]


def test_model_answering_without_a_decision_fails_closed(notified):
    """A model that answers but calls no tool: no decision, a card, nothing runs."""
    resp = MagicMock()
    resp.choices[0].message.tool_calls = None
    resp.usage = None
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=resp)
    assert conn.writes() == [] and notified == [] and final["outcome"]["executed"] is False
    assert len(_cards()) == 1


def test_every_decision_call_is_bounded(monkeypatch):
    """A provider that hangs: LiteLLM's own default is 6000 s an attempt (three with the
    retries) — the VM's queue held for hours, no card. The call carries its bound."""
    import litellm
    from glorfindel.agent import decide
    from tests.unit.test_agent_nodes import _state
    seen = []

    def completion(**kw):
        assert "timeout" in kw, "the decision call passes no bound: LiteLLM's default applies"
        seen.append(kw["timeout"])
        raise litellm.Timeout("timed out", model="x", llm_provider="anthropic")
    with patch("litellm.completion", side_effect=completion):
        out = decide(_state(), model="anthropic/claude-test", autonomy=AutonomyConfig("non_disruptive"))
    assert seen == [120.0], seen                   # GLORFINDEL_LLM_TIMEOUT_S unset: 120 s
    assert out["escalate"] is True and out["action"] == "" and out["cycle_error"]


@pytest.mark.parametrize("raw, expected", [
    ("", 120.0), ("30", 30.0), ("abc", 120.0), ("0", 120.0), ("-5", 120.0),
    ("inf", 120.0), ("nan", 120.0), ("86400", 120.0),
])
def test_the_llm_bound_never_unbounds_on_a_malformed_value(monkeypatch, raw, expected):
    from glorfindel.config import llm_timeout_s
    monkeypatch.setenv("GLORFINDEL_LLM_TIMEOUT_S", raw)
    assert llm_timeout_s() == expected


def test_the_rule_authoring_call_is_bounded_too(monkeypatch):
    """propose_detection_rule runs in the VM's queue on a detection_missed: bounded too."""
    from glorfindel import detection_authoring
    seen = []

    def completion(**kw):
        seen.append(kw.get("timeout"))
        raise TimeoutError("hung")
    with patch("litellm.completion", side_effect=completion), pytest.raises(TimeoutError):
        detection_authoring.author_rule(
            model="anthropic/claude-test", ttp="T1486", source="azure_monitor",
            workspace_id="ws-g2", resource_id=RID)
    assert seen and all(t is not None and 0 < t <= 3600 for t in seen)


# ── 2. The cloud API ──────────────────────────────────────────────────────────

def test_cloud_down_during_the_readiness_check_holds_the_vm(notified):
    """A VM configured autonomous, never checked, and Azure unreachable: the check
    can't conclude → the VM stays in human_only. It used to be the gap a VM acts
    alone through when its check never landed."""
    conn = Recorder(outage=True)
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive"), gate="real"),
                     _ransomware(), llm=_llm("isolate_vm"))
    _assert_closed(final, conn, notified, "mode_hold")
    assert "check_permissions" in conn.calls            # the check was tried, and failed
    assert final["autonomy_mode"] == "human_only"
    assert final["autonomy_gate"]["reason"] == "not_checked"


def test_cloud_control_the_readiness_check_with_azure_up_concludes(notified):
    """The same VM, the same production gate, Azure up: the check concludes (it reads the
    rights, the OS and the NSGs) and the isolation runs — the hold above is the outage's
    doing, not a check that could never conclude."""
    from glorfindel import readiness
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive"), gate="real"),
                     _ransomware(), llm=_llm("isolate_vm"))
    assert {"check_permissions", "vm_os", "check_nsg_access"} <= set(conn.calls)
    assert readiness.get(RID)["verdict"] == "ready"
    assert (final.get("autonomy_gate") or {}).get("reason") != "not_checked"
    assert final["autonomy_mode"] == "non_disruptive"
    assert conn.writes() == ["isolate_vm"] and [n["action"] for n in notified] == ["isolate_vm"]


def test_cloud_down_at_execution_is_an_action_failed_card(notified):
    """The VM is ready, the isolation is tried and Azure fails: a card that says it
    failed, nothing announced done, nothing verified."""
    conn = Recorder(outage=True)
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"))
    assert conn.calls == ["isolate_vm"]                  # tried once, never "verified"
    assert notified == [] and final["outcome"]["executed"] is False
    assert [c["escalation_type"] for c in _cards()] == ["action_failed"]
    assert "unreachable" in _cards()[0]["reason"]


def test_cloud_down_during_the_verification_claims_nothing(notified):
    """Isolated, then the read-back fails: not a success — a card with the action kept."""
    conn = Recorder()

    def verify_down(resource_id):
        conn.calls.append("verify_isolation")
        raise ConnectionError("management.azure.com unreachable")
    conn.verify_isolation = verify_down
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"))
    assert conn.writes() == ["isolate_vm"] and notified == []
    assert final["outcome"]["executed"] is True and final["outcome"].get("unverified")
    assert [c["escalation_type"] for c in _cards()] == ["verification_failed"]


# ── 3. The telemetry ──────────────────────────────────────────────────────────

def test_telemetry_down_during_the_investigation_holds_the_isolation(notified):
    """Log Analytics refuses the investigative queries: the model read them as empty —
    no backup agent, no reboot — and those absences argue for isolating. Held."""
    conn = Recorder()
    law = LogAnalytics(fail=True)
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"), law=law)
    assert law.queries == 3
    _assert_closed(final, conn, notified, "telemetry_gap")
    assert final["telemetry_gaps"] == ["top_write_processes", "backup_agent_check", "heartbeat_gap"]
    assert "Télémétrie incomplète" in _cards()[0]["reason"]
    assert _debug()[-1]["telemetry_gaps"] == final["telemetry_gaps"]


def test_telemetry_down_is_named_on_a_card_an_earlier_gate_held(notified):
    """Low confidence holds the isolation first: the card is `low_confidence`, and its
    reason now says the investigative queries failed — the operator approving it in one
    click must know the evidence around the detection was never read."""
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm", confidence=0.5),
                     law=LogAnalytics(fail=True))
    _assert_closed(final, conn, notified, "low_confidence")
    reason = _cards()[0]["reason"]
    assert reason.startswith("Low confidence (50%)")
    assert "Télémétrie incomplète" in reason and "backup_agent_check" in reason


def test_telemetry_control_no_mention_when_the_queries_succeed(notified):
    conn = Recorder()
    _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
             _ransomware(), llm=_llm("isolate_vm", confidence=0.5), law=LogAnalytics(fail=False))
    assert "Télémétrie" not in _cards()[0]["reason"]


def test_telemetry_control_empty_queries_that_succeed_let_it_run(notified):
    """Empty but successful queries are an answer: the isolation runs (the guard reads
    failures, not absences)."""
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"), law=LogAnalytics(fail=False))
    assert conn.writes() == ["isolate_vm"] and final["telemetry_gaps"] == []


def test_telemetry_down_leaves_a_snapshot_autonomous(notified):
    """A snapshot disrupts nothing: it still runs with the telemetry incomplete."""
    conn = Recorder()
    with patch("glorfindel.agent._backup_vault_target", return_value=("rsv-g2", "rg")), \
            patch("glorfindel.jobs.record_snapshot_job"):
        _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                 _ransomware(), llm=_llm("snapshot"), law=LogAnalytics(fail=True))
    assert conn.writes() == ["snapshot"]


def test_what_the_model_sees_is_unchanged_by_a_failed_query():
    """The failure is kept apart from the signal: the model's input is the same for a
    query that failed and one that found nothing (no end-to-end run required)."""
    from glorfindel.agent import _build_user_message, investigate
    from tests.unit.test_agent_nodes import _inv_state
    seen = {}
    for fail in (True, False):
        state = _inv_state(first_row={"Computer": "vm-g2", "MaxWrite": 147000000})
        with patch("glorfindel.detectors.detector_for", return_value=LogAnalytics(fail=fail)):
            out = investigate(state)
        seen[fail] = (_build_user_message(out["signal"], []), out["telemetry_gaps"])
    assert seen[True][0] == seen[False][0]
    assert seen[True][1] and not seen[False][1]


def test_a_telemetry_gap_card_can_be_approved_in_one_click():
    """Held, not refused: the operator who re-ran the queries approves it like a
    low-confidence card."""
    api = pytest.importorskip("eregion_console.api")
    assert "telemetry_gap" in api._APPROVABLE_TYPES


# ── 4. The configuration ──────────────────────────────────────────────────────

def _broken_config(monkeypatch, tmp_path):
    import glorfindel.config as config
    path = tmp_path / "glorfindel-config.yaml"
    path.write_text("autonomy:\n  default: human_only\n  assets:\n    - match: vm-g2\n      mode: [unclosed\n")
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [path])
    with pytest.raises(config.ConfigError):
        config.load_glorfindel_config()


def test_unreadable_config_runs_every_vm_in_human_only_even_with_mode(monkeypatch, tmp_path, notified):
    """`watch --mode non_disruptive` over an unreadable glorfindel-config.yaml: the
    per-asset rules (this VM pinned human_only) are lost with the file, and the session
    mode used to make every VM autonomous. Now: human_only, and the card says why."""
    _broken_config(monkeypatch, tmp_path)
    conn = Recorder()
    final = _respond(_agent(conn, mode="non_disruptive"), _ransomware(), llm=_llm("isolate_vm"))
    _assert_closed(final, conn, notified, "mode_hold")
    assert final["autonomy_mode"] == "human_only"
    assert final["autonomy_gate"]["reason"] == "config_unreadable"
    reason = _cards()[0]["reason"]
    assert "illisible" in reason and "`--mode non_disruptive` de la session ignoré" in reason
    assert "Réponse autonome configurée" not in reason


def test_unreadable_config_without_mode_says_the_mode_is_unknown(monkeypatch, tmp_path, notified):
    """No --mode: the card used to read « Réponse autonome configurée (inconnu) » — nothing
    was configured autonomous, the file just can't be read. It says that now."""
    _broken_config(monkeypatch, tmp_path)
    conn = Recorder()
    final = _respond(_agent(conn), _ransomware(), llm=_llm("isolate_vm"))
    _assert_closed(final, conn, notified, "mode_hold")
    reason = _cards()[0]["reason"]
    assert "mode configuré de la VM inconnu" in reason and "--mode" in reason
    assert "inconnu)" not in reason and "ignoré" not in reason


def test_the_watch_banner_says_unreadable_config_not_the_session_mode(monkeypatch, tmp_path):
    """`watch --mode non_disruptive` over an unreadable config printed
    `default = non_disruptive` while every VM ran in human_only."""
    _broken_config(monkeypatch, tmp_path)
    from glorfindel.agent import GlorfindelAgent
    agent = GlorfindelAgent(connector=Recorder(), memory_path="unused", model="anthropic/claude-test",
                            dry_run=True, autonomy_default="non_disruptive")
    assert agent.config_error and agent.autonomy.default == "human_only"


def test_config_control_a_readable_config_with_mode_runs(monkeypatch, tmp_path, notified):
    import glorfindel.config as config
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [tmp_path / "absent.yaml"])
    conn = Recorder()
    final = _respond(_agent(conn, mode="non_disruptive"), _ransomware(), llm=_llm("isolate_vm"))
    assert conn.writes() == ["isolate_vm"] and final["autonomy_mode"] == "non_disruptive"


@pytest.mark.parametrize("raw", ["abc", "nan", "-1", "1.5", "O.95", "inf"])
def test_a_malformed_confidence_threshold_holds_every_autonomous_action(monkeypatch, raw, notified):
    """A threshold that can't be read used to fall back to 0.7 (laxer than the 0.95
    mistyped "O.95"), and `nan` parsed: `confidence < nan` is never true, the gate let
    everything through. Now every autonomous action is held until it is fixed."""
    monkeypatch.setenv("GLORFINDEL_CONFIDENCE_THRESHOLD", raw)
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm", confidence=0.99))
    _assert_closed(final, conn, notified, "low_confidence")
    assert "Seuil de confiance invalide" in _cards()[0]["reason"]


@pytest.mark.parametrize("raw, expected", [("", 0.7), ("0.9", 0.9), ("0", 0.0), ("1", 1.0)])
def test_a_valid_or_unset_threshold_reads_as_written(monkeypatch, raw, expected):
    from glorfindel.agent import _confidence_threshold
    from glorfindel.config import confidence_threshold
    monkeypatch.setenv("GLORFINDEL_CONFIDENCE_THRESHOLD", raw)
    assert _confidence_threshold() == expected == confidence_threshold()


def test_a_nan_confidence_from_the_model_is_held(notified):
    """`_parse_decision` takes the model's NaN as it comes (JSON `NaN` parses): the gate
    reads `not confidence >= threshold`, which holds it — `confidence < threshold` was
    never true for a NaN and let the isolation through."""
    conn = Recorder()
    final = _respond(_agent(conn, autonomy=AutonomyConfig(default="non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm", confidence=math.nan))
    _assert_closed(final, conn, notified, "low_confidence")
    assert final["held_by"] == "confidence"


@pytest.mark.parametrize("raw, bounded", [(5.0, 1.0), (85, 1.0), (math.inf, 1.0),
                                          (-0.4, 0.0), (-math.inf, 0.0), (0.42, 0.42)])
def test_the_model_confidence_is_bounded_to_0_1(raw, bounded):
    """A 5.0 read as 500 % on the card and in the memory; it is 100 % now, and a negative
    one 0 %. What the model sees is unchanged: this is its answer, read after."""
    from glorfindel.agent import _parse_decision
    d, _raw = _parse_decision(_llm("isolate_vm", confidence=raw))
    assert d["confidence"] == bounded


def test_a_bounded_confidence_shows_as_100_percent_on_the_card(monkeypatch, notified):
    """End to end: a 5.0 held by the mode reads 100 % on its card, not 500 %."""
    conn = Recorder()
    _respond(_agent(conn, autonomy=AutonomyConfig(default="human_only")),
             _ransomware(), llm=_llm("isolate_vm", confidence=5.0))
    assert conn.writes() == []
    reason = _cards()[0]["reason"]
    assert "100%" in reason and "500%" not in reason


@pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", "y", "enabled", " 1 "])
def test_a_read_only_switch_set_any_way_keeps_glorfindel_read_only(monkeypatch, raw):
    """The connector accepted 1/true/yes and the War Room 1/true/True: `on`, `TRUE`, `y`
    left the writes on — the observe-only deployment, silently not one."""
    from glorfindel.actions import AzureConnector
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", raw)
    assert AzureConnector(dry_run=False).read_only is True
    api = pytest.importorskip("eregion_console.api")
    assert api._read_only() is True


@pytest.mark.parametrize("raw", ["", "0", "false", "FALSE", "no", "off", "n"])
def test_a_read_only_switch_clearly_off_lets_the_writes_on(monkeypatch, raw):
    from glorfindel.actions import AzureConnector
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", raw)
    assert AzureConnector(dry_run=False).read_only is False


def test_a_read_only_switch_set_to_on_blocks_the_isolation(monkeypatch, notified):
    """End to end on the real connector: `GLORFINDEL_READ_ONLY=on`, the VM ready, the
    model sure — the write is refused before Azure, a write_blocked card."""
    from glorfindel.actions import AzureConnector
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", "on")
    final = _respond(_agent(AzureConnector(dry_run=False), autonomy=AutonomyConfig("non_disruptive")),
                     _ransomware(), llm=_llm("isolate_vm"))
    assert notified == [] and final["outcome"]["executed"] is False
    assert [c["escalation_type"] for c in _cards()] == ["write_blocked"]


@pytest.mark.parametrize("raw, expected", [
    ("", 2.0), ("4", 4.0), ("abc", 2.0), ("nan", 2.0), ("inf", 2.0), ("-1", -1.0), ("0", 0.0),
    ("-inf", -math.inf),
])
def test_the_approval_age_limit_never_lifts_on_a_malformed_value(monkeypatch, raw, expected):
    """`nan` and `inf` parsed: `age > nan` is never true, a card of any age could be
    executed from the War Room — both read 2 h. Zero or negative is kept as written: it
    closes one-click approval (below), it is not lifted to 2 h."""
    api = pytest.importorskip("eregion_console.api")
    monkeypatch.setenv("GLORFINDEL_APPROVAL_MAX_AGE_H", raw)
    assert api._approval_max_age_h() == expected
    assert not math.isnan(api._approval_max_age_h()) and api._approval_max_age_h() != math.inf


def _fresh_card(minutes_ago: float = 1) -> dict:
    from datetime import datetime, timedelta, timezone
    seen = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    return {"id": "c1", "escalation_type": "low_confidence", "last_seen": seen}


@pytest.mark.parametrize("raw", ["0", "-1", "-inf"])
def test_an_approval_age_limit_of_zero_or_less_refuses_every_card(monkeypatch, raw):
    """Before G2, 0 or -1 refused every one-click approval (`age > 0`): closed on purpose.
    G2 brought them back to 2 h, reopening them. Closed again — a card dated a little
    ahead of this clock included (its age is negative)."""
    api = pytest.importorskip("eregion_console.api")
    monkeypatch.setenv("GLORFINDEL_APPROVAL_MAX_AGE_H", raw)
    for card in (_fresh_card(1), _fresh_card(-5)):
        refusal = api._approval_refusal(card, "vm-g2")
        assert refusal and "fermée" in refusal, refusal


def test_approval_control_a_fresh_card_is_approvable_by_default(monkeypatch):
    api = pytest.importorskip("eregion_console.api")
    assert api._approval_refusal(_fresh_card(1), "vm-g2") is None


# ── The War Room reads the gate without the agent (G2 review) ─────────────────

@pytest.mark.parametrize("raw, shown", [("", 0.7), ("0.9", 0.9), ("abc", 1.0)])
def test_the_war_room_shows_the_threshold_even_when_the_agent_cannot_load(monkeypatch, raw, shown):
    """/api/state read the threshold from glorfindel.agent: an import that failed there
    (a model dependency missing in the War Room's image) dropped the whole capability
    matrix, silently. It reads config now."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import sys
    from .console_client import console
    import eregion_console.api  # noqa: F401  (imported before the agent cannot be)
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    monkeypatch.setenv("GLORFINDEL_CONFIDENCE_THRESHOLD", raw)
    monkeypatch.setitem(sys.modules, "glorfindel.agent", None)     # import fails
    with pytest.raises(ImportError):
        import glorfindel.agent  # noqa: F401
    capability = console().get("/api/state").json()["capability"]
    assert capability, "the capability matrix vanished with the agent's import"
    assert capability["confidence_threshold"] == shown
    assert "isolate_vm" in capability["autonomous_actions"]


# ── The containers get the switches (G2 review) ───────────────────────────────

def test_the_g2_switches_reach_the_containers(monkeypatch):
    """docker compose passes an explicit list (`x-env`): a switch set in .envrc but
    missing from it is ignored by `make glorfindel-start` and the hosted watch. Each is
    passed empty when unset — and empty is its reader's default."""
    import yaml
    from glorfindel.config import confidence_threshold, llm_timeout_s, read_only_requested
    compose = yaml.safe_load(
        (Path(__file__).resolve().parents[2] / "docker-compose.yml").read_text(encoding="utf-8"))
    switches = ("GLORFINDEL_CONFIDENCE_THRESHOLD", "GLORFINDEL_LLM_TIMEOUT_S",
                "GLORFINDEL_APPROVAL_MAX_AGE_H", "GLORFINDEL_READ_ONLY")
    for var in switches:
        assert compose["x-env"].get(var) == "${%s:-}" % var, var
        monkeypatch.setenv(var, "")
    api = pytest.importorskip("eregion_console.api")
    assert (confidence_threshold(), llm_timeout_s(), api._approval_max_age_h(),
            read_only_requested()) == (0.7, 120.0, 2.0, False)
    for service in ("watch", "bot", "war-room"):
        env = compose["services"][service]["environment"]
        assert all(var in env for var in switches), service
