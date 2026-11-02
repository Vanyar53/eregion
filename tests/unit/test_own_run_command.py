"""SID1 (#409): Glorfindel's own identity watched — a Run Command under its identity outside
the session drain of an isolation it decided on that VM is a critical card.

A fake AzureActivity (rows shaped like the table's) handed to the real AzureActivityDetector
through its parent's query, and the real isolation states in a throwaway HOME (no Azure, no
LLM). What is held:
  - during an isolation, its drain's Run Command → nothing (one drain, one operation; the drain
    remembered after the release, forgotten by a restart);
  - outside an isolation, or outside its drain → a critical card that says why;
  - an unreadable state, an unreadable time, its identity unknown → a card (A0);
  - another identity → not this rule's; the AL1 rules unchanged;
  - decided by the code: no model, no action on the VM, never one click;
  - `isolate_vm` records when its drain's Run Command was asked.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import glorfindel.detection_rules as dr
from glorfindel.detection_rules import RulePoller, load_config
from glorfindel.detectors import AzureActivityDetector
from glorfindel.providers.azure import activity, own_run_command as orc
from glorfindel.providers.azure.monitor import AzureMonitorDetector

SHIPPED = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
RULE = "run-command-by-glorfindel-outside-isolation"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
VM1 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm1"
VM2 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm2"
NSG = f"{SUB}/resourcegroups/rg-bench/providers/microsoft.network/networksecuritygroups/nsg-web"
# Placeholders, never real ids.
OWN_APP = "a1111111-b111-c111-d111-e11111111111"
OWN_OID = "a2222222-b222-c222-d222-e22222222222"
OUTSIDER = "someone@example.org"
RUN_OP = "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
DRAIN = datetime(2026, 11, 2, 10, 0, 0, tzinfo=timezone.utc)


def _at(seconds: float) -> str:
    return (DRAIN + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _run(vm=VM1, caller=OWN_OID, after=30.0, corr="c-run", scoped=True, **extra):
    """A Run Command row of the shipped rule: started `after` seconds after the drain."""
    row = {"TimeGenerated": _at(after + 40), "Started": _at(after), "OperationNameValue": RUN_OP,
           "ActivityStatusValue": "Success", "Caller": caller, "CallerIpAddress": "198.51.100.4",
           "CallerAppId": "", "CallerObjectId": caller if caller != OUTSIDER else "",
           "_ResourceId": vm.lower(), "ResourceGroup": "rg-bench", "CorrelationId": corr}
    if scoped:
        row["WatchedCaller"] = "glorfindel"
    row.update(extra)
    return row


def _isolated(vm=VM1, drains=(DRAIN.isoformat(),), raw=None):
    """Glorfindel's isolation state of `vm`, with the drains it recorded."""
    import glorfindel.actions as actions
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    name = vm.rsplit("/", 1)[-1]
    f = d / f"{name}.json"
    if raw is not None:
        f.write_text(raw)
    else:
        f.write_text(json.dumps({"resource_id": vm, "placements": [], "drains_at": list(drains)}))
    return f


def _jwt(claims: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


class _Credential:
    def __init__(self, claims=None, error=None):
        self.claims, self.error = claims or {}, error

    def get_token(self, _scope):
        if self.error:
            raise self.error
        return SimpleNamespace(token=_jwt(self.claims))


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)


@pytest.fixture()
def law(monkeypatch):
    state = {"rows": []}
    monkeypatch.setattr(AzureMonitorDetector, "run_query",
                        lambda self, query, timespan=None: [dict(r) for r in state["rows"]])
    return state


def _detector(claims=None, error=None):
    return AzureActivityDetector("ws-test", credential=_Credential(
        {"appid": OWN_APP, "oid": OWN_OID, "idtyp": "app"} if claims is None else claims, error))


def _cfg():
    return SimpleNamespace(monitoring_backends=[SimpleNamespace(
        name="law-bench", type="azure_monitor", workspace_id="ws-test", endpoint="")])


def _shipped(name=RULE):
    return next(r for r in load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False).rules
                if r.name == name)


class _Registry:
    def __init__(self, *rids):
        self.assets = [SimpleNamespace(name=r.rsplit("/", 1)[-1], resource_id=r) for r in rids]

    def for_backend(self, _name):
        return self.assets


def _poll(det, rule, rows_holder, rows, *vms):
    rows_holder["rows"] = rows
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _rule: det
    p._registry = _Registry(*(vms or (VM1, VM2)))
    p.poll_once(rule)
    return sent


def _kept(rows, own=frozenset({OWN_APP, OWN_OID})):
    return activity.prepare_rows(rows, set(own))


# ── the shipped rule ──────────────────────────────────────────────────────────

def test_the_shipped_rule_watches_run_command_by_glorfindel_on_the_activity_log():
    r = _shipped()
    assert (r.source, r.ttp, r.enabled, r.workspace_id) == ("azure_activity", "T1651", True, "ws-test")
    assert r.monitoring_backend_name == "law-bench"
    assert RUN_OP in r.query
    assert dr._query_lookback_s(r.query) >= activity.MIN_LOOKBACK_S
    # Its caller's ids, the operation's identity, when it started, and whose identity it watches.
    for col in ("CallerAppId", "CallerObjectId", "CorrelationId", "Started", "WatchedCaller"):
        assert col in r.query
    assert 'WatchedCaller = "glorfindel"' in r.query
    # A refused attempt under its identity is kept: no failure filter.
    assert "Failure" not in r.query


# ── during an isolation, outside, unreadable ─────────────────────────────────

def test_its_drain_during_an_isolation_it_recorded_is_nothing(law):
    _isolated()
    assert _kept([_run()]) == []
    assert _poll(_detector(), _shipped(), law, [_run()]) == []


def test_the_window_is_a_few_minutes_around_the_drain():
    _isolated()
    before, after = orc.DRAIN_BEFORE_S, orc.DRAIN_AFTER_S
    assert (before, after) == (120.0, 420.0)
    for i, t in enumerate((-before + 1, after - 1)):
        assert _kept([_run(after=t, corr=f"in-{i}")]) == [], t
    for i, t in enumerate((-before - 1, after + 1, 3600)):
        [row] = _kept([_run(after=t, corr=f"out-{i}")])
        assert row[orc.MARK] == "outside_drain", t


def test_outside_an_isolation_it_is_a_critical_card(law):
    """vm2: no isolation of Glorfindel recorded there. The card is critical, anchored on the
    VM, and says the identity ran a command outside an isolation."""
    _isolated()                                     # vm1 isolated, not vm2
    sent = _poll(_detector(), _shipped(), law, [_run(vm=VM2, corr="c-2")])
    assert len(sent) == 1
    sig = sent[0]
    row = sig["raw_signal"]["first_result_row"]
    assert sig["severity"] == "critical"
    assert row[orc.MARK] == "no_isolation" and row["GlorfindelIdentity"] is True
    assert sig["resource_id"].lower() == VM2.lower() and sig["context"]["plane"] == "control"
    from glorfindel.agent import _control_plane_decision
    d = _control_plane_decision(_initial(sig))
    assert "a lancé une commande sur vm2 par Run Command hors d'une isolation" in d["escalation_reason"]
    assert orc.REASONS["no_isolation"] in d["escalation_reason"]
    assert "Sévérité : critique" in d["escalation_reason"]
    assert any("runCommand" in s for s in d["suggested_steps"])
    # The generic sentence of AL1 gives way to the reason.
    assert "une opération qu'il ne fait pas" not in d["escalation_reason"]


def test_without_any_isolation_state_it_is_a_card():
    [row] = _kept([_run()])
    assert row[orc.MARK] == "no_isolation"


def test_an_isolation_without_a_drain_at_that_time_is_a_card():
    _isolated(drains=())                            # an isolation, its drain never recorded
    [row] = _kept([_run()])
    assert row[orc.MARK] == "outside_drain"


def test_an_unreadable_isolation_state_is_a_card():
    """A0: never dropped on an unknown — its drain can't be read."""
    _isolated(raw="{not json")
    [row] = _kept([_run()])
    assert row[orc.MARK] == "state_unreadable"
    assert dr._grave(row)


def test_states_that_cannot_be_read_at_all_are_a_card(monkeypatch):
    _isolated()
    import glorfindel.response.state as st
    monkeypatch.setattr(st, "active_isolations", lambda: (_ for _ in ()).throw(OSError("disk")))
    [row] = _kept([_run()])
    assert row[orc.MARK] == "state_unreadable"


def test_a_drain_time_that_cannot_be_read_attaches_nothing():
    _isolated(drains=("hier", 12))
    [row] = _kept([_run()])
    assert row[orc.MARK] == "outside_drain"


def test_an_operation_whose_time_cannot_be_read_is_a_card():
    _isolated()
    [row] = _kept([_run(Started="", TimeGenerated="?")])
    assert row[orc.MARK] == "time_unreadable"


def test_its_identity_unknown_every_run_command_of_the_rule_is_a_card(law):
    """No identity known (no token, nothing configured): a Run Command can't be told
    Glorfindel's or not — under the rule that watches it, each one is a card (A0)."""
    _isolated()
    [row] = activity.prepare_rows([_run(caller=OUTSIDER)], set())
    assert row[orc.MARK] == "identity_unknown" and row["GlorfindelIdentity"] is False
    sent = _poll(_detector(error=RuntimeError("no token")), _shipped(), law, [_run(caller=OUTSIDER)])
    assert [s["severity"] for s in sent] == ["critical"]
    from glorfindel.agent import _control_plane_decision
    assert "n'a pas pu être lue" in _control_plane_decision(_initial(sent[0]))["escalation_reason"]


def test_a_row_that_names_no_caller_is_a_card(law):
    """A0 on the caller: under the rule that watches Glorfindel, a row with no Caller, no ids
    and no Claims can't be told another's — a card, never dropped."""
    _isolated()
    blank = _run(vm=VM2, caller="", corr="c-blank", CallerObjectId="", CallerAppId="", Claims="")
    [row] = _kept([blank])
    assert row[orc.MARK] == "caller_unreadable" and dr._grave(row)
    sent = _poll(_detector(), _shipped(), law, [blank])
    assert [s["severity"] for s in sent] == ["critical"]
    from glorfindel.agent import _control_plane_decision
    assert "aucun appelant" in _control_plane_decision(_initial(sent[0]))["escalation_reason"]
    # Under a client's rule (no WatchedCaller): not this module's — the generic path keeps it.
    [kept] = _kept([{**blank, "WatchedCaller": ""}])
    assert orc.MARK not in kept


# ── another identity: not this rule's; AL1 unchanged ─────────────────────────

def test_another_identity_running_a_command_is_not_this_rules(law):
    _isolated()
    assert _kept([_run(caller=OUTSIDER, vm=VM2)]) == []
    assert _poll(_detector(), _shipped(), law, [_run(caller=OUTSIDER, vm=VM2)]) == []
    # A client's own rule on Run Command (no WatchedCaller): every caller kept, unmarked.
    [row] = _kept([_run(caller=OUTSIDER, vm=VM2, scoped=False)])
    assert orc.MARK not in row and row["GlorfindelIdentity"] is False and not dr._grave(row)


def test_the_al1_rules_are_unchanged_for_another_identity(law):
    """An outsider's write on a customer's NSG rule: the same card as before, high."""
    rule = _shipped("nsg-change-outside-glorfindel")
    row = {"TimeGenerated": "2026-11-02T10:00:00Z", "OperationNameValue":
           "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE", "ActivityStatusValue": "Success",
           "Caller": OUTSIDER, "CallerIpAddress": "203.0.113.7", "CallerAppId": "", "CallerObjectId": "",
           "_ResourceId": f"{NSG}/securityrules/allow-web", "ResourceGroup": "rg-bench", "CorrelationId": "c-n"}
    sent = _poll(_detector(), rule, law, [row])
    assert len(sent) == 1 and sent[0]["severity"] == "high"
    kept = sent[0]["raw_signal"]["first_result_row"]
    assert orc.MARK not in kept
    assert (kept["GlorfindelIdentity"], kept["GlorfindelManaged"]) == (False, False)


def test_its_run_command_under_a_client_rule_is_still_watched():
    """A client's rule on Run Command, without the column: Glorfindel's own command outside
    a drain is still marked; its drain still dropped."""
    _isolated()
    assert _kept([_run(scoped=False)]) == []
    [row] = _kept([_run(vm=VM2, scoped=False)])
    assert row[orc.MARK] == "no_isolation"


# ── one drain, one operation; remembered, forgotten ─────────────────────────

def test_one_drain_takes_one_run_command_the_second_is_a_card(law):
    _isolated()
    # Read in any order: the drain goes to the first operation after it.
    rows = [_run(after=60, corr="c-more"), _run(after=20, corr="c-drain")]
    [row] = _kept(rows)
    assert row["CorrelationId"] == "c-more" and row[orc.MARK] == "outside_drain"
    # The card names the operation that took the drain: the human reads both commands.
    assert row[orc.TAKEN_BY] == ["c-drain"]
    from glorfindel.agent import _control_plane_text
    what, _ = _control_plane_text({"raw_signal": {"first_result_row": row}, "ttp": "T1651"})
    assert "correspond déjà à l'opération c-drain" in what
    # Outside any drain's window: no operation named.
    [far] = _kept([_run(after=3600, corr="c-far")])
    assert orc.TAKEN_BY not in far
    # Across polls, the drain stays taken by its operation.
    det = _detector()
    law["rows"] = rows
    assert [r["CorrelationId"] for r in det.run_query("q")] == ["c-more"]
    assert [r["CorrelationId"] for r in det.run_query("q")] == ["c-more"]


def test_two_drains_take_two_run_commands():
    _isolated(drains=(DRAIN.isoformat(), (DRAIN + timedelta(seconds=90)).isoformat()))
    assert _kept([_run(after=20, corr="c-1"), _run(after=100, corr="c-2")]) == []


def test_a_drain_is_remembered_after_the_release_and_forgotten_by_a_restart(law):
    """The release clears the state; the drain's row lands minutes later."""
    state = _isolated()
    det = _detector()
    law["rows"] = []
    det.run_query("q")                              # a poll while the state is there
    state.unlink()
    law["rows"] = [_run()]
    assert det.run_query("q") == []
    [row] = _detector().run_query("q")              # restarted: a card
    assert row[orc.MARK] == "no_isolation"
    with patch.object(activity.time, "time", return_value=activity.time.time() + activity.RECORDED_TTL_S + 1):
        assert len(det.run_query("q")) == 1


def test_poll_alert_drops_the_drain_and_marks_what_it_keeps(monkeypatch):
    _isolated()
    rows = [_run(corr="c-drain"), _run(vm=VM2, corr="c-2")]

    def fake_poll(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        for r in rows:
            if match_row is None or match_row(r):
                return 1, r
        return None

    monkeypatch.setattr(AzureMonitorDetector, "poll_alert", fake_poll)
    _, row = _detector().poll_alert("q", since=0, timeout_s=1)
    assert row["CorrelationId"] == "c-2" and row[orc.MARK] == "no_isolation"


def test_times_as_log_analytics_writes_them():
    assert orc.epoch("2026-11-02T10:00:00.1234567Z") == pytest.approx(DRAIN.timestamp() + 0.123456)
    assert orc.epoch(DRAIN) == DRAIN.timestamp()
    assert orc.epoch(DRAIN.replace(tzinfo=None)) == DRAIN.timestamp()
    assert orc.epoch("") is None and orc.epoch(None) is None and orc.epoch("x") is None
    # No `Started`: the row's own time.
    assert orc.started({"TimeGenerated": DRAIN}) == DRAIN.timestamp()


def test_the_summary_card_says_a_run_command_was_among_its_operations():
    rest = [{"OperationNameValue": "X", "Caller": OUTSIDER, "_ResourceId": NSG},
            {**_run(), orc.MARK: "no_isolation", "GlorfindelIdentity": True}]
    summary = dr._control_plane_summary(rest)
    assert summary[orc.MARK] == "no_isolation" and dr._grave(summary)
    assert summary["OmittedOperations"][1][orc.MARK] == "no_isolation"
    from glorfindel.agent import _control_plane_text
    what, _ = _control_plane_text({"raw_signal": {"first_result_row": summary}, "ttp": "T1651"})
    assert "Run Command hors d'une isolation" in what


# ── decided by the code: nothing acts on the VM ───────────────────────────────

def _llm(action, confidence=0.99):
    tool_call = MagicMock()
    tool_call.function.arguments = json.dumps({
        "reasoning": "x", "confidence": confidence, "action": action, "reversible": True,
        "explanation": "x", "escalate": False, "escalation_reason": "", "suggested_steps": []})
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(tool_calls=[tool_call]))]
    return resp


def _initial(signal):
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": False,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None}


@pytest.mark.parametrize("action", ["isolate_vm", "block_suspicious_ip", "snapshot"])
def test_the_card_acts_on_nothing_the_vm_included(tmp_path, monkeypatch, law, action):
    """The card is anchored on the VM the command ran on, in non_disruptive: a model that
    would act at 99 % is never asked — nothing runs against the VM, no investigation, the
    escalation is `control_plane_change`, recommends no action, never approvable in one click."""
    from glorfindel import escalations
    from glorfindel.agent import _build_graph
    from glorfindel.config import AutonomyConfig
    from glorfindel.memory import CycleMemory
    import glorfindel.agent as agent
    sent = _poll(_detector(), _shipped(), law, [_run(vm=VM1)], VM1)
    assert len(sent) == 1 and sent[0]["context"]["attribution"] == "asset"
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir(exist_ok=True)
    queries: list = []
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: queries.append(q) or [])
    connector = MagicMock()
    connector.dry_run = False
    graph = _build_graph(CycleMemory(path=tmp_path / "cycles"), connector, "claude-test",
                         autonomy=AutonomyConfig(default="non_disruptive"))
    with patch("litellm.completion", return_value=_llm(action)) as llm:
        final = graph.invoke(_initial(sent[0]))
    llm.assert_not_called()
    assert queries == []
    for name in ("isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation",
                 "drain_connections", "restore_from_backup"):
        getattr(connector, name).assert_not_called()
    assert final["outcome"]["escalation_type"] == "control_plane_change"
    assert final["held_by"] == "control_plane" and final["action"] == ""
    [card] = escalations.pending()
    assert card["action"] == "" and "hors d'une isolation" in card["reason"]
    from eregion_console.api import _approval_refusal
    assert _approval_refusal(card, "vm1")


# ── isolate_vm records its drain, when its Run Command is asked ───────────────

def _isolating(monkeypatch, os_type="Linux", get_error=None, during=None):
    """isolate_vm with its real drain: the compute client faked. `during`: called while the
    drain waits for its Run Command (an Activity Log poll at that moment)."""
    from glorfindel.actions import AzureConnector
    from tests.unit.test_glorfindel import _nic_target
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target(scope="nic")])
    net = MagicMock()
    net.security_rules.list.return_value = []
    connector._network = net
    compute = MagicMock()
    compute.virtual_machines.get.return_value.storage_profile.os_disk.os_type = os_type
    if get_error:
        compute.virtual_machines.get.side_effect = get_error
    res = MagicMock()
    res.value = [MagicMock(message="Enable succeeded:\n[stdout]\nglorfindel-drain-remaining=0\n")]

    def result(timeout=None):
        if during:
            during()
        return res

    compute.virtual_machines.begin_run_command.return_value.result.side_effect = result
    connector._compute = compute
    return connector


def test_isolate_vm_records_when_its_drain_was_asked(monkeypatch):
    from glorfindel.actions import _load_isolation_state
    from tests.unit.test_glorfindel import _RID
    connector = _isolating(monkeypatch)
    before = datetime.now(timezone.utc).timestamp()
    assert connector.isolate_vm(_RID)["drain"] == {"status": "drained"}
    [at] = _load_isolation_state(_RID)["drains_at"]
    assert before - 1 <= orc.epoch(at) <= datetime.now(timezone.utc).timestamp() + 1
    # Isolated again: both drains kept.
    connector.isolate_vm(_RID)
    assert len(_load_isolation_state(_RID)["drains_at"]) == 2
    # And the activity log reads them as this VM's drains.
    book = orc.read_book()
    assert len(book.times[_RID.rstrip("/").lower()]) == 2


def test_a_row_ingested_while_the_drain_waits_is_not_a_card(monkeypatch):
    """The drain waits for its Run Command up to 300 s; its row may be ingested, and polled,
    before it returns: the drain is already noted."""
    from tests.unit.test_glorfindel import _RID
    seen: list = []

    def poll():
        now = datetime.now(timezone.utc).isoformat()
        seen.append(_kept([_run(vm=_RID, Started=now, TimeGenerated=now, corr="c-wait")]))

    _isolating(monkeypatch, during=poll).isolate_vm(_RID)
    assert seen == [[]]


def test_no_drain_noted_where_no_command_was_asked(monkeypatch):
    """Windows (no command), or the VM unread before the call: no window opened."""
    from glorfindel.actions import _load_isolation_state
    from tests.unit.test_glorfindel import _RID
    out = _isolating(monkeypatch, os_type="Windows").isolate_vm(_RID)
    assert out["drain"]["status"] == "unsupported"
    assert "drains_at" not in _load_isolation_state(_RID)
    connector = _isolating(monkeypatch, get_error=RuntimeError("(ResourceNotFound) vm"))
    assert connector.isolate_vm(_RID)["drain"]["status"] == "failed"
    assert "drains_at" not in _load_isolation_state(_RID)
    connector._compute.virtual_machines.begin_run_command.assert_not_called()


def test_a_drain_called_alone_notes_nothing(monkeypatch):
    from glorfindel.actions import _load_isolation_state
    from tests.unit.test_glorfindel import _RID
    connector = _isolating(monkeypatch)
    _isolated(vm=_RID, drains=())
    assert connector.drain_connections(_RID) == {"status": "drained"}
    assert _load_isolation_state(_RID)["drains_at"] == []


def test_the_drains_kept_are_bounded():
    from glorfindel.providers.azure.isolation import _drains_at
    prev = {"drains_at": [f"t{i}" for i in range(orc.DRAINS_KEPT)] + [3]}
    out = _drains_at(prev, "now")["drains_at"]
    assert len(out) == orc.DRAINS_KEPT and out[-1] == "now" and 3 not in out
    assert _drains_at({"drains_at": "x"}, "now") == {"drains_at": ["now"]}
