"""C2 (#199), the defensive half: Entra ID's logs as a detection source — detection only.

Fake Entra logs: rows shaped like what the shipped rules project from AuditLogs and
AADServicePrincipalSignInLogs (EntraKind, EntraOperation, EventId, Actor*, Target*…), handed
to the real AzureEntraDetector through its parent's query (no Azure, no LLM). What is held:
  - each of the four rules — a credential added (T1098.001), a consent (T1528), a privileged
    directory role (T1098.003), an unusual sign-in of a service principal (T1078.004) —
    detects, and escalates `identity_change` with its steps (who, what, how to revoke), the
    model never called, no action run, no investigation, no incident, nothing in the
    decision memory;
  - no UPN reaches the model's provider: not on the identity cycle, not later through the
    memory a data-plane decision reads;
  - two locks, each measured: `decide` builds the decision (no model), and the route after
    `decide` never sends an identity detection to an action;
  - the thresholds in code: failures, a role that is not privileged, a service principal
    without history; never a row silenced for a missing column;
  - Glorfindel's identity: nothing dropped under it, actor or target marked critical — and
    no event on a customer's identity is silenced or marked by it;
  - one card per finding (EventId), capped per poll, a summary card naming the rest;
  - the Terraform proposal is disabled and reads nothing of the tenant.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import glorfindel.detection_rules as dr
from glorfindel.detection_rules import RulePoller, load_config, normalize_row
from glorfindel.detectors import (
    AzureEntraDetector,
    backend_type_of,
    detector_for,
    is_control_plane_source,
    is_identity_source,
    plane_of,
)
from glorfindel.providers.azure import entra
from glorfindel.providers.azure.monitor import AzureMonitorDetector

ROOT = Path(__file__).resolve().parents[2]
SHIPPED = ROOT / "glorfindel/rules/azure/detection_rules.yaml"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
VM1 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm1"
VM2 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm2"
# Placeholders, never real ids. Glorfindel's service principal (its token's appid and oid);
# a customer's administrator, application, service principal.
OWN_APP = "00000000-0000-0000-0000-0000000000a1"
OWN_OID = "00000000-0000-0000-0000-0000000000a2"
ADMIN_UPN = "admin@example.org"
ADMIN_OID = "00000000-0000-0000-0000-0000000000b1"
APP_OID = "00000000-0000-0000-0000-0000000000c1"
SP_OID = "00000000-0000-0000-0000-0000000000c2"
USER_OID = "00000000-0000-0000-0000-0000000000d1"

RULES = {"credential": ("entra-credential-added", "T1098.001"),
         "consent": ("entra-app-consent", "T1528"),
         "role": ("entra-privileged-role-assigned", "T1098.003"),
         "signin": ("entra-sp-unusual-signin", "T1078.004")}
# What a card's steps must say to revoke, per kind.
REVOKE = {"credential": "az ad app credential delete",
          "consent": "oauth2PermissionGrants",
          "role": "roleManagement/directory/roleAssignments",
          "signin": "az ad sp credential delete"}


def _row(kind="credential", corr="c-1", ts="2026-10-27T10:00:00Z", **extra):
    """A row as the shipped rule of `kind` projects it."""
    row = {"TimeGenerated": ts, "EntraKind": kind, "Result": "success", "CorrelationId": corr,
           "ActorName": ADMIN_UPN, "ActorId": ADMIN_OID, "ActorAppId": "", "ActorIp": "203.0.113.7"}
    if kind == "credential":
        row.update(EntraOperation="Update application – Certificates and secrets management ",
                   TargetName="app-billing", TargetId=APP_OID, TargetType="Application",
                   CredentialAdded='["[KeyIdentifier=00000000-0000-0000-0000-000000000001,'
                                   'KeyType=Password,KeyUsage=Verify,DisplayName=ci]"]')
    elif kind == "consent":
        row.update(EntraOperation="Consent to application", TargetName="app-mail-reader",
                   TargetId=SP_OID, TargetType="ServicePrincipal",
                   Permissions="Mail.Read offline_access", AdminConsent=True)
    elif kind == "role":
        row.update(EntraOperation="Add member to role", RoleName="Global Administrator",
                   TargetName="new-admin@example.org", TargetId=USER_OID, TargetType="User")
    elif kind == "signin":
        row.update(EntraOperation="Service principal sign-in", Result="success",
                   ActorName="sp-ci-deploy", ActorId=SP_OID, ActorAppId=APP_OID,
                   ActorIp="198.51.100.23", Location="FR",
                   TargetName="Windows Azure Service Management API", TargetId="",
                   SignIns=3, BaselineSignIns=420, BaselineDays=12)
    row.setdefault("EventId", f"{corr}|{row.get('TargetId') or row.get('ActorId')}")
    row.update(extra)
    if kind == "signin" and "EventId" not in extra:
        row["EventId"] = f"{row['ActorId']}|{row['ActorIp']}"
    return row


def _jwt(claims: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


class _Credential:
    def __init__(self, claims):
        self.claims = claims

    def get_token(self, _scope):
        return SimpleNamespace(token=_jwt(self.claims))


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)


@pytest.fixture()
def law(monkeypatch):
    """The workspace: what the parent detector's query returns."""
    state = {"rows": [], "queries": []}

    def run_query(self, query, timespan=None):
        state["queries"].append(query)
        return list(state["rows"])
    monkeypatch.setattr(AzureMonitorDetector, "run_query", run_query)
    return state


def _detector(claims=None):
    return AzureEntraDetector("ws-test", credential=_Credential(
        {"appid": OWN_APP, "oid": OWN_OID} if claims is None else claims))


def _cfg():
    return SimpleNamespace(monitoring_backends=[SimpleNamespace(
        name="law-bench", type="azure_monitor", workspace_id="ws-test", endpoint="")])


def _loaded():
    return load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False)


def _shipped(name):
    return next(r for r in _loaded().rules if r.name == name)


class _Registry:
    def __init__(self, *rids):
        self.assets = [SimpleNamespace(name=r.rsplit("/", 1)[-1], resource_id=r) for r in rids]

    def for_backend(self, _name):
        return self.assets


def _poller(det, rule, *vms):
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _rule: det
    p._registry = _Registry(*(vms or (VM1, VM2)))
    return p, sent


class _Memory:
    """The decision memory, in a list: what is stored is what a later cycle retrieves."""
    def __init__(self):
        self.cycles: list[dict] = []

    def store(self, cycle):
        self.cycles.append(cycle)

    def retrieve_similar(self, signal, n=3):
        return [{"summary": json.dumps(c, ensure_ascii=False)} for c in self.cycles[-n:]]

    def count(self):
        return len(self.cycles)


def _llm(action, confidence=0.99):
    tool_call = MagicMock()
    tool_call.function.arguments = json.dumps({
        "reasoning": "x", "confidence": confidence, "action": action, "reversible": True,
        "explanation": "x", "escalate": False, "escalation_reason": "", "suggested_steps": []})
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(tool_calls=[tool_call]))]
    return resp


def _graph(tmp_path, monkeypatch, connector, queries=None, memory=None, incidents=None):
    from glorfindel.agent import _build_graph
    from glorfindel.config import AutonomyConfig
    import glorfindel.agent as agent
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir(exist_ok=True)
    asked = queries if queries is not None else []
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: asked.append(q) or [])
    return _build_graph(memory if memory is not None else _Memory(), connector, "claude-test",
                        incidents=incidents, autonomy=AutonomyConfig(default="non_disruptive"))


def _initial(signal):
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": False,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None}


def _signal(kind="credential", **ctx):
    row = entra.prepare_rows([_row(kind)], {OWN_APP, OWN_OID})[0]
    return {"event": "detection", "ttp": RULES[kind][1], "resource_id": VM1, "severity": "high",
            "context": {"plane": "identity", "attribution": "unattributed", **ctx},
            "raw_signal": {"detection_source": "azure_entra", "first_result_row": row,
                           "normalized_signal": normalize_row(row)}}


# ── the source, and the shipped rules ─────────────────────────────────────────

def test_entra_is_an_identity_source_read_from_the_monitor_workspace():
    assert is_identity_source("azure_entra") and plane_of("azure_entra") == "identity"
    assert not is_control_plane_source("azure_entra")
    assert not is_identity_source("azure_activity") and not is_identity_source("azure_monitor")
    assert plane_of("azure_monitor") == "data" and plane_of("nope") == "data"
    assert backend_type_of("azure_entra") == "azure_monitor"
    assert isinstance(detector_for("azure_entra", workspace_id="ws"), AzureEntraDetector)


def test_the_four_shipped_rules_load_bound_to_the_workspace_and_say_nothing():
    cfg = _loaded()
    rules = {r.name: r for r in cfg.rules if r.source == "azure_entra"}
    assert {(n, r.ttp) for n, r in rules.items()} == set(RULES.values())
    for r in rules.values():
        assert r.enabled and r.workspace_id == "ws-test"
        assert dr._query_lookback_s(r.query) >= entra.MIN_LOOKBACK_S
        assert "EventId" in r.query and "EntraKind" in r.query and "EntraOperation" in r.query
    assert not [n for n in cfg.notes if "entra-" in n]


def test_each_rule_keeps_successes_only_and_the_signin_baseline_leaves_the_last_hour_out():
    for kind, (name, _ttp) in RULES.items():
        q = _shipped(name).query
        assert f'EntraKind = "{kind}"' in q
        assert ('Result =~ "success"' in q) if kind != "signin" else ('ResultType == "0"' in q)
    signin = _shipped("entra-sp-unusual-signin").query
    assert "between (ago(14d) .. ago(1h))" in signin and "leftanti" in signin
    assert "join kind=inner history" in signin                  # no history, no row
    role = _shipped("entra-privileged-role-assigned").query
    assert '!has "PIM activation"' in role                       # its eligible assignment had its card


# ── each rule detects and escalates, never the model, never an action ─────────

@pytest.mark.parametrize("kind", list(RULES))
def test_each_rule_detects_and_escalates_with_its_steps_without_model_or_action(
        tmp_path, monkeypatch, law, kind):
    """Fini quand (partie code) : on fake Entra logs, each rule detects and escalates with
    its steps — the model never called (a model that would isolate at 99 % in
    non_disruptive is ready), no action, no investigation, no incident, no memory."""
    from glorfindel import escalations
    from glorfindel.incidents import IncidentRegistry
    from eregion_console.api import _approval_refusal
    name, ttp = RULES[kind]
    rule = _shipped(name)
    law["rows"] = [_row(kind)]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert len(sent) == 1
    sig = sent[0]
    assert sig["ttp"] == ttp and sig["context"]["plane"] == "identity"
    assert sig["raw_signal"]["detection_source"] == "azure_entra"
    assert sig["context"]["attribution"] == "unattributed" and sig["severity"] == "high"
    connector, queries, memory = MagicMock(dry_run=False), [], _Memory()
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl")
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        final = _graph(tmp_path, monkeypatch, connector, queries, memory=memory,
                       incidents=incidents).invoke(_initial(sig))
    llm.assert_not_called()
    assert queries == []
    for action in ("isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation"):
        getattr(connector, action).assert_not_called()
    assert final["held_by"] == "identity" and final["action"] == ""
    assert final["outcome"]["escalation_type"] == "identity_change"
    assert final["incident"] is None and incidents.get_active(VM1) is None
    assert memory.count() == 0
    cards = escalations.pending()
    assert [c["escalation_type"] for c in cards] == ["identity_change"] and cards[0]["action"] == ""
    assert _approval_refusal(cards[0], "vm1")
    steps = " ".join(cards[0]["suggested_steps"])
    assert REVOKE[kind] in steps and "c-1" in steps
    reason = cards[0]["reason"]
    assert "Détection seule" in reason and "sans appel au modèle" in reason
    who = "sp-ci-deploy" if kind == "signin" else ADMIN_UPN
    assert who in reason


def test_what_each_card_says():
    from glorfindel.agent import _identity_decision
    texts = {k: _identity_decision(_initial(_signal(k)))["escalation_reason"] for k in RULES}
    assert "KeyIdentifier=00000000-0000-0000-0000-000000000001" in texts["credential"]
    assert "app-billing" in texts["credential"]
    assert "Mail.Read" in texts["consent"] and "consentement d'administrateur" in texts["consent"]
    assert "« Global Administrator »" in texts["role"] and "new-admin@example.org" in texts["role"]
    assert "198.51.100.23" in texts["signin"] and "12 jours" in texts["signin"]
    assert all("Sévérité : haute" in t for t in texts.values())


def test_no_upn_reaches_the_models_provider_nor_the_memory_it_reads(tmp_path, monkeypatch, law):
    """An identity cycle never calls the model, and is never stored in the memory a later
    data-plane decision reads (its text names a user): that decision's call to the
    provider carries no UPN. The campaign report (IA0) picks no decision without action."""
    from glorfindel.agent import decide
    from glorfindel.config import AutonomyConfig
    from analysis.campaign_report import _decision_of
    rule = _shipped("entra-privileged-role-assigned")
    law["rows"] = [_row("role")]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    memory = _Memory()
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        _graph(tmp_path, monkeypatch, MagicMock(dry_run=False), memory=memory).invoke(_initial(sent[0]))
    llm.assert_not_called()
    assert memory.count() == 0
    # A data-plane cycle on the same VM afterwards: the model is called, without a UPN.
    data = {"event": "detection", "ttp": "T1486", "resource_id": VM1, "context": {},
            "raw_signal": {"detection_source": "azure_monitor",
                           "first_result_row": {"Computer": "vm1", "MaxWrite": 9e7}}}
    state = {**_initial(data), "past_cycles": memory.retrieve_similar(data)}
    with patch("litellm.completion", return_value=_llm("snapshot")) as llm:
        decide(state, model="claude-test", autonomy=AutonomyConfig(default="non_disruptive"))
    llm.assert_called_once()
    sent_text = json.dumps([str(a) for a in llm.call_args.args] + [str(v) for v in llm.call_args.kwargs.values()])
    for upn in (ADMIN_UPN, "new-admin@example.org"):
        assert upn not in sent_text
    debug = list((tmp_path / "runs").glob("*_debug.jsonl"))
    assert debug and _decision_of(debug[0]) == {}


# ── two locks, each measured ──────────────────────────────────────────────────

def test_the_route_after_decide_never_sends_an_identity_detection_to_an_action():
    """The second lock: a decision that would act — a model reached by mistake — is sent
    to a human. A data-plane decision is unchanged."""
    from glorfindel.agent import _route_after_decide
    acting = {**_initial(_signal("credential")), "action": "isolate_vm", "escalate": False}
    assert _route_after_decide(acting) == "escalate_to_human"
    data = {**acting, "signal": {"event": "detection", "context": {},
                                 "raw_signal": {"first_result_row": {"Computer": "vm1"}}}}
    assert _route_after_decide(data) == "execute_action"


def test_past_a_decide_that_would_act_nothing_runs(tmp_path, monkeypatch, law):
    """`decide` bypassed (it returns isolate_vm at 99 %, no escalation): the route still
    sends the identity detection to a human — the connector is never called."""
    import glorfindel.agent as agent
    rule = _shipped("entra-credential-added")
    law["rows"] = [_row("credential")]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    monkeypatch.setattr(agent, "decide", lambda s, **_kw: {
        **s, "action": "isolate_vm", "confidence": 0.99, "escalate": False, "held_by": ""})
    connector = MagicMock(dry_run=False)
    final = _graph(tmp_path, monkeypatch, connector).invoke(_initial(sent[0]))
    connector.isolate_vm.assert_not_called()
    # Its card keeps its type: never one the console approves in one click.
    from glorfindel import escalations
    from eregion_console.api import _approval_refusal
    assert final["outcome"]["escalation_type"] == "identity_change"
    card = escalations.pending()[0]
    assert card["escalation_type"] == "identity_change" and _approval_refusal(card, "vm1")


def test_the_identity_decision_reads_the_plane_or_the_source():
    """Either says so, even when the row's columns say nothing (a client rule's own
    projection)."""
    from glorfindel.agent import _is_identity
    assert _is_identity({"context": {"plane": "identity"}, "raw_signal": {}})
    assert _is_identity({"context": {}, "raw_signal": {"detection_source": "azure_entra",
                                                       "first_result_row": {"Who": ADMIN_UPN}}})
    assert not _is_identity({"context": {"plane": "control"}, "raw_signal": {"detection_source": "azure_activity"}})


@pytest.mark.parametrize("raw", [
    {"detection_source": "azure_monitor", "first_result_row": _row("consent")},
    {"first_result_row": {"OperationName": "Consent to application",
                          "InitiatedBy": {"user": {"userPrincipalName": ADMIN_UPN}},
                          "TargetResources": [{"id": SP_OID}]}},
    {"detected_data": {"Type": "AADServicePrincipalSignInLogs", "IPAddress": "198.51.100.23"}},
    {"normalized_signal": {"indicator_key": "identity_operation"}},
])
def test_an_entra_row_read_by_another_source_is_still_decided_by_the_code(raw):
    """In depth: an Entra row read by a rule of another source has no plane nor its source;
    its columns, its table or its indicator say so — never the model."""
    from glorfindel.agent import _is_identity, decide
    sig = {"event": "detection", "ttp": "T1528", "resource_id": VM1, "context": {}, "raw_signal": raw}
    assert _is_identity(sig)
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        d = decide(_initial(sig), model="claude-test")
    llm.assert_not_called()
    assert d["held_by"] == "identity" and d["action"] == ""


def test_a_data_plane_row_is_not_an_identity():
    from glorfindel.agent import _is_identity
    for row in ({"Computer": "vm1", "MaxWrite": 9e7}, {"CallerIpAddress": "10.0.0.4", "AccountName": "st"},
                {"OperationNameValue": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"}):
        assert not _is_identity({"context": {}, "raw_signal": {"first_result_row": row}})


def test_respond_mode_says_the_detection_came_from_entra(monkeypatch):
    """`glorfindel respond`: an attack_started on an Entra rule's TTP carries its source;
    `decide` builds its decision without the model."""
    from glorfindel.agent import decide, resolve_attack_started
    monkeypatch.setattr(AzureEntraDetector, "own_identities", lambda self: {OWN_APP})

    def poll(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        row = _row("credential")
        return (5, row) if match_row is None or match_row(row) else None
    monkeypatch.setattr(AzureMonitorDetector, "poll_alert", poll)
    out = resolve_attack_started({"event": "attack_started", "ttp": "T1098.001",
                                  "raw_signal": {"detection_timeout_s": 1}})
    assert out["event"] == "detection" and out["raw_signal"]["detection_source"] == "azure_entra"
    assert out["raw_signal"]["detected_data"]["GlorfindelIdentity"] is False
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        d = decide(_initial(out), model="claude-test")
    llm.assert_not_called()
    assert d["held_by"] == "identity" and ADMIN_UPN in d["escalation_reason"]


# ── the thresholds, in code ───────────────────────────────────────────────────

def test_the_thresholds_failures_roles_and_history(law):
    own = {OWN_APP, OWN_OID}
    keep = [_row("role", corr="c-r1"),
            _row("role", corr="c-r2", RoleName="privileged role administrator"),   # any case
            _row("role", corr="c-r3", RoleName=""),             # name unread: never silenced
            _row("signin", BaselineDays=entra.MIN_BASELINE_DAYS),
            _row("signin", ActorIp="198.51.100.24", BaselineDays=None),   # column absent
            _row("consent", Result="")]
    drop = [_row("role", corr="c-r4", RoleName="Directory Readers"),
            _row("credential", Result="failure"),
            _row("signin", ActorIp="198.51.100.25", BaselineDays=entra.MIN_BASELINE_DAYS - 1),
            _row("signin", ActorIp="198.51.100.26", Result="failure")]
    kept = entra.prepare_rows(keep + drop, own)
    assert [r["EventId"] for r in kept] == [r["EventId"] for r in keep]
    # Through the poller: a non-privileged role dispatches nothing.
    rule = _shipped("entra-privileged-role-assigned")
    law["rows"] = [_row("role", RoleName="Directory Readers")]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert sent == []


# ── Glorfindel's identity: marked, never an excuse to silence ─────────────────

def test_no_event_on_a_customers_identity_is_silenced_or_marked_by_glorfindels(monkeypatch, law):
    """Fini quand: the exclusion of Glorfindel's identity silences no event on a customer's
    identity — with its ids known (token, AZURE_CLIENT_ID, GLORFINDEL_OWN_CALLERS), every
    customer finding of each kind is dispatched, unmarked, high. A customer application
    named after Glorfindel is a customer's: a name is no proof."""
    monkeypatch.setenv("AZURE_CLIENT_ID", OWN_APP)
    monkeypatch.setenv("GLORFINDEL_OWN_CALLERS", f"{OWN_OID},00000000-0000-0000-0000-0000000000a3")
    for kind, (name, _ttp) in RULES.items():
        rule = _shipped(name)
        law["rows"] = [_row(kind, corr=f"c-{kind}-1"),
                       _row(kind, corr=f"c-{kind}-2", ActorIp="198.51.100.30",
                            TargetName="glorfindel-sp", ActorName="glorfindel-pipeline@example.org")]
        p, sent = _poller(_detector(), rule, VM1)
        p.poll_once(rule)
        assert len(sent) == 2, kind
        for s in sent:
            row = s["raw_signal"]["first_result_row"]
            assert row["GlorfindelIdentity"] is False and row["GlorfindelManaged"] is False
            assert s["severity"] == "high"


def test_glorfindels_identity_as_actor_or_target_is_kept_critical_and_first(law):
    """Nothing is dropped under its identity: as the actor (it writes nothing in Entra ID),
    or as the target (a credential added to its service principal), critical, first."""
    from glorfindel.agent import _identity_decision
    rule = _shipped("entra-credential-added")
    law["rows"] = [_row("credential", corr="c-cust", ts="2026-10-27T10:05:00Z"),
                   _row("credential", corr="c-tgt", ts="2026-10-27T10:00:00Z",
                        TargetId=OWN_OID, TargetType="ServicePrincipal", TargetName="sp-glorfindel"),
                   _row("credential", corr="c-act", ts="2026-10-27T10:01:00Z",
                        ActorName="sp-glorfindel", ActorId=OWN_OID, ActorAppId=OWN_APP)]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert [s["raw_signal"]["first_result_row"]["CorrelationId"] for s in sent] == ["c-act", "c-tgt", "c-cust"]
    assert [s["severity"] for s in sent] == ["critical", "critical", "high"]
    act, tgt = (s["raw_signal"]["first_result_row"] for s in sent[:2])
    assert act["GlorfindelIdentity"] is True and tgt["GlorfindelManaged"] is True
    d_act = _identity_decision(_initial(sent[0]))
    d_tgt = _identity_decision(_initial(sent[1]))
    assert "l'identité de Glorfindel" in d_act["escalation_reason"] and "Sévérité : critique" in d_act["escalation_reason"]
    assert any("Renouveler les identifiants de Glorfindel" in s for s in d_act["suggested_steps"])
    assert "La cible est l'identité de Glorfindel" in d_tgt["escalation_reason"]


def test_its_own_signin_from_a_new_address_is_kept_critical(law):
    """Its usual sign-ins are left out by the baseline, as anyone's; one from an address
    never seen is its credential used elsewhere — kept, critical."""
    rule = _shipped("entra-sp-unusual-signin")
    law["rows"] = [_row("signin", ActorName="sp-glorfindel", ActorId=OWN_OID, ActorAppId=OWN_APP)]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    assert sent[0]["raw_signal"]["normalized_signal"]["glorfindel_identity"] is True


def test_no_identity_known_marks_nothing_and_drops_nothing():
    rows = [_row("credential"), _row("credential", corr="c-2", ActorId=OWN_OID)]
    out = entra.prepare_rows(rows, set())
    assert len(out) == 2 and not any(r["GlorfindelIdentity"] or r["GlorfindelManaged"] for r in out)


# ── one card per finding ──────────────────────────────────────────────────────

def test_two_findings_at_the_same_instant_are_two_cards_and_never_twice(law):
    """The dedup follows EventId: two consents in the same second are two cards; the same
    finding seen again, or after a restart, is not re-sent; a row ingested late is new."""
    rule = _shipped("entra-app-consent")
    law["rows"] = [_row("consent", corr="c-a"), _row("consent", corr="c-b")]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert len(sent) == 2
    law["rows"] += [_row("consent", corr="c-late", ts="2026-10-27T09:30:00Z")]
    p.poll_once(rule)
    assert len(sent) == 3 and sent[2]["raw_signal"]["first_result_row"]["CorrelationId"] == "c-late"
    p2, sent2 = _poller(_detector(), rule, VM1)
    p2.poll_once(rule)
    assert sent2 == []


def test_past_the_cap_one_summary_card_names_every_finding_left(law):
    from glorfindel.agent import _identity_decision
    cap = dr._CONTROL_PLANE_CARDS_PER_POLL
    rule = _shipped("entra-privileged-role-assigned")
    law["rows"] = [_row("role", corr=f"c-{i}", ts=f"2026-10-27T10:{i:02d}:00Z",
                        TargetName=f"member-{i}@example.org") for i in range(cap + 2)]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert len(sent) == cap + 1
    summary = sent[cap]["raw_signal"]["first_result_row"]["OmittedOperations"]
    named = [s["raw_signal"]["first_result_row"]["TargetName"] for s in sent[:cap]] + \
            [o["TargetName"] for o in summary]
    assert sorted(named) == sorted(f"member-{i}@example.org" for i in range(cap + 2))
    d = _identity_decision(_initial(sent[cap]))
    assert all(o["TargetName"] in d["escalation_reason"] for o in summary) and d["action"] == ""


def test_an_identity_card_is_never_folded_into_the_previous_one():
    from glorfindel import escalations
    for reason in ("rôle attribué à un membre", "identifiant ajouté à Glorfindel"):
        escalations.record(signal_id=reason, resource_id=VM1, action="",
                           escalation_type="identity_change", reason=reason)
    assert [c["reason"] for c in escalations.pending()] == [
        "rôle attribué à un membre", "identifiant ajouté à Glorfindel"]
    assert "identity_change" in escalations._ESCALATION_LABELS


def test_no_button_nor_command_on_an_identity_card():
    pytest.importorskip("discord")
    from glorfindel.bot import _cli_command, _make_action_button
    for action in ("restore_from_backup", "isolate_vm", ""):
        esc = {"id": "e1", "action": action, "escalation_type": "identity_change", "resource_id": VM1}
        assert _make_action_button(esc) is None
        assert _cli_command(esc) == "glorfindel ack e1"


# ── loading: what is said ─────────────────────────────────────────────────────

def _layer(tmp_path, source, query):
    p = tmp_path / "rules.yaml"
    p.write_text("rules:\n  - name: custom\n    enabled: true\n    source: " + source +
                 "\n    ttp: T1528\n    assets: [auto]\n    query: |\n" +
                 "".join(f"      {line}\n" for line in query.splitlines()))
    return load_config(p, glorfindel_cfg=_cfg(), client_layer=False)


def test_an_identity_rule_without_event_id_is_said(tmp_path):
    cfg = _layer(tmp_path, "azure_entra", "AuditLogs\n| where TimeGenerated > ago(1h)\n| project TimeGenerated")
    assert any("ne projette pas EventId" in n for n in cfg.notes)


def test_an_entra_table_read_by_another_source_is_said(tmp_path):
    cfg = _layer(tmp_path, "azure_monitor", "AuditLogs\n| where TimeGenerated > ago(1h)")
    assert any("sans la source azure_entra" in n for n in cfg.notes)
    quiet = _layer(tmp_path, "azure_monitor", "Perf\n| where TimeGenerated > ago(5m) // not AuditLogs")
    assert not any("azure_entra" in n for n in quiet.notes)


def test_an_identity_row_normalises_to_its_operation_and_actor():
    row = entra.prepare_rows([_row("role")], {OWN_APP})[0]
    assert normalize_row(row) == {
        "resource": USER_OID, "indicator_key": "identity_operation",
        "indicator_value": "Add member to role", "actor": ADMIN_UPN, "actor_ip": "203.0.113.7",
        "glorfindel_managed": False, "glorfindel_identity": False}
    assert not dr.has_recognized_indicator(row)


# ── the bench's proposal (Terraform) ─────────────────────────────────────────

def test_the_disabled_proposal_reads_nothing_of_the_tenant_and_sends_only_what_rules_read():
    tf = (ROOT / "infra/terraform/entra_logs.tf").read_text()
    assert 'resource "azurerm_monitor_aad_diagnostic_setting" "entra" {\n  count = local.entra_logs_enabled ? 1 : 0' in tf
    assert "local.instance == \"default\"" in tf
    assert "data \"" not in tf                                   # nothing read of the tenant
    cats = [line.split('"')[1] for line in tf.splitlines() if line.strip().startswith("category")]
    assert cats == ["AuditLogs", "ServicePrincipalSignInLogs"]
    import yaml
    cfg = yaml.safe_load((ROOT / "infra/terraform/config.yaml").read_text())
    assert cfg["entra_logs"] == {"enabled": False}
