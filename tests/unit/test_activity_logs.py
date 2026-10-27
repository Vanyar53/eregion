"""AL1 (#225): Azure's Activity Log (`AzureActivity`) as a detection source — detection only.

A fake AzureActivity: rows shaped like the table's (OperationNameValue, Caller,
CallerIpAddress, Claims, _ResourceId, CorrelationId…) handed to the real
AzureActivityDetector through its parent's query (no Azure, no LLM). What is held:
  - a modification of an NSG from outside Glorfindel is dispatched, and escalates;
  - Glorfindel's own writes (its isolation, quarantine, blocks) are not — its identity is
    read (token, AZURE_CLIENT_ID, GLORFINDEL_OWN_CALLERS), never written in code; under a
    user's token, its oid only (the appid is the CLI's); only on what is its own (its
    rules, its quarantine NSGs, what an isolation state records) — its identity on a
    customer's rule is kept, marked, critical;
  - another caller's write on a rule Glorfindel manages is the gravest case: marked,
    critical, first;
  - each operation of a poll has its card, up to a cap; beyond, one summary card names
    every operation left — never a row marked sent without a card;
  - a control-plane detection is decided by the code: no model, no investigation, no
    action recommended, no incident on the anchor VM, nothing in the decision memory —
    `control_plane_change`, never one click; no button on the Discord card;
  - the window covers the ingestion latency, and a row arriving late is neither missed nor
    dispatched twice.
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
    AzureActivityDetector,
    backend_type_of,
    detector_for,
    is_control_plane_source,
)
from glorfindel.providers.azure import activity
from glorfindel.providers.azure.monitor import AzureMonitorDetector

SHIPPED = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourcegroups/rg-bench/providers"
VM1 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm1"
VM2 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm2"
NSG = f"{RG}/microsoft.network/networksecuritygroups/nsg-web"
# Placeholders, never real ids: Glorfindel's service principal and an outsider.
OWN_APP = "a1111111-b111-c111-d111-e11111111111"
OWN_OID = "a2222222-b222-c222-d222-e22222222222"
OUTSIDER = "someone@example.org"

GL_RULE = f"{NSG}/securityrules/glorfindel-iso-vm1-nic-vm1-a1b2c3"

RULE_OP = "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
ROLE_OP = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"


def _row(op=RULE_OP, target=f"{NSG}/securityrules/allow-web", caller=OUTSIDER, ip="203.0.113.7",
         ts="2026-10-27T10:00:00Z", corr="c-1", status="Success", **extra):
    row = {"TimeGenerated": ts, "OperationNameValue": op, "ActivityStatusValue": status,
           "Caller": caller, "CallerIpAddress": ip, "CallerAppId": "", "CallerObjectId": "",
           "_ResourceId": target, "ResourceGroup": "rg-bench", "CorrelationId": corr}
    row.update(extra)
    return row


def _own_isolation(**kw):
    """Glorfindel isolating vm1: its identity, writing a glorfindel-iso-* rule."""
    return _row(caller=OWN_OID, ip="198.51.100.4", corr="c-own",
                target=f"{NSG}/securityrules/glorfindel-iso-vm1-nic-vm1-a1b2c3",
                CallerAppId=OWN_APP, CallerObjectId=OWN_OID, **kw)


def _jwt(claims: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


class _Credential:
    def __init__(self, claims=None, error=None):
        self.claims, self.error, self.calls = claims or {}, error, 0

    def get_token(self, _scope):
        self.calls += 1
        if self.error:
            raise self.error
        return SimpleNamespace(token=_jwt(self.claims))


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)


@pytest.fixture(autouse=True)
def _vm1_isolated():
    """Glorfindel isolated vm1: its state names the rules it placed (GL_RULE and its -out)
    — what makes a `glorfindel-*` rule on a customer's NSG its own."""
    import glorfindel.actions as actions
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    name = GL_RULE.rsplit("/", 1)[-1]
    (d / "vm1.json").write_text(json.dumps({"resource_id": VM1, "placements": [
        {"nic_id": f"{VM1}-nic", "nsg_rg": "rg-bench", "nsg_name": "nsg-web",
         "rule_in": name, "rule_out": f"{name}-out", "bumped": [], "applied": [name]}]}))


@pytest.fixture()
def law(monkeypatch):
    """The workspace: what the parent detector's query returns (a list per call)."""
    state = {"rows": []}
    monkeypatch.setattr(AzureMonitorDetector, "run_query",
                        lambda self, query, timespan=None: list(state["rows"]))
    return state


def _detector(claims=None, error=None):
    return AzureActivityDetector("ws-test", credential=_Credential(
        {"appid": OWN_APP, "oid": OWN_OID} if claims is None else claims, error))


def _cfg():
    return SimpleNamespace(monitoring_backends=[SimpleNamespace(
        name="law-bench", type="azure_monitor", workspace_id="ws-test", endpoint="")])


def _shipped(name):
    return next(r for r in load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False).rules
                if r.name == name)


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


# ── the source ────────────────────────────────────────────────────────────────

def test_the_activity_log_is_a_control_plane_source_read_from_the_monitor_workspace():
    assert is_control_plane_source("azure_activity")
    assert not is_control_plane_source("azure_monitor") and not is_control_plane_source("nope")
    assert backend_type_of("azure_activity") == "azure_monitor"
    assert backend_type_of("azure_monitor") == "azure_monitor" and backend_type_of("splunk") == "splunk"
    assert isinstance(detector_for("azure_activity", workspace_id="ws"), AzureActivityDetector)


def test_the_shipped_control_plane_rules_load_bound_to_the_workspace():
    rules = {r.name: r for r in load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False).rules}
    for name, ttp in (("nsg-change-outside-glorfindel", "T1562.007"),
                      ("role-assignment-write", "T1098.003"),
                      ("snapshot-by-unexpected-caller", "T1578.001")):
        r = rules[name]
        assert (r.source, r.ttp, r.enabled, r.workspace_id) == ("azure_activity", ttp, True, "ws-test")
        assert r.auto_apply and r.monitoring_backend_name == "law-bench"
        # The window covers the ingestion latency (minutes, sometimes more than ten).
        assert dr._query_lookback_s(r.query) >= activity.MIN_LOOKBACK_S
        assert not dr._truncates_before_vm_filter(r.query)
        # Its caller's ids, for the exclusion of Glorfindel's own writes.
        assert "CallerAppId" in r.query and "CallerObjectId" in r.query and "CorrelationId" in r.query
    # The data-plane rules keep their source.
    assert rules["ransomware-disk-write"].source == "azure_monitor"


def test_a_control_plane_rule_shorter_than_the_ingestion_latency_is_said(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n"
        "  - name: short\n    source: azure_activity\n    ttp: T1562.007\n    assets: [auto]\n"
        "    query: |\n      AzureActivity\n      | where TimeGenerated > ago(10m)\n"
        "  - name: long\n    source: azure_activity\n    ttp: T1562.007\n    assets: [auto]\n"
        "    query: |\n      AzureActivity\n      | where TimeGenerated > ago(2h)\n")
    notes = load_config(path, glorfindel_cfg=_cfg(), client_layer=False).notes
    assert any("« short »" in n and "latence d'ingestion" in n for n in notes)
    assert not any("« long »" in n and "latence d'ingestion" in n for n in notes)


# ── Glorfindel's own writes ───────────────────────────────────────────────────

def test_own_operations_are_the_rights_its_capabilities_declare():
    ops = activity.own_operations()
    assert "microsoft.network/networksecuritygroups/securityrules/write" in ops
    assert "microsoft.network/networkinterfaces/write" in ops
    assert ROLE_OP.lower() not in ops and "microsoft.compute/snapshots/write" not in ops


def test_glorfindel_own_isolation_is_dropped_an_outsiders_write_kept():
    own = {OWN_APP, OWN_OID}
    kept = activity.prepare_rows([_own_isolation(), _row()], own, activity.recorded_targets())
    assert [r["Caller"] for r in kept] == [OUTSIDER]
    assert kept[0]["GlorfindelManaged"] is False and kept[0]["GlorfindelIdentity"] is False


def test_the_caller_is_matched_by_any_of_its_ids_whatever_the_case():
    own = {OWN_APP}
    # The id only in Claims (a rule that projects it), and in capitals; on its own rule.
    from_claims = _row(caller="", corr="c-2", target=GL_RULE, Claims=json.dumps({"appid": OWN_APP.upper()}))
    from_column = _row(caller=OWN_APP.upper(), corr="c-3", target=GL_RULE)
    assert activity.prepare_rows([from_claims, from_column], own, activity.recorded_targets()) == []


# ── its identity on what is not its own (review 5.5, constat 2) ─────────────────

def test_its_identity_writing_a_customer_rule_is_kept_marked_and_critical(law):
    """Glorfindel's identity, an operation it does (a rule written or deleted) — on a
    customer's rule no isolation state names: its credential may be in other hands. The
    card is critical and says so."""
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row(caller=OWN_OID, corr="c-w", CallerObjectId=OWN_OID),
                   _row(op="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
                        caller=OWN_OID, corr="c-d", target=f"{NSG}/securityrules/allow-rdp")]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == 2
    for sig in sent:
        assert sig["severity"] == "critical"
        assert sig["raw_signal"]["first_result_row"]["GlorfindelIdentity"] is True
        assert sig["raw_signal"]["first_result_row"]["GlorfindelManaged"] is False
    from glorfindel.agent import _control_plane_decision
    d = _control_plane_decision(_initial(sent[0]))
    assert "identité de Glorfindel" in d["escalation_reason"] and "Sévérité : critique" in d["escalation_reason"]


def test_its_identity_on_its_own_nsg_doing_what_it_never_does_is_kept():
    """A role assigned under its identity, scoped on its quarantine NSG: the target is
    Glorfindel's, the operation is not one it does."""
    row = _row(op=ROLE_OP, caller=OWN_OID, corr="c-q",
               target=f"{RG}/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope"
                      "/providers/microsoft.authorization/roleassignments/abc")
    kept = activity.prepare_rows([row], {OWN_OID})
    assert len(kept) == 1 and kept[0]["GlorfindelIdentity"] is True


def _isolation_state(vm="vm1", **placement):
    import glorfindel.actions as actions
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{vm}.json").write_text(json.dumps({"resource_id": VM1, "placements": [placement]}))
    return d / f"{vm}.json"


def test_a_customer_rule_its_isolation_moved_is_its_own_while_recorded():
    """`bumped`: a customer rule whose priority an isolation moved, put back by its release
    (network.py `_restore_bumped`) — its write under Glorfindel's identity is dropped."""
    _isolation_state(nsg_rg="rg-bench", nsg_name="nsg-web",
                     bumped=[{"name": "allow-web", "original_priority": 100}])
    rec = activity.recorded_targets()
    assert "00000000-0000-0000-0000-000000000000/rg-bench/nsg-web/allow-web" in rec   # with its subscription
    own_bump = _row(caller=OWN_OID, corr="c-b")
    assert activity.prepare_rows([own_bump], {OWN_OID}, rec) == []
    # Another rule of the same NSG, not recorded: kept, marked.
    other = _row(caller=OWN_OID, corr="c-o", target=f"{NSG}/securityrules/allow-rdp")
    assert activity.prepare_rows([other], {OWN_OID}, rec)[0]["GlorfindelIdentity"] is True
    # Someone else on the moved rule: kept (not Glorfindel's identity).
    assert len(activity.prepare_rows([_row(corr="c-x")], {OWN_OID}, rec)) == 1


def test_a_nic_it_put_in_quarantine_is_its_own():
    nic = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Network/networkInterfaces/nic-vm1"
    _isolation_state(kind="quarantine", nic_id=nic, nsg_rg="rg-bench",
                     nsg_name="nsg-glorfindel-quarantine-westeurope", bumped=[])
    rec = activity.recorded_targets()
    attach = _row(op="MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE", caller=OWN_OID, corr="c-n",
                  target=nic.lower())
    assert activity.prepare_rows([attach], {OWN_OID}, rec) == []
    assert len(activity.prepare_rows([attach], {OWN_OID}, frozenset())) == 1


def test_what_was_recorded_stays_its_own_after_the_release(law):
    """The release puts the rule back and clears the state; its row lands minutes later.
    The detector remembers (RECORDED_TTL_S); a restart forgets — the write escalates."""
    state = _isolation_state(nsg_rg="rg-bench", nsg_name="nsg-web",
                             bumped=[{"name": "allow-web", "original_priority": 100}])
    det = _detector()
    det.run_query("AzureActivity")                      # a poll while the state is there
    state.unlink()
    law["rows"] = [_row(caller=OWN_OID, corr="c-r", CallerObjectId=OWN_OID)]
    assert det.run_query("AzureActivity") == []
    assert len(_detector().run_query("AzureActivity")) == 1
    with patch.object(activity.time, "time", return_value=activity.time.time() + activity.RECORDED_TTL_S + 1):
        assert len(det.run_query("AzureActivity")) == 1


def test_another_caller_on_a_glorfindel_rule_is_the_gravest_case():
    managed = [
        _row(target=f"{NSG}/securityrules/glorfindel-iso-vm1-nic-vm1-a1b2c3"),
        _row(op="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE",
             target=f"{NSG}/securityrules/glorfindel-block-203-0-113-9-vm1"),
        _row(op="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
             target=f"{RG}/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope"),
    ]
    for row in activity.prepare_rows(managed, {OWN_APP}):
        assert row["GlorfindelManaged"] is True, row["_ResourceId"]
    customer = activity.prepare_rows([_row(), _row(op="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
                                                   target=NSG)], {OWN_APP})
    assert [r["GlorfindelManaged"] for r in customer] == [False, False]


def test_glorfindel_identity_doing_what_it_never_does_is_kept_and_marked():
    """Its identity assigning a role: its credential may be in other hands."""
    rows = activity.prepare_rows([_row(op=ROLE_OP, caller=OWN_OID, corr="c-9",
                                       target=f"{SUB}/providers/microsoft.authorization/roleassignments/x")],
                                 {OWN_OID})
    assert len(rows) == 1 and rows[0]["GlorfindelIdentity"] is True


def test_its_identity_is_read_from_its_token_and_the_environment(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_ID", OWN_APP.upper())
    monkeypatch.setenv("GLORFINDEL_OWN_CALLERS", " ops@example.org , ")
    det = _detector({"oid": OWN_OID, "appid": "a3333333-b333-c333-d333-e33333333333", "idtyp": "app"})
    assert det.own_identities() == {OWN_APP, OWN_OID, "a3333333-b333-c333-d333-e33333333333",
                                    "ops@example.org"}
    det.own_identities()
    assert det._credential.calls == 1            # read once


# Placeholders: the client tool a user signs in with (the same for the whole tenant), the
# operator Glorfindel runs as, and another operator using the same tool.
CLI_APP = "a4444444-b444-c444-d444-e44444444444"
USER_OID = "a5555555-b555-c555-d555-e55555555555"


def test_an_application_token_or_a_users():
    assert activity.is_app_token({"idtyp": "app", "appid": OWN_APP})
    assert not activity.is_app_token({"idtyp": "user", "appid": CLI_APP})
    assert activity.is_app_token({"appid": OWN_APP, "oid": OWN_OID})          # neither scp nor upn
    # A user's token without idtyp: its delegated scopes, or its name, say so.
    assert not activity.is_app_token({"appid": CLI_APP, "scp": "user_impersonation"})
    assert not activity.is_app_token({"appid": CLI_APP, "upn": "op@example.org"})


def test_a_user_token_the_clis_appid_excludes_nothing(law, caplog):
    """Glorfindel under `az login`: its token's appid is the Azure CLI's, the same for
    every user of the tenant — only its oid is its own. Another operator's `az` write on a
    Glorfindel rule is kept, the gravest case; said once."""
    claims = {"appid": CLI_APP, "azp": CLI_APP, "oid": USER_OID, "scp": "user_impersonation",
              "upn": "operator@example.org", "idtyp": "user"}
    det = _detector(claims)
    with caplog.at_level("WARNING", logger="glorfindel.providers.azure.activity"):
        assert det.own_identities() == {USER_OID}
        det.own_identities()
    assert sum("jeton d'utilisateur" in r.getMessage() for r in caplog.records) == 1
    other = _row(caller="colleague@example.org", corr="c-cli", target=GL_RULE,
                 CallerAppId=CLI_APP, Claims=json.dumps({"appid": CLI_APP, "oid": "x"}))
    mine = _row(caller="operator@example.org", corr="c-me", target=GL_RULE,
                CallerAppId=CLI_APP, CallerObjectId=USER_OID)
    law["rows"] = [other, mine]
    kept = det.run_query("AzureActivity")
    assert [r["CorrelationId"] for r in kept] == ["c-cli"]
    assert kept[0]["GlorfindelManaged"] is True and kept[0]["GlorfindelIdentity"] is False


def test_an_unreadable_token_leaves_the_configured_ids_and_is_retried(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_OWN_CALLERS", OWN_APP)
    det = _detector(error=RuntimeError("no credential"))
    assert det.own_identities() == {OWN_APP}
    det._credential.error = None
    det._credential.claims = {"oid": OWN_OID}
    assert det.own_identities() == {OWN_APP, OWN_OID}


def test_no_identity_known_excludes_nothing():
    """Fail loud: without an identity, its own writes escalate — never a silent drop."""
    assert len(activity.prepare_rows([_own_isolation()], set())) == 1


def test_the_detector_filters_its_rows_and_its_polls(law):
    law["rows"] = [_own_isolation(), _row()]
    det = _detector()
    assert [r["Caller"] for r in det.run_query("AzureActivity")] == [OUTSIDER]

    def fake_poll(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        row = next(r for r in law["rows"] if match_row(r))
        return 3, row
    with patch.object(AzureMonitorDetector, "poll_alert", fake_poll):
        elapsed, row = det.poll_alert("AzureActivity", since=0, timeout_s=1, verbose=False)
    assert elapsed == 3 and row["Caller"] == OUTSIDER and row["GlorfindelManaged"] is False


# ── the RulePoller ────────────────────────────────────────────────────────────

def test_an_nsg_change_from_outside_is_dispatched_and_its_own_isolation_is_not(law):
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_own_isolation(), _row()]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == 1
    sig = sent[0]
    assert sig["ttp"] == "T1562.007" and sig["context"]["plane"] == "control"
    assert sig["raw_signal"]["detection_source"] == "azure_activity"
    # The NSG names no VM: an unattributed detection, anchored on one card.
    assert sig["context"]["attribution"] == "unattributed" and sig["severity"] == "high"
    norm = sig["raw_signal"]["normalized_signal"]
    assert norm == {"resource": f"{NSG}/securityrules/allow-web",
                    "indicator_key": "control_plane_operation", "indicator_value": RULE_OP,
                    "caller": OUTSIDER, "caller_ip": "203.0.113.7",
                    "glorfindel_managed": False, "glorfindel_identity": False}


def test_its_own_isolation_alone_dispatches_nothing(law):
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_own_isolation()]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert sent == []


def test_each_operation_of_a_poll_has_its_card_the_gravest_first(law):
    """Control plane (review 5.5, constat 3): two NSG rules changed in the same minute are
    two findings — each its card; a write on Glorfindel's rules first, critical. An
    operation's Start and Success lines in the same poll are one card."""
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row(target=GL_RULE, corr="c-m", ts="2026-10-27T10:00:00Z"),
                   _row(corr="c-n", ts="2026-10-27T10:05:00Z"),             # newer, not Glorfindel's
                   _row(corr="c-o", ts="2026-10-27T10:03:00Z", target=f"{NSG}/securityrules/allow-rdp",
                        status="Start"),
                   _row(corr="c-o", ts="2026-10-27T10:03:20Z", target=f"{NSG}/securityrules/allow-rdp")]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    rows = [s["raw_signal"]["first_result_row"] for s in sent]
    assert [r["CorrelationId"] for r in rows] == ["c-m", "c-n", "c-o"]
    assert [s["severity"] for s in sent] == ["critical", "high", "high"]
    assert sent[0]["raw_signal"]["normalized_signal"]["glorfindel_managed"] is True
    assert rows[2]["ActivityStatusValue"] == "Success"            # the operation's latest line
    p.poll_once(rule)
    assert len(sent) == 3


def test_past_the_cap_one_summary_card_names_every_operation_left(law):
    """Never a row marked sent without a card: beyond the cap, one summary card lists each
    operation that did not get its own."""
    cap = dr._CONTROL_PLANE_CARDS_PER_POLL
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row(corr=f"c-{i}", ts=f"2026-10-27T10:{i:02d}:00Z",
                        target=f"{NSG}/securityrules/rule-{i}") for i in range(cap + 2)]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == cap + 1
    individual = [s["raw_signal"]["first_result_row"] for s in sent[:cap]]
    summary = sent[cap]["raw_signal"]["first_result_row"]
    listed = [o["_ResourceId"] for o in summary["OmittedOperations"]]
    assert len(listed) == 2
    # Every operation: its own card, or named on the summary — once.
    assert sorted([r["_ResourceId"] for r in individual] + listed) == sorted(
        f"{NSG}/securityrules/rule-{i}" for i in range(cap + 2))
    from glorfindel.agent import _control_plane_decision
    d = _control_plane_decision(_initial(sent[cap]))
    assert all(t in d["escalation_reason"] for t in listed) and d["action"] == ""
    p.poll_once(rule)
    assert len(sent) == cap + 1


def test_a_row_arriving_late_is_neither_missed_nor_dispatched_twice(law):
    """AzureActivity lands minutes after the operation: a row older than the last one
    dispatched, seen for the first time, is a new detection; the operation's later
    lines (Start → Success) are the same one."""
    rule = _shipped("nsg-change-outside-glorfindel")
    p, sent = _poller(_detector(), rule)
    law["rows"] = [_row(corr="c-a", ts="2026-10-27T10:10:00Z", status="Start")]
    p.poll_once(rule)
    assert len(sent) == 1
    # The same operation's Success line; and another, older one, ingested late.
    law["rows"] = [_row(corr="c-a", ts="2026-10-27T10:10:30Z", status="Success"),
                   _row(corr="c-b", ts="2026-10-27T09:55:00Z", target=f"{NSG}/securityrules/allow-rdp")]
    p.poll_once(rule)
    assert len(sent) == 2 and sent[1]["raw_signal"]["first_result_row"]["CorrelationId"] == "c-b"
    p.poll_once(rule)
    assert len(sent) == 2
    # A restart reads the dispatched set back: still nothing twice.
    p2, sent2 = _poller(_detector(), rule)
    p2.poll_once(rule)
    assert sent2 == []


def test_the_dedup_outlives_the_window_the_row_stays_visible_in(law):
    """An entry is pruned `lookback + margin` after its dispatch; the row leaves the
    query `lookback` after it happened — always before."""
    rule = _shipped("nsg-change-outside-glorfindel")
    window = dr._query_lookback_s(rule.query) + dr._INGESTION_MARGIN_S
    assert window > dr._query_lookback_s(rule.query) >= activity.MIN_LOOKBACK_S
    p, sent = _poller(_detector(), rule)
    law["rows"] = [_row(corr="c-a")]
    p.poll_once(rule)
    with patch.object(dr.time, "time", return_value=dr.time.time() + dr._query_lookback_s(rule.query)):
        p.poll_once(rule)
    assert len(sent) == 1


def test_a_role_assigned_on_a_watched_vm_is_attributed_to_it(law):
    rule = _shipped("role-assignment-write")
    law["rows"] = [_row(op=ROLE_OP, corr="c-r",
                        target=f"{VM2}/providers/Microsoft.Authorization/roleAssignments/abc".lower())]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == 1
    assert sent[0]["resource_id"] == VM2 and sent[0]["context"]["attribution"] == "asset"


def test_a_data_plane_row_keeps_its_three_keys():
    assert normalize_row({"Computer": "vm1", "MaxWrite": 9e7}) == {
        "resource": "vm1", "indicator_key": "disk_write_rate_bps", "indicator_value": 9e7}
    # StorageBlobLogs' CallerIpAddress stays what it was.
    assert normalize_row({"CallerIpAddress": "10.0.0.4", "AccountName": "st"})["indicator_key"] == "caller_ip"
    # A control-plane indicator is not a curated threat indicator: defence in depth
    # behind the control-plane decision.
    assert not dr.has_recognized_indicator(_row())


# ── decide: built by the code, never an action, never the model ───────────────

def _signal(**ctx):
    row = activity.prepare_rows([_row()], {OWN_APP})[0]
    return {"event": "detection", "ttp": "T1562.007", "resource_id": VM1, "severity": "high",
            "context": {"plane": "control", **ctx},
            "raw_signal": {"detection_source": "azure_activity", "first_result_row": row,
                           "normalized_signal": normalize_row(row)}}


def test_the_control_plane_decision_escalates_and_recommends_nothing():
    """Review 5.5, constat 5: the decision is the code's — an escalation, no action (the
    card's VM is an anchor: « Recommandé : isoler la VM » would be about a VM the operation
    never touched), the operation, its status, the caller, its address, the target and the
    severity in the reason."""
    from glorfindel.agent import _control_plane_decision
    d = _control_plane_decision(_initial(_signal()))
    assert d["escalate"] is True and d["held_by"] == "control_plane" and d["action"] == ""
    assert d["llm_usage"] is None and d["mode_hold"] is False and d["confidence"] == 0.0
    for text in (RULE_OP, "(Success)", OUTSIDER, "203.0.113.7", f"{NSG}/securityrules/allow-web",
                 "Sévérité : haute", "Détection seule", "sans appel au modèle"):
        assert text in d["escalation_reason"], text
    assert d["suggested_steps"] and "c-1" in d["suggested_steps"][0]


def test_the_control_plane_decision_reads_the_plane_or_the_source():
    from glorfindel.agent import _is_control_plane
    assert _is_control_plane({"context": {"plane": "control"}, "raw_signal": {}})
    assert _is_control_plane({"context": {}, "raw_signal": {"detection_source": "azure_activity"}})
    assert not _is_control_plane({"context": {}, "raw_signal": {"detection_source": "azure_monitor"}})


def test_the_control_plane_decision_names_the_gravest_cases():
    from glorfindel.agent import _control_plane_decision
    sig = {**_signal(), "severity": "critical"}
    sig["raw_signal"]["normalized_signal"].update(glorfindel_managed=True, glorfindel_identity=True)
    d = _control_plane_decision(_initial(sig))
    assert "règle gérée par Glorfindel" in d["escalation_reason"]
    assert "identité de Glorfindel" in d["escalation_reason"]
    assert "Sévérité : critique" in d["escalation_reason"]


def test_an_operation_read_at_its_start_says_so():
    """Seen at `Start`, the operation may fail afterwards: its card is already open, and
    says the status it read."""
    from glorfindel.agent import _control_plane_decision
    sig = _signal()
    sig["raw_signal"]["first_result_row"]["ActivityStatusValue"] = "Start"
    assert "a pu échouer" in _control_plane_decision(_initial(sig))["escalation_reason"]


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
    from glorfindel.memory import CycleMemory
    import glorfindel.agent as agent
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir(exist_ok=True)
    asked = queries if queries is not None else []
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: asked.append(q) or [])
    return _build_graph(memory or CycleMemory(path=tmp_path / "cycles"), connector, "claude-test",
                        incidents=incidents, autonomy=AutonomyConfig(default="non_disruptive"))


def _initial(signal):
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": False,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None}


@pytest.mark.parametrize("action", ["isolate_vm", "block_suspicious_ip", "snapshot"])
def test_an_outside_nsg_change_escalates_and_nothing_acts(tmp_path, monkeypatch, law, action):
    """Fini quand (#225): a fake AzureActivity, an NSG changed from outside → the RulePoller
    dispatches it; a model that would act at 99 % in non_disruptive is never asked — nothing
    runs, no investigation on the anchor VM, the card is `control_plane_change`, recommends
    no action, never approvable in one click."""
    from glorfindel import escalations
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_own_isolation(), _row(target=GL_RULE)]
    p, sent = _poller(_detector(), rule, VM1)        # one VM watched
    p.poll_once(rule)
    assert len(sent) == 1
    connector = MagicMock()
    connector.dry_run = False
    queries: list = []
    with patch("litellm.completion", return_value=_llm(action)) as llm:
        final = _graph(tmp_path, monkeypatch, connector, queries).invoke(_initial(sent[0]))
    llm.assert_not_called()
    assert queries == []
    for name in ("isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation"):
        getattr(connector, name).assert_not_called()
    assert final["outcome"]["escalation_type"] == "control_plane_change"
    assert final["held_by"] == "control_plane" and final["action"] == ""
    cards = escalations.pending()
    assert [c["escalation_type"] for c in cards] == ["control_plane_change"]
    assert cards[0]["action"] == "" and "règle gérée par Glorfindel" in cards[0]["reason"]
    from eregion_console.api import _approval_refusal
    assert _approval_refusal(cards[0], "vm1")


def test_a_control_plane_detection_attributed_to_a_vm_still_acts_on_nothing(tmp_path, monkeypatch, law):
    """A role assigned on the VM itself: attributed — still no model, no action."""
    rule = _shipped("role-assignment-write")
    law["rows"] = [_row(op=ROLE_OP, corr="c-r",
                        target=f"{VM1}/providers/Microsoft.Authorization/roleAssignments/abc")]
    p, sent = _poller(_detector(), rule, VM1, VM2)
    p.poll_once(rule)
    assert sent[0]["context"]["attribution"] == "asset"
    connector = MagicMock()
    connector.dry_run = False
    with patch("litellm.completion", return_value=_llm("snapshot")) as llm:
        final = _graph(tmp_path, monkeypatch, connector).invoke(_initial(sent[0]))
    llm.assert_not_called()
    connector.snapshot.assert_not_called()
    assert final["outcome"]["escalation_type"] == "control_plane_change"


def test_a_data_plane_signal_still_asks_the_model(tmp_path, monkeypatch):
    """The data-plane path is unchanged: the model decides, the gates follow."""
    from glorfindel.agent import decide
    from glorfindel.config import AutonomyConfig
    sig = {"event": "detection", "ttp": "T1486", "resource_id": VM1, "context": {},
           "raw_signal": {"detection_source": "azure_monitor",
                          "first_result_row": {"Computer": "vm1", "MaxWrite": 9e7}}}
    with patch("litellm.completion", return_value=_llm("snapshot")) as llm:
        d = decide(_initial(sig), model="claude-test", autonomy=AutonomyConfig(default="non_disruptive"))
    llm.assert_called_once()
    assert d["action"] == "snapshot" and d.get("held_by", "") != "control_plane"


# ── the anchor VM's incident, and the memory (review 5.5, constat 6) ──────────

def test_an_unattributed_control_plane_signal_opens_no_incident_and_stays_out_of_the_memory(
        tmp_path, monkeypatch, law):
    """The card's VM is an anchor: its incident is neither opened nor fed (the next
    data-plane cycle there would read « T1562.007, 2 signals »), and the cycle — decided by
    the code — never enters the decision memory a data-plane cycle retrieves from. Its
    debug line is written."""
    from glorfindel.incidents import IncidentRegistry
    from glorfindel.memory import CycleMemory
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row()]
    p, sent = _poller(_detector(), rule, VM1)
    p.poll_once(rule)
    assert sent[0]["context"]["attribution"] == "unattributed"
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl")
    memory = CycleMemory(path=tmp_path / "cycles")
    final = _graph(tmp_path, monkeypatch, MagicMock(dry_run=False), memory=memory,
                   incidents=incidents).invoke(_initial(sent[0]))
    assert final["incident"] is None and final["past_cycles"] == []
    assert incidents.get_active(VM1) is None
    assert memory.count() == 0
    assert list((tmp_path / "runs").glob("*_debug.jsonl"))
    # A data-plane cycle on the same VM: a fresh incident, one signal.
    from dataclasses import asdict
    assert asdict(incidents.get_or_create(resource_id=VM1, ttp="T1486"))["signals_count"] == 1


def test_an_attributed_control_plane_signal_feeds_its_vms_incident(tmp_path, monkeypatch, law):
    """A role assigned on the VM itself: that VM's — its incident says so."""
    from glorfindel.incidents import IncidentRegistry
    rule = _shipped("role-assignment-write")
    law["rows"] = [_row(op=ROLE_OP, corr="c-r",
                        target=f"{VM1}/providers/Microsoft.Authorization/roleAssignments/abc")]
    p, sent = _poller(_detector(), rule, VM1, VM2)
    p.poll_once(rule)
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl")
    final = _graph(tmp_path, monkeypatch, MagicMock(dry_run=False),
                   incidents=incidents).invoke(_initial(sent[0]))
    assert final["incident"]["ttps"] == ["T1098.003"]
    assert incidents.get_active(VM1) is not None


# ── the Discord card (review 5.5, constat 4) ──────────────────────────────────

@pytest.mark.parametrize("etype", ["control_plane_change", "unattributed_signal"])
def test_no_button_nor_command_on_a_card_anchored_on_a_vm(etype):
    """Its VM is an anchor: a one-click Restore or Revert would act on a VM the detection
    says nothing of."""
    pytest.importorskip("discord")
    from glorfindel.bot import _cli_command, _make_action_button
    for action in ("restore_from_backup", "isolate_vm", ""):
        esc = {"id": "e1", "action": action, "escalation_type": etype, "resource_id": VM1}
        assert _make_action_button(esc) is None
        assert _cli_command(esc) == "glorfindel ack e1"
    # Elsewhere, unchanged.
    restore = {"id": "e2", "action": "restore_from_backup", "escalation_type": "destructive_action",
               "resource_id": VM1}
    assert _make_action_button(restore) is not None and "restore" in _cli_command(restore)


def test_the_escalation_type_has_a_label():
    from glorfindel.escalations import _ESCALATION_LABELS
    assert "control_plane_change" in _ESCALATION_LABELS


def test_two_control_plane_cards_are_never_folded_into_one():
    """Each is one operation: the next — perhaps on Glorfindel's own rules — is its own
    card, notified, never a silent `occurrences + 1` on the first one's text."""
    from glorfindel import escalations
    for reason in ("NSG du client modifié", "règle gérée par Glorfindel écrite"):
        escalations.record(signal_id=reason, resource_id=VM1, action="isolate_vm",
                           escalation_type="control_plane_change", reason=reason)
    assert [c["reason"] for c in escalations.pending()] == [
        "NSG du client modifié", "règle gérée par Glorfindel écrite"]
    # Every other type still merges.
    for _ in range(2):
        escalations.record(signal_id="s", resource_id=VM2, action="isolate_vm",
                           escalation_type="mode_hold", reason="r")
    assert len(escalations.pending()) == 3


def test_respond_mode_says_the_detection_came_from_the_control_plane(monkeypatch):
    """`glorfindel respond` resolves an attack_started by the rule of its TTP: on an
    AzureActivity rule, the detection carries its source, and `decide` builds its
    decision without the model. A data-plane detection is unchanged."""
    from glorfindel.agent import decide, resolve_attack_started
    monkeypatch.setattr(AzureActivityDetector, "own_identities", lambda self: {OWN_APP})

    def poll(self, query, since, timeout_s, interval_s=10.0, verbose=True, match_row=None):
        row = _row()
        return (5, row) if match_row is None or match_row(row) else None
    monkeypatch.setattr(AzureMonitorDetector, "poll_alert", poll)
    out = resolve_attack_started({"event": "attack_started", "ttp": "T1562.007",
                                  "raw_signal": {"detection_timeout_s": 1}})
    assert out["event"] == "detection"
    assert out["raw_signal"]["detection_source"] == "azure_activity"
    assert out["raw_signal"]["detected_data"]["GlorfindelManaged"] is False
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        d = decide(_initial(out), model="claude-test")
    llm.assert_not_called()
    assert d["held_by"] == "control_plane" and d["action"] == "" and OUTSIDER in d["escalation_reason"]

    monkeypatch.setattr(AzureMonitorDetector, "poll_alert",
                        lambda self, *a, **k: (5, {"Computer": "vm1", "MaxWrite": 9e7}))
    data = resolve_attack_started({"event": "attack_started", "ttp": "T1486",
                                   "raw_signal": {"detection_timeout_s": 1}})
    assert data["event"] == "detection" and "detection_source" not in data["raw_signal"]


# ── the bench's proposal (Terraform) ─────────────────────────────────────────

def test_the_disabled_proposal_reads_no_subscription_and_sends_only_what_rules_read():
    """Review 5.5, constat 8: disabled, nothing runs — the subscription's read carries
    the same `count` as the setting. Only the category a rule reads (Administrative)."""
    tf = (Path(__file__).resolve().parents[2] / "infra/terraform/activity_log.tf").read_text()
    assert 'data "azurerm_subscription" "current" {\n  count = local.activity_log_enabled ? 1 : 0' in tf
    assert "data.azurerm_subscription.current[0].id" in tf
    assert 'category = "Administrative"' in tf and 'category = "Security"' not in tf


# ── second 5.5 review: three limits closed before the merge ──────────────────

def test_its_identity_hiding_an_allow_rule_behind_a_glorfindel_name_escalates(law):
    """A `glorfindel-*` name on a customer's NSG is no proof: whoever holds Glorfindel's
    credential writes `glorfindel-x` there, no state names it — kept, critical."""
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row(caller=OWN_OID, corr="c-x", CallerObjectId=OWN_OID,
                        target=f"{NSG}/securityrules/glorfindel-x")]
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    row = sent[0]["raw_signal"]["first_result_row"]
    assert row["GlorfindelIdentity"] is True and row["GlorfindelManaged"] is True


def test_the_rules_its_states_name_are_its_own_with_their_subscription():
    """Isolation (`rule_in`/`rule_out`, a legacy state's `rule_names`) and block (`rule`,
    `<rule>-out`, its placements) states name the rules Glorfindel placed — keyed with the
    subscription of the state's VM: the same names in another subscription are not its."""
    import glorfindel.actions as actions
    sub = SUB.rsplit("/", 1)[-1]
    d = actions._BLOCK_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / "vm2.json").write_text(json.dumps([
        {"ip": "203.0.113.9", "resource_id": VM2, "nsg": "rg-bench/nsg-web", "rule": "glorfindel-block-a",
         "scoped": True, "placements": [{"nsg_rg": "rg-bench", "nsg_name": "nsg-app",
                                         "rule": "glorfindel-block-b"}]}]))
    (actions._ISOLATION_STATE_DIR / "vm3.json").write_text(json.dumps(
        {"resource_id": VM2.replace("vm2", "vm3"), "nsg_rg": "rg-bench", "nsg_name": "nsg-old",
         "rule_names": ["glorfindel-iso-old"]}))
    rec = activity.recorded_targets()
    for key in ("rg-bench/nsg-web/glorfindel-block-a", "rg-bench/nsg-web/glorfindel-block-a-out",
                "rg-bench/nsg-app/glorfindel-block-b", "rg-bench/nsg-app/glorfindel-block-b-out",
                "rg-bench/nsg-old/glorfindel-iso-old",
                "rg-bench/nsg-web/glorfindel-iso-vm1-nic-vm1-a1b2c3-out"):
        assert f"{sub}/{key}" in rec, key
    own = _row(caller=OWN_OID, corr="c-b", target=f"{NSG}/securityrules/glorfindel-block-a")
    assert activity.prepare_rows([own], {OWN_OID}, rec) == []
    elsewhere = _row(caller=OWN_OID, corr="c-e", target=f"{NSG}/securityrules/glorfindel-block-a".replace(
        sub, "11111111-1111-1111-1111-111111111111"))
    assert activity.prepare_rows([elsewhere], {OWN_OID}, rec)[0]["GlorfindelIdentity"] is True
    # Its quarantine NSG is its own by name: it is Glorfindel's NSG, not the customer's.
    quarantine = _row(caller=OWN_OID, corr="c-q", target=f"{RG}/microsoft.network/networksecuritygroups/"
                      "nsg-glorfindel-quarantine-westeurope/securityrules/glorfindel-quarantine-deny-in")
    assert activity.prepare_rows([quarantine], {OWN_OID}, frozenset()) == []


@pytest.mark.parametrize("raw", [
    {"detection_source": "azure_monitor", "first_result_row": _row()},
    {"detection_source": "splunk", "detected_data": _row()},
    {"detection_source": "azure_monitor", "first_result_row": {"Computer": "vm1"},
     "normalized_signal": {"indicator_key": "control_plane_operation", "indicator_value": RULE_OP}},
])
def test_an_activity_row_read_by_another_source_is_still_the_control_plane(raw):
    """In depth: an AzureActivity row read by a rule `source: azure_monitor` (or bound to a
    backend of another type) carries neither `plane` nor its source — its row says so, and
    the model is never asked: no snapshot alone in non_disruptive."""
    from glorfindel.agent import _is_control_plane, decide
    from glorfindel.config import AutonomyConfig
    sig = {"event": "detection", "ttp": "T1562.007", "resource_id": VM1, "context": {"attribution": "asset"},
           "raw_signal": raw}
    assert _is_control_plane(sig)
    with patch("litellm.completion", return_value=_llm("snapshot")) as llm:
        d = decide(_initial(sig), model="claude-test", autonomy=AutonomyConfig(default="non_disruptive"))
    llm.assert_not_called()
    assert d["action"] == "" and d["escalate"] is True and d["held_by"] == "control_plane"


def test_a_control_plane_rule_without_correlation_id_is_said(tmp_path):
    """Without its CorrelationId, an operation is its time: two at the same instant fold
    into one card — said at load, the client's layer included."""
    base = tmp_path / "rules.yaml"
    base.write_text(
        "rules:\n"
        "  - name: no-corr\n    source: azure_activity\n    ttp: T1562.007\n    assets: [auto]\n"
        "    query: |\n      AzureActivity\n      | where TimeGenerated > ago(2h)\n"
        "      | project TimeGenerated, OperationNameValue, _ResourceId\n"
        "  - name: monitor-on-activity\n    source: azure_monitor\n    ttp: T1562.007\n    assets: [auto]\n"
        "    query: |\n      AzureActivity\n      | where TimeGenerated > ago(2h)\n"
        "  - name: data\n    source: azure_monitor\n    ttp: T1486\n    assets: [auto]\n"
        "    query: |\n      Perf\n      | where TimeGenerated > ago(5m)\n")
    client = tmp_path / "client_rules.yaml"
    client.write_text(
        "rules:\n"
        "  - name: client-no-corr\n    source: azure_activity\n    ttp: T1098.003\n    assets: [auto]\n"
        "    query: |\n      AzureActivity\n      | where TimeGenerated > ago(2h)\n")
    notes = load_config(base, glorfindel_cfg=_cfg(), client_layer=client).notes
    said = {n.split("«")[1].split("»")[0].strip() for n in notes if "CorrelationId" in n}
    assert said == {"no-corr", "monitor-on-activity", "client-no-corr"}
    # The shipped rules project it: nothing said.
    shipped = load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False).notes
    assert not any("CorrelationId" in n for n in shipped)
