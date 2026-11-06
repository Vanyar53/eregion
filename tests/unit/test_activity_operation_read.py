"""AL1d (#600): in the shipped rules on Azure's Activity Log (`source: azure_activity`), an
operation that succeeded is always read — whatever its latest line.

The shipped queries run as written (`tests/unit/kql_subset.py`, a KQL subset in memory) on
lines shaped like AzureActivity's (TimeGenerated, OperationNameValue, ActivityStatusValue,
Caller, CallerIpAddress, Claims, _ResourceId, ResourceGroup, CorrelationId), then through
the real AzureActivityDetector and RulePoller. What is held, for each rule:
  - an operation with a line that succeeded is one row, one card, even when its latest line
    is a failure — the card says it took effect;
  - an operation that only failed is no row, no card;
  - the ordinary operation (Start, Success) is one row, one card; one at its Start only too;
  - what each rule already leaves out stays out: another operation, a line older than its
    window, Glorfindel's own isolation; one row per operation; the same columns, plus
    `Succeeded`; the dedup of an operation across polls is unchanged.
The Run Command rule (SID1) keeps failures by design: every operation is read already. The
restore point rule (AL2) reads what succeeded in its own form — held here with the others, and
in tests/unit/test_restore_points.py. And in the first four rules, a latest line that names
no caller keeps the caller its operation's other lines name: Glorfindel's own isolation stays
out, its identity elsewhere stays critical, its Run Command is read as its own and another's
is not this rule's.

Every identifier is made up (repository public): 00000000-… GUIDs, example names,
documentation addresses (RFC 5737). No Azure, no model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import yaml

import glorfindel.detection_rules as dr
from glorfindel.detection_rules import RulePoller, load_config, shipped_rules_path
from glorfindel.providers.azure import activity
from glorfindel.providers.azure.monitor import AzureMonitorDetector

from . import kql_subset

SHIPPED_PATH = shipped_rules_path()
SHIPPED = {r["name"]: r for r in yaml.safe_load(SHIPPED_PATH.read_text())["rules"]}
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
RG = f"{SUB}/resourceGroups/rg-example/providers"
VM1 = f"{RG}/Microsoft.Compute/virtualMachines/vm1"
NSG = f"{RG}/Microsoft.Network/networkSecurityGroups/nsg-web"
GL_RULE = f"{NSG}/securityRules/glorfindel-iso-vm1-nic-vm1-a1b2c3"
OWN_APP = "a1111111-b111-c111-d111-e11111111111"
OWN_OID = "a2222222-b222-c222-d222-e22222222222"
OUTSIDER = "someone@example.org"
OUTSIDER_OID = "b3333333-c333-d333-e333-f33333333333"
OID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier"

# Each rule whose query sets failures aside, and an operation it reads.
RULES = {
    "nsg-change-outside-glorfindel": ("MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
                                      f"{NSG}/securityRules/allow-web"),
    "role-assignment-write": ("MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
                              f"{SUB}/providers/Microsoft.Authorization/roleAssignments/"
                              "00000000-0000-0000-0000-0000000000aa"),
    "snapshot-by-unexpected-caller": ("MICROSOFT.COMPUTE/SNAPSHOTS/WRITE",
                                      f"{RG}/Microsoft.Compute/snapshots/snap-example"),
}
RUN_COMMAND = "run-command-by-glorfindel-outside-isolation"
RUN_OP = "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION"
# AL2's sister rule sets failures aside too, in its own form (Azure Backup excluded, the row's
# columns taken on the lines that name someone else): held here for what every rule holds,
# and in tests/unit/test_restore_points.py for what is its own.
RESTOREPOINT = "restorepoint-by-unexpected-caller"
RESTOREPOINT_OP = ("MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/RESTOREPOINTS/RETRIEVESASURIS/ACTION",
                   f"{RG}/Microsoft.Compute/restorePointCollections/rpc-vm1/restorePoints/rp-1")
OPS = {**RULES, RESTOREPOINT: RESTOREPOINT_OP}
COLUMNS = ["TimeGenerated", "OperationNameValue", "ActivityStatusValue", "Succeeded", "Caller",
           "CallerIpAddress", "CallerAppId", "CallerObjectId", "_ResourceId", "ResourceGroup",
           "CorrelationId"]

NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    global NOW
    NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)


def _line(rule, status, minutes_ago, corr="c-1", caller=OUTSIDER, oid=OUTSIDER_OID, app="",
          op=None, target=None, bare=False):
    """One line of AzureActivity, as the table writes it; `bare`: a line that names no
    caller (no Caller, no address, no Claims)."""
    rule_op, rule_target = OPS.get(rule, (RUN_OP, VM1))
    return {"Type": "AzureActivity", "TimeGenerated": NOW - timedelta(minutes=minutes_ago),
            "OperationNameValue": op or rule_op, "ActivityStatusValue": status,
            "Caller": "" if bare else caller, "CallerIpAddress": "" if bare else "203.0.113.7",
            "Claims": "" if bare else json.dumps({"appid": app, OID_CLAIM: oid}),
            "_ResourceId": target or rule_target, "ResourceGroup": "rg-example",
            "CorrelationId": corr}


def _run(rule, lines):
    return kql_subset.run(SHIPPED[rule]["query"], lines, now=NOW)


# ── the queries, as written ─────────────────────────────────────────────────────

def test_every_shipped_activity_rule_is_held_here():
    """A new rule on the Activity Log is read here before it ships: it says whether it sets
    failures aside, and is held to read an operation that succeeded."""
    assert {n for n, r in SHIPPED.items() if r.get("source") == "azure_activity"} == {
        *RULES, RUN_COMMAND, RESTOREPOINT}


@pytest.mark.parametrize("rule", [*RULES, RESTOREPOINT])
def test_every_rule_that_sets_failures_aside_reads_what_succeeded(rule):
    """The issue's two criteria, in each shipped rule that sets failures aside: an operation
    with a line that succeeded is one row whatever its latest line; one that only failed is
    none."""
    rows = _run(rule, [_line(rule, "Start", 6), _line(rule, "Success", 5), _line(rule, "Failure", 4)])
    assert [(r["ActivityStatusValue"], r["Succeeded"], r["Caller"]) for r in rows] == [("Failure", 1, OUTSIDER)]
    assert _run(rule, [_line(rule, "Start", 6), _line(rule, "Failure", 5)]) == []
    assert _run(rule, [_line(rule, "Failed", 5)]) == []


@pytest.mark.parametrize("rule", RULES)
@pytest.mark.parametrize("statuses", [("Start", "Success", "Failure"),
                                      ("Started", "Succeeded", "Failed"),
                                      ("Accept", "success", "FAILURE")])
def test_an_operation_that_succeeded_is_read_whatever_its_latest_line(rule, statuses):
    start, ok, failed = statuses
    rows = _run(rule, [_line(rule, start, 6), _line(rule, ok, 5), _line(rule, failed, 4)])
    assert len(rows) == 1
    assert rows[0]["ActivityStatusValue"] == failed and rows[0]["Succeeded"] == 1


@pytest.mark.parametrize("rule", RULES)
def test_a_success_ingested_after_a_later_failure_is_read_too(rule):
    """The order the lines land in is not the order they were written: the failure is the
    latest, the success arrives last — one row."""
    rows = _run(rule, [_line(rule, "Failure", 3), _line(rule, "Start", 6), _line(rule, "Success", 5)])
    assert [r["Succeeded"] for r in rows] == [1]


@pytest.mark.parametrize("rule", RULES)
@pytest.mark.parametrize("statuses", [("Start", "Failure"), ("Started", "Failed"),
                                      ("Start", "Accept", "Failure"), ("Failure",)])
def test_an_operation_that_only_failed_is_not_read(rule, statuses):
    lines = [_line(rule, s, 6 - i) for i, s in enumerate(statuses)]
    assert _run(rule, lines) == []


@pytest.mark.parametrize("rule", RULES)
def test_the_ordinary_operation_is_one_row_its_latest_line(rule):
    rows = _run(rule, [_line(rule, "Start", 6), _line(rule, "Success", 5)])
    assert len(rows) == 1
    row = rows[0]
    assert list(row) == COLUMNS                                    # the same columns, plus Succeeded
    assert (row["ActivityStatusValue"], row["Succeeded"]) == ("Success", 1)
    assert (row["Caller"], row["CallerObjectId"], row["CorrelationId"]) == (OUTSIDER, OUTSIDER_OID, "c-1")
    assert row["TimeGenerated"] == NOW - timedelta(minutes=5)


@pytest.mark.parametrize("rule", RULES)
def test_an_operation_at_its_start_only_is_read_as_before(rule):
    rows = _run(rule, [_line(rule, "Start", 2)])
    assert [(r["ActivityStatusValue"], r["Succeeded"]) for r in rows] == [("Start", 0)]


@pytest.mark.parametrize("rule", RULES)
def test_what_each_rule_leaves_out_stays_out(rule):
    lines = [_line(rule, "Success", 5, op="MICROSOFT.COMPUTE/VIRTUALMACHINES/READ", corr="c-other"),
             _line(rule, "Success", 90, corr="c-old"),             # older than its window
             _line(rule, "Start", 8, corr="c-fail"), _line(rule, "Failure", 7, corr="c-fail")]
    assert _run(rule, lines) == []


@pytest.mark.parametrize("rule", RULES)
def test_one_row_per_operation(rule):
    _, target = RULES[rule]
    lines = [_line(rule, "Start", 9, corr="c-a"), _line(rule, "Success", 8, corr="c-a"),
             _line(rule, "Success", 7, corr="c-a", target=target + "-other"),
             _line(rule, "Start", 6, corr="c-b"), _line(rule, "Success", 5, corr="c-b"),
             _line(rule, "Failure", 4, corr="c-b"),
             _line(rule, "Start", 3, corr="c-c"), _line(rule, "Failure", 2, corr="c-c")]
    rows = _run(rule, lines)
    assert sorted((r["CorrelationId"], r["_ResourceId"] == target) for r in rows) == [
        ("c-a", False), ("c-a", True), ("c-b", True)]


def test_the_three_rules_share_one_form():
    """The same reading of an operation, word for word, in each rule: from its `summarize`
    to its last line."""
    def form(query):
        return query[query.index("| summarize"):]
    forms = {rule: form(SHIPPED[rule]["query"]) for rule in RULES}
    first = forms["nsg-change-outside-glorfindel"]
    assert "Succeeded = countif(" in first and "take_anyif(Caller, " in first
    assert all(f == first for f in forms.values())


def test_the_run_command_rule_reads_every_operation_already():
    """SID1 keeps failures by design (a refused try of its identity says as much): an
    operation with a success and a later failure is one row, like one that only failed."""
    def line(status, minutes_ago, corr):
        return _line(RUN_COMMAND, status, minutes_ago, corr=corr, caller=OWN_OID, oid=OWN_OID, app=OWN_APP)
    rows = _run(RUN_COMMAND, [line("Start", 9, "c-a"), line("Success", 8, "c-a"), line("Failure", 7, "c-a"),
                              line("Start", 6, "c-b"), line("Failure", 5, "c-b")])
    assert sorted((r["CorrelationId"], r["ActivityStatusValue"]) for r in rows) == [
        ("c-a", "Failure"), ("c-b", "Failure")]
    assert {r["CorrelationId"]: r["Started"] for r in rows}["c-a"] == NOW - timedelta(minutes=9)


# ── through the detector and the RulePoller ─────────────────────────────────────

class _Credential:
    def get_token(self, _scope):
        import base64

        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return SimpleNamespace(token=f"{b64({'alg': 'none'})}.{b64({'appid': OWN_APP, 'oid': OWN_OID})}.sig")


@pytest.fixture()
def workspace(monkeypatch):
    """The workspace runs the rule's query on the lines it holds; the client receives the
    instants as text, like the SDK's rows once serialised."""
    lines: list[dict] = []

    def run_query(self, query, timespan=None):
        return [{k: (v.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(v, datetime) else v)
                 for k, v in r.items()} for r in kql_subset.run(query, lines, now=NOW)]
    monkeypatch.setattr(AzureMonitorDetector, "run_query", run_query)
    return lines


@pytest.fixture()
def _vm1_isolated():
    import glorfindel.actions as actions
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    name = GL_RULE.rsplit("/", 1)[-1]
    (d / "vm1.json").write_text(json.dumps({"resource_id": VM1, "placements": [
        {"nic_id": f"{VM1}-nic", "nsg_rg": "rg-example", "nsg_name": "nsg-web",
         "rule_in": name, "rule_out": f"{name}-out", "bumped": [], "applied": [name]}]}))


def _poller(rule_name):
    cfg = SimpleNamespace(monitoring_backends=[SimpleNamespace(
        name="law-example", type="azure_monitor", workspace_id="ws-test", endpoint="")])
    rule = next(r for r in load_config(SHIPPED_PATH, glorfindel_cfg=cfg, client_layer=False).rules
                if r.name == rule_name)
    det = activity.AzureActivityDetector("ws-test", credential=_Credential())
    sent: list = []
    p = RulePoller([rule], sent.append)
    p._detector = lambda _rule: det
    p._registry = SimpleNamespace(for_backend=lambda _name: [SimpleNamespace(name="vm1", resource_id=VM1)])
    return p, rule, sent


@pytest.mark.parametrize("rule_name", RULES)
def test_a_succeeded_operation_whose_latest_line_failed_has_its_card(workspace, rule_name):
    from glorfindel.agent import _control_plane_text
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6), _line(rule_name, "Success", 5), _line(rule_name, "Failure", 4)]
    p.poll_once(rule)
    assert len(sent) == 1
    row = sent[0]["raw_signal"]["first_result_row"]
    assert (row["ActivityStatusValue"], row["Succeeded"]) == ("Failure", 1)
    what, _steps = _control_plane_text(sent[0])
    assert "une de ses lignes a réussi" in what and "a pris effet" in what
    p.poll_once(rule)                                            # the same operation: one card
    assert len(sent) == 1


@pytest.mark.parametrize("rule_name", RULES)
def test_an_operation_that_only_failed_has_no_card(workspace, rule_name):
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6), _line(rule_name, "Failure", 5)]
    p.poll_once(rule)
    assert sent == []


@pytest.mark.parametrize("rule_name", RULES)
def test_the_ordinary_operation_has_its_card_and_says_no_more(workspace, rule_name):
    from glorfindel.agent import _control_plane_text
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6), _line(rule_name, "Success", 5)]
    p.poll_once(rule)
    assert len(sent) == 1
    what, _steps = _control_plane_text(sent[0])
    assert "(Success)" in what and "a réussi" not in what and "a pu échouer" not in what


def test_a_failure_line_after_the_card_makes_no_second_card(workspace):
    """The dedup follows the operation (CorrelationId, operation, resource), unchanged: its
    failure line, a poll later, is the same operation."""
    rule_name = "role-assignment-write"
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6), _line(rule_name, "Success", 5)]
    p.poll_once(rule)
    workspace.append(_line(rule_name, "Failure", 4))
    p.poll_once(rule)
    assert len(sent) == 1
    assert dr._row_identity(sent[0]["raw_signal"]["first_result_row"]).startswith("op:c-1|")


def test_its_own_isolation_stays_out_whatever_its_lines(workspace, _vm1_isolated):
    """Glorfindel writing a rule its isolation state names: set aside by the adapter, its
    success and a later failure alike; another caller on the same rule is the gravest card."""
    rule_name = "nsg-change-outside-glorfindel"
    p, rule, sent = _poller(rule_name)

    def own(status, minutes_ago):
        return _line(rule_name, status, minutes_ago, corr="c-own", caller=OWN_OID, oid=OWN_OID,
                     app=OWN_APP, target=GL_RULE)
    workspace += [own("Start", 6), own("Success", 5), own("Failure", 4)]
    p.poll_once(rule)
    assert sent == []
    workspace += [_line(rule_name, "Start", 3, corr="c-out", target=GL_RULE),
                  _line(rule_name, "Success", 2, corr="c-out", target=GL_RULE),
                  _line(rule_name, "Failure", 1, corr="c-out", target=GL_RULE)]
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    assert sent[0]["raw_signal"]["normalized_signal"]["glorfindel_managed"] is True


def test_a_row_without_its_count_says_what_it_read():
    """A rule of the client's layer that does not project `Succeeded`: the card says the
    status it read, nothing more."""
    from glorfindel.agent import _control_plane_text
    op, target = RULES["role-assignment-write"]
    for succeeded in (None, "n/a", 0):
        row = {"OperationNameValue": op, "ActivityStatusValue": "Failure", "Caller": OUTSIDER,
               "_ResourceId": target, "CorrelationId": "c-1", "Succeeded": succeeded}
        what, _ = _control_plane_text({"raw_signal": {"first_result_row": row}})
        assert "(Failure)" in what and "a réussi" not in what


# ── the caller, when the latest line names none ────────────────────────────────

@pytest.mark.parametrize("rule", [*RULES, RUN_COMMAND])
def test_a_bare_latest_line_keeps_the_caller_its_operation_names(rule):
    """Start names its caller, Success names none: the row names the caller, its address
    and its ids; a latest line that names one keeps its own."""
    rows = _run(rule, [_line(rule, "Start", 6), _line(rule, "Success", 5, bare=True)])
    assert [(r["ActivityStatusValue"], r["Caller"], r["CallerIpAddress"], r["CallerObjectId"])
            for r in rows] == [("Success", OUTSIDER, "203.0.113.7", OUTSIDER_OID)]
    # The line that names it may be neither the first nor the last.
    rows = _run(rule, [_line(rule, "Start", 7, bare=True), _line(rule, "Accept", 6),
                       _line(rule, "Success", 5, bare=True)])
    assert [(r["Caller"], r["CallerObjectId"]) for r in rows] == [(OUTSIDER, OUTSIDER_OID)]
    rows = _run(rule, [_line(rule, "Start", 6, caller="first@example.org"), _line(rule, "Success", 5)])
    assert [r["Caller"] for r in rows] == [OUTSIDER]
    rows = _run(rule, [_line(rule, "Start", 6, bare=True), _line(rule, "Success", 5, bare=True)])
    assert len(rows) == 1 and not any(rows[0][c] for c in ("Caller", "CallerAppId", "CallerObjectId"))


def test_its_own_isolation_with_a_bare_latest_line_stays_out(workspace, _vm1_isolated):
    rule_name = "nsg-change-outside-glorfindel"
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6, corr="c-own", caller=OWN_OID, oid=OWN_OID, app=OWN_APP,
                        target=GL_RULE),
                  _line(rule_name, "Success", 5, corr="c-own", target=GL_RULE, bare=True)]
    p.poll_once(rule)
    assert sent == []


@pytest.mark.parametrize("rule_name", ["role-assignment-write", "snapshot-by-unexpected-caller"])
def test_its_identity_with_a_bare_latest_line_is_still_critical(workspace, rule_name):
    """Glorfindel never does these: under its identity, the gravest — read from the line that
    names it, the latest naming none."""
    p, rule, sent = _poller(rule_name)
    workspace += [_line(rule_name, "Start", 6, caller=OWN_OID, oid=OWN_OID, app=OWN_APP),
                  _line(rule_name, "Success", 5, bare=True)]
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    assert sent[0]["raw_signal"]["normalized_signal"]["glorfindel_identity"] is True
    assert sent[0]["raw_signal"]["first_result_row"]["CallerObjectId"] == OWN_OID


def test_its_run_command_with_a_bare_latest_line_is_read_as_its_own(workspace):
    """SID1: its identity's Run Command, no isolation recorded — `no_isolation`, not an
    unreadable caller; another caller's, with a bare latest line, is not this rule's."""
    p, rule, sent = _poller(RUN_COMMAND)
    workspace += [_line(RUN_COMMAND, "Start", 6, corr="c-own", caller=OWN_OID, oid=OWN_OID, app=OWN_APP),
                  _line(RUN_COMMAND, "Success", 5, corr="c-own", bare=True),
                  _line(RUN_COMMAND, "Start", 6, corr="c-other"),
                  _line(RUN_COMMAND, "Success", 5, corr="c-other", bare=True)]
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    row = sent[0]["raw_signal"]["first_result_row"]
    assert (row["CorrelationId"], row["GlorfindelRunCommand"]) == ("c-own", "no_isolation")
