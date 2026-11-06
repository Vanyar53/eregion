"""AL2 (#598): `restorepoint-by-unexpected-caller`, the sister of the snapshot rule — Azure
Backup excluded, by its public application id, and it alone.

Measured on the bench on 05/11 (ID1's hypothesis A2): an Azure Backup of gondolin goes
through restore points (`RESTOREPOINTS/WRITE`, then `RETRIEVESASURIS`), never through a
snapshot — `snapshot-by-unexpected-caller` does not see it, and no rule read the SAS URLs it
hands out. The shipped rule runs here as written (`kql_subset`) over AzureActivity lines the
test writes, then through the real AzureActivityDetector (Glorfindel's own identity) and the
RulePoller — no Azure, no model. What is held:
  - Azure Backup's lines make no card: its id in Claims or as the Caller, on one line of the
    operation at least (the latest may carry neither);
  - a line that names no one decides nothing: a backup astride the window's edge, a bare line
    ingested alone make no card — anyone else's card comes at the pass where their line lands;
  - the same operations by a human, or by any other principal, make a card — under a
    backup's own correlation id too (a client chooses it);
  - a failure makes none — the operation's latest line is read;
  - RETRIEVESASURIS alone makes one; so does a disk restore point's download access;
  - the card names the operation and the resource, and the caller that decided it — a bare
    latest line, or Azure Backup's, takes the caller another line names;
  - Glorfindel's identity on a restore point is kept, critical — its latest line bare too;
  - the snapshot rule does not change.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from glorfindel.detection_rules import RulePoller, load_config
from glorfindel.detectors import AzureActivityDetector
from glorfindel.providers.azure import activity
from glorfindel.providers.azure.monitor import AzureMonitorDetector

from . import kql_subset

SHIPPED = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
RULE_NAME = "restorepoint-by-unexpected-caller"

# Azure Backup's application (Backup Management Service): public, the same in every tenant
# (Microsoft Learn, « Back up and restore Azure VMs with PowerShell »).
AZURE_BACKUP = "262044b1-e2ce-469f-a196-69ab7ada62d3"

# Placeholders, never real ids.
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
VM1 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm1"
VM2 = f"{SUB}/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm2"
RPC = f"{SUB}/resourcegroups/rg-bench/providers/microsoft.compute/restorepointcollections/rpc-vm1"
RP = f"{RPC}/restorepoints/rp-1"
DRP = f"{RP}/diskrestorepoints/disk-vm1-data_00000000-0000-0000-0000-000000000001"
OWN_APP = "a1111111-b111-c111-d111-e11111111111"
OWN_OID = "a2222222-b222-c222-d222-e22222222222"
OTHER_APP = "b3333333-c333-d333-e333-f33333333333"    # another principal: a pipeline, a tool
HUMAN = "someone@example.org"

_OPS = "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS"
WRITE = f"{_OPS}/RESTOREPOINTS/WRITE"
SAS = f"{_OPS}/RESTOREPOINTS/RETRIEVESASURIS/ACTION"
DISK_SAS = f"{_OPS}/RESTOREPOINTS/DISKRESTOREPOINTS/BEGINGETACCESS/ACTION"
DELETE = f"{_OPS}/RESTOREPOINTS/DELETE"
COLLECTION = f"{_OPS}/WRITE"
TARGET = {WRITE: RP, SAS: RP, DISK_SAS: DRP, DELETE: RP, COLLECTION: RPC}

NOW = datetime.now(timezone.utc)


def _line(op=WRITE, status="Success", caller=HUMAN, appid="", oid="", corr="c-1",
          minutes_ago=5.0, target=None, claims=True):
    """One AzureActivity line, as the table holds it: Claims a JSON string."""
    claim = {"appid": appid, "http://schemas.microsoft.com/identity/claims/objectidentifier": oid}
    return {"Type": "AzureActivity", "TimeGenerated": NOW - timedelta(minutes=minutes_ago),
            "OperationNameValue": op, "ActivityStatusValue": status, "Caller": caller,
            "CallerIpAddress": "203.0.113.7", "Claims": json.dumps(claim) if claims else "",
            "_ResourceId": target or TARGET[op], "ResourceGroup": "rg-bench", "CorrelationId": corr}


def _operation(op, corr, **kw):
    """An operation's lines: Start, then Success a few seconds later."""
    return [_line(op, "Start", corr=corr, minutes_ago=5.0, **kw),
            _line(op, "Success", corr=corr, minutes_ago=4.9, **kw)]


def _backup(op, corr, where="claims"):
    """Azure Backup's lines: its id in Claims (where='claims'), as the Caller ('caller'), or
    on the Start line only, the Success line bare ('start_only')."""
    if where == "claims":
        return _operation(op, corr, caller="", appid=AZURE_BACKUP)
    if where == "caller":
        return _operation(op, corr, caller=AZURE_BACKUP, claims=False)
    return [_line(op, "Start", corr=corr, caller="", appid=AZURE_BACKUP, minutes_ago=5.0),
            _line(op, "Success", corr=corr, caller="", claims=False, minutes_ago=4.9)]


def _shipped_rule():
    cfg = SimpleNamespace(monitoring_backends=[SimpleNamespace(
        name="law-bench", type="azure_monitor", workspace_id="ws-test", endpoint="")])
    return next(r for r in load_config(SHIPPED, glorfindel_cfg=cfg, client_layer=False).rules
                if r.name == RULE_NAME)


def _yaml_rule(name):
    return next(r for r in yaml.safe_load(SHIPPED.read_text())["rules"] if r["name"] == name)


def _iso(row):
    t = row.get("TimeGenerated")
    return {**row, "TimeGenerated": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")} if isinstance(t, datetime) else row


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)


@pytest.fixture()
def table(monkeypatch):
    """The workspace: the rule's query run as written over the lines the test writes."""
    lines: list[dict] = []
    monkeypatch.setattr(AzureMonitorDetector, "run_query",
                        lambda self, query, timespan=None: [_iso(r) for r in kql_subset.run(query, lines, now=NOW)])
    return lines


class _Credential:
    """Glorfindel's token: an application's (its appid and oid)."""

    def get_token(self, _scope):
        import base64

        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return SimpleNamespace(token=f"{b64({'alg': 'none'})}.{b64({'appid': OWN_APP, 'oid': OWN_OID, 'idtyp': 'app'})}.sig")


class _Registry:
    def for_backend(self, _name):
        return [SimpleNamespace(name=r.rsplit("/", 1)[-1], resource_id=r) for r in (VM1, VM2)]


def _cards(lines: list[dict]) -> list[dict]:
    rule = _shipped_rule()
    sent: list = []
    p = RulePoller([rule], sent.append)
    det = AzureActivityDetector("ws-test", credential=_Credential())
    p._detector = lambda _rule: det
    p._registry = _Registry()
    p.poll_once(rule)
    return sent


def _rows(lines: list[dict]) -> list[dict]:
    return kql_subset.run(_yaml_rule(RULE_NAME)["query"], lines, now=NOW)


# ── the rule, shipped ──────────────────────────────────────────────────────────

def test_the_rule_ships_in_the_family_of_the_snapshot_rule():
    r = _shipped_rule()
    assert (r.source, r.ttp, r.enabled, r.workspace_id) == ("azure_activity", "T1578.001", True, "ws-test")
    assert r.auto_apply and r.expected_latency_s == 1200
    # Its two techniques, why it exists and what it does not see — in its description.
    for text in ("T1578.001", "T1530", "A2", "05/11", "Ne voit pas"):
        assert text in r.description, text
    from glorfindel import detection_rules as dr
    assert dr._query_lookback_s(r.query) >= activity.MIN_LOOKBACK_S
    assert "CorrelationId" in r.query and "CallerAppId" in r.query and "CallerObjectId" in r.query


def test_its_card_is_the_control_plane_never_an_action(table):
    table += _operation(WRITE, "c-w")
    [sig] = _cards(table)
    assert sig["context"]["plane"] == "control"
    assert sig["raw_signal"]["detection_source"] == "azure_activity"
    from glorfindel.agent import _control_plane_decision
    d = _control_plane_decision(_initial(sig))
    assert d["escalate"] is True and d["action"] == "" and d["llm_usage"] is None


# ── Azure Backup: no card ─────────────────────────────────────────────────────

@pytest.mark.parametrize("where", ["claims", "caller", "start_only"])
def test_azure_backups_lines_make_no_card(table, where):
    """What the bench showed on 05/11 after a backup: restore points written, their SAS
    retrieved, older ones deleted — every line Azure Backup's."""
    table += [*_backup(WRITE, "b-w1", where), *_backup(WRITE, "b-w2", where),
              *_backup(SAS, "b-s1", where), *_backup(SAS, "b-s2", where),
              *_backup(DELETE, "b-d1", where)]
    assert _rows(table) == []
    assert _cards(table) == []


def test_azure_backup_is_matched_whatever_the_case(table):
    table += _operation(SAS, "b-up", caller="", appid=AZURE_BACKUP.upper())
    assert _cards(table) == []


# ── anyone else: a card ───────────────────────────────────────────────────────

@pytest.mark.parametrize("op", [WRITE, SAS, DISK_SAS])
@pytest.mark.parametrize("who", [
    {"caller": HUMAN, "oid": "c4444444-d444-e444-f444-a44444444444"},       # a human (az login)
    {"caller": OTHER_APP, "appid": OTHER_APP},                               # another principal
    {"caller": "", "appid": OTHER_APP},                                      # its id in Claims only
    {"caller": "", "oid": "c5555555-d555-e555-f555-a55555555555"},           # its object id only
    # Azure Backup's id is matched whole: a Caller that only starts with it is someone else.
    {"caller": f"{AZURE_BACKUP}@example.onmicrosoft.com"},
], ids=["human", "principal", "claims_only", "object_id_only", "backup_id_as_a_prefix"])
def test_the_same_operations_by_anyone_else_make_a_card(table, op, who):
    table += _operation(op, "c-x", **who)
    [sig] = _cards(table)
    assert sig["raw_signal"]["normalized_signal"]["indicator_value"] == op
    assert sig["severity"] == "high"


def test_retrievesasuris_alone_makes_a_card(table):
    """No restore point written in the window (made long before, or by Azure Backup): the
    SAS URLs alone are the exit."""
    table += [*_backup(WRITE, "b-w"), *_operation(SAS, "c-s", caller=HUMAN)]
    [sig] = _cards(table)
    assert sig["raw_signal"]["normalized_signal"]["indicator_value"] == SAS


def test_one_card_per_operation_never_one_per_line(table):
    table += [*_operation(WRITE, "c-1"), *_operation(SAS, "c-2"), *_operation(DISK_SAS, "c-3")]
    assert sorted(s["raw_signal"]["normalized_signal"]["indicator_value"] for s in _cards(table)) == \
        sorted([WRITE, SAS, DISK_SAS])


def test_two_operations_under_one_correlation_id_make_two_cards(table):
    """A correlation id is the client's, and may cover several requests: a restore point
    written, then its SAS URLs retrieved, under the same id — two operations, two cards."""
    table += [*_operation(WRITE, "c-same"), *_operation(SAS, "c-same")]
    assert sorted(s["raw_signal"]["normalized_signal"]["indicator_value"] for s in _cards(table)) == \
        sorted([WRITE, SAS])


@pytest.mark.parametrize("op", [
    "Microsoft.Compute/restorePointCollections/restorePoints/write",
    "Microsoft.Compute/restorePointCollections/restorePoints/retrieveSasUris/action",
])
def test_an_operation_name_in_any_case_is_read(table, op):
    """The case of OperationNameValue varies from one operation to the next (docs/azure.md)."""
    table += [_line(op, "Start", corr="c-case", minutes_ago=5.0, target=RP),
              _line(op, "Success", corr="c-case", minutes_ago=4.9, target=RP)]
    [sig] = _cards(table)
    assert sig["raw_signal"]["normalized_signal"]["indicator_value"] == op


def test_a_backup_in_the_same_window_hides_no_one_else(table):
    table += [*_backup(WRITE, "b-w"), *_backup(SAS, "b-s"), *_operation(SAS, "c-s", caller=HUMAN)]
    [sig] = _cards(table)
    assert sig["raw_signal"]["first_result_row"]["Caller"] == HUMAN


@pytest.mark.parametrize("who", [
    {"caller": HUMAN, "oid": "c4444444-d444-e444-f444-a44444444444"},
    {"caller": "", "appid": OTHER_APP},
    {"caller": OTHER_APP, "claims": False},
], ids=["human", "claims_only", "caller_only"])
def test_a_backup_s_correlation_id_hides_no_one_else(table, who):
    """A correlation id is the client's to choose (`x-ms-correlation-request-id`): someone who
    reads the log retrieves a backup's restore point under the backup's own id, on the same
    restore point. One of the operation's lines names Azure Backup — another names someone
    else: a card."""
    table += [*_backup(SAS, "b-s"),
              _line(SAS, "Start", corr="b-s", minutes_ago=2.0, **who),
              _line(SAS, "Success", corr="b-s", minutes_ago=1.9, **who)]
    assert len(_rows(table)) == 1
    [sig] = _cards(table)
    assert sig["raw_signal"]["normalized_signal"]["indicator_value"] == SAS


# ── a line that names no one decides nothing ───────────────────────────────────

def test_a_backup_astride_the_window_s_edge_makes_no_card(table):
    """Its Start line, Azure Backup's, just out of ago(1h); its Success line bare, in."""
    table += [_line(WRITE, "Start", corr="b-edge", caller="", appid=AZURE_BACKUP, minutes_ago=61.0),
              _line(WRITE, "Success", corr="b-edge", caller="", claims=False, minutes_ago=59.0)]
    assert _rows(table) == []
    assert _cards(table) == []


@pytest.mark.parametrize("op", [WRITE, SAS])
def test_a_bare_success_line_ingested_alone_makes_no_card(table, op):
    """Its Start line not in the workspace yet: lines are not ingested in order."""
    table += [_line(op, "Success", corr="b-late", caller="", claims=False, minutes_ago=2.0)]
    assert _rows(table) == []
    assert _cards(table) == []


def test_anyone_else_s_card_comes_at_the_pass_where_their_line_lands():
    """Only a deferral: a human's operation whose last line is bare. Its Start line names
    them — a card at the pass where it lands, alone or with the rest; once it has left the
    window, its bare line alone makes no second one."""
    query = _yaml_rule(RULE_NAME)["query"]
    start = _line(SAS, "Start", corr="c-late", caller=HUMAN, minutes_ago=61.0)
    bare = _line(SAS, "Success", corr="c-late", caller="", claims=False, minutes_ago=59.0)
    [row] = kql_subset.run(query, [start], now=NOW - timedelta(minutes=58))
    assert (row["Caller"], row["ActivityStatusValue"]) == (HUMAN, "Start")
    [row] = kql_subset.run(query, [start, bare], now=NOW - timedelta(minutes=2))
    assert (row["CorrelationId"], row["Caller"], row["ActivityStatusValue"]) == ("c-late", HUMAN, "Success")
    assert kql_subset.run(query, [start, bare], now=NOW) == []


# ── a failure: no card ────────────────────────────────────────────────────────

@pytest.mark.parametrize("status", ["Failure", "Failed", "failed"])
def test_a_failure_makes_no_card(table, status):
    """Started, then refused (no right, a policy): its latest line is the failure."""
    table += [_line(SAS, "Start", corr="c-f", minutes_ago=5.0),
              _line(SAS, status, corr="c-f", minutes_ago=4.9)]
    assert _cards(table) == []


# ── what it does not read ─────────────────────────────────────────────────────

def test_a_collection_alone_or_a_deletion_is_not_read(table):
    """A collection holds nothing until a restore point is written in it; a deletion takes
    nothing out."""
    table += [*_operation(COLLECTION, "c-c"), *_operation(DELETE, "c-d")]
    assert _cards(table) == []


# ── the card ──────────────────────────────────────────────────────────────────

def test_the_card_names_the_operation_and_the_resource(table):
    table += _operation(DISK_SAS, "c-n", caller=HUMAN)
    [sig] = _cards(table)
    norm = sig["raw_signal"]["normalized_signal"]
    assert norm["indicator_key"] == "control_plane_operation"
    assert (norm["indicator_value"], norm["resource"], norm["caller"]) == (DISK_SAS, DRP, HUMAN)
    from glorfindel.agent import _control_plane_decision
    reason = _control_plane_decision(_initial(sig))["escalation_reason"]
    for text in (DISK_SAS, DRP, HUMAN, "203.0.113.7"):
        assert text in reason, text


def test_a_humans_start_then_a_bare_success_names_the_human(table):
    """The operation's latest line names no one: the card names whoever its Start line
    names — never an empty caller."""
    table += [_line(SAS, "Start", corr="c-h", caller=HUMAN, oid="c4444444-d444-e444-f444-a44444444444",
                    minutes_ago=5.0),
              _line(SAS, "Success", corr="c-h", caller="", claims=False, minutes_ago=4.9)]
    [sig] = _cards(table)
    row = sig["raw_signal"]["first_result_row"]
    assert (row["ActivityStatusValue"], row["Caller"]) == ("Success", HUMAN)
    assert row["CallerObjectId"] == "c4444444-d444-e444-f444-a44444444444"
    assert sig["raw_signal"]["normalized_signal"]["caller"] == HUMAN
    assert sig["severity"] == "high"


@pytest.mark.parametrize("where", ["claims", "caller"])
def test_a_backup_s_latest_line_never_names_the_card(table, where):
    """A backup's correlation id taken up by someone else, Azure Backup's lines the latest
    (and first in the table): the card names the other caller, never Azure Backup."""
    table += [*[{**line, "TimeGenerated": NOW - timedelta(minutes=m)}
                for line, m in zip(_backup(SAS, "b-s", where), (1.0, 0.9))],
              *_operation(SAS, "b-s", caller=HUMAN)]
    [sig] = _cards(table)
    row = sig["raw_signal"]["first_result_row"]
    assert row["Caller"] == HUMAN
    assert AZURE_BACKUP not in (row.get("CallerAppId") or "", row.get("CallerObjectId") or "")


def test_glorfindels_start_then_a_bare_success_is_critical(table):
    """Under Glorfindel's identity, the operation's latest line bare: its Start line names
    Glorfindel — the row carries it, the card is critical."""
    table += [_line(SAS, "Start", corr="c-gb", caller=OWN_OID, appid=OWN_APP, oid=OWN_OID, minutes_ago=5.0),
              _line(SAS, "Success", corr="c-gb", caller="", claims=False, minutes_ago=4.9)]
    [sig] = _cards(table)
    row = sig["raw_signal"]["first_result_row"]
    assert sig["severity"] == "critical"
    assert row["GlorfindelIdentity"] is True
    assert (row["Caller"], row["CallerAppId"], row["CallerObjectId"]) == (OWN_OID, OWN_APP, OWN_OID)


def test_the_reader_s_take_anyif_and_iif():
    """kql_subset: take_anyif keeps only what its predicate keeps (nulls left out); iif
    chooses."""
    rows = [{"Type": "T", "k": 1, "v": None, "p": True}, {"Type": "T", "k": 1, "v": "no", "p": False},
            {"Type": "T", "k": 1, "v": "yes", "p": True}]
    [out] = kql_subset.run("T | summarize V = take_anyif(v, p) by k | extend W = iif(V == \"yes\", 1, 2)", rows)
    assert (out["V"], out["W"]) == ("yes", 1)


def test_glorfindels_identity_on_a_restore_point_is_kept_and_critical(table):
    """Glorfindel never makes a restore point: under its identity, its credential may be in
    other hands (as a snapshot under its identity, AL1)."""
    table += _operation(SAS, "c-g", caller=OWN_OID, appid=OWN_APP, oid=OWN_OID)
    [sig] = _cards(table)
    assert sig["severity"] == "critical"
    assert sig["raw_signal"]["first_result_row"]["GlorfindelIdentity"] is True


# ── the sister rule does not change ───────────────────────────────────────────

# sha256 of `snapshot-by-unexpected-caller` as origin/main shipped it on 06/11 (13e98ec8),
# every key and value: AL2 adds a rule, it does not touch this one (Jonathan, 06/11).
_SNAPSHOT_RULE_SHA256 = "7bf204b6997ac1e6d88e571ed2224bfe45f89bf3c72531d16f4c6ba4bb831cc4"


def test_the_snapshot_rule_does_not_change():
    rule = _yaml_rule("snapshot-by-unexpected-caller")
    digest = hashlib.sha256(json.dumps(rule, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    assert digest == _SNAPSHOT_RULE_SHA256
    # Nor does it read what the sister reads.
    assert "RESTOREPOINT" not in rule["query"].upper()


def _initial(signal):
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": False,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None}
