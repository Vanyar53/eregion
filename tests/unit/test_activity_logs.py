"""AL1 (#225): Azure's Activity Log (`AzureActivity`) as a detection source — detection only.

A fake AzureActivity: rows shaped like the table's (OperationNameValue, Caller,
CallerIpAddress, Claims, _ResourceId, CorrelationId…) handed to the real
AzureActivityDetector through its parent's query (no Azure, no LLM). What is held:
  - a modification of an NSG from outside Glorfindel is dispatched, and escalates;
  - Glorfindel's own writes (its isolation, quarantine, blocks) are not — its identity is
    read (token, AZURE_CLIENT_ID, GLORFINDEL_OWN_CALLERS), never written in code;
  - another caller's write on a rule Glorfindel manages is the gravest case: marked,
    critical, chosen first;
  - no autonomous action follows a control-plane detection, whatever the model says (the
    control-plane guard of `decide`) — `control_plane_change`, never one click;
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
    assert not any("« long »" in n for n in notes)


# ── Glorfindel's own writes ───────────────────────────────────────────────────

def test_own_operations_are_the_rights_its_capabilities_declare():
    ops = activity.own_operations()
    assert "microsoft.network/networksecuritygroups/securityrules/write" in ops
    assert "microsoft.network/networkinterfaces/write" in ops
    assert ROLE_OP.lower() not in ops and "microsoft.compute/snapshots/write" not in ops


def test_glorfindel_own_isolation_is_dropped_an_outsiders_write_kept():
    own = {OWN_APP, OWN_OID}
    kept = activity.prepare_rows([_own_isolation(), _row()], own)
    assert [r["Caller"] for r in kept] == [OUTSIDER]
    assert kept[0]["GlorfindelManaged"] is False and kept[0]["GlorfindelIdentity"] is False


def test_the_caller_is_matched_by_any_of_its_ids_whatever_the_case():
    own = {OWN_APP}
    # The id only in Claims (a rule that projects it), and in capitals.
    from_claims = _row(caller="", corr="c-2", Claims=json.dumps({"appid": OWN_APP.upper()}))
    from_column = _row(caller=OWN_APP.upper(), corr="c-3")
    assert activity.prepare_rows([from_claims, from_column], own) == []


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
    det = _detector({"oid": OWN_OID, "upn": "glorfindel@example.org"})
    assert det.own_identities() == {OWN_APP, OWN_OID, "glorfindel@example.org", "ops@example.org"}
    det.own_identities()
    assert det._credential.calls == 1            # read once


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


def test_a_write_on_glorfindel_rules_is_critical_and_chosen_first(law):
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_row(target=f"{NSG}/securityrules/glorfindel-iso-vm1-nic-vm1-a1b2c3", corr="c-m",
                        ts="2026-10-27T10:00:00Z"),
                   _row(corr="c-n", ts="2026-10-27T10:05:00Z")]       # newer, not Glorfindel's
    p, sent = _poller(_detector(), rule)
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["severity"] == "critical"
    assert sent[0]["raw_signal"]["normalized_signal"]["glorfindel_managed"] is True


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
    # behind the control-plane guard.
    assert not dr.has_recognized_indicator(_row())


# ── decide: never an autonomous action on the control plane ───────────────────

def _signal(**ctx):
    row = activity.prepare_rows([_row()], {OWN_APP})[0]
    return {"event": "detection", "ttp": "T1562.007", "resource_id": VM1,
            "context": {"plane": "control", **ctx},
            "raw_signal": {"detection_source": "azure_activity", "first_result_row": row,
                           "normalized_signal": normalize_row(row)}}


@pytest.mark.parametrize("action", ["isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation"])
def test_the_guard_holds_every_autonomous_action(action):
    from glorfindel.agent import _apply_control_plane_guard
    d = {"action": action, "escalate": False}
    _apply_control_plane_guard(d, _signal())
    assert d["escalate"] is True and d["held_by"] == "control_plane"
    assert RULE_OP in d["escalation_reason"] and OUTSIDER in d["escalation_reason"]
    assert "Détection seule" in d["escalation_reason"]


def test_the_guard_reads_the_plane_or_the_source():
    from glorfindel.agent import _is_control_plane
    assert _is_control_plane({"context": {"plane": "control"}, "raw_signal": {}})
    assert _is_control_plane({"context": {}, "raw_signal": {"detection_source": "azure_activity"}})
    assert not _is_control_plane({"context": {}, "raw_signal": {"detection_source": "azure_monitor"}})


def test_the_guard_names_the_gravest_cases_and_keeps_the_models_reason():
    from glorfindel.agent import _apply_control_plane_guard
    sig = _signal()
    sig["raw_signal"]["normalized_signal"].update(glorfindel_managed=True, glorfindel_identity=True)
    d = {"action": "isolate_vm", "escalate": True, "escalation_reason": "doute du modèle"}
    _apply_control_plane_guard(d, sig)
    assert d["held_by"] == "control_plane"
    assert "règle gérée par Glorfindel" in d["escalation_reason"]
    assert "identité de Glorfindel" in d["escalation_reason"]
    assert d["escalation_reason"].endswith("Le modèle : doute du modèle")


def test_a_data_plane_signal_passes_the_guard_untouched():
    from glorfindel.agent import _apply_control_plane_guard
    d = {"action": "isolate_vm", "escalate": False}
    _apply_control_plane_guard(d, {"context": {}, "raw_signal": {"detection_source": "azure_monitor",
                                                                 "first_result_row": {"MaxWrite": 9e7}}})
    assert d == {"action": "isolate_vm", "escalate": False}


def _llm(action, confidence=0.99):
    tool_call = MagicMock()
    tool_call.function.arguments = json.dumps({
        "reasoning": "x", "confidence": confidence, "action": action, "reversible": True,
        "explanation": "x", "escalate": False, "escalation_reason": "", "suggested_steps": []})
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(tool_calls=[tool_call]))]
    return resp


def _graph(tmp_path, monkeypatch, connector):
    from glorfindel.agent import _build_graph
    from glorfindel.config import AutonomyConfig
    from glorfindel.memory import CycleMemory
    import glorfindel.agent as agent
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir(exist_ok=True)
    monkeypatch.setattr(agent, "_run_investigative_query", lambda ws, q: [])
    return _build_graph(CycleMemory(path=tmp_path / "cycles"), connector, "claude-test",
                        autonomy=AutonomyConfig(default="non_disruptive"))


def _initial(signal):
    return {"signal": signal, "past_cycles": [], "incident": None, "dry_run": False,
            "reasoning": "", "confidence": 0.0, "action": "", "reversible": True,
            "explanation": "", "escalate": False, "escalation_reason": "",
            "suggested_steps": [], "outcome": None}


@pytest.mark.parametrize("action", ["isolate_vm", "block_suspicious_ip", "snapshot"])
def test_an_outside_nsg_change_escalates_and_nothing_acts(tmp_path, monkeypatch, law, action):
    """Fini quand (#225): a fake AzureActivity, an NSG changed from outside → the RulePoller
    dispatches it, the model wants to act at 99 % in non_disruptive — nothing runs, the
    card is `control_plane_change`, never approvable in one click."""
    from glorfindel import escalations
    rule = _shipped("nsg-change-outside-glorfindel")
    law["rows"] = [_own_isolation(), _row(target=f"{NSG}/securityrules/glorfindel-iso-vm1-nic-vm1-a1b2c3")]
    p, sent = _poller(_detector(), rule, VM1)        # one VM watched
    p.poll_once(rule)
    assert len(sent) == 1
    connector = MagicMock()
    connector.dry_run = False
    with patch("litellm.completion", return_value=_llm(action)):
        final = _graph(tmp_path, monkeypatch, connector).invoke(_initial(sent[0]))
    for name in ("isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation"):
        getattr(connector, name).assert_not_called()
    assert final["outcome"]["escalation_type"] == "control_plane_change"
    assert final["held_by"] == "control_plane"
    cards = escalations.pending()
    assert [c["escalation_type"] for c in cards] == ["control_plane_change"]
    assert "règle gérée par Glorfindel" in cards[0]["reason"]
    from eregion_console.api import _approval_refusal
    assert _approval_refusal(cards[0], "vm1")


def test_a_control_plane_detection_attributed_to_a_vm_still_acts_on_nothing(tmp_path, monkeypatch, law):
    """A role assigned on the VM itself: attributed, so the attribution guard lets a snapshot
    through — the control-plane guard does not."""
    rule = _shipped("role-assignment-write")
    law["rows"] = [_row(op=ROLE_OP, corr="c-r",
                        target=f"{VM1}/providers/Microsoft.Authorization/roleAssignments/abc")]
    p, sent = _poller(_detector(), rule, VM1, VM2)
    p.poll_once(rule)
    assert sent[0]["context"]["attribution"] == "asset"
    connector = MagicMock()
    connector.dry_run = False
    with patch("litellm.completion", return_value=_llm("snapshot")):
        final = _graph(tmp_path, monkeypatch, connector).invoke(_initial(sent[0]))
    connector.snapshot.assert_not_called()
    assert final["outcome"]["escalation_type"] == "control_plane_change"


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
    AzureActivity rule, the detection carries its source, and the guard holds it. A
    data-plane detection is unchanged (what the model sees stays the same)."""
    from glorfindel.agent import _apply_control_plane_guard, resolve_attack_started
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
    d = {"action": "isolate_vm", "escalate": False}
    _apply_control_plane_guard(d, out)
    assert d["held_by"] == "control_plane"

    monkeypatch.setattr(AzureMonitorDetector, "poll_alert",
                        lambda self, *a, **k: (5, {"Computer": "vm1", "MaxWrite": 9e7}))
    data = resolve_attack_started({"event": "attack_started", "ttp": "T1486",
                                   "raw_signal": {"detection_timeout_s": 1}})
    assert data["event"] == "detection" and "detection_source" not in data["raw_signal"]
