"""IR1a (#552), the console's side: an identity card carries its plan, « Verify » asks the watch,
the watch reads a fake Graph (tests/unit/fake_graph.py) and notes held, not held or unreadable on
the card's thread. The console never reads Graph: it writes the request, and shows what the watch
wrote — every field escaped (tests/unit/test_console_escaping.py reads the page's script).
"""
from __future__ import annotations

import pytest

from glorfindel.providers.azure import entra, graph
from tests.unit.console_client import console
from tests.unit.fake_graph import FakeGraph

pytest.importorskip("fastapi")

VM = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
APP = "00000000-0000-0000-0000-0000000000c1"
KEY = "00000000-0000-0000-0000-000000000001"
HOSTILE = '<img src=x onerror="fetch(`/api/action/revert/vm1`)">'


def _tenant():
    g = FakeGraph()
    g.apps[APP] = {"id": APP, "appId": APP, "passwordCredentials": [{"keyId": KEY}], "keyCredentials": []}
    return g


def _card(monkeypatch, reader) -> str:
    """An identity card, as the watch writes it: `decide`, then `escalate_to_human`."""
    from glorfindel import agent, escalations
    monkeypatch.setattr(graph, "default_reader", lambda: reader)
    row = entra.prepare_rows([{
        "TimeGenerated": "2026-11-05T10:00:00Z", "EntraKind": "credential", "Result": "success",
        "EntraOperation": "Update application", "CorrelationId": "c-1", "ActorName": HOSTILE,
        "ActorId": "00000000-0000-0000-0000-0000000000b1", "TargetName": HOSTILE, "TargetId": APP,
        "TargetType": "Application", "CredentialAdded": f"[KeyIdentifier={KEY},KeyType=Password]"}], set())[0]
    sig = {"signal_id": "s-1", "resource_id": VM, "severity": "high", "ttp": "T1098.001",
           "context": {"plane": "identity", "attribution": "unattributed"},
           "raw_signal": {"detection_source": "azure_entra", "first_result_row": row}}
    state = agent._identity_decision({"signal": sig, "dry_run": False, "outcome": None})
    agent.escalate_to_human(state)
    (card,) = escalations.pending()
    return card["id"]


def test_the_card_carries_its_plan_and_verify_is_answered_by_the_watch(monkeypatch):
    from glorfindel import escalations
    from glorfindel.identity_checks import run_requested
    tenant = _tenant()
    cid = _card(monkeypatch, tenant)
    card = escalations.pending()[0]
    assert card["escalation_type"] == "identity_change" and card["action"] == ""
    assert card["identity_plan"]["items"][0]["command"] == f"az ad app credential delete --id {APP} --key-id {KEY}"
    assert card["identity_checks"] == []
    assert run_requested(tenant) == []                    # nothing asked: nothing read
    assert tenant.calls[-1][0] == "get" and len(tenant.calls) == 1   # only the plan's read

    r = console().post(f"/api/identity/verify/{cid}", json={})
    assert r.status_code == 200 and r.json()["ok"] is True
    asked = escalations.pending()[0]["identity_check_requested"]
    assert asked == r.json()["requested_at"]
    (out,) = run_requested(tenant)
    assert out["verdict"] == "not_held"
    card = escalations.pending()[0]
    assert [c["verdict"] for c in card["identity_checks"]] == ["not_held"]
    assert "identity_check_requested" not in card

    tenant.apps[APP]["passwordCredentials"] = []          # the human's gesture
    console().post(f"/api/identity/verify/{cid}", json={})
    run_requested(tenant)
    assert [c["verdict"] for c in escalations.pending()[0]["identity_checks"]] == ["not_held", "held"]


def test_graph_unreadable_the_thread_says_unreadable_never_held(monkeypatch):
    from glorfindel import escalations
    from glorfindel.identity_checks import run_requested
    tenant = _tenant()
    cid = _card(monkeypatch, tenant)
    tenant.apps[APP]["passwordCredentials"] = []
    tenant.fail = "right"
    console().post(f"/api/identity/verify/{cid}", json={})
    (out,) = run_requested(tenant)
    assert out["verdict"] == "unreadable" and "droit absent" in out["items"][0]["why"]
    assert escalations.pending()[0]["identity_checks"][-1]["verdict"] == "unreadable"


def test_without_graph_the_card_still_has_its_plan_and_verify_says_unreadable(monkeypatch):
    """H0 today: no right on Graph. The plan is written from the log, what it did not read
    marked; Verify says unreadable."""
    from glorfindel import escalations
    from glorfindel.identity_checks import run_requested
    cid = _card(monkeypatch, graph.NoGraph("droit absent sur Graph (403)"))
    plan = escalations.pending()[0]["identity_plan"]
    assert plan["graph"]["read"] is False and plan["items"][0]["complete"]
    console().post(f"/api/identity/verify/{cid}", json={})
    (out,) = run_requested(graph.NoGraph("droit absent sur Graph (403)"))
    assert out["verdict"] == "unreadable"


def test_verify_only_on_a_pending_identity_card_with_a_plan(monkeypatch):
    from glorfindel import escalations
    c = console()
    assert "not found" in c.post("/api/identity/verify/nope", json={}).json()["error"]
    other = escalations.record(signal_id="x", resource_id=VM, action="isolate_vm",
                               escalation_type="mode_hold", reason="r")
    assert "no identity plan" in c.post(f"/api/identity/verify/{other}", json={}).json()["error"]
    assert "identity_check_requested" not in next(e for e in escalations.pending() if e["id"] == other)


def test_the_console_hands_the_plan_as_text_the_page_escapes(monkeypatch):
    """A name chosen by an attacker reaches the page as text in JSON: the page writes it through
    _attr (test_console_escaping.py), never as markup; it is never in a command."""
    from glorfindel import escalations
    _card(monkeypatch, _tenant())
    plan = escalations.pending()[0]["identity_plan"]
    assert any(HOSTILE in i["what"] for i in plan["items"])
    assert not any(HOSTILE in (i["command"] or "") for i in plan["items"])
    js = (__import__("pathlib").Path(__file__).resolve().parents[2]
          / "eregion_console/static/glorfindel.js").read_text()
    assert "${_attr(i.what)}" in js and "${_attr(value)}" in js


def test_the_page_names_its_verify_action_and_the_bot_shows_no_button(monkeypatch):
    pytest.importorskip("discord")
    from glorfindel import escalations
    from glorfindel.bot import _make_action_button
    _card(monkeypatch, _tenant())
    card = escalations.pending()[0]
    assert _make_action_button(card) is None
    assert any(f"--key-id {KEY}" in s for s in card["suggested_steps"])    # the bot shows the plan
