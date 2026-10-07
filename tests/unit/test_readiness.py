"""Activation readiness (lot L6): verdict + reasons from Azure, nothing written."""
from __future__ import annotations

from unittest.mock import MagicMock

from glorfindel.readiness import activation_refusal, assess

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def _conn(missing=(), precedence=(), nsg_ok=True, os_type="linux", read_only=False):
    c = MagicMock()
    c.read_only = read_only
    c.check_permissions.return_value = {"ok": True, "missing": [
        {"scope": "rg", "action": a, "used_by": "isolate_vm"} for a in missing]}
    c.check_nsg_access.return_value = (
        {"ok": True, "precedence": list(precedence)} if nsg_ok
        else {"ok": False, "error": "NIC nic and its subnet have no NSG — cannot isolate VM"})
    c.vm_os.return_value = os_type
    return c


def test_all_rights_and_no_bypass_is_ready():
    a = assess(_RID, _conn())
    assert a["verdict"] == "ready" and a["reserve_codes"] == []
    assert [r["level"] for r in a["reasons"]] == ["info"]          # AVNM / Policy not checked


def test_read_only_credentials_are_not_ready():
    assert assess(_RID, _conn(read_only=True))["verdict"] == "not_ready"


def test_no_right_to_isolate_at_all_is_not_ready():
    a = assess(_RID, _conn(missing=[
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/networkSecurityGroups/securityRules/write"]))
    assert a["verdict"] == "not_ready"
    assert "cannot_isolate" in {r["code"] for r in a["reasons"]}


def test_missing_run_command_is_a_reserve_open_sessions_survive():
    a = assess(_RID, _conn(missing=["Microsoft.Compute/virtualMachines/runCommand/action"]))
    assert a["verdict"] == "reserve" and a["reserve_codes"] == ["no_drain"]


def test_rules_fallback_exposes_the_isolation_to_customer_allows():
    a = assess(_RID, _conn(
        missing=["Microsoft.Network/networkInterfaces/write"],
        precedence=[{"rule": "allow-ssh", "action": "isolate_vm"},
                    {"rule": "allow-ssh", "action": "block_suspicious_ip"}]))
    assert a["reserve_codes"] == ["block_may_be_bypassed", "isolation_bypassed", "rules_fallback"]


def test_jit_isolation_ignores_isolation_precedence_but_not_blocks():
    a = assess(_RID, _conn(precedence=[{"rule": "allow-ssh", "action": "isolate_vm"},
                                       {"rule": "allow-https", "action": "block_suspicious_ip"}]))
    assert a["reserve_codes"] == ["block_may_be_bypassed"]


def test_no_nsg_anywhere_still_isolates_but_cannot_block():
    a = assess(_RID, _conn(nsg_ok=False))
    assert a["reserve_codes"] == ["no_nsg_for_blocks"]


def test_windows_has_no_session_drain():
    assert "windows_no_drain" in assess(_RID, _conn(os_type="windows"))["reserve_codes"]


def test_activation_needs_every_reserve_acknowledged():
    a = assess(_RID, _conn(missing=["Microsoft.Compute/virtualMachines/runCommand/action"]))
    assert "no_drain" in activation_refusal(a, [])
    assert activation_refusal(a, ["no_drain"]) is None
    assert "pas prête" in activation_refusal(assess(_RID, _conn(read_only=True)), ["read_only"])


# ── The gate: a VM configured autonomous acts alone only once its readiness allows ──

from glorfindel import escalations, readiness  # noqa: E402
from glorfindel.config import AutonomyConfig, AutonomyRule, GlorfindelConfig  # noqa: E402
from glorfindel.discovery import DiscoveredAsset  # noqa: E402

_NO_DRAIN = ["Microsoft.Compute/virtualMachines/runCommand/action"]


def _asset(rid=_RID):
    return DiscoveredAsset(name=rid.rsplit("/", 1)[-1], resource_id=rid,
                           monitoring_backend="law", last_seen="2026-10-07T08:00:00+00:00")


def _tracker(conn, default="non_disruptive", assets=(), interval_s=1800, override=None):
    cfg = GlorfindelConfig(autonomy=AutonomyConfig(default=default, assets=list(assets)))
    return readiness.ReadinessTracker(conn, interval_s=interval_s, autonomy_override=override,
                                      config_loader=lambda: cfg)


def _cards():
    return [e for e in escalations.pending() if e["escalation_type"] == "readiness_hold"]


def test_a_vm_never_checked_is_held():
    mode, hold = readiness.effective_mode("vm", "non_disruptive")
    assert mode == "human_only" and hold["reason"] == "not_checked"
    assert readiness.effective_mode("vm", "human_only") == ("human_only", {})


def test_a_ready_vm_acts_alone_and_reserves_must_be_acknowledged():
    readiness.record_assessment(assess(_RID, _conn()), _RID)
    assert readiness.effective_mode("vm", "non_disruptive") == ("non_disruptive", {})
    readiness.record_assessment(assess(_RID, _conn(missing=_NO_DRAIN)), _RID)
    mode, hold = readiness.effective_mode("vm", "non_disruptive")
    assert mode == "human_only" and hold["codes"] == ["no_drain"]
    readiness.acknowledge("vm", ["no_drain"], by="test")
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "non_disruptive"


def test_global_default_new_ready_vm_turns_autonomous_without_a_card():
    """The hole: the global default made every VM — current and future — autonomous
    without a readiness check. A new ready VM still needs nothing from the operator."""
    events = _tracker(_conn()).refresh([_asset()])
    assert events == [{"vm": "vm", "event": "activated"}]
    assert readiness.get("vm")["active_since"] and _cards() == []


def test_global_default_new_vm_with_reserves_is_held_with_one_card():
    t = _tracker(_conn(missing=_NO_DRAIN))
    assert t.refresh([_asset()])[0]["event"] == "held"
    t.refresh([_asset()])                                   # next discovery pass
    cards = _cards()
    assert len(cards) == 1 and "no_drain" in cards[0]["reason"]
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "human_only"


def test_confirming_the_reserves_lifts_the_hold_and_closes_the_card():
    t = _tracker(_conn(missing=_NO_DRAIN))
    t.refresh([_asset()])
    readiness.acknowledge("vm", ["no_drain"], by="war-room")
    assert t.refresh([_asset()]) == [{"vm": "vm", "event": "activated"}]
    assert _cards() == []


def test_a_reserve_that_appears_after_activation_puts_the_vm_back_with_an_alert():
    conn = _conn()
    t = _tracker(conn, interval_s=0)                        # re-checked every pass
    t.refresh([_asset()])
    conn.check_permissions.return_value = {"ok": True, "missing": [
        {"scope": "rg", "action": _NO_DRAIN[0], "used_by": "drain"}]}
    assert t.refresh([_asset()])[0]["event"] == "demoted"
    assert "repasse en observation" in _cards()[0]["reason"]
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "human_only"


def test_a_read_error_on_an_active_vm_is_confirmed_before_holding_it():
    """A throttled permissions API must not flap the mode: re-checked on the next pass."""
    conn = _conn()
    t = _tracker(conn, interval_s=0)
    t.refresh([_asset()])
    conn.check_permissions.return_value = {"ok": False, "error": "429 throttled"}
    assert t.refresh([_asset()]) == []                      # still active
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "non_disruptive"
    assert t.refresh([_asset()])[0]["event"] == "demoted"   # seen twice: held


def test_a_vm_in_human_only_is_not_checked():
    conn = _conn()
    t = _tracker(conn, default="human_only")
    assert t.refresh([_asset()]) == []
    conn.check_permissions.assert_not_called()


def test_a_pattern_and_the_session_override_are_gated_too():
    conn = _conn(missing=_NO_DRAIN)
    t = _tracker(conn, default="human_only", assets=[AutonomyRule(match="v*", mode="non_disruptive")])
    assert t.refresh([_asset()])[0]["event"] == "held"
    other = _RID.replace("/vm", "/other")
    t2 = _tracker(conn, default="human_only", override="non_disruptive")
    assert t2.refresh([_asset(other)])[0]["event"] == "held"


def test_going_back_to_human_only_closes_the_card():
    t = _tracker(_conn(missing=_NO_DRAIN))
    t.refresh([_asset()])
    _tracker(_conn(), default="human_only").refresh([_asset()])
    assert _cards() == []


def test_an_aks_cluster_is_held_without_azure_calls_or_card():
    aks = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks"
    conn = _conn()
    assert _tracker(conn).refresh([_asset(aks)])[0]["event"] == "held"
    conn.check_permissions.assert_not_called()
    assert _cards() == []


def test_the_tracker_rechecks_at_the_posture_cadence_only():
    conn = _conn()
    t = _tracker(conn, interval_s=3600)
    t.refresh([_asset()])
    t.refresh([_asset()])
    assert conn.check_permissions.call_count == 1


def test_decide_gate_checks_an_unseen_vm_on_demand():
    """A signal before the first discovery pass (or a VM outside discovery): checked now."""
    gate = readiness.ReadinessGate(_conn())
    assert gate("vm", _RID, "non_disruptive") == ("non_disruptive", {})
    broken = MagicMock(read_only=False)
    broken.check_permissions.side_effect = RuntimeError("boom")
    mode, hold = readiness.ReadinessGate(broken)("other", _RID.replace("/vm", "/other"), "non_disruptive")
    assert mode == "human_only" and hold["reason"] == "not_checked"


# ── Quatrième passe (Q3) : un homonyme n'hérite pas du verdict de l'autre ─────────────

def test_a_homonym_does_not_inherit_ready_or_acknowledged_reserves():
    a = _RID.replace("/vm", "/web")
    b = a.replace("/rg/", "/rg-b/")
    readiness.record_assessment(readiness._verdict("web", []), a)
    readiness._update(a, active_since="t")
    assert readiness.effective_mode(a, "non_disruptive")[0] == "non_disruptive"
    mode, hold = readiness.effective_mode(b, "non_disruptive")
    assert mode == "human_only" and hold["reason"] == "not_checked"      # never checked itself
    readiness.record_assessment(readiness._verdict("web", [readiness._reason("no_drain", "reserve", "x")]), b)
    assert readiness.effective_mode("web", "non_disruptive")[0] == "human_only"   # ambiguous name: held


def test_a_name_keyed_record_is_read_for_its_own_vm_and_migrated():
    import glorfindel.readiness as rd
    rd._STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    rd._write({"vm": {"vm": "vm", "resource_id": _RID, "verdict": "ready", "reserve_codes": [], "reasons": []}})
    assert rd.effective_mode(_RID, "non_disruptive")[0] == "non_disruptive"
    assert rd.effective_mode(_RID.replace("/rg/", "/rg-b/"), "non_disruptive")[0] == "human_only"
    rd.acknowledge(_RID, ["no_drain"], by="test")
    assert rd._key(_RID) in rd._read() and "vm" not in rd._read()


def test_revoke_by_name_matches_the_whole_name_and_every_homonym():
    """`split("--")` cut `web--01` at its first `--`: revoke("web--01") did nothing and
    revoke("web") wiped web--01 (fifth review, C3). On a homonym name, revoke reached
    neither VM while set_asset_mode had switched both (C4)."""
    w01 = _RID.replace("/vm", "/web--01")
    web_a = _RID.replace("/vm", "/web")
    web_b = web_a.replace("/rg/", "/rg-b/")
    for rid, name in ((w01, "web--01"), (web_a, "web"), (web_b, "web")):
        readiness.record_assessment(readiness._verdict(name, []), rid)
        readiness.acknowledge(rid, ["no_drain"], by="t")
    readiness.revoke("web")
    assert not readiness.get(web_a).get("acknowledged") and not readiness.get(web_b).get("acknowledged")
    assert readiness.get(w01)["acknowledged"] == ["no_drain"]
    readiness.revoke("web--01")
    assert not readiness.get(w01).get("acknowledged")
