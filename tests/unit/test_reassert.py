"""Reassertion of isolations and blocks whose rules vanished from Azure (lot L5)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from glorfindel import escalations, readiness, reassert_quarantine
from glorfindel.actions import (
    _load_block_entries, _load_isolation_state, _save_block_state, _save_isolation_state,
)
from glorfindel.config import AutonomyConfig
from glorfindel.reassert import reassert_active

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
_ACT = AutonomyConfig(default="non_disruptive")


@pytest.fixture(autouse=True)
def _vm_is_ready():
    """The VM was checked ready (L6 gate): its configured mode is its effective mode."""
    readiness.record_assessment(readiness._verdict("vm", []), _RID)


def _isolated(**extra):
    _save_isolation_state("vm", {"resource_id": _RID, "isolated_at": "2026-10-06T08:00:00+00:00",
                                 "placements": [], **extra})


def _connector(verify_iso=None, verify_blk=None):
    c = MagicMock()
    c.verify_isolation.return_value = verify_iso or {"verified": True}
    c.verify_block_ip.return_value = verify_blk or {"verified": True}

    def isolated(rid):               # put back: Azure, read again, has the isolation whole (RW3)
        _isolated()
        c.verify_isolation.return_value = {"verified": True}
        return {"status": "isolated"}
    c.isolate_vm.side_effect = isolated

    def blocked(*a, **k):            # put back: Azure, read again, has the block whole (RB1)
        c.verify_block_ip.return_value = {"verified": True}
        return {"status": "blocked"}
    c.block_suspicious_ip.side_effect = blocked
    return c


def test_rules_in_place_nothing_to_do():
    _isolated()
    c = _connector()
    assert reassert_active(c, _ACT) == []
    c.isolate_vm.assert_not_called()


def test_vanished_isolation_is_put_back_once_and_alerted():
    """A `terraform apply` on an NSG with inline rules deletes Glorfindel's rules: the
    state said ISOLATED while nothing was enforced."""
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    report = reassert_active(c, _ACT)
    c.isolate_vm.assert_called_once_with(_RID)
    assert report[0]["outcome"] == "reapplied"
    state = _load_isolation_state("vm")
    assert state["reasserted_at"] and state["isolated_at"] == "2026-10-06T08:00:00+00:00"   # TTL kept
    assert [e["escalation_type"] for e in escalations.pending()] == ["verification_failed"]


def test_vanished_again_is_not_fought():
    """Removed twice: deliberate (a person, or a pipeline that will keep deleting it)."""
    _isolated(reasserted_at="2026-10-06T08:05:00+00:00")
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    report = reassert_active(c, _ACT)
    c.isolate_vm.assert_not_called()
    assert report[0]["outcome"] == "escalated"
    assert "deuxième fois" in escalations.pending()[0]["reason"]


def test_human_only_alerts_without_reapplying():
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    report = reassert_active(c, AutonomyConfig(default="human_only"))
    c.isolate_vm.assert_not_called()
    assert report[0]["outcome"] == "escalated"


def test_a_bypass_is_not_a_missing_rule():
    """Re-applying doesn't fix an allow evaluated before the deny: not put back — said, on a
    card of its own (V-16, SEC4b), never folded into the drift card."""
    _isolated()
    c = _connector({"verified": False, "shadowed_by": [{"rule": "allow-ssh"}]})
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["bypassed"]
    c.isolate_vm.assert_not_called()
    assert [e["escalation_type"] for e in escalations.pending()] == ["bypassed"]


def test_rules_gone_behind_a_bypass_are_said_gone_and_put_back_once():
    """L1B (#355): an isolation bypassed (an older pair, an allow before it) while the rules
    the state records are gone: the bypass on its card, the disappearance on its own —
    said in human_only, put back once outside it, as any rule gone (L1)."""
    _isolated()
    gone = {"verified": False, "method": "nsg_check", "shadowed_by": [{"rule": "allow-ssh"}],
            "missing_rules": ["glorfindel-iso-vm-nic-a", "glorfindel-iso-vm-nic-a-out"]}
    c = _connector(gone)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["bypassed", "escalated"]
    c.isolate_vm.assert_not_called()
    assert sorted(e["action"] for e in escalations.pending()) == ["isolate_vm", "review_bypass"]
    _isolated()
    escalations._STORE.unlink()
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["bypassed", "reapplied"]
    c.isolate_vm.assert_called_once()


# ── V-16 (SEC4b): an isolation or a block bypassed by someone else's allow ──────────────

_ALLOW = {"rule": "allow-ssh", "priority": 150, "direction": "inbound", "ports": "22",
          "nsg": "rg/nsg-subnet", "threat_port_open": True}


def _bypass(*allows):
    return {"verified": False, "method": "nsg_check", "shadowed_by": [dict(a) for a in allows]}


def _bypass_cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "bypassed"
            and (status is None or e["status"] == status)]


def test_a_bypassed_isolation_is_said_once_per_change_and_never_fixed():
    """An allow of someone else's before our deny, on the NIC's or the subnet's NSG: the
    reassertion was silent (V-16). Said once — not at every pass, not again once
    acknowledged — and the rule is never touched (I2): no write at all."""
    _isolated()
    c = _connector(_bypass(_ALLOW))
    for _ in range(3):
        reassert_active(c, _ACT)
    (card,) = _bypass_cards()
    assert card["status"] == "pending" and card["action"] == "review_bypass" and card["resource_id"] == _RID
    assert "allow-ssh" in card["reason"] and "rg/nsg-subnet" in card["reason"] and card["severity"] == "high"
    assert card["occurrences"] == 1 and card["suggested_steps"]
    assert {n for n, *_ in c.mock_calls} <= {"verify_isolation", "recent_changes", "nsg_listing",
                                            "find_altered_quarantines", "find_orphan_rules"}, c.mock_calls
    escalations.resolve(card["id"])                       # acknowledged
    assert reassert_active(c, _ACT) == [] and not _bypass_cards("pending")


def test_a_changed_bypass_is_a_new_card_and_a_holding_isolation_closes_it():
    _isolated()
    c = _connector(_bypass(_ALLOW))
    reassert_active(c, _ACT)
    c.verify_isolation.return_value = _bypass(_ALLOW, {**_ALLOW, "rule": "allow-rdp", "ports": "3389"})
    reassert_active(c, _ACT)
    (now,) = _bypass_cards("pending")
    assert "allow-rdp" in now["reason"] and len(_bypass_cards()) == 2
    c.verify_isolation.return_value = {"verified": False, "uncovered_nics": ["nic-a"]}
    reassert_active(c, AutonomyConfig(default="human_only"))
    assert _bypass_cards("pending") == [now]              # rules gone: precedence unread, kept
    c.verify_isolation.return_value = {"verified": True}
    reassert_active(c, _ACT)
    assert not _bypass_cards("pending") and "bypass_said" not in _load_isolation_state("vm")
    c.verify_isolation.return_value = _bypass(_ALLOW)     # back: a new episode, said again
    reassert_active(c, _ACT)
    assert len(_bypass_cards("pending")) == 1


def test_an_unreadable_precedence_keeps_the_bypass_card():
    _isolated()
    c = _connector(_bypass(_ALLOW))
    reassert_active(c, _ACT)
    c.verify_isolation.return_value = {"verified": None, "precedence_unknown": ["rg/nsg-subnet"]}
    reassert_active(c, _ACT)
    assert len(_bypass_cards("pending")) == 1


def test_a_bypassed_block_is_said_on_its_own_card():
    """Each IP its card; the isolation's card of the same VM is another (SEC2: one per address)."""
    ip = "203.0.113.9"
    _save_block_state("vm", ip, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    _isolated()
    c = _connector(_bypass(_ALLOW), _bypass({**_ALLOW, "direction": "outbound", "ports": "*"}))
    report = reassert_active(c, _ACT)
    assert sorted(r["kind"] for r in report) == ["block", "isolation"]
    cards = _bypass_cards("pending")
    assert len(cards) == 2 and {(e["action_params"] or {}).get("ip") for e in cards} == {None, ip}
    c.block_suspicious_ip.assert_not_called()
    assert _load_block_entries("vm")[0]["bypass_said"]
    c.verify_block_ip.return_value = {"verified": True}
    reassert_active(c, _ACT)
    assert [(e["action_params"] or {}).get("ip") for e in _bypass_cards("pending")] == [None]


@pytest.mark.parametrize("port", [22, None], ids=["ssh", "any port"])
def test_vanished_block_is_put_back_once_with_its_threat_port(port):
    """Its own port, None (any) too: put back whole, the block writes the port it is given into
    its entry (L1P) — a 22 there judged a block of any port on 22 alone."""
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=port)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    report = reassert_active(c, _ACT)
    c.block_suspicious_ip.assert_called_once_with("203.0.113.9", _RID, scope="vm", threat_port=port)
    assert report[0]["outcome"] == "reapplied"
    assert _load_block_entries("vm")[0]["reasserted_at"]


def test_second_removal_is_a_new_card_not_folded_into_the_first():
    """The store merged the second alert into the 're-applied once' card, which kept
    its text and sent no notification (validation run, 2026-10-06)."""
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    reassert_active(c, _ACT)                       # first removal: re-applied
    c.verify_isolation.return_value = {"verified": False, "uncovered_nics": ["nic-a"]}
    reassert_active(c, _ACT)                       # gone again: alert only
    pending = escalations.pending()
    assert len(pending) == 1 and "deuxième fois" in pending[0]["reason"]


def test_a_held_isolation_records_when_it_was_last_verified():
    """Glorfindel must know the real state at time T: every check that holds is dated."""
    _isolated()
    reassert_active(_connector({"verified": True}), _ACT)
    assert _load_isolation_state("vm")["verified_at"]


def test_the_alert_says_who_changed_the_nic():
    _isolated(placements=[{"nic_id": "/subscriptions/s/.../networkInterfaces/nic-a", "kind": "quarantine"}])
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    c.recent_changes.return_value = ["10:41:02 alice@example.com — Create or Update Network Interface"]
    reassert_active(c, AutonomyConfig(default="human_only"))
    assert "alice@example.com" in escalations.pending()[0]["reason"]


def test_one_alert_per_disappearance_not_one_per_minute():
    """human_only + isolation gone: every 60-s cycle used to resolve the card and open
    a new one — a webhook notification per minute, acknowledgements undone (06/10)."""
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    human = AutonomyConfig(default="human_only")
    for _ in range(3):
        reassert_active(c, human)
    assert len(escalations.pending()) == 1
    first = escalations.pending()[0]["id"]
    escalations.resolve(first)                       # the operator acknowledges
    reassert_active(c, human)
    assert escalations.pending() == []               # the ack holds
    c.verify_isolation.return_value = {"verified": True}
    reassert_active(c, human)                        # back in place...
    c.verify_isolation.return_value = {"verified": False, "uncovered_nics": ["nic-a"]}
    reassert_active(c, human)                        # ...gone again: a new episode
    assert len(escalations.pending()) == 1


def test_a_vm_held_by_its_readiness_gets_an_alert_not_a_reapplication():
    """Configured autonomous, but a reserve appeared since: the effective mode is
    human_only, so reassertion alerts instead of putting the isolation back."""
    readiness.record_assessment(readiness._verdict("vm", [
        readiness._reason("no_drain", "reserve", "sessions survive")]), _RID)
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    report = reassert_active(c, _ACT)
    c.isolate_vm.assert_not_called()
    assert report[0]["outcome"] == "escalated"


# ── Un seul écrivain par VM (troisième passe, T2) ─────────────────────────────────────

def test_a_release_in_progress_is_not_put_back():
    """The release removes the NSGs NIC by NIC and clears the state at the end: seen
    halfway, the isolation looked 'removed outside Glorfindel' and was re-isolated."""
    from datetime import datetime, timezone
    _isolated(releasing_at=datetime.now(timezone.utc).isoformat())
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    assert reassert_active(c, _ACT) == []
    c.isolate_vm.assert_not_called()


def test_a_partly_failed_release_is_left_to_the_operator():
    """It kept the state without `partial`: reassertion re-isolated every NIC within a
    minute and overwrote release_failed."""
    _isolated(release_failed=["nic-b: rule left"])
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    assert reassert_active(c, _ACT) == []
    c.isolate_vm.assert_not_called()


def test_reassertion_waits_for_a_running_release_then_sees_it_done():
    """The release holds the VM's lock; the reassertion reads the state again once it
    gets the lock, and finds nothing left to reassert."""
    import threading
    from glorfindel.actions import _clear_isolation_state, _vm_lock
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    entered, done = threading.Event(), threading.Event()

    def release():
        with _vm_lock("vm"):
            entered.set()
            done.wait(2)
            _clear_isolation_state("vm")

    t = threading.Thread(target=release)
    t.start()
    entered.wait(2)
    result = []
    r = threading.Thread(target=lambda: result.append(reassert_active(c, _ACT)))
    r.start()
    done.set()
    t.join(5)
    r.join(5)
    assert result == [[]]
    c.isolate_vm.assert_not_called()


def test_the_vm_lock_is_reentrant():
    from glorfindel.actions import _vm_lock
    with _vm_lock("vm"):
        with _vm_lock("vm"):
            pass


def test_an_unblock_in_progress_is_not_put_back():
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}])
    from glorfindel.actions import _update_block_entry
    from datetime import datetime, timezone
    _update_block_entry("vm", "203.0.113.9", unblocking_at=datetime.now(timezone.utc).isoformat())
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    assert reassert_active(c, _ACT) == []
    c.block_suspicious_ip.assert_not_called()



# ── Quatrième passe (Q1, Q10) ─────────────────────────────────────────────────────────

def test_an_interrupted_release_is_alerted_once_not_forgotten():
    """A release cut off midway (War Room timeout, crash) kept its marker forever: the
    VM was ignored by the reassertion for good, and nothing said so (fourth review, Q10)."""
    _isolated(releasing_at="2026-10-07T08:00:00+00:00")
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    assert reassert_active(c, _ACT)[0]["outcome"] == "escalated"
    assert "interrompue" in escalations.pending()[0]["reason"]
    assert reassert_active(c, _ACT) == []                          # once
    c.isolate_vm.assert_not_called()                               # never re-isolated against the intent


def test_past_the_ttl_an_isolation_is_escalated_never_released():
    """The watch released every isolation older than 4 h — no human, no mode, no
    precondition: a ransomware VM waiting for its restore went back on the network."""
    from glorfindel.reassert import ttl_alerts
    _isolated()                                                     # isolated at 08:00 on 06/10
    out = ttl_alerts(4.0)
    assert [a["vm"] for a in out] == ["vm"]
    card = escalations.pending()[0]
    assert card["escalation_type"] == "ttl_exceeded" and "ne lève pas" in card["reason"]
    assert _load_isolation_state("vm") is not None                 # still isolated
    assert ttl_alerts(4.0) == []                                    # one card, not one per minute


def test_reassertion_skips_a_vm_whose_lock_is_busy():
    import threading
    from glorfindel.actions import _vm_lock
    import glorfindel.reassert as ra
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    held, release = threading.Event(), threading.Event()

    def writer():
        with _vm_lock("vm"):
            held.set()
            release.wait(5)
    t = threading.Thread(target=writer)
    t.start()
    held.wait(2)
    old = ra._LOCK_WAIT_S
    ra._LOCK_WAIT_S = 0.2
    try:
        assert reassert_active(c, _ACT) == []
    finally:
        ra._LOCK_WAIT_S = old
        release.set()
        t.join(5)
    c.verify_isolation.assert_not_called()


# ── L1F : « déjà alerté » seulement une fois la carte écrite ──────────────────────────

class _Died(BaseException):
    """The process dies here (not an Exception: nothing in the code catches it)."""


def test_a_block_that_could_not_be_put_back_keeps_its_card_through_a_crash(monkeypatch):
    """Putting the block back failed (role removed), and the process died on the next state
    write. The "already alerted" marker was written before the card: it survived, the card
    never existed, and every later pass returned on the marker — the block gone in silence
    (L1F, invariant machine). The card comes first now."""
    import glorfindel.actions as actions
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    c.block_suspicious_ip.side_effect = RuntimeError("AuthorizationFailed")
    real = actions._update_block_entry

    def dies_on_the_marker(vm, ip, **fields):
        real(vm, ip, **fields)
        if "drift_alerted_at" in fields:
            raise _Died()
    monkeypatch.setattr(actions, "_update_block_entry", dies_on_the_marker)
    with pytest.raises(_Died):
        reassert_active(c, _ACT)
    monkeypatch.setattr(actions, "_update_block_entry", real)
    cards = [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]
    assert cards and "a échoué" in cards[0]["reason"]
    reassert_active(c, AutonomyConfig(default="human_only"))       # the next pass: still said
    assert [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def test_a_block_gone_in_human_only_keeps_its_card_through_a_crash(monkeypatch):
    """In human_only the order already held — the card, then the marker: kept so (L1F)."""
    import glorfindel.actions as actions
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    real = actions._update_block_entry

    def dies_on_the_marker(vm, ip, **fields):
        real(vm, ip, **fields)
        if "drift_alerted_at" in fields:
            raise _Died()
    monkeypatch.setattr(actions, "_update_block_entry", dies_on_the_marker)
    with pytest.raises(_Died):
        reassert_active(c, AutonomyConfig(default="human_only"))
    c.block_suspicious_ip.assert_not_called()
    assert [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def test_an_isolation_that_could_not_be_put_back_keeps_its_card_through_a_crash(monkeypatch):
    """The same order for an isolation: the card, then "already alerted" (L1F)."""
    import glorfindel.reassert as ra
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    c.isolate_vm.side_effect = RuntimeError("AuthorizationFailed")
    real = ra._mark_alerted

    def dies_on_the_marker(vm, now):
        real(vm, now)
        raise _Died()
    monkeypatch.setattr(ra, "_mark_alerted", dies_on_the_marker)
    with pytest.raises(_Died):
        reassert_active(c, _ACT)
    cards = [e for e in escalations.pending() if e.get("action") == "isolate_vm"]
    assert cards and "a échoué" in cards[0]["reason"]


# ── our quarantine NSGs, whatever the local state says (I1F, #226) ───────────────────

_QNSG = "/subscriptions/s/resourceGroups/rg-sec/providers/Microsoft.Network/networkSecurityGroups/nsg-glorfindel-quarantine-westeurope"
_QNIC = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/vm-nic"
_DENY_IN = ["glorfindel-quarantine-deny-in"]


def _quarantines(*entries):
    """A connector whose quarantine listing reads `entries` in turn: (status, diff), None
    for an empty subscription, or an exception the listing raises. An NSG absent from the
    listing is read again by its id (I1S): not found, here."""
    c = MagicMock()
    c.read_quarantine.return_value = None
    c.verify_isolation.side_effect = AssertionError("no state: no isolation to verify")
    c.find_altered_quarantines.side_effect = [
        e if isinstance(e, Exception) else
        [] if e is None else [{"nsg_id": _QNSG, "nics": [_QNIC], "status": e[0], "diff": list(e[1])}]
        for e in entries]
    return c


def _cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "quarantine_altered"
            and (status is None or e["status"] == status)]


def _http_error(status: int):
    from azure.core.exceptions import HttpResponseError
    exc = HttpResponseError(message=f"({status}) listing refused")
    exc.status_code = status
    return exc


def test_the_watch_pass_reads_the_quarantines_without_any_state():
    """The watch's pass, nothing recorded: the quarantines are read all the same — a state
    lost is what they are read for (the pass used to stop before any Azure call)."""
    from glorfindel import cli
    c = _quarantines(("altered", _DENY_IN))
    report = cli._watch_reassert_pass(c, None)
    c.find_altered_quarantines.assert_called_once()
    assert [r["kind"] for r in report] == ["quarantine"]
    (card,) = _cards("pending")
    assert card["resource_id"] == _QNSG and "vm-nic" in card["reason"] and card["severity"] == "high"
    assert card["suggested_steps"]


def test_the_watch_pass_closes_the_card_once_the_nsg_is_whole_without_any_isolation():
    from glorfindel import cli
    c = _quarantines(("altered", _DENY_IN), ("ok", []))
    cli._watch_reassert_pass(c, None)
    cli._watch_reassert_pass(c, None)
    assert not _cards("pending") and len(_cards()) == 1


def test_the_watch_pass_reads_the_quarantines_with_isolations_recorded_too():
    from glorfindel import cli
    _isolated()
    c = _quarantines(("altered", _DENY_IN))
    c.verify_isolation.side_effect = None
    c.verify_isolation.return_value = {"verified": True}
    cli._watch_reassert_pass(c, "non_disruptive")
    c.verify_isolation.assert_called_once()
    assert len(_cards("pending")) == 1


def test_the_watch_reaches_its_pass_with_no_guard_on_the_local_state():
    """What the behaviour above can't see: the watch's closures. `_reassert` (its timer)
    and `_reassert_pass` (its thread) hand over to `_watch_reassert_pass` without reading
    the local state — a guard there left the quarantines unread (I1F, review)."""
    import ast
    import inspect
    from glorfindel import cli
    tree = ast.parse(inspect.getsource(cli))
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
           and n.name in ("_reassert", "_reassert_pass")}
    assert set(fns) == {"_reassert", "_reassert_pass"}
    for name, fn in fns.items():
        used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | \
            {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
        assert not used & {"active_isolations", "active_blocks", "_load_isolation_state"}, name
    assert any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "_watch_reassert_pass"
               for n in ast.walk(fns["_reassert_pass"]))


@pytest.mark.parametrize("status", [429, 403])
def test_a_listing_that_fails_keeps_the_cards_open(status):
    """The NSGs can't be listed (throttled, the role removed): the cards stay as they are
    — nothing read is not "whole again" — and the pass goes on."""
    from glorfindel import cli
    c = _quarantines(("altered", _DENY_IN), _http_error(status))
    cli._watch_reassert_pass(c, None)
    assert cli._watch_reassert_pass(c, None) == []
    assert len(_cards("pending")) == 1


def test_an_acknowledged_card_stays_closed_while_its_change_stands():
    """Acknowledged (resolved by the operator) with the NSG still altered: no new card at
    every pass — one again only for another change, or after the NSG was whole."""
    from glorfindel.reassert import reassert_pass
    deny_out = ["glorfindel-quarantine-deny-out"]
    c = _quarantines(("altered", _DENY_IN), ("altered", _DENY_IN), ("altered", _DENY_IN),
                     ("altered", deny_out), ("ok", []), ("altered", deny_out))
    reassert_pass(c, _ACT)
    escalations.resolve(_cards("pending")[0]["id"])
    reassert_pass(c, _ACT)
    reassert_pass(c, _ACT)
    assert len(_cards()) == 1 and not _cards("pending")
    reassert_pass(c, _ACT)                            # another change: said
    assert len(_cards()) == 2 and len(_cards("pending")) == 1
    escalations.resolve(_cards("pending")[0]["id"])
    reassert_pass(c, _ACT)                            # whole again: forgotten
    reassert_pass(c, _ACT)                            # the same change, a new episode
    assert len(_cards()) == 3 and len(_cards("pending")) == 1


def test_a_card_is_not_closed_on_an_nsg_that_cannot_be_read():
    """Configuration unreadable (our denies hold, the forensic access unknown): its card
    stays. Gone from the subscription's listing, and not found when read again: closed."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(("altered", _DENY_IN), ("unknown", ["config illisible"]), None)
    reassert_pass(c, _ACT)
    reassert_pass(c, _ACT)
    assert len(_cards("pending")) == 1
    reassert_pass(c, _ACT)
    assert not _cards("pending")


def test_an_unreadable_configuration_is_said_once_not_every_pass(monkeypatch):
    import io
    from rich.console import Console
    from glorfindel import cli, config as cfg
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=200))
    monkeypatch.setattr(cfg, "load_glorfindel_config", MagicMock(side_effect=cfg.ConfigError("broken")))
    seen: dict = {}
    c = _quarantines(None, None, None)
    for _ in range(3):
        cli._watch_reassert_pass(c, None, seen=seen)
    assert out.getvalue().count("config illisible") == 1


# ── a card's NSG absent from the listing is read again before it closes (I1S, #231) ──

class _Calls(list):
    """The fake Azure's calls, by operation (its `chaos` hook sees every one)."""

    def __call__(self, op, phase, write):
        if phase == "before":
            self.append(op)

    def __bool__(self):                 # empty, still the fake's hook (`chaos or …`)
        return True


def _quarantined_world():
    """Our quarantine NSG holding `web-nic`, its NIC's state lost (no isolation recorded),
    its inbound deny removed by someone; the real connector on the fake Azure."""
    from glorfindel.actions import AzureConnector
    from .fake_azure import FakeAzure, key
    calls = _Calls()
    f = FakeAzure(chaos=calls)
    sub = f.add_subnet("rg-net", "vnet", "app", None)
    f.add_vm("rg-app", "web", [{"rg": "rg-app", "name": "web-nic", "ips": ["10.0.0.4"],
                                "subnet": sub, "nsg": None}])
    c = AzureConnector(dry_run=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    q = c._ensure_quarantine_nsg("westeurope", "rg-sec")["nsg_id"]
    f.nics[next(iter(f.nics))]["nsg"] = q
    f.nsgs[key(q)]["rules"].pop("glorfindel-quarantine-deny-in")
    return f, c, key(q), calls


def _said_once(c):
    from glorfindel.reassert import reassert_pass
    reassert_pass(c, None)
    (card,) = _cards("pending")
    return card


@pytest.mark.parametrize("how", ["role removed", "untagged", "both"])
def test_a_card_stays_while_its_nsg_is_out_of_the_listing(how):
    """Said, then out of the listing without an error: the role removed on its group
    (a listing ARM filters by the caller's rights — a hypothesis, to measure on the
    bench), our tag taken off as well as our rules, or both. The NSG is still altered and
    still holds web-nic: the card stays, and no second one comes. Read again once the
    role is back and the rules put back by hand — its tag still off —: closed."""
    from glorfindel import reassert
    f, c, q, _ = _quarantined_world()
    card = _said_once(c)
    if how != "untagged":
        f.unreadable.add(q)
    if how != "role removed":
        del f.nsgs[q]["tags"]["managed-by"]
    for _ in range(2):
        reassert.reassert_pass(c, None)
    assert [e["id"] for e in _cards("pending")] == [card["id"]] and len(_cards()) == 1
    assert q in reassert_quarantine._load_quarantine_alerts()
    f.unreadable.discard(q)
    f.nsgs[q]["rules"]["glorfindel-quarantine-deny-in"] = dict(
        f.nsgs[q]["rules"]["glorfindel-quarantine-deny-out"], name="glorfindel-quarantine-deny-in",
        direction="Inbound")
    reassert.reassert_pass(c, None)
    assert not _cards("pending") and q not in reassert_quarantine._load_quarantine_alerts()


def test_a_card_whose_nsg_cannot_be_read_again_stays():
    """The listing empty, the NSG read again by its id: refused (403) — the card stays."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(("altered", _DENY_IN), None, None)
    c.read_quarantine.side_effect = _http_error(403)
    reassert_pass(c, _ACT)
    reassert_pass(c, _ACT)
    assert len(_cards("pending")) == 1
    c.read_quarantine.assert_called_once_with(_QNSG)
    reassert_pass(c, _ACT)
    assert len(_cards("pending")) == 1


def test_a_card_whose_nsg_is_gone_closes():
    """No card for ever: the NSG deleted (our quarantine taken off its NIC first), read
    again by its id and not found — the card closes, its change is forgotten."""
    from glorfindel import reassert
    f, c, q, _ = _quarantined_world()
    _said_once(c)
    f.nics[next(iter(f.nics))]["nsg"] = None
    assert f.delete_nsg(f.nsgs[q]["id"])
    reassert.reassert_pass(c, None)
    assert not _cards("pending") and not reassert_quarantine._load_quarantine_alerts()


@pytest.mark.parametrize("homonym", [False, True])
def test_a_card_of_another_subscription_stays(homonym):
    """A card on an NSG of another subscription (AZURE_SUBSCRIPTION_ID changed, the same
    ~/.glorfindel): never in this subscription's listing, and never read here — the
    clients run in this one, where its homonym (whole, or none at all) is not it."""
    from glorfindel import reassert
    f, c, q, calls = _quarantined_world()
    other = f.nsgs[q]["id"].replace("/subscriptions/s/", "/subscriptions/other/")
    if homonym:
        c._ensure_quarantine_nsg("westeurope", "rg-sec")        # ours, whole again
    else:
        f.nics[next(iter(f.nics))]["nsg"] = None
        f.delete_nsg(f.nsgs[q]["id"])
    escalations.record(signal_id=f"{reassert_quarantine._QUARANTINE_PREFIX}other-1", resource_id=other,
                       action="restore_quarantine_nsg", escalation_type="quarantine_altered",
                       reason="altered", severity="high")
    calls.clear()
    reassert.reassert_pass(c, None)
    (card,) = _cards("pending")
    assert card["resource_id"] == other and "nsg.get" not in calls


def _warnings(caplog, text: str) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.name == "glorfindel.reassert" and r.levelname == "WARNING" and text in r.getMessage()]


@pytest.mark.parametrize("acknowledged", [False, True])
def test_a_card_of_another_subscription_is_said_once_never_read(monkeypatch, caplog, acknowledged):
    """A card — or a change acknowledged — on an NSG of another subscription: filtered
    before `read_quarantine`, never read, kept, and said ONCE (ISU, #264). It used to be
    handed to the reader, refused there, and a warning written at every pass, without end.
    Its name as Azure wrote it, not the lowercase key of the acknowledgement."""
    import logging
    from glorfindel import reassert
    monkeypatch.setattr(reassert_quarantine, "_SAID_ELSEWHERE", set())
    f, c, q, calls = _quarantined_world()
    other = ("/subscriptions/other/resourceGroups/RG-Sec/providers/Microsoft.Network/networkSecurityGroups/"
             "NSG-Glorfindel-Quarantine-WestEurope")
    e = escalations.record(signal_id=f"{reassert_quarantine._QUARANTINE_PREFIX}other-1", resource_id=other,
                           action="restore_quarantine_nsg", escalation_type="quarantine_altered",
                           reason="altered", severity="high")
    if acknowledged:
        escalations.resolve(e)
        reassert_quarantine._save_quarantine_alerts({other.lower(): f"{reassert_quarantine._QUARANTINE_PREFIX}other-1"})
    read = MagicMock(side_effect=c.read_quarantine)
    monkeypatch.setattr(c, "read_quarantine", read)
    caplog.set_level(logging.WARNING, logger="glorfindel.reassert")
    for _ in range(3):
        reassert.reassert_pass(c, None)
    assert not [a for a in read.call_args_list if "/subscriptions/other/" in a.args[0]]
    said = _warnings(caplog, "NSG-Glorfindel-Quarantine-WestEurope")
    assert len(said) == 1 and "other" in said[0], [r.getMessage() for r in caplog.records]
    assert not _warnings(caplog, "nsg-glorfindel-quarantine-westeurope is in")
    if acknowledged:
        assert other.lower() in reassert_quarantine._load_quarantine_alerts()      # kept, not forgotten
        return
    assert other in [x["resource_id"] for x in _cards("pending")]        # kept
    escalations.resolve(e)                                              # closed by the operator:
    reassert.reassert_pass(c, None)                                     # nothing left to say,
    escalations.record(signal_id=f"{reassert_quarantine._QUARANTINE_PREFIX}other-2", resource_id=other,
                       action="restore_quarantine_nsg", escalation_type="quarantine_altered",
                       reason="altered", severity="high")
    reassert.reassert_pass(c, None)                                     # a new card: said again
    assert len(_warnings(caplog, "NSG-Glorfindel-Quarantine-WestEurope")) == 2


def test_a_card_whose_nsg_is_refused_warns_at_every_pass_in_its_case(monkeypatch, caplog):
    """The 403 of an NSG of this subscription is a real state: said at every pass, unlike
    another subscription's (ISU, #264). An acknowledged change alone names its NSG as Azure
    wrote it, not by the lowercase key it is acknowledged under."""
    import logging
    from glorfindel import reassert
    monkeypatch.setattr(reassert_quarantine, "_SAID_ELSEWHERE", set())
    f, c, q, _ = _quarantined_world()
    cased = "NSG-Glorfindel-Quarantine-WestEurope"
    nsg = f.nsgs.pop(q)
    nsg["id"] = nsg["id"].rsplit("/", 1)[0] + "/" + cased
    f.nsgs[q] = nsg
    f.nics[next(iter(f.nics))]["nsg"] = nsg["id"]
    escalations.resolve(_said_once(c)["id"])                             # acknowledged
    assert q in reassert_quarantine._load_quarantine_alerts()
    f.unreadable.add(q)
    caplog.set_level(logging.WARNING, logger="glorfindel.reassert")
    for _ in range(3):
        reassert.reassert_pass(c, None)
    assert len(_warnings(caplog, f"{cased} not read again")) == 3, [r.getMessage() for r in caplog.records]
    assert q in reassert_quarantine._load_quarantine_alerts()


def test_only_a_missing_card_nsg_is_read_again():
    """The cost (no `get` of every NSG at every pass): a card whose NSG is listed is
    judged on the listing; the NSG of a card the listing doesn't show is read once."""
    from glorfindel.reassert import reassert_pass
    f, c, q, calls = _quarantined_world()
    calls.clear()
    _said_once(c)
    reassert_pass(c, None)
    assert "nsg.get" not in calls
    f.unreadable.add(q)
    calls.clear()
    reassert_pass(c, None)
    assert calls.count("nsg.get") == 1


def test_an_acknowledged_change_is_forgotten_once_its_nsg_is_gone():
    """Acknowledged, then the NSG deleted while out of the listing: its change is
    forgotten. Made again by an isolation and altered the same way, it is said — the
    acknowledgement of a deleted NSG doesn't silence the next one."""
    from glorfindel import reassert
    f, c, q, _ = _quarantined_world()
    escalations.resolve(_said_once(c)["id"])
    f.nics[next(iter(f.nics))]["nsg"] = None
    assert f.delete_nsg(f.nsgs[q]["id"])
    reassert.reassert_pass(c, None)
    assert not reassert_quarantine._load_quarantine_alerts()
    rid = c._ensure_quarantine_nsg("westeurope", "rg-sec")["nsg_id"]
    f.nics[next(iter(f.nics))]["nsg"] = rid
    f.nsgs[q]["rules"].pop("glorfindel-quarantine-deny-in")
    reassert.reassert_pass(c, None)
    assert len(_cards("pending")) == 1


def test_a_reread_keeps_to_the_clients_subscription_and_never_in_dry_run():
    """The connector's own guard: another subscription raises before any call; in
    dry-run, nothing is read (the card stays)."""
    from glorfindel.actions import AzureConnector
    from glorfindel.response.policy import WrongSubscriptionError
    f, c, q, calls = _quarantined_world()
    calls.clear()
    with pytest.raises(WrongSubscriptionError):
        c.read_quarantine(f.nsgs[q]["id"].replace("/subscriptions/s/", "/subscriptions/other/"))
    assert calls == []
    assert c.read_quarantine(f.nsgs[q]["id"])["status"] == "altered"
    with pytest.raises(RuntimeError):
        AzureConnector(dry_run=True).read_quarantine(f.nsgs[q]["id"])


# ── L2Q (#331): a change that comes back is said again, whatever the file kept ───────────

_FORENSIC = _DENY_IN + ["glorfindel-quarantine-forensic-in"]


def _alerts_unwritable(monkeypatch):
    """quarantine_alerts.json can't be written (a full disk) — every other write goes
    through. Returns what gives the disk back."""
    from glorfindel import actions
    real = actions._atomic_write_text

    def write(path, text):
        if str(path).endswith("quarantine_alerts.json"):
            raise OSError(28, "No space left on device")
        real(path, text)
    monkeypatch.setattr(actions, "_atomic_write_text", write)
    return lambda: monkeypatch.setattr(actions, "_atomic_write_text", real)


def test_a_change_that_comes_back_after_its_record_was_lost_is_said_again(monkeypatch):
    """Seed 101 (L2Q, #331): change A said; a forensic access added makes change B — A's
    card closed, B's written, but not quarantine_alerts.json (a full disk): it keeps A. The
    access taken off, the diff is A's again: said again — the file read « A said, or
    acknowledged » left the NSG stripped with no card. Glorfindel's closures say so (a note);
    the change, once said, is not said again at every pass."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(*[("altered", d) for d in (_DENY_IN, _FORENSIC, _DENY_IN, _DENY_IN)])
    reassert_pass(c, _ACT)
    a = _cards("pending")[0]["signal_id"]
    give_back = _alerts_unwritable(monkeypatch)
    reassert_pass(c, _ACT)
    give_back()
    assert reassert_quarantine._load_quarantine_alerts() == {_QNSG.lower(): a}     # the file kept A
    reassert_pass(c, _ACT)
    (card,) = _cards("pending")
    assert card["signal_id"] == a and "glorfindel-quarantine-deny-in" in card["reason"]
    assert len(_cards()) == 3 and all(e.get("resolution") for e in _cards("resolved"))
    reassert_pass(c, _ACT)
    assert len(_cards()) == 3 and len(_cards("pending")) == 1


def test_a_change_whose_card_could_not_be_written_leaves_the_former_unsilenced(monkeypatch):
    """Change A said; B: B's card not written (the escalations store refused). A's card was
    closed first, and nothing said the NSG until the pass came back; it is closed only in
    B's write now, refused with it: A's card still waits (L1A). Back to A, with the file
    still saying A: said — A's own card, never silenced by the file."""
    from glorfindel import cli
    c = _quarantines(*[("altered", d) for d in (_DENY_IN, _FORENSIC, _DENY_IN)])
    cli._watch_reassert_pass(c, None)
    a = _cards("pending")[0]["signal_id"]
    real = escalations.record
    monkeypatch.setattr(escalations, "record", MagicMock(side_effect=OSError(28, "No space left on device")))
    cli._watch_reassert_pass(c, None)
    monkeypatch.setattr(escalations, "record", real)
    assert [e["signal_id"] for e in _cards("pending")] == [a]
    assert reassert_quarantine._load_quarantine_alerts() == {_QNSG.lower(): a}
    cli._watch_reassert_pass(c, None)
    (card,) = _cards("pending")
    assert card["signal_id"] == a


def test_only_the_operators_last_word_silences_a_change(monkeypatch):
    """A acknowledged; B said, its record lost (the file keeps A), B acknowledged; back to A.
    The operator's last word was on B, not on this A: said again. Then A acknowledged, and
    standing: never said again."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(*[("altered", d) for d in (_DENY_IN, _FORENSIC, _DENY_IN, _DENY_IN, _DENY_IN)])
    reassert_pass(c, _ACT)
    escalations.resolve(_cards("pending")[0]["id"])                     # the operator
    give_back = _alerts_unwritable(monkeypatch)
    reassert_pass(c, _ACT)
    give_back()
    (b,) = _cards("pending")
    escalations.resolve(b["id"])                                        # the operator
    reassert_pass(c, _ACT)
    (card,) = _cards("pending")
    assert card["signal_id"] != b["signal_id"] and "forensic" not in card["reason"]
    escalations.resolve(card["id"])
    reassert_pass(c, _ACT)
    reassert_pass(c, _ACT)
    assert not _cards("pending") and len(_cards()) == 3


def test_an_acknowledgement_is_read_on_its_own_nsg_only():
    """Two quarantine NSGs altered: the first's change acknowledged stays silent while the
    second's card, written after, stays pending — the latest card of each NSG is read,
    not the latest of all."""
    from glorfindel.reassert import reassert_pass
    other = _QNSG.replace("westeurope", "northeurope")
    c = MagicMock()
    c.read_quarantine.return_value = None
    c.verify_isolation.side_effect = AssertionError("no state")
    c.find_altered_quarantines.return_value = [
        {"nsg_id": n, "nics": [_QNIC], "status": "altered", "diff": list(_DENY_IN)} for n in (_QNSG, other)]
    c.find_altered_quarantines.side_effect = None
    reassert_pass(c, _ACT)
    first = next(e for e in _cards("pending") if e["resource_id"] == _QNSG)
    escalations.resolve(first["id"])                                    # the operator
    for _ in range(2):
        reassert_pass(c, _ACT)
    assert len(_cards()) == 2 and [e["resource_id"] for e in _cards("pending")] == [other]


def test_a_change_brought_back_by_an_unreadable_config_is_said_and_so_is_the_config(monkeypatch):
    """The real connector on the fake Azure. Our inbound deny removed: change A said. A
    forensic access configured: change B, the file not written. The configuration then
    unreadable: the forensic access can't be checked, the diff reads A again — the NSG
    still stripped is said (never « config unreadable, nothing to say », A0), and the
    configuration is said itself, once (SEC4b)."""
    import io
    from rich.console import Console
    from glorfindel import cli, config as cfg
    f, c, q, _ = _quarantined_world()
    forensic: list = []

    def sources():
        if forensic is None:
            raise cfg.ConfigError("broken")
        return list(forensic)
    monkeypatch.setattr(c, "_forensic_sources", sources)
    monkeypatch.setattr(c, "_forensic_ports", lambda: [22])
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=200))
    seen: dict = {}
    cli._watch_reassert_pass(c, None, seen=seen)
    a = _cards("pending")[0]["signal_id"]
    forensic.append("10.9.9.9")
    give_back = _alerts_unwritable(monkeypatch)
    cli._watch_reassert_pass(c, None, seen=seen)
    give_back()
    assert "forensic" in _cards("pending")[0]["reason"]
    forensic = None
    monkeypatch.setattr(cfg, "load_glorfindel_config", MagicMock(side_effect=cfg.ConfigError("broken")))
    for _ in range(2):
        cli._watch_reassert_pass(c, None, seen=seen)
    (card,) = _cards("pending")
    assert card["signal_id"] == a and card["resource_id"].lower() == q
    assert out.getvalue().count("config illisible") == 1


# ── RB1 (#321): a merged block put back whole, and said exactly ─────────────────────────

def _merged(**extra):
    """A `block_perimeter` then a `block` of one IP: one entry, `scoped: false`."""
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg-subnet", nsg_scope="subnet",
                      rule="glorfindel-block-203-0-113-9", scoped=False, threat_port=22)
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r", "nic_id": "n"}], **extra)


def _block_cards():
    return [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def test_a_merged_block_puts_back_its_perimeter_and_its_vms_rules():
    """The perimeter alone was put back: a VM rule turned into an allow stayed so (RB1)."""
    _merged()
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"], "open_nics": ["nic-b"]})
    report = reassert_active(c, _ACT)
    assert [call.kwargs["scope"] for call in c.block_suspicious_ip.call_args_list] == ["subnet", "vm"]
    assert report[0]["outcome"] == "reapplied" and "reposé une fois" in _block_cards()[0]["reason"]


def test_a_block_put_back_that_still_doesnt_hold_is_never_said_put_back():
    """Written again, Azure read again: what still doesn't hold is said, never « reposé »;
    once said, the next passes are quiet until it holds (one card per episode)."""
    _merged()
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"], "open_nics": ["nic-b"]})
    c.block_suspicious_ip.side_effect = None                 # Azure still has the rule turned
    report = reassert_active(c, _ACT)
    (card,) = _block_cards()
    assert report[0]["outcome"] == "partial", report
    assert "reposé" not in card["reason"] and "n'est plus bloquée sur nic-b" in card["reason"], card["reason"]
    assert reassert_active(c, _ACT) == [] and len(_block_cards()) == 1
    c.verify_block_ip.return_value = {"verified": True}
    reassert_active(c, _ACT)
    assert not _load_block_entries("vm")[0].get("drift_alerted_at")


@pytest.mark.parametrize("held", [{"held_by_perimeter": ["nic-a"], "perimeter_rule": "glorfindel-block-203-0-113-9"},
                                  {}])
def test_rules_gone_while_the_ip_stays_blocked_are_said_so(held):
    """Its own rules gone, the IP still cut off — by the perimeter, or by the quarantine
    (`held_missing`): « l'IP n'est plus bloquée » was said of it."""
    _merged()
    c = _connector(verify_blk={"verified": True, "held_missing": ["r", "r-out"], **held})
    reassert_active(c, AutonomyConfig(default="human_only"))
    reason = _block_cards()[0]["reason"]
    assert "n'est plus bloquée" not in reason and "l'IP reste bloquée" in reason, reason
    assert ("nic-a par la règle de périmètre" in reason) is bool(held), reason
    c.block_suspicious_ip.assert_not_called()


def test_a_write_that_failed_is_never_said_put_back_even_read_whole():
    """RB1, review: putting back the perimeter failed, the VM's rules were written, and
    Azure read the block whole — « reposé une fois » was said, the error swallowed. A
    write that failed is said, whatever the reading."""
    _merged()
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"], "open_nics": ["nic-b"]})

    def write(ip, rid, scope="vm", **k):
        if scope == "subnet":
            raise RuntimeError("(AuthorizationFailed) nsg-subnet")
        c.verify_block_ip.return_value = {"verified": True}
        return {"status": "blocked"}
    c.block_suspicious_ip.side_effect = write
    report = reassert_active(c, _ACT)
    (card,) = _block_cards()
    assert report[0]["outcome"] == "partial", report
    assert "reposé" not in card["reason"] and "AuthorizationFailed" in card["reason"], card["reason"]


# ── L2C (#343): the other cards of the reassertion, said again when a change comes back ──

def _unwritable(monkeypatch, part: str):
    """The local state files whose path holds `part` can't be written (a full disk) —
    every other write goes through. Returns what gives the disk back."""
    from glorfindel import actions
    real = actions._atomic_write_text

    def write(path, text):
        if part in str(path):
            raise OSError(28, "No space left on device")
        real(path, text)
    monkeypatch.setattr(actions, "_atomic_write_text", write)
    return lambda: monkeypatch.setattr(actions, "_atomic_write_text", real)


_IP = "203.0.113.9"
_RDP = {**_ALLOW, "rule": "allow-rdp", "ports": "3389"}
_STATE_DIR = {"isolation": "/isolation/", "block": "/blocks/"}


def _bypassed(kind: str, *allows):
    """An isolation, or a block of _IP, that `allows` pass before."""
    c = _connector()
    if kind == "isolation":
        _isolated()
    else:
        _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)
    _read(c, kind, *allows)
    return c


def _read(c, kind: str, *allows) -> None:
    """What the next verification reads: `allows` before our deny, or (none) it holds."""
    v = _bypass(*allows) if allows else {"verified": True}
    (c.verify_isolation if kind == "isolation" else c.verify_block_ip).return_value = v


def _mark(kind: str):
    return (_load_isolation_state("vm") if kind == "isolation" else _load_block_entries("vm")[0]).get("bypass_said")


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_bypass_that_comes_back_after_its_mark_was_kept_is_said_again(monkeypatch, kind):
    """L2C: a bypass said (A); it holds again — the card closes, with Glorfindel's note — but
    the mark can't be taken off (a full disk): it keeps A. The same allow back: the mark read
    « A said, or acknowledged » left the bypass with no card. Said again; and once said,
    not at every pass."""
    c = _bypassed(kind, _ALLOW)
    reassert_active(c, _ACT)
    (a,) = _bypass_cards("pending")
    _read(c, kind)
    give_back = _unwritable(monkeypatch, _STATE_DIR[kind])
    reassert_active(c, _ACT)                                  # not written: logged
    give_back()
    assert not _bypass_cards("pending") and _bypass_cards("resolved")[0]["resolution"]
    assert _mark(kind) == a["signal_id"]                      # the mark kept A
    _read(c, kind, _ALLOW)
    for _ in range(2):
        reassert_active(c, _ACT)
    (card,) = _bypass_cards("pending")
    assert card["signal_id"] == a["signal_id"] and len(_bypass_cards()) == 2


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_bypass_back_to_its_former_change_closes_the_stale_card(monkeypatch, kind):
    """A said; B (another allow too): A's card closed, B's written, the mark not (it keeps A).
    Back to A: B's card no longer says what passes — closed, with a note — and A is said.
    Then A acknowledged by the operator: never said again while it stands."""
    c = _bypassed(kind, _ALLOW)
    reassert_active(c, _ACT)
    (a,) = _bypass_cards("pending")
    _read(c, kind, _ALLOW, _RDP)
    give_back = _unwritable(monkeypatch, _STATE_DIR[kind])
    reassert_active(c, _ACT)                                  # not written: logged
    give_back()
    (b,) = _bypass_cards("pending")
    assert "allow-rdp" in b["reason"] and _mark(kind) == a["signal_id"]
    _read(c, kind, _ALLOW)
    reassert_active(c, _ACT)
    (card,) = _bypass_cards("pending")
    assert card["signal_id"] == a["signal_id"] and "allow-rdp" not in card["reason"]
    assert all(e.get("resolution") for e in _bypass_cards("resolved"))
    escalations.resolve(card["id"])                           # the operator
    for _ in range(2):
        reassert_active(c, _ACT)
    assert not _bypass_cards("pending") and len(_bypass_cards()) == 3


def test_the_operators_word_on_another_bypass_does_not_silence_this_one(monkeypatch):
    """A said; B said, the mark kept A; the operator closes B (its allow gone, say). Back to
    A: the operator's last word was on B, not on A — said again."""
    c = _bypassed("isolation", _ALLOW)
    reassert_active(c, _ACT)
    _read(c, "isolation", _ALLOW, _RDP)
    give_back = _unwritable(monkeypatch, "/isolation/")
    reassert_active(c, _ACT)                                  # not written: logged
    give_back()
    (b,) = _bypass_cards("pending")
    escalations.resolve(b["id"])                              # the operator
    _read(c, "isolation", _ALLOW)
    reassert_active(c, _ACT)
    (card,) = _bypass_cards("pending")
    assert "allow-rdp" not in card["reason"]


def test_a_bypass_acknowledgement_is_read_on_its_own_card_only():
    """The isolation's bypass acknowledged; the block's of the same VM said after it, still
    pending: the latest card of the isolation's own is read — it stays silent."""
    c = _bypassed("isolation", _ALLOW)
    reassert_active(c, _ACT)
    (iso,) = _bypass_cards("pending")
    escalations.resolve(iso["id"])                            # the operator
    _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    _read(c, "block", _ALLOW)
    for _ in range(2):
        reassert_active(c, _ACT)
    assert [(e["action_params"] or {}).get("ip") for e in _bypass_cards("pending")] == [_IP]
    assert len(_bypass_cards()) == 2


def _broken(name: str) -> None:
    from glorfindel import actions
    actions._ISOLATION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    (actions._ISOLATION_STATE_DIR / name).write_text('{"resource_id": ')


def _state_cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "state_unreadable"
            and (status is None or e["status"] == status)]


def test_an_unreadable_state_that_comes_back_after_its_record_was_kept_is_said_again(monkeypatch):
    """L2C: a state file unreadable, said; it reads again — the card closes, with its note —
    but state_alerts.json can't be written (a full disk) and keeps that set. The same file
    unreadable again: read « said, or acknowledged » — no card. Said again, once."""
    from glorfindel import actions
    from glorfindel.reassert_cards import _load_alerts, say_unreadable_states
    _broken("a--00000000.json")
    say_unreadable_states([])
    (a,) = _state_cards("pending")
    (actions._ISOLATION_STATE_DIR / "a--00000000.json").unlink()
    give_back = _unwritable(monkeypatch, "state_alerts.json")
    say_unreadable_states([])
    give_back()
    assert not _state_cards("pending") and _load_alerts() == {"unreadable_states": a["signal_id"]}
    _broken("a--00000000.json")
    for _ in range(2):
        say_unreadable_states([])
    (card,) = _state_cards("pending")
    assert card["signal_id"] == a["signal_id"] and len(_state_cards()) == 2


def test_an_unreadable_set_back_to_its_former_files_is_said_again(monkeypatch):
    """A (one file) said; B (a second file too): A's card closed, B's written, the record
    not (it keeps A). The second file read again: back to A — B's card closed, with its
    note, and A said, not read « said » from the record. The operator then acknowledges
    A: never said again while it stands."""
    from glorfindel import actions
    from glorfindel.reassert_cards import say_unreadable_states
    _broken("a--00000000.json")
    say_unreadable_states([])
    (a,) = _state_cards("pending")
    _broken("b--00000000.json")
    give_back = _unwritable(monkeypatch, "state_alerts.json")
    say_unreadable_states([])
    give_back()
    (b,) = _state_cards("pending")
    assert b["signal_id"] != a["signal_id"]
    (actions._ISOLATION_STATE_DIR / "b--00000000.json").unlink()
    say_unreadable_states([])
    (card,) = _state_cards("pending")
    assert card["signal_id"] == a["signal_id"] and all(e.get("resolution") for e in _state_cards("resolved"))
    escalations.resolve(card["id"])                           # the operator
    for _ in range(2):
        say_unreadable_states([])
    assert not _state_cards("pending") and len(_state_cards()) == 3


def _left(*rules):
    """The block of _IP on vm, whose placement left `rules` (I4A) — read back as the pass does."""
    from glorfindel.actions import _update_block_entry
    if not _load_block_entries("vm"):
        _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)
    left = [{"nsg": "rg/nsg", "rule": r, "to": "10.0.0.9", "on": "other", "kind": "turned"} for r in rules]
    _update_block_entry("vm", _IP, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r", "left": left}])
    return _load_block_entries("vm")[0]


def _left_cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "rule_left"
            and (status is None or e["status"] == status)]


def test_a_changed_set_of_left_rules_gets_its_own_card():
    """I4A's card names the rules a block left; another set left since (the block written
    again) was folded into the former card by the store, which kept naming the former
    rules. The former card closes, with a note; the new set has its own card."""
    from glorfindel.reassert_cards import say_left
    say_left("vm", _RID, _IP, _left("glorfindel-block-a"), [], _RID)
    say_left("vm", _RID, _IP, _left("glorfindel-block-b"), [], _RID)
    (card,) = _left_cards("pending")
    assert "glorfindel-block-b" in card["reason"] and "glorfindel-block-a" not in card["reason"]
    assert _left_cards("resolved")[0]["resolution"]


def test_left_rules_back_to_a_set_already_said_are_said_again(monkeypatch):
    """A said; B said, its mark not written (a full disk: left_said keeps A); back to A —
    read « said, or acknowledged » from the mark, with B's card naming rules no longer
    left. B closed, A said again; the operator acknowledges A: never said again while it
    stands."""
    from glorfindel.reassert_cards import say_left
    say_left("vm", _RID, _IP, _left("glorfindel-block-a"), [], _RID)
    (a,) = _left_cards("pending")
    entry = _left("glorfindel-block-b")
    give_back = _unwritable(monkeypatch, "/blocks/")
    with pytest.raises(OSError):
        say_left("vm", _RID, _IP, entry, [], _RID)
    give_back()
    assert _load_block_entries("vm")[0]["left_said"] == a["signal_id"]
    say_left("vm", _RID, _IP, _left("glorfindel-block-a"), [], _RID)
    (card,) = _left_cards("pending")
    assert card["signal_id"] == a["signal_id"] and "glorfindel-block-b" not in card["reason"]
    escalations.resolve(card["id"])                           # the operator
    for _ in range(2):
        say_left("vm", _RID, _IP, _left("glorfindel-block-a"), [], _RID)
    assert not _left_cards("pending")


def test_left_rules_acknowledged_are_read_on_their_own_block_only():
    """Two blocks of the VM, each with rules it left: the first's card acknowledged, the
    second's said after it and still pending — the latest card of the first block's own
    is read: it stays silent (L2C, review)."""
    from glorfindel.actions import _update_block_entry
    from glorfindel.reassert_cards import say_left
    other = "198.51.100.4"
    for ip in (_IP, other):
        _save_block_state("vm", ip, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)
        _update_block_entry("vm", ip, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r", "left": [
            {"nsg": "rg/nsg", "rule": f"glorfindel-block-{ip}", "to": "10.0.0.9", "on": "x", "kind": "turned"}]}])

    def entry(ip):
        return next(e for e in _load_block_entries("vm") if e["ip"] == ip)
    say_left("vm", _RID, _IP, entry(_IP), [], _RID)
    escalations.resolve(_left_cards("pending")[0]["id"])     # the operator
    say_left("vm", _RID, other, entry(other), [], _RID)
    for _ in range(2):
        say_left("vm", _RID, _IP, entry(_IP), [], _RID)
    assert [(e["action_params"] or {}).get("ip") for e in _left_cards("pending")] == [other]
    assert len(_left_cards()) == 2


# ── L2C, its review: a disappearance said again after one acknowledged ───────────────────

_HUMAN = AutonomyConfig(default="human_only")


def _drift_cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "verification_failed"
            and (status is None or e["status"] == status)]


def _gone(kind: str):
    """An isolation, or a block of _IP, whose rules are gone from Azure."""
    if kind == "isolation":
        _isolated()
        return _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    return _connector(verify_blk={"verified": False, "missing_rules": ["r"]})


def _drift_mark(kind: str):
    return (_load_isolation_state("vm") if kind == "isolation" else _load_block_entries("vm")[0]).get(
        "drift_alerted_at")


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_disappearance_after_one_acknowledged_and_held_again_is_said(monkeypatch, kind):
    """The review of L2C: gone, said; the operator acknowledges — said for its episode, not
    again while it stays gone. Held again, but the mark can't be taken off (a full disk);
    gone again: the mark read « already said » left the VM unisolated (or unblocked) with
    no card. A new episode is said, once."""
    c = _gone(kind)
    reassert_active(c, _HUMAN)
    (card,) = _drift_cards("pending")
    escalations.resolve(card["id"])                           # the operator
    reassert_active(c, _HUMAN)
    assert not _drift_cards("pending")                        # its episode: acknowledged
    held, gone = {"verified": True}, dict((c.verify_isolation if kind == "isolation"
                                           else c.verify_block_ip).return_value)
    verify = c.verify_isolation if kind == "isolation" else c.verify_block_ip
    verify.return_value = held
    give_back = _unwritable(monkeypatch, _STATE_DIR[kind])
    reassert_active(c, _HUMAN)                                  # not written: logged
    give_back()
    assert _drift_mark(kind)                                  # the mark kept
    verify.return_value = gone
    for _ in range(2):
        reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1 and len(_drift_cards()) == 2

@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_disappearance_is_over_once_its_rules_are_back_even_bypassed(kind):
    """Gone, said, acknowledged; its rules put back, but an allow of the customer's passes
    them — bypassed, said on its own card. Only a hold ended the episode: gone again, the
    mark read « already said » for ever. The rules back end it; the next one is said."""
    c = _gone(kind)
    reassert_active(c, _HUMAN)
    escalations.resolve(_drift_cards("pending")[0]["id"])     # the operator
    verify = c.verify_isolation if kind == "isolation" else c.verify_block_ip
    gone = verify.return_value
    verify.return_value = _bypass(_ALLOW)
    reassert_active(c, _HUMAN)
    assert _bypass_cards("pending") and not _drift_mark(kind)
    verify.return_value = gone
    reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1


def test_an_episode_is_known_over_before_any_write_of_its_pass(monkeypatch):
    """Graine 777 at 2 000 (L2C, review): the block held again, but the first write of its
    pass — its bypass mark taken off, before the drift mark — refused; the episode was not
    known over, the next disappearance unsaid. Known over from the reading itself."""
    from glorfindel.actions import _update_block_entry
    c = _gone("block")
    reassert_active(c, _HUMAN)
    escalations.resolve(_drift_cards("pending")[0]["id"])     # the operator
    _update_block_entry("vm", _IP, bypass_said="reassert-bypass-block-vm-x")
    gone = c.verify_block_ip.return_value
    c.verify_block_ip.return_value = {"verified": True}
    give_back = _unwritable(monkeypatch, "/blocks/")
    reassert_active(c, _HUMAN)
    give_back()
    assert _drift_mark("block")
    c.verify_block_ip.return_value = gone
    reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1


def test_a_state_refused_on_one_vm_does_not_stop_the_pass(monkeypatch):
    """A full disk on the first VM's state: the pass went no further — the next VM, held
    again, never seen so, its drift mark kept. Each VM is read; each refusal is said in the
    pass's report (and logged), with what it risks."""
    from glorfindel import reassert_cards
    from glorfindel.actions import _save_isolation_state
    other = _RID.replace("/vm", "/vm2")
    for rid in (_RID, other):
        _save_isolation_state(rid, {"resource_id": rid, "isolated_at": "2026-10-06T08:00:00+00:00",
                                    "placements": [], "drift_alerted_at": "2026-10-06T09:00:00+00:00"})
    c = _connector()
    give_back = _unwritable(monkeypatch, "/isolation/")
    report = reassert_active(c, _HUMAN)
    give_back()
    assert not reassert_cards._EPISODE_OPEN                # both seen held again: over
    failed = [r for r in report if r["outcome"] == "failed"]
    assert sorted(r["vm"] for r in failed) == ["vm", "vm2"] and all(r["kind"] == "isolation" for r in failed)
    assert all("État local non écrit" in r["detail"] and "redite" in r["detail"] for r in failed), failed


def test_a_state_refused_on_a_block_is_printed_by_the_watch(monkeypatch):
    """The watch prints a refused write of a block's state as any other failure of the pass."""
    import io
    from rich.console import Console
    from glorfindel import cli
    c = _gone("block")
    reassert_active(c, _HUMAN)
    c.verify_block_ip.return_value = {"verified": True}
    out = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=out, width=200))
    give_back = _unwritable(monkeypatch, "/blocks/")
    report = cli._watch_reassert_pass(c, "human_only")
    give_back()
    (failed,) = [r for r in report if r["outcome"] == "failed"]
    assert failed["kind"] == "block" and failed["ip"] == _IP and "non écrit" in failed["detail"]
    assert f"reassert block vm {_IP} → failed" in out.getvalue()


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_disappearance_held_again_then_gone_after_a_restart_is_said(monkeypatch, kind):
    """The second review's probe: gone, said, acknowledged; held again with the disk full
    (the mark kept); the watch restarted (its memory empty); gone again — said."""
    from glorfindel import reassert_cards
    c = _gone(kind)
    reassert_active(c, _HUMAN)
    escalations.resolve(_drift_cards("pending")[0]["id"])     # the operator
    verify = c.verify_isolation if kind == "isolation" else c.verify_block_ip
    gone = verify.return_value
    verify.return_value = {"verified": True}
    give_back = _unwritable(monkeypatch, _STATE_DIR[kind])
    reassert_active(c, _HUMAN)
    give_back()
    assert _drift_mark(kind)
    reassert_cards._EPISODE_OPEN.clear()                      # the watch restarted
    verify.return_value = gone
    reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_an_acknowledged_disappearance_still_there_at_start_is_said_once(kind):
    """Decided 30/10 (Jonathan): a restart is noisy, never silent. Gone, said, acknowledged,
    still gone when the watch restarts: said again once — a new card —, then silent."""
    from glorfindel import reassert_cards
    c = _gone(kind)
    reassert_active(c, _HUMAN)
    escalations.resolve(_drift_cards("pending")[0]["id"])     # the operator
    reassert_active(c, _HUMAN)
    assert not _drift_cards("pending")
    reassert_cards._EPISODE_OPEN.clear()                      # the watch restarted
    for _ in range(3):
        reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1 and len(_drift_cards()) == 2


def test_after_a_restart_a_failed_reapplication_is_said_and_tried_once_more():
    """Decided 30/10 (Jonathan): outside human_only, the first pass after a restart says
    again, and tries once more, a putting back that had failed — a write that closes, which
    the mode already allows, once per restart. Then nothing more."""
    from glorfindel import reassert_cards
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    c.isolate_vm.side_effect = RuntimeError("AuthorizationFailed")
    reassert_active(c, _ACT)
    assert c.isolate_vm.call_count == 1 and _load_isolation_state("vm").get("drift_alerted_at")
    escalations.resolve(_drift_cards("pending")[0]["id"])     # the operator
    reassert_active(c, _ACT)
    assert c.isolate_vm.call_count == 1                       # acknowledged: not tried again
    reassert_cards._EPISODE_OPEN.clear()                      # the watch restarted
    reassert_cards._HISTORY.clear()
    for _ in range(3):
        reassert_active(c, _ACT)
    assert c.isolate_vm.call_count == 2 and len(_drift_cards("pending")) == 1
    assert "a échoué" in _drift_cards("pending")[0]["reason"]


def test_a_drift_card_closed_with_a_note_is_no_acknowledgement():
    """Gone, said; the card then closed with a note — Glorfindel's way, as `_alert` closes
    the card it replaces — and no card after it: only the operator's word silences a
    disappearance, never the mark alone. Said again."""
    c = _gone("isolation")
    reassert_active(c, _HUMAN)
    (card,) = _drift_cards("pending")
    escalations.resolve(card["id"], note="Remplacée par une nouvelle alerte.")
    reassert_active(c, _HUMAN)
    assert len(_drift_cards("pending")) == 1


def test_an_alert_closes_the_card_it_replaces_with_a_note():
    """`_alert`'s closures carry a note: read as Glorfindel's, never as acknowledged."""
    from glorfindel.reassert import _alert
    _alert("reassert-vm-x", resource_id=_RID, action="isolate_vm", reason="a")
    _alert("reassert-vm-x", resource_id=_RID, action="isolate_vm", reason="b")
    (closed,) = _drift_cards("resolved")
    assert closed["resolution"] and [e["reason"] for e in _drift_cards("pending")] == ["b"]


def test_a_block_written_again_after_a_failed_unblock_is_checked():
    """A block, an unblock that failed (`unblock_failed`), then the block written again,
    whole: `_save_block_state` merged it into the entry and kept the mark. Its rules then
    vanished: the pass left it to the operator, `verify_block_ip` never called — nothing
    said (seed 777 at 2 000, L2C). L1B: a whole block supersedes the unblock, its marks go."""
    from glorfindel.actions import _update_block_entry
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)
    _update_block_entry("vm", _IP, unblock_failed=["r: (AuthorizationFailed)"])
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)     # blocked again
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    reassert_active(c, _HUMAN)
    assert [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def test_only_a_whole_block_supersedes_a_cut_off_unblock():
    """L1B: an unblock cut off midway (`unblocking_at`), then the IP blocked again — in
    part: the operation unfinished, the entry held, the interruption said; whole: its marks
    go, the stale card's mark too (a later cut-off unblock is said again), and the block is
    checked."""
    from glorfindel.actions import _load_block_entries, _update_block_entry
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)
    _update_block_entry("vm", _IP, unblocking_at="2026-10-06T08:00:00+00:00")
    _save_block_state("vm", _IP, _RID, placements=placed, partial=True, threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]       # interrupted
    assert "interrompu" in escalations.pending()[0]["reason"]
    reassert_active(c, _HUMAN)
    c.verify_block_ip.assert_not_called()
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)     # whole
    (entry,) = _load_block_entries("vm")
    assert not {"unblock_failed", "unblocking_at", "stale_alerted_at"} & set(entry)
    reassert_active(c, _HUMAN)
    c.verify_block_ip.assert_called()
    assert [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def test_a_block_written_again_after_an_acknowledged_drift_is_said_again():
    """L1Q (#363): a merged block's perimeter pair gone, said, the card acknowledged — said
    for its episode. Then the IP blocked again on the VM, whole: a new block, a new episode,
    as a re-isolation writes its state anew. The drift mark used to survive the merge: the
    pair, still named and still gone, read « already said » under rules rewritten since — no
    card. A partial block written again keeps the episode (the entry is held: nothing read)."""
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    pair = {"nsg": "rg/nsg", "nsg_scope": "subnet", "rule": "glorfindel-block-203-0-113-9", "scoped": False}
    _save_block_state("vm", _IP, _RID, **pair, placements=placed, threat_port=22)
    gone = {"verified": True, "held_missing": ["glorfindel-block-203-0-113-9"]}
    c = _connector(verify_blk=gone)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (card,) = escalations.pending()
    escalations.resolve(card["id"])                                   # the operator acknowledges
    assert reassert_active(c, _HUMAN) == [] and escalations.pending() == []     # said, its episode
    _save_block_state("vm", _IP, _RID, placements=placed, partial=True, threat_port=22)
    (entry,) = _load_block_entries("vm")
    assert entry.get("drift_alerted_at")                              # held: its episode kept
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)       # blocked again, whole
    (entry,) = _load_block_entries("vm")
    assert not {"drift_alerted_at", "drift_said"} & set(entry)
    assert entry["scoped"] is False                                   # the pair still named
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (card,) = escalations.pending()
    assert "disparu" in card["reason"] and _IP in card["reason"]
    c.block_suspicious_ip.assert_not_called()                         # human_only: said, never written


_PAIR = "glorfindel-block-203-0-113-9"
_BOTH_GONE = {"verified": False, "missing_rules": ["r", "r-out"], "held_missing": [_PAIR], "open_nics": ["nic-a"]}
_PAIR_GONE = {"verified": True, "held_missing": [_PAIR]}
_R_GONE = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic-a"]}


def _merged_block():
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule=_PAIR, scoped=False,
                      placements=placed, threat_port=22)


def _said_and_acknowledged(c):
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (card,) = escalations.pending()
    escalations.resolve(card["id"])                                   # the operator acknowledges
    return card


@pytest.mark.parametrize("full_disk", [False, True])
def test_a_rule_back_then_gone_again_is_said_while_the_pair_stays_gone(monkeypatch, full_disk):
    """L1Q (#363): a merged block's pair and its VM rule gone, said, acknowledged. The VM rule
    back (the pair still gone: the episode goes on), then gone again — « not worse than the
    card », silent. What still holds of the card is the new baseline, in memory (no write: a
    full disk changes nothing) — the rule gone again is said."""
    from glorfindel import actions
    _merged_block()
    c = _connector(verify_blk=_BOTH_GONE)
    _said_and_acknowledged(c)
    c.verify_block_ip.return_value = _PAIR_GONE                       # the VM rule back
    real = actions._atomic_write_text
    if full_disk:
        def full(*a, **k):
            raise OSError(28, "No space left on device")
        monkeypatch.setattr(actions, "_atomic_write_text", full)
    assert reassert_active(c, _HUMAN) == [] and escalations.pending() == []    # better: nothing to say
    monkeypatch.setattr(actions, "_atomic_write_text", real)
    c.verify_block_ip.return_value = _BOTH_GONE                       # gone again
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (card,) = escalations.pending()
    assert "disparu" in card["reason"]


def test_a_drift_that_comes_and_goes_under_a_pending_card_makes_a_card_at_each_return():
    """L1Q's second review, a known limit, wanted: the card pending, the VM rule back then gone
    again — the baseline narrows at every pass better than the card, so each return is a new
    card (replacing the one before: one pending). Noise, on the careful side: a card too many
    rather than a disappearance unsaid (test_a_drift_better_under_a_pending_card_…)."""
    _merged_block()
    c = _connector(verify_blk=_BOTH_GONE)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    for v, said in ((_PAIR_GONE, []), (_BOTH_GONE, ["escalated"]), (_PAIR_GONE, []), (_BOTH_GONE, ["escalated"])):
        c.verify_block_ip.return_value = v
        assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == said
    assert len(escalations.pending()) == 1


def test_a_drift_better_under_a_pending_card_then_acknowledged_then_worse_is_said():
    """L1Q's second review (the reviewer's probe): the pair and the VM rules gone, the card said
    and pending; the operator puts the rules back by hand, a pass reads the pair alone; the
    operator acknowledges the card; before the next pass, the VM rules go again. Narrowed only
    once the card was acknowledged, the pass compared with the card — « not worse » — and stayed
    silent for the whole episode. Narrowed at every better pass, the disappearance is said."""
    _merged_block()
    c = _connector(verify_blk=_BOTH_GONE)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]     # 1. said, pending
    c.verify_block_ip.return_value = _PAIR_GONE                                    # 2. rules back by hand
    assert reassert_active(c, _HUMAN) == []
    (card,) = escalations.pending()
    escalations.resolve(card["id"])                                                # 3. acknowledged
    c.verify_block_ip.return_value = _BOTH_GONE                                    # 4. the rules go again
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]     # 5. said
    (card,) = escalations.pending()
    assert "disparu" in card["reason"]


def test_a_new_episode_never_compares_with_what_held_of_the_one_before():
    """L1Q's review: episode 1 — the pair and the VM rules gone, said, acknowledged; the rules
    back (the baseline narrowed to the pair alone), then all back: over. Episode 2 — the VM
    rule gone, the pair there: said, acknowledged; then the rule back and the pair gone again:
    worse than its card. The first episode's baseline kept, it read « not worse », silent."""
    _merged_block()
    c = _connector(verify_blk=_BOTH_GONE)
    _said_and_acknowledged(c)
    c.verify_block_ip.return_value = _PAIR_GONE
    assert reassert_active(c, _HUMAN) == []                           # narrowed: the pair alone
    c.verify_block_ip.return_value = {"verified": True}
    assert reassert_active(c, _HUMAN) == []                           # all back: over
    c.verify_block_ip.return_value = _R_GONE
    _said_and_acknowledged(c)                                         # episode 2: the rule gone
    c.verify_block_ip.return_value = _PAIR_GONE                       # the rule back, the pair gone
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (card,) = escalations.pending()
    assert _PAIR in card["reason"]


def test_a_block_written_again_whole_is_put_back_again_once():
    """L1Q's review: a block put back once by the reassertion (`reasserted_at`), then blocked
    again by the operator, whole — a new episode, its marks gone with it. Its next
    disappearance is put back, never « une deuxième fois (déjà reposée le <before>) »; a
    partial block keeps the mark."""
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r", placements=placed,
                      threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    c.block_suspicious_ip.side_effect = lambda *a, **k: setattr(
        c.verify_block_ip, "return_value", {"verified": True})
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["reapplied"]
    _save_block_state("vm", _IP, _RID, placements=placed, partial=True, threat_port=22)
    assert _load_block_entries("vm")[0].get("reasserted_at")          # partial: kept
    _save_block_state("vm", _IP, _RID, placements=placed, threat_port=22)       # blocked again, whole
    assert not _load_block_entries("vm")[0].get("reasserted_at")
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["r"]}  # gone again
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["reapplied"]
    assert c.block_suspicious_ip.call_count == 2
    assert not any("deuxième fois" in e["reason"] for e in escalations.pending())


# ── SEC13 (V-16): a check that raises, said on one card ───────────────────────────────

def _unverified(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "unverified"
            and (status is None or e["status"] == status)]


@pytest.mark.parametrize("what", ["isolation", "block"])
def test_a_check_that_keeps_raising_is_said_on_one_card_closed_when_it_passes(what):
    """The reassertion's check raised (a role removed, the API down): a log line, at every
    pass, for as long as it lasted — the isolation or the block unchecked, said nowhere an
    operator looks. One card now, not one per pass; closed, with a note, once the check
    passes again; a later failure, a new card."""
    if what == "isolation":
        _isolated()
    else:
        _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                          placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector()
    check = c.verify_isolation if what == "isolation" else c.verify_block_ip
    check.side_effect = RuntimeError("(AuthorizationFailed) no read on the NSG")
    reports = [reassert_active(c, _ACT) for _ in range(3)]
    (card,) = _unverified()
    assert card["status"] == "pending" and card["resource_id"] == _RID and card["occurrences"] == 1
    assert "AuthorizationFailed" in card["reason"] and card["action"] == "review_unverified"
    assert (card["action_params"] or {}).get("ip", "") == ("" if what == "isolation" else _IP)
    assert [len(r) for r in reports] == [1, 0, 0] and reports[0][0]["outcome"] == "unverified"
    c.isolate_vm.assert_not_called()
    c.block_suspicious_ip.assert_not_called()
    check.side_effect = None
    assert reassert_active(c, _ACT) == []
    (card,) = _unverified()
    assert card["status"] == "resolved" and card.get("resolution")
    check.side_effect = RuntimeError("(ServiceUnavailable)")
    reassert_active(c, _ACT)
    assert len(_unverified("pending")) == 1 and len(_unverified()) == 2


def test_a_check_still_raising_once_acknowledged_is_not_said_again():
    """Acknowledged by the operator while it still raises: silent until it passes — then a
    new failure is a new card."""
    _isolated()
    c = _connector()
    c.verify_isolation.side_effect = RuntimeError("(TooManyRequests)")
    reassert_active(c, _ACT)
    (card,) = _unverified()
    escalations.resolve(card["id"])
    for _ in range(2):
        assert reassert_active(c, _ACT) == []
    assert not _unverified("pending")
    c.verify_isolation.side_effect = None
    reassert_active(c, _ACT)
    c.verify_isolation.side_effect = RuntimeError("(TooManyRequests)")
    reassert_active(c, _ACT)
    assert len(_unverified("pending")) == 1


def test_a_check_raising_on_one_vm_says_it_for_that_vm_only():
    """Two homonyms in two groups: one card each, by resource id; one passing closes its own."""
    other = _RID.replace("/rg/", "/rg-b/")
    _isolated()
    _save_isolation_state(other, {"resource_id": other, "isolated_at": "2026-10-06T08:00:00+00:00",
                                  "placements": []})
    readiness.record_assessment(readiness._verdict("vm", []), other)
    c = _connector()
    c.verify_isolation.side_effect = lambda rid: (_ for _ in ()).throw(RuntimeError("(AuthorizationFailed)"))
    reassert_active(c, _ACT)
    assert sorted(e["resource_id"] for e in _unverified("pending")) == sorted([_RID, other])
    c.verify_isolation.side_effect = lambda rid: (
        {"verified": True} if rid == _RID else (_ for _ in ()).throw(RuntimeError("(AuthorizationFailed)")))
    reassert_active(c, _ACT)
    assert [e["resource_id"] for e in _unverified("pending")] == [other]


def test_a_check_that_raised_closes_its_card_once_the_vm_is_released():
    """Released (or unblocked) while its check raised: nothing left to check — the card closes
    at the next pass, with a note. Not while a state can't be read: it may still hold it."""
    from glorfindel.actions import _ISOLATION_STATE_DIR, _clear_isolation_state
    from glorfindel.reassert import reassert_pass
    _isolated()
    c = _connector()
    c.dry_run = True                         # no listing of the NSGs: the local passes only
    c.verify_isolation.side_effect = RuntimeError("(AuthorizationFailed)")
    reassert_pass(c, _ACT)
    assert len(_unverified("pending")) == 1
    _clear_isolation_state(_RID)
    (_ISOLATION_STATE_DIR / "other--00000000.json").write_text("{")
    reassert_pass(c, _ACT)
    assert len(_unverified("pending")) == 1                     # unknown: kept
    (_ISOLATION_STATE_DIR / "other--00000000.json").unlink()
    reassert_pass(c, _ACT)
    (card,) = _unverified()
    assert card["status"] == "resolved" and card.get("resolution")


@pytest.mark.parametrize("what", ["isolation", "block"])
def test_a_check_that_cant_tell_never_closes_the_card_and_says_so(what):
    """Review of SEC13: the card closed « the check passes again » on any answer that didn't
    raise — `verified: None` included, Azure's « can't tell » (rules or NICs unreadable, their
    precedence unknown); then nothing more was said (A0). An unknown keeps it open, said on the
    same card with the error it gives; only a real answer closes it. On its own, too: a check
    that can't tell from the start opens the card."""
    if what == "isolation":
        _isolated()
    else:
        _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                          placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector()
    check = c.verify_isolation if what == "isolation" else c.verify_block_ip
    unknown = {"verified": None, "method": "nsg_check", "error": "non vérifiable : règles illisibles sur nsg"}
    check.side_effect = RuntimeError("(AuthorizationFailed) no read on the NSG")
    reassert_active(c, _ACT)
    check.side_effect, check.return_value = None, unknown
    for _ in range(2):
        reassert_active(c, _ACT)
    (card,) = _unverified()
    assert card["status"] == "pending" and card["occurrences"] == 1
    assert "première erreur : (AuthorizationFailed)" in card["reason"] and "règles illisibles" in card["reason"]
    check.return_value = {"verified": True}
    reassert_active(c, _ACT)
    assert [e["status"] for e in _unverified()] == ["resolved"]
    check.return_value = unknown
    reassert_active(c, _ACT)
    assert len(_unverified("pending")) == 1
    check.return_value = {"verified": None, "method": "dry_run"}      # a dry run says nothing
    assert reassert_active(c, _ACT) == [] and len(_unverified("pending")) == 1


def test_the_card_keeps_the_last_error_of_a_check_that_keeps_raising():
    """The card said the first error only: a role removed, then the API down, read as the role
    still. First and last now, on the one card — written once per change, not at every pass."""
    _isolated()
    c = _connector()
    c.verify_isolation.side_effect = RuntimeError("(AuthorizationFailed) first")
    reassert_active(c, _ACT)
    c.verify_isolation.side_effect = RuntimeError("(ServiceUnavailable) last")
    reassert_active(c, _ACT)
    (card,) = _unverified()
    assert "première erreur : (AuthorizationFailed) first ; dernière : (ServiceUnavailable) last" in card["reason"]
    stamp = card["updated_at"]
    reassert_active(c, _ACT)
    (card,) = _unverified()
    assert card["updated_at"] == stamp and card["occurrences"] == 1


def test_an_acknowledged_check_card_is_its_own_not_a_longer_ips():
    """Review of SEC13: the acknowledgement was read by prefix — the card of …-10.0.0.1 took
    the latest card of …-10.0.0.10 for its own, was read as not acknowledged, and was said
    again. Read by its exact signal id now."""
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}]
    for ip in ("10.0.0.1", "10.0.0.10"):
        _save_block_state("vm", ip, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r", placements=placed,
                          threat_port=22)
    c = _connector()
    c.verify_block_ip.side_effect = RuntimeError("(AuthorizationFailed)")
    reassert_active(c, _ACT)
    by_ip = {e["action_params"]["ip"]: e for e in _unverified()}
    assert set(by_ip) == {"10.0.0.1", "10.0.0.10"}
    escalations.resolve(by_ip["10.0.0.1"]["id"])
    for _ in range(2):
        reassert_active(c, _ACT)
    assert [e["action_params"]["ip"] for e in _unverified("pending")] == ["10.0.0.10"]
    assert len(_unverified()) == 2

@pytest.mark.parametrize("merged", [False, True], ids=["perimeter", "merged"])
@pytest.mark.parametrize("listed", [("db", "web"), ("web", "db")])
def test_a_perimeter_is_put_back_before_the_vm_blocks_of_its_subnet(monkeypatch, listed, merged):
    """L1Qr (seed 6): web's perimeter pair turned into an allow, Db's own rule for a NIC whose
    address changed gone. Read first — the directory listing's order —, Db's block was rewritten,
    read again under the turned pair, and said « n'est plus bloquée » of its NICs; web's entry
    then put the pair back, a moment later in the same pass: the card false once the pass ended.
    The perimeters first, whatever the listing, web's entry merged with its own block or not:
    Db's block is read with the pair whole."""
    from glorfindel import actions as facade
    rid = {v: f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{v}"
           for v in ("db", "web")}
    for v in rid:
        readiness.record_assessment(readiness._verdict(v, []), rid[v])
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-db"}]
    _save_block_state("db", _IP, rid["db"], placements=placed, threat_port=22)
    _save_block_state("web", _IP, rid["web"], nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair",
                      scoped=False, threat_port=22,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-web"}] if merged else None)
    real = facade.active_blocks
    monkeypatch.setattr(facade, "active_blocks", lambda: sorted(
        real(), key=lambda b: listed.index(b["vm_name"])))
    world = {"pair": False, "db": False}
    read = []

    def verify(ip, r):
        vm = r.rsplit("/", 1)[-1]
        read.append(vm)
        if vm == "web":
            return {"verified": True} if world["pair"] else {"verified": False, "missing_rules": ["pair"]}
        if world["pair"]:                 # behind the pair: held, whatever its own rule
            return {"verified": True} if world["db"] else {
                "verified": True, "held_missing": ["r-db"], "held_by_perimeter": ["nic-a", "nic-b"]}
        return {"verified": False, "missing_rules": [] if world["db"] else ["r-db"],
                "open_nics": ["nic-a", "nic-b"]}

    def block(ip, r, scope, threat_port=None):
        world["pair" if scope == "subnet" else r.rsplit("/", 1)[-1]] = True
        return {"status": "blocked"}
    c = MagicMock()
    c.verify_block_ip.side_effect = verify
    c.block_suspicious_ip.side_effect = block
    reassert_active(c, _ACT)
    assert read[0] == "web"
    assert not [e["reason"] for e in escalations.pending() if "n'est plus bloquée" in e["reason"]]


# ── The nightly machine after SEC13: a card write refused never silences what comes next ──

def _block_drift_cards(status="pending"):
    return [e for e in escalations.all_escalations() if e["action"] == "block_suspicious_ip"
            and (e.get("signal_id") or "").startswith("reassert-") and e["status"] == status]


def test_a_drift_better_on_one_side_is_kept_when_its_card_cannot_be_written(monkeypatch):
    """A block's drift said and acknowledged (a rule gone, the IP no longer blocked). Then held
    again — by the quarantine or a perimeter — while a second rule is gone: worse on that side,
    better on the other (blocked), and the card that says it refused (a full disk). Back to what
    was first said: the pass compared it with the acknowledged card, « not worse », and was
    silent — the IP open again, unsaid (L1). What got better is the baseline before the write
    now: said."""
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}, {"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r2"}]
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r", placements=placed,
                      threat_port=22)
    gone_open = {"verified": False, "missing_rules": ["r"]}
    c = _connector(verify_blk=gone_open)
    human = AutonomyConfig(default="human_only")
    reassert_active(c, human)
    (card,) = _block_drift_cards()
    escalations.resolve(card["id"])                                  # the operator acknowledges it
    assert reassert_active(c, human) == []
    c.verify_block_ip.return_value = {"verified": True, "held_missing": ["r", "r2"]}

    def full(*a, **k):
        raise OSError(28, "No space left on device")
    real = escalations.record
    monkeypatch.setattr(escalations, "record", full)
    assert [r["outcome"] for r in reassert_active(c, human)] == ["failed"]       # said: not written
    monkeypatch.setattr(escalations, "record", real)
    c.verify_block_ip.return_value = gone_open
    reassert_active(c, human)
    assert len(_block_drift_cards()) == 1


def test_a_check_card_refused_never_cuts_the_blocks_pass(monkeypatch):
    """A check that raised left its `unverified` card; the next pass reads the block's rules gone
    and closes that card first — refused (a full disk), the OSError cut the pass: the drift
    neither put back nor said (L1). The check card's writes never raise into the pass."""
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector()
    c.verify_block_ip.side_effect = RuntimeError("(AuthorizationFailed)")
    reassert_active(c, AutonomyConfig(default="human_only"))
    (check,) = [e for e in escalations.pending() if e["escalation_type"] == "unverified"]
    c.verify_block_ip.side_effect = None
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["r"]}
    real = escalations.resolve

    def resolve(escalation_id, note=""):
        if escalation_id == check["id"]:
            raise OSError(28, "No space left on device")
        return real(escalation_id, note=note)
    monkeypatch.setattr(escalations, "resolve", resolve)
    report = reassert_active(c, AutonomyConfig(default="human_only"))
    assert [r["outcome"] for r in report] == ["escalated"] and len(_block_drift_cards()) == 1
    monkeypatch.setattr(escalations, "resolve", real)
    reassert_active(c, AutonomyConfig(default="human_only"))
    assert not [e for e in escalations.pending() if e["escalation_type"] == "unverified"]   # closed next


# ── I3C (#436): the reassertion's cards, whatever the case of the VM's name ───────────────

_DB = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/Db--01"


def _held_as(rid: str, kind: str) -> None:
    """Db--01's isolation, or its block of _IP, recorded under `rid`: its canonical id, or the
    lowercase one Log Analytics reports (`_ResourceId`) — the state of a VM isolated or blocked
    again by it names the VM `db--01`. Written anew, as an isolation or a block is: no mark."""
    from glorfindel.actions import _clear_block_state
    readiness.record_assessment(readiness._verdict("Db--01", []), _DB)
    if kind == "isolation":
        _save_isolation_state(rid, {"resource_id": rid, "isolated_at": "2026-10-06T08:00:00+00:00",
                                    "placements": []})
    else:
        _clear_block_state(_DB, _IP)
        _save_block_state(rid, _IP, rid, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)


def _gone_from_db(kind: str):
    c = (_connector({"verified": False, "uncovered_nics": ["nic-a"]}) if kind == "isolation"
         else _connector(verify_blk={"verified": False, "missing_rules": ["r"]}))
    c.isolate_vm.side_effect = lambda rid: _read_whole_again(c)
    return c


def _read_whole_again(c) -> dict:
    """Put back, its state left as it is: Azure, read again, has the isolation whole (RW3)."""
    c.verify_isolation.return_value = {"verified": True}
    return {"status": "isolated"}


def _older(kind: str, prefix: str = "reassert-", tail: str = "", **card) -> dict:
    """A card an older version said under Db--01's canonical name (before I3C), pending."""
    from glorfindel.actions import _rid_hash
    ip = _IP if kind == "block" else ""
    sid = f"{prefix}Db--01-{_rid_hash(_DB)}" + (f"-{ip}" if ip else "") + tail
    escalations.record(signal_id=sid, resource_id=_DB, reason="Dite par une version antérieure.",
                       action_params={"ip": ip} if ip else None, **card)
    return next(e for e in escalations.pending() if e["signal_id"] == sid)


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_disappearance_said_under_the_canonical_name_is_said_once_by_the_lowercase_id(kind):
    """I3C (#436), found by I3R's review: Db--01's rules gone, said under its canonical name;
    then isolated (blocked) again by its lowercase id — its state names it `db--01` — and gone
    again. The card's id carried the name's case: the new alert neither closed the former card
    nor was read « said » — the store folded it into the former one, which kept its id —, said
    again at every pass. With `web`, no capital, it held."""
    c = _gone_from_db(kind)
    _held_as(_DB, kind)
    reassert_active(c, _HUMAN)
    (first,) = _drift_cards("pending")
    assert first["signal_id"] == first["signal_id"].lower()         # written in lowercase, whatever the state's case
    _held_as(_DB.lower(), kind)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]   # a new episode
    for _ in range(2):
        assert reassert_active(c, _HUMAN) == []                                  # said once
    (card,) = _drift_cards("pending")
    assert card["id"] != first["id"] and card["signal_id"] == card["signal_id"].lower()
    assert next(e for e in _drift_cards() if e["id"] == first["id"])["resolution"]   # closed, with a note


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_disappearance_put_back_after_one_said_under_the_canonical_name_has_its_own_card(kind):
    """The same outside human_only: said « ne les repose pas » under the canonical name; taken
    up again by the lowercase id, gone again, put back once — the « reposée » was folded into
    the card that said it would not be, which went on saying so."""
    c = _gone_from_db(kind)
    _held_as(_DB, kind)
    reassert_active(c, _HUMAN)
    _held_as(_DB.lower(), kind)
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["reapplied"]
    (card,) = _drift_cards("pending")
    assert "une fois" in card["reason"] and "repose pas" not in card["reason"]


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_drift_card_an_older_version_said_under_the_canonical_name_is_closed_by_the_next(kind):
    """A drift card pending from before I3C carries the name's case. After the upgrade (a
    restart: said once again, by design — L2C), the new alert closes it, with a note, and the
    next passes read their own: never a card left pending that nothing closes, nor the
    disappearance said at every pass."""
    old = _older(kind, action="isolate_vm" if kind == "isolation" else "block_suspicious_ip",
                 escalation_type="verification_failed")
    c = _gone_from_db(kind)
    _held_as(_DB, kind)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    for _ in range(2):
        assert reassert_active(c, _HUMAN) == []
    (card,) = _drift_cards("pending")
    assert card["id"] != old["id"] and "antérieure" not in card["reason"]
    assert next(e for e in _drift_cards() if e["id"] == old["id"])["resolution"]


def _db_mark(kind: str, rid: str, field: str, sid: str) -> None:
    from glorfindel.actions import _update_block_entry
    if kind == "isolation":
        _save_isolation_state(rid, {**_load_isolation_state(rid), field: sid})
    else:
        _update_block_entry(rid, _IP, **{field: sid})


@pytest.mark.parametrize("kind", ["isolation", "block"])
@pytest.mark.parametrize("rid", [_DB, _DB.lower()])
def test_a_bypass_of_a_vm_whose_name_has_capitals_is_said_once(kind, rid):
    """Db--01 bypassed, its state under either case: one card, said once (I3C)."""
    c = _connector()
    _held_as(rid, kind)
    _read(c, kind, _ALLOW)
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["bypassed"]
    for _ in range(2):
        assert reassert_active(c, _HUMAN) == []
    assert len(_bypass_cards()) == 1


@pytest.mark.parametrize("kind", ["isolation", "block"])
@pytest.mark.parametrize("acknowledged", [False, True])
def test_a_bypass_said_under_the_canonical_name_stays_said(kind, acknowledged):
    """A bypass said by an older version under Db--01's canonical name, its mark too, pending
    or acknowledged by the operator; the state now names the VM in lowercase. The same allow
    read again stays said: neither said at every pass nor its acknowledgement undone (I3C)."""
    from glorfindel.reassert_cards import _allow_key, _digest
    _held_as(_DB.lower(), kind)
    old = _older(kind, f"reassert-bypass-{'iso' if kind == 'isolation' else 'block'}-",
                 f"-{_digest([_allow_key(_ALLOW)])}", action="review_bypass", escalation_type="bypassed")
    _db_mark(kind, _DB.lower(), "bypass_said", old["signal_id"])
    if acknowledged:
        escalations.resolve(old["id"])                            # the operator
    c = _connector()
    _read(c, kind, _ALLOW)
    for _ in range(2):
        assert reassert_active(c, _HUMAN) == []
    assert [e["id"] for e in _bypass_cards()] == [old["id"]]


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_a_check_card_said_under_the_canonical_name_is_the_vms_own(kind):
    """A check that raised, said by an older version under Db--01's canonical name: still
    raising, it is that card — not one more at every pass; the VM still held, it stays open;
    the check passing again, it closes, with a note (I3C)."""
    from glorfindel.reassert_cards import unverified_released
    _held_as(_DB.lower(), kind)
    old = _older(kind, f"reassert-unverified-{'iso' if kind == 'isolation' else 'block'}-",
                 action="review_unverified", escalation_type="unverified")
    c = _connector()
    check = c.verify_isolation if kind == "isolation" else c.verify_block_ip
    check.side_effect = RuntimeError("(AuthorizationFailed)")
    for _ in range(2):
        assert reassert_active(c, _HUMAN) == []
    unverified_released()
    assert [e["id"] for e in _unverified("pending")] == [old["id"]]
    check.side_effect = None
    reassert_active(c, _HUMAN)
    (card,) = _unverified()
    assert card["status"] == "resolved" and card.get("resolution")


def _db_left(rid: str) -> dict:
    from glorfindel.actions import _update_block_entry
    left = [{"nsg": "rg/nsg", "rule": "glorfindel-block-a", "to": "10.0.0.9", "on": "other", "kind": "turned"}]
    _update_block_entry(rid, _IP, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r", "left": left}])
    return _load_block_entries(rid)[0]


@pytest.mark.parametrize("rid", [_DB, _DB.lower()])
def test_rules_left_by_a_vm_whose_name_has_capitals_are_said_once(rid):
    """What Db--01's block left, its state under either case: one card, said once (I3C)."""
    from glorfindel.reassert_cards import say_left
    _held_as(rid, "block")
    vm = rid.rsplit("/", 1)[-1]
    for n in range(3):
        report: list[dict] = []
        say_left(vm, rid, _IP, _db_left(rid), report, rid)
        assert len(report) == (1 if n == 0 else 0)
    assert len(_left_cards()) == 1


def test_rules_left_said_under_the_canonical_name_stay_said():
    """The rules a block left, said by an older version under Db--01's canonical name: read
    again by the lowercase id, that card — never one more (I3C)."""
    from glorfindel.reassert_cards import _digest, say_left
    _held_as(_DB.lower(), "block")
    _db_left(_DB.lower())
    old = _older("block", "reassert-left-", f"-{_digest(['rg/nsg/glorfindel-block-a'])}",
                 action="review_left_rule", escalation_type="rule_left")
    _db_mark("block", _DB.lower(), "left_said", old["signal_id"])
    for _ in range(2):
        report: list[dict] = []
        say_left("db--01", _DB.lower(), _IP, _load_block_entries(_DB.lower())[0], report, _DB.lower())
        assert report == []
    assert [e["id"] for e in _left_cards()] == [old["id"]]


_IP6 = "2001:DB8::9"


def test_a_block_of_an_ipv6_in_capitals_has_its_own_cards():
    """I3C's review: the ids took the VM's name in lowercase, the IP as written — and the store's
    ids were read in lowercase whole. A block of an IPv6 written `2001:DB8::9`: its check card,
    the block still held, closed at every pass as « no longer recorded » and made again; its
    bypass said again at every pass; the rules it left too. Each is its own card, said once."""
    from glorfindel.actions import _update_block_entry
    from glorfindel.reassert_cards import say_left, unverified_released
    _save_block_state("vm", _IP6, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    c = _connector()
    c.verify_block_ip.side_effect = RuntimeError("(AuthorizationFailed)")
    for _ in range(3):
        reassert_active(c, _HUMAN)
        unverified_released()
    assert len(_unverified()) == 1 and len(_unverified("pending")) == 1
    c.verify_block_ip.side_effect = None
    c.verify_block_ip.return_value = _bypass(_ALLOW)
    outcomes = [[r["outcome"] for r in reassert_active(c, _HUMAN)] for _ in range(3)]
    assert outcomes == [["bypassed"], [], []]
    (card,) = _bypass_cards()
    assert card.get("occurrences", 1) == 1
    left = [{"nsg": "rg/nsg", "rule": "glorfindel-block-a", "to": "10.0.0.9", "on": "other", "kind": "turned"}]
    _update_block_entry("vm", _IP6, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r", "left": left}])
    said = []
    for _ in range(3):
        report: list[dict] = []
        entry = next(e for e in _load_block_entries("vm") if e["ip"] == _IP6)
        say_left("vm", _RID, _IP6, entry, report, _RID)
        said.append(len(report))
    assert said == [1, 0, 0] and len(_left_cards()) == 1


# ── I3G (#446): an alert of the reassertion never folds into a card of the graph ──────────

_GRAPH_TEXT = "Vérification après action en échec : une carte reste ouverte."
_GRAPH_SID = "rule-ssh-brute-force-abcdef12"


def _graph_card(kind: str, ip: str = _IP) -> str:
    """The graph's own card on the VM, as `escalate_to_human` writes it after an action whose
    check failed: its signal id (the RulePoller's), its confidence, the IP and port for a block."""
    return escalations.record(
        signal_id=_GRAPH_SID, resource_id=_RID,
        action="isolate_vm" if kind == "isolation" else "block_suspicious_ip",
        escalation_type="verification_failed", reason=_GRAPH_TEXT, confidence=0.9, severity="high",
        action_params=None if kind == "isolation" else {"ip": ip, "port": 22}, rule_name="ssh-brute-force")


def _notified(monkeypatch) -> list[dict]:
    """The cards the operator was notified of (the webhook or the bot's thread)."""
    sent: list[dict] = []
    monkeypatch.setattr(escalations, "_notify", lambda esc: sent.append(dict(esc)))
    return sent


@pytest.mark.parametrize("theirs", ["reassert-vm-5a64476b", "REASSERT-Vm-5a64476b", "reassert-bypass-iso-vm-x-1",
                                    "state-unreadable-0a1b2c3d"])
@pytest.mark.parametrize("graph_first", [True, False])
def test_a_card_of_the_reassertion_never_folds_into_one_of_another_origin(monkeypatch, theirs, graph_first):
    """I3G, at the store: a card of the reassertion's (its ids, whatever their case) and a card
    of another origin — same action, resource (any case), type, IP — are two cards, each with
    its text, each notified. Folded, the graph's card took in the alert (its text overwritten at
    the first fold, the confidence moving from 0.9 to 0; kept at the next, no notification), and
    the other way, the graph's re-fire overwrote the alert, whose id still read « said »."""
    sent = _notified(monkeypatch)
    cards = [dict(signal_id=_GRAPH_SID, reason=_GRAPH_TEXT, confidence=0.9),
             dict(signal_id=theirs, reason="L'isolation de vm a disparu d'Azure.", confidence=0.0)]
    for card in (cards if graph_first else cards[::-1]):
        escalations.record(resource_id=_RID if card is cards[0] else _RID.lower(), action="isolate_vm",
                           escalation_type="verification_failed", **card)
    said = {e["signal_id"]: e for e in escalations.pending()}
    assert set(said) == {_GRAPH_SID, theirs}
    assert all(said[c["signal_id"]]["reason"] == c["reason"] and said[c["signal_id"]]["occurrences"] == 1
               for c in cards)
    assert sorted(e["signal_id"] for e in sent) == sorted(said)


def test_a_card_still_folds_into_one_of_its_own_origin():
    """What the store folded before still folds: the graph's re-fires, whatever their signal ids
    (the RulePoller's, a run's), and a re-fire of the reassertion's own card."""
    for sid in (_GRAPH_SID, "watch-ssh-brute-force-1700000000"):
        escalations.record(signal_id=sid, resource_id=_RID, action="isolate_vm",
                           escalation_type="verification_failed", reason=_GRAPH_TEXT)
    for _ in range(2):
        escalations.record(signal_id="reassert-vm-5a64476b", resource_id=_RID, action="isolate_vm",
                           escalation_type="verification_failed", reason="L'isolation de vm a disparu d'Azure.")
    assert sorted(e["occurrences"] for e in escalations.pending()) == [2, 2]


def _gone_beside(kind: str):
    """Gone; put back (outside human_only), taken off again before the next pass — `again()`."""
    c = _gone(kind)
    c.isolate_vm.side_effect = lambda rid: _read_whole_again(c)
    verify = c.verify_isolation if kind == "isolation" else c.verify_block_ip
    gone = dict(verify.return_value)

    def again():
        verify.return_value = dict(gone)
    c.again = again
    return c


@pytest.mark.parametrize("kind", ["isolation", "block"])
@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
def test_a_disappearance_beside_the_graphs_card_is_said_by_its_own(monkeypatch, kind, mode):
    """I3G (#446), measured by I3C's review: the graph's `verification_failed` card on the VM,
    pending, took in every alert of the reassertion. In human_only, the disappearance said again
    at every pass in the report (`occurrences` up to 5), never notified; outside it, the card
    stayed « reposée une fois », and the second disappearance (« ne la repose pas ») was folded
    in, its text unchanged, no notification — the VM no longer isolated (or blocked): an alert
    gone silent. Each alert now has its own card, its text and its notification; the graph's
    card keeps its own."""
    graph = _graph_card(kind)
    sent = _notified(monkeypatch)
    c = _gone_beside(kind)
    autonomy = AutonomyConfig(default=mode)
    passes = []
    for _ in range(4):
        passes.append(reassert_active(c, autonomy))
        c.again()
    said = [r for report in passes for r in report]
    assert said and [len(p) for p in passes[2:]] == [0, 0], f"said again at every pass: {passes}"
    for r in said:
        card = next((e for e in escalations.all_escalations() if e["reason"] == r["detail"]
                     and e["signal_id"].startswith("reassert-")), None)
        assert card is not None, f"« {r['detail'][:60]}… » has no card of its own"
        assert any(e["id"] == card["id"] for e in sent), f"« {r['detail'][:60]}… » never notified"
    if mode == "non_disruptive":
        assert [r["outcome"] for r in said][0] == "reapplied" and len(said) == 2
        (last,) = [e for e in escalations.pending() if e["signal_id"].startswith("reassert-")]
        assert "repose pas" in last["reason"] or "réécrit pas" in last["reason"]
    (mine,) = [e for e in escalations.all_escalations() if e["id"] == graph]
    assert (mine["status"], mine["reason"], mine["occurrences"]) == ("pending", _GRAPH_TEXT, 1)


@pytest.mark.parametrize("kind", ["isolation", "block"])
def test_the_graphs_card_after_an_alert_never_overwrites_it(kind):
    """The other way: the alert said, pending; the graph acts again on a new detection, its check
    fails — its card was folded into the alert, overwriting its text (the confidence moved), the
    alert's id kept: the reassertion read its disappearance « said », with the graph's words on
    its card. Two cards, each with its text."""
    c = _gone_beside(kind)
    reassert_active(c, _HUMAN)
    (alert,) = escalations.pending()
    _graph_card(kind)
    assert reassert_active(c, _HUMAN) == []
    said = {e["signal_id"]: e["reason"] for e in escalations.pending()}
    assert said == {alert["signal_id"]: alert["reason"], _GRAPH_SID: _GRAPH_TEXT}


def test_a_drift_card_of_the_name_only_key_for_an_ipv6_in_capitals_is_closed_by_the_next():
    """Seen in passing (I3C's review, second round): the former key, `reassert-{vm}-{ip}` (before
    A0), kept the IP as written, the id read in lowercase. A card of it still pending for an IPv6
    in capitals was never closed: the new alert folded into it, under its old id."""
    escalations.record(signal_id=f"reassert-vm-{_IP6}", resource_id=_RID, action="block_suspicious_ip",
                       escalation_type="verification_failed", reason="Dite par une version antérieure.",
                       action_params={"ip": _IP6})
    _save_block_state("vm", _IP6, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    assert [r["outcome"] for r in reassert_active(c, _HUMAN)] == ["escalated"]
    (old,) = [e for e in escalations.all_escalations() if e["signal_id"] == f"reassert-vm-{_IP6}"]
    (new,) = escalations.pending()
    assert old["status"] == "resolved" and old["resolution"] and "antérieure" not in new["reason"]


# ── L1Qs (#424): the reassertion of the blocks in two times ────────────────────────────────

def _two_perimeters(monkeypatch, listed, db_mode="non_disruptive"):
    """web blocked on its subnet (pair1); db blocked on another subnet and for itself (pair2 and its
    rule r-db, one merged entry), nic-a of db behind web's pair only (its own rule passed by an
    allow), nic-b behind pair2 or r-db. Both pairs and r-db gone. The listing's order is `listed`."""
    from glorfindel import actions as facade
    from glorfindel import reassert as reassert_mod
    rid = {v: f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{v}"
           for v in ("db", "web")}
    for v in rid:
        readiness.record_assessment(readiness._verdict(v, []), rid[v])
    _save_block_state("web", _IP, rid["web"], nsg="rg/nsg-app", nsg_scope="subnet", rule="pair1",
                      scoped=False, threat_port=22)
    _save_block_state("db", _IP, rid["db"], nsg="rg/nsg-data", nsg_scope="subnet", rule="pair2",
                      scoped=False, threat_port=22,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-data", "rule": "r-db"}])
    real = facade.active_blocks
    monkeypatch.setattr(facade, "active_blocks", lambda: sorted(real(), key=lambda b: listed.index(b["vm_name"])))
    monkeypatch.setattr(reassert_mod, "_mode", lambda a, vm, ref="": db_mode if vm == "db" else "non_disruptive")
    world = {"pair1": False, "pair2": False, "db": False}
    writes = []

    def verify(ip, r):
        if r.endswith("/web"):
            return {"verified": True} if world["pair1"] else {"verified": False, "missing_rules": ["pair1"]}
        gone = [n for n, k in (("pair2", "pair2"), ("r-db", "db")) if not world[k]]
        held = (["nic-a"] if world["pair1"] else []) + (["nic-b"] if world["pair2"] or world["db"] else [])
        opened = [n for n in ("nic-a", "nic-b") if n not in held]
        if not gone:
            return {"verified": True} if not opened else {"verified": False, "open_nics": opened}
        if not opened:
            return {"verified": True, "held_missing": gone, "held_by_perimeter": held}
        return {"verified": False, "missing_rules": gone, "open_nics": opened,
                **({"held_by_perimeter": held} if held else {})}

    def block(ip, r, scope, threat_port=None):
        vm = r.rsplit("/", 1)[-1]
        writes.append((vm, scope))
        world[("pair1" if vm == "web" else "pair2") if scope == "subnet" else vm] = True
        return {"status": "blocked"}
    c = MagicMock()
    c.verify_block_ip.side_effect = verify
    c.block_suspicious_ip.side_effect = block
    return c, world, writes


def _db_cards():
    return [e["reason"] for e in escalations.pending()
            if e.get("action") == "block_suspicious_ip" and e["resource_id"].endswith("/db")]


@pytest.mark.parametrize("listed", [("db", "web"), ("web", "db")])
def test_two_perimeters_on_two_subnets_are_both_put_back_before_a_block_is_read_again(monkeypatch, listed):
    """L1Qs, the first case of #424: two entries each holding a perimeter, on two subnets, db with
    a NIC behind each. Read entry after entry, db first (perimeters first, then the listing's
    order): its pair and its rule rewritten, read again with web's pair still gone — « ses règles
    réécrites une fois, il ne tient pas en entier — n'est plus bloquée sur nic-a »; web's entry put
    its pair back a moment later: the card false once the pass ended. No order suits two entries
    that wait for each other. Two times: every pair first, then each entry finished."""
    c, world, writes = _two_perimeters(monkeypatch, listed)
    reassert_active(c, _ACT)
    assert all(world.values()), world
    assert sorted(w for w in writes if w[1] == "subnet") == [("db", "subnet"), ("web", "subnet")], writes
    assert writes.index(("db", "vm")) > max(writes.index(("db", "subnet")), writes.index(("web", "subnet")))
    (card,) = _db_cards()
    assert "reposé une fois" in card and "n'est plus bloquée" not in card, card
    from glorfindel.actions import active_blocks
    entries = {e["vm_name"]: e for e in active_blocks()}
    assert entries["db"].get("reasserted_at") and entries["web"].get("reasserted_at")
    assert not entries["db"].get("drift_alerted_at")


@pytest.mark.parametrize("listed", [("db", "web"), ("web", "db")])
def test_a_block_in_human_only_is_said_once_its_neighbours_perimeter_is_back(monkeypatch, listed):
    """The same, db in human_only (its card, nothing written for it), web outside it: db read before
    web's pair was put back said nic-a « n'est plus bloquée » — web's pair cut it off again a moment
    later. Read in the second time: nic-a « reste bloquée », what is gone of db's own said."""
    c, world, writes = _two_perimeters(monkeypatch, listed, db_mode="human_only")
    reassert_active(c, _ACT)
    assert writes == [("web", "subnet")], writes
    (card,) = _db_cards()
    assert "n'est plus bloquée sur nic-a" not in card and "pair2" in card, card


def test_a_pair_put_back_by_the_first_time_whose_reread_fails_is_said_partial(monkeypatch):
    """Its pair put back by the first time, the entry's re-read in the second raises: never left
    unsaid, never « reposé » — the card says its rules rewritten, and what can't be read."""
    c, world, writes = _two_perimeters(monkeypatch, ("web", "db"))
    real = c.verify_block_ip.side_effect
    seen = {"web": 0}

    def verify(ip, r):
        if r.endswith("/web"):
            seen["web"] += 1
            if seen["web"] == 2:
                raise RuntimeError("(TooManyRequests) networkSecurityGroups")
        return real(ip, r)
    c.verify_block_ip.side_effect = verify
    reassert_active(c, _ACT)
    (card,) = [e["reason"] for e in escalations.pending() if e["resource_id"].endswith("/web")]
    assert "réécrites une fois" in card and "relecture impossible" in card and "reposé une" not in card, card


@pytest.mark.parametrize("merged", [False, True], ids=["perimeter", "merged"])
@pytest.mark.parametrize("listed", [("db", "web"), ("web", "db")])
def test_a_perimeter_left_to_the_second_time_is_still_put_back_before_the_vm_blocks(monkeypatch, listed, merged):
    """The first time leaves an entry it couldn't check (its read raised, a 429): the second puts
    its pair back — before the VM blocks of its subnet, whatever the listing, web's entry merged
    with its own block or not (L1Qr's order, kept for that case)."""
    from glorfindel import actions as facade
    rid = {v: f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{v}"
           for v in ("db", "web")}
    for v in rid:
        readiness.record_assessment(readiness._verdict(v, []), rid[v])
    _save_block_state("db", _IP, rid["db"], placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-db"}],
                      threat_port=22)
    _save_block_state("web", _IP, rid["web"], nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair",
                      scoped=False, threat_port=22,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-web"}] if merged else None)
    real = facade.active_blocks
    monkeypatch.setattr(facade, "active_blocks", lambda: sorted(real(), key=lambda b: listed.index(b["vm_name"])))
    world = {"pair": False, "db": False, "web": False, "web reads": 0}

    def verify(ip, r):
        if r.endswith("/web"):
            world["web reads"] += 1
            if world["web reads"] == 1:
                raise RuntimeError("(TooManyRequests) networkSecurityGroups")
            return {"verified": True} if world["pair"] else {"verified": False, "missing_rules": ["pair"]}
        if world["pair"]:
            return {"verified": True} if world["db"] else {
                "verified": True, "held_missing": ["r-db"], "held_by_perimeter": ["nic-a"]}
        return {"verified": False, "missing_rules": [] if world["db"] else ["r-db"], "open_nics": ["nic-a"]}

    def block(ip, r, scope, threat_port=None):
        world["pair" if scope == "subnet" else r.rsplit("/", 1)[-1]] = True
        return {"status": "blocked"}
    c = MagicMock()
    c.verify_block_ip.side_effect = verify
    c.block_suspicious_ip.side_effect = block
    reassert_active(c, _ACT)
    assert world["pair"] and world["db"]
    assert not [e["reason"] for e in escalations.pending() if "n'est plus bloquée" in e["reason"]]


def _a_gone_perimeter(**extra):
    """web blocked on its subnet alone, its pair gone from Azure; a write puts it back unless it fails."""
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"
    readiness.record_assessment(readiness._verdict("web", []), rid)
    _save_block_state("web", _IP, rid, nsg="rg/nsg-app", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    if extra:
        from glorfindel.actions import _update_block_entry
        _update_block_entry(rid, _IP, **extra)
    world = {"pair": False, "fail": False}

    def block(ip, r, scope, threat_port=None):
        if world["fail"]:
            raise RuntimeError("(AuthorizationFailed) securityRules/write")
        world["pair"] = True
        return {"status": "blocked"}
    c = MagicMock()
    c.verify_block_ip.side_effect = lambda ip, r: (
        {"verified": True} if world["pair"] else {"verified": False, "missing_rules": ["pair", "pair-out"]})
    c.block_suspicious_ip.side_effect = block
    return c, world


@pytest.mark.parametrize("case", ["put back once before", "said, no worse", "held by an unblock"])
def test_the_first_time_writes_only_what_the_second_would(case):
    """The first time decides as the second would (L1Qs): a pair put back once before is said,
    never written again; a disappearance whose write failed, said and no worse, is not retried at
    every pass; an entry an unblock holds is not written."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    extra = {"put back once before": {"reasserted_at": now}, "said, no worse": {},
             "held by an unblock": {"unblocking_at": now}}[case]
    c, world = _a_gone_perimeter(**extra)
    if case == "said, no worse":
        world["fail"] = True
        reassert_active(c, _ACT)                 # the write refused: said, « a échoué »
        assert c.block_suspicious_ip.call_count == 1
        world["fail"] = False
    calls = c.block_suspicious_ip.call_count
    reassert_active(c, _ACT)
    assert c.block_suspicious_ip.call_count == calls, c.block_suspicious_ip.call_args_list
    assert not world["pair"]


def test_a_pair_the_first_time_failed_to_write_is_never_said_put_back():
    """The first time's write refused: the second time says it failed, never « réécrites » nor
    « reposé » on a read that follows nothing written (L1Qs)."""
    c, world = _a_gone_perimeter()
    world["fail"] = True
    reassert_active(c, _ACT)
    (card,) = [e["reason"] for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]
    assert "le reposer a échoué" in card and "AuthorizationFailed" in card, card
    assert c.block_suspicious_ip.call_count == 1


def test_a_drift_better_in_a_pass_whose_first_write_fails_then_gone_again_is_said(monkeypatch):
    """Found by the machine (L1Qs, seed 1 at 500 on the code before the two times; red on `main`):
    a merged block's rules and pair gone, said in human_only, the card acknowledged; the VM's
    rules put back — better than the card, the pair still gone —, in a pass whose first write is
    refused (a full disk: the bypass mark taken off as the block holds); then the rules gone again.
    The baseline was narrowed after that write, never reached: « not worse than the card », in
    silence. Narrowed first, in memory, before any write of the pass: said."""
    from glorfindel import actions as facade
    from glorfindel.actions import _update_block_entry
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-vm"}], threat_port=22)
    gone = {"verified": False, "missing_rules": ["r-vm", "r-vm-out", "pair", "pair-out"], "open_nics": ["nic-a"]}
    held = {"verified": True, "held_missing": ["pair", "pair-out"], "blocked_nics": ["nic-a"]}
    c = _connector(verify_blk=gone)
    reassert_active(c, _HUMAN)
    (card,) = [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]
    escalations.resolve(card["id"])                              # the operator acknowledges it
    _update_block_entry(_RID, _IP, bypass_said=f"reassert-bypass-block-vm-x-{_IP}-0")
    c.verify_block_ip.side_effect = None
    c.verify_block_ip.return_value = held
    real = facade._atomic_write_text

    def full(path, text):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(facade, "_atomic_write_text", full)
    reassert_active(c, _HUMAN)                                    # better, its first write refused
    monkeypatch.setattr(facade, "_atomic_write_text", real)
    c.verify_block_ip.return_value = gone
    reassert_active(c, _HUMAN)                                    # gone again
    assert [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"], (
        "the rules gone again after a better pass were never said")


def _gone_better_worse_gone(scoped: bool):
    """L1Qs' 5.5 review (blocking): a block's pair and its VM's rule gone, the write refused — « a
    échoué », acknowledged; then the VM's rule back and the pair's other half gone — better and worse
    — written: « reposé une fois »; then the pair and the VM's rule gone again. A connector that leaves
    the entry's marks as they are (the Azure adapter clears them on a whole write, L1Q). Returns the
    cards the last pass made."""
    readiness.record_assessment(readiness._verdict("vm", []), _RID)
    if scoped:
        _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                          placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-vm"}], threat_port=22)
    else:
        _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-vm"},
                                                       {"nsg_rg": "rg", "nsg_name": "nsg-nic", "rule": "pair"}],
                          threat_port=22)
    world = {"fail": True, "whole": False, "now": None}

    def block(ip, r, scope, threat_port=None):
        if world["fail"]:
            raise RuntimeError("(AuthorizationFailed) securityRules/write")
        world["whole"] = True
        return {"status": "blocked"}
    c = MagicMock()
    c.block_suspicious_ip.side_effect = block
    c.verify_block_ip.side_effect = lambda ip, r: {"verified": True} if world["whole"] else world["now"]
    world["now"] = {"verified": False, "missing_rules": ["pair", "r-vm"], "open_nics": ["nic-a"]}
    reassert_active(c, _ACT)
    for e in escalations.pending():
        escalations.resolve(e["id"])                                     # the operator acknowledges it
    world["fail"] = False
    world["now"] = {"verified": False, "missing_rules": ["pair", "pair-out"], "open_nics": ["nic-a"]}
    reassert_active(c, _ACT)
    assert any("reposé une fois" in e["reason"] for e in escalations.pending())
    world["whole"] = False
    world["now"] = {"verified": False, "missing_rules": ["pair", "r-vm"], "open_nics": ["nic-a"]}
    n = len(escalations.all_escalations())
    reassert_active(c, _ACT)
    return [e["reason"] for e in escalations.all_escalations()[n:]]


@pytest.mark.parametrize("scoped", [True, False], ids=["perimeter, the first time", "vm block"])
def test_a_drift_better_and_worse_in_a_pass_that_writes_narrows_its_baseline(scoped):
    """The entry the first time writes (a perimeter) has the same first read as any: its baseline
    narrowed — the VM's rule back is what holds —, the same rules gone again are worse than it, said.
    It wasn't: the second time skipped the read's prologue for that entry (red before the fix; a VM
    block, read by the second time alone, said it)."""
    assert _gone_better_worse_gone(scoped), "the rules gone again after a pass that wrote were never said"


def test_a_perimeter_whose_write_fails_again_narrows_its_baseline_before_a_refused_card(monkeypatch):
    """MUT3 (#599, M3153): the first time hands a perimeter entry to the second (`pair`) only when it
    tries its write — since L1O, a write that holds clears the drift mark first, so the narrowing of
    an entry with its `pair` is reached only when the write fails again. Its pair and its VM's rule
    gone, said, acknowledged; then the VM's rule back and the pair's other half gone (better and
    worse), the write refused again and the card's write too (a full disk); then the first read
    again: worse than what held, said. Without the narrowing, the baseline stayed the card's, and
    the same rules gone again read « not worse », in silence."""
    readiness.record_assessment(readiness._verdict("vm", []), _RID)
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg-subnet", "rule": "r-vm"}], threat_port=22)
    c = MagicMock()
    c.block_suspicious_ip.side_effect = RuntimeError("(AuthorizationFailed) securityRules/write")
    first = {"verified": False, "missing_rules": ["pair", "r-vm"], "open_nics": ["nic-a"]}
    c.verify_block_ip.return_value = first
    reassert_active(c, _ACT)
    assert _block_cards(), "the first disappearance was never said"
    for e in escalations.pending():
        escalations.resolve(e["id"])                                     # the operator acknowledges it
    give_back = _store_full(monkeypatch)
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["pair", "pair-out"], "open_nics": ["nic-a"]}
    reassert_active(c, _ACT)                                             # better and worse, its card refused
    give_back()
    c.verify_block_ip.return_value = first
    n = len(escalations.all_escalations())
    reassert_active(c, _ACT)                                             # the first read again
    assert [e for e in escalations.all_escalations()[n:] if e.get("action") == "block_suspicious_ip"], (
        "the rules gone again after a refused card were read « not worse » than the card, unsaid")


def test_a_check_that_raised_is_over_once_the_first_time_reads_and_writes():
    """The entry's check raised — said on its card (V-16); next pass, the first time reads it and puts
    its pair back: the check answered, its card is closed in that pass, as for any entry read (the
    second time shares the first read's prologue: `unverified_over`, the bypass)."""
    readiness.record_assessment(readiness._verdict("vm", []), _RID)
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    c = MagicMock()
    c.verify_block_ip.side_effect = RuntimeError("(AuthorizationFailed) networkSecurityGroups/read")
    reassert_active(c, _ACT)
    assert [e for e in escalations.pending() if e.get("action") == "review_unverified"]
    reads = iter([{"verified": False, "missing_rules": ["pair", "pair-out"]}, {"verified": True}])
    c.verify_block_ip.side_effect = lambda ip, r: next(reads)
    c.block_suspicious_ip.side_effect = None
    c.block_suspicious_ip.return_value = {"status": "blocked"}
    reassert_active(c, _ACT)
    assert not [e for e in escalations.pending() if e.get("action") == "review_unverified"]


# ── L1G (#461): an acknowledged drift holds while none of its rules is written again or more gone ──

_PAIR_SEEN = {"rg/nsg-subnet/pair": None, "rg/nsg-subnet/pair-out": None}
_VM_SEEN = {"rg/nsg/r": None, "rg/nsg/r-out": None}
_GONE_BOTH = {"verified": False, "missing_rules": ["pair", "pair-out", "r", "r-out"], "open_nics": ["nic"],
              "rules_seen": {**_PAIR_SEEN, **_VM_SEEN}}
_PAIR_BACK = {"verified": True, "held_missing": ["r", "r-out"], "held_by_perimeter": ["nic"], "perimeter_rule": "pair",
              "rules_seen": {"rg/nsg-subnet/pair": "a1", "rg/nsg-subnet/pair-out": "a2", **_VM_SEEN}}


def _block_cards():
    return [e for e in escalations.pending() if e.get("action") == "block_suspicious_ip"]


def _said_then(first: dict, then: dict, acknowledged: bool, mode: str = "human_only", merged: bool = True):
    """A block (merged with its perimeter, or the VM's alone) read `first` — said, in human_only —,
    the card acknowledged or left pending, then read `then` in `mode`: the cards pending after."""
    if merged:
        _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                          threat_port=22)
    _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    c = _connector(verify_blk=first)
    reassert_active(c, AutonomyConfig(default="human_only"))
    (card,) = _block_cards()
    if acknowledged:
        escalations.resolve(card["id"])
    c.verify_block_ip.return_value = then
    reassert_active(c, AutonomyConfig(default=mode))
    return c, card, _block_cards()


@pytest.mark.parametrize("acknowledged", [True, False], ids=["acknowledged", "pending"])
def test_a_pair_written_again_after_an_acknowledged_card_ends_its_episode(acknowledged):
    """Seed 29's cause (L1G): a merged entry's pair and its VM's rules gone — said, acknowledged; then
    the pair written again under our name (another VM's perimeter block: one pair per IP and subnet),
    the VM's rules still gone. « Better than the card, not worse »: nothing was said, and the operator
    never heard that what they had acknowledged was over. Said anew now; under a pending card, what
    came back narrows its baseline, nothing more (L1Q)."""
    c, card, after = _said_then(_GONE_BOTH, _PAIR_BACK, acknowledged)
    if acknowledged:
        (new,) = after
        assert new["id"] != card["id"] and "reste bloquée" in new["reason"], new["reason"]
    else:
        assert [e["id"] for e in after] == [card["id"]]
    c.block_suspicious_ip.assert_not_called()                  # human_only: said, never written


def test_a_pair_written_again_after_an_acknowledged_card_is_put_back_outside_human_only():
    """The same, outside human_only and never put back before: a new episode — the VM's rules put back
    once, as for any disappearance not said yet."""
    c, _, after = _said_then(_GONE_BOTH, _PAIR_BACK, True, mode="non_disruptive")
    assert c.block_suspicious_ip.called
    assert [e for e in after if "reposé une fois" in e["reason"]], [e["reason"] for e in after]


@pytest.mark.parametrize("acknowledged", [True, False], ids=["acknowledged", "pending"])
def test_a_rule_read_there_then_deleted_is_a_rule_more_gone(acknowledged):
    """The L1 of L1Qs' `xfail` (L1G): the VM's rules still on Azure, aimed at its old address — named
    « gone » by the check —, said; then deleted. Gone by name both times: « no worse », in silence. A
    rule the card's check read there, now absent, is worse: said again, the card pending or not."""
    first = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic"],
             "rules_seen": {"rg/nsg/r": "old-address", "rg/nsg/r-out": "old-address-out"}}
    then = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic"], "rules_seen": dict(_VM_SEEN)}
    _, card, after = _said_then(first, then, acknowledged, merged=False)
    (new,) = after
    assert new["id"] != card["id"], "the rules deleted after their card went unsaid"


@pytest.mark.parametrize("then_seen", [{"rg/nsg/r": "set-right", "rg/nsg/r-out": None}, None],
                         ids=["set right by hand", "a provider that doesn't say"])
def test_an_acknowledged_drift_set_right_by_hand_says_nothing(then_seen):
    """A rule turned by someone, said, acknowledged; set right by hand — on Azure all along, never
    deleted nor written again: better, nothing said (RB1). A check without `rules_seen` (another
    provider, an older one): as before, by the names."""
    first = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic"],
             **({"rules_seen": {"rg/nsg/r": "turned", "rg/nsg/r-out": None}} if then_seen else {})}
    then = {"verified": False, "missing_rules": ["r-out"], "open_nics": ["nic"],
            **({"rules_seen": then_seen} if then_seen else {})}
    _, _, after = _said_then(first, then, True, merged=False)
    assert not after, [e["reason"] for e in after]


def test_a_rule_the_cards_check_never_read_is_never_read_back():
    """Only the rules both checks read count (L1G): an NSG the card's check never listed, listed
    since, holds rules that were never said gone — nothing written again, nothing said."""
    first = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic"], "rules_seen": dict(_VM_SEEN)}
    then = {**first, "rules_seen": {**_VM_SEEN, "rg/nsg-other/r": "there", "rg/nsg-other/r-out": "there"}}
    _, _, after = _said_then(first, then, True, merged=False)
    assert not after, [e["reason"] for e in after]


def test_a_rule_this_check_did_not_read_is_never_read_deleted():
    """The other side (MUT3, #599, M3282): a rule the card's check read on Azure, left out of this
    check — its NSG not listed now, or unreadable (`_rules_seen` leaves its rules out) — is unknown
    now, not deleted: nothing more gone, nothing said again on an acknowledged card."""
    first = {"verified": False, "missing_rules": ["r"], "open_nics": ["nic"],
             "rules_seen": {"rg/nsg/r": None, "rg/nsg/r-out": "there"}}
    then = {k: v for k, v in first.items() if k != "rules_seen"}
    _, _, after = _said_then(first, then, True, merged=False)
    assert not after, [e["reason"] for e in after]


def test_the_first_time_decides_on_an_acknowledged_episode_as_the_second():
    """The first time decides as the second (L1Qs, `_to_write`): a merged entry's acknowledged drift
    whose pair was written again is over — what is gone is written, never left to a card that no
    longer stands; read the same as its card, said, nothing written."""
    from glorfindel.reassert_cards import new_pass
    from glorfindel.reassert_perimeters import _to_write
    from glorfindel.reassert_said import _situation

    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    reassert_active(_connector(verify_blk=_GONE_BOTH), AutonomyConfig(default="human_only"))
    (card,) = _block_cards()
    escalations.resolve(card["id"])
    new_pass()                                                  # the next pass reads the cards again
    b = _load_block_entries(_RID)[0]
    assert b["drift_said"] == _situation(_GONE_BOTH)
    assert _to_write(b, _PAIR_BACK, _ACT, "vm", _RID, _IP, _RID)
    assert not _to_write(b, _GONE_BOTH, _ACT, "vm", _RID, _IP, _RID)


# ── L1A (#480): a card is closed in the write of the card that replaces it, never before ──

def _store_full(monkeypatch):
    """The escalations store refuses the write that adds a card (the disk full by then: the
    machine's fault from its n-th write lands on it, as at the seed 42) — a rewrite of the cards
    it holds, a closure, goes through, as does every other write. Returns what gives the disk back."""
    real = escalations._write_lines

    def full(lines):
        held = escalations._STORE.read_text().splitlines() if escalations._STORE.exists() else []
        if len([ln for ln in lines if ln.strip()]) > len([ln for ln in held if ln.strip()]):
            raise OSError(28, "No space left on device")
        real(lines)
    monkeypatch.setattr(escalations, "_write_lines", full)
    return lambda: monkeypatch.setattr(escalations, "_write_lines", real)


def test_a_card_replaced_is_closed_in_the_write_of_its_successor(monkeypatch):
    """`record(replaces=…)`: the former card closed, with its note, in the very write of the new
    one — refused, neither happens; a card the operator closed meanwhile keeps his word."""
    a = escalations.record(signal_id="reassert-a", resource_id=_RID, action="isolate_vm",
                           escalation_type="verification_failed", reason="A")
    give_back = _store_full(monkeypatch)
    with pytest.raises(OSError):
        escalations.record(signal_id="reassert-a", resource_id=_RID, action="isolate_vm",
                           escalation_type="verification_failed", reason="B", replaces={a: "Remplacée."})
    give_back()
    assert [(e["id"], e["status"]) for e in escalations.all_escalations()] == [(a, "pending")]
    b = escalations.record(signal_id="reassert-a", resource_id=_RID, action="isolate_vm",
                           escalation_type="verification_failed", reason="B", replaces={a: "Remplacée."})
    old, new = escalations.all_escalations()
    assert (old["id"], old["status"], old["resolution"]) == (a, "resolved", "Remplacée.")
    assert (new["id"], new["status"], new["reason"]) == (b, "pending", "B")       # never folded into A
    escalations.resolve(b)                                                         # the operator
    escalations.record(signal_id="reassert-a", resource_id=_RID, action="isolate_vm",
                       escalation_type="verification_failed", reason="C", replaces={b: "Remplacée."})
    assert "resolution" not in escalations.all_escalations()[1]


def test_a_block_said_again_on_a_full_store_keeps_its_card_while_unchecked(monkeypatch):
    """The seed 42 at 500 (L1A, #480), by hand: a block's drift said, its card pending; worse (a
    second rule gone), said again — `_alert` closed the pending card, then the new one was refused
    (a full disk): no card, the mark kept from before. The next pass can't check the block (the
    check raises): it said nothing — gone, unsaid (L1). The former card waits now; read again,
    the drift is said, the former card closed in that write."""
    placed = [{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}, {"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r2"}]
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r", placements=placed,
                      threat_port=22)
    human = AutonomyConfig(default="human_only")
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    reassert_active(c, human)
    (card,) = _block_drift_cards()
    mark = _load_block_entries("vm")[0]["drift_alerted_at"]
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["r", "r2"]}
    give_back = _store_full(monkeypatch)
    assert [r["outcome"] for r in reassert_active(c, human)] == ["failed"]         # said: not written
    give_back()
    assert [e["id"] for e in _block_drift_cards()] == [card["id"]]
    assert _load_block_entries("vm")[0]["drift_alerted_at"] == mark                # the mark as it was
    c.verify_block_ip.side_effect = RuntimeError("(AuthorizationFailed)")
    reassert_active(c, human)
    assert [e["id"] for e in _block_drift_cards()] == [card["id"]]                # still said
    c.verify_block_ip.side_effect = None
    reassert_active(c, human)
    (now,) = _block_drift_cards()
    assert now["id"] != card["id"]
    (old,) = [e for e in escalations.all_escalations() if e["id"] == card["id"]]
    assert old["status"] == "resolved" and old["resolution"].startswith("Remplacée")


def test_an_isolation_gone_again_on_a_full_store_keeps_its_card_and_no_mark(monkeypatch):
    """Put back once, said (« reposée une fois »); gone again, the second card refused: the first
    still waits, no mark written (L1F) — the next pass says it, the first card closed in that write."""
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    reassert_active(c, _ACT)
    (first,) = escalations.pending()
    c.verify_isolation.return_value = {"verified": False, "uncovered_nics": ["nic-a"]}     # gone again
    give_back = _store_full(monkeypatch)
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["failed"]
    give_back()
    assert [e["id"] for e in escalations.pending()] == [first["id"]]
    assert "drift_alerted_at" not in _load_isolation_state("vm")
    reassert_active(c, _ACT)
    (now,) = escalations.pending()
    assert "deuxième fois" in now["reason"] and now["id"] != first["id"]


def test_a_bypass_changed_on_a_full_store_keeps_its_former_card(monkeypatch):
    """A bypass A said; it changes to B, B's card refused: A was closed first, and a pass that
    can't tell (`verified: None`) said nothing of the bypass. A waits now, its mark too; B read
    again, B's card closes A in its write."""
    _isolated()
    c = _connector(_bypass(_ALLOW))
    reassert_active(c, _ACT)
    (a,) = _bypass_cards("pending")
    c.verify_isolation.return_value = _bypass(_ALLOW, _RDP)
    give_back = _store_full(monkeypatch)
    reassert_active(c, _ACT)
    give_back()
    assert _bypass_cards("pending") == [a] and _load_isolation_state("vm")["bypass_said"] == a["signal_id"]
    c.verify_isolation.return_value = {"verified": None, "error": "règles illisibles"}
    reassert_active(c, _ACT)
    assert [e["id"] for e in _bypass_cards("pending")] == [a["id"]]
    c.verify_isolation.return_value = _bypass(_ALLOW, _RDP)
    reassert_active(c, _ACT)
    (b,) = _bypass_cards("pending")
    assert "allow-rdp" in b["reason"]
    assert [e["resolution"] for e in _bypass_cards("resolved")] == ["Contournement changé : une nouvelle carte le dit."]


def test_left_rules_changed_on_a_full_store_keep_their_former_card(monkeypatch):
    """Another set of rules left, its card refused: the former card still waits (L1A)."""
    from glorfindel.reassert_cards import say_left
    say_left("vm", _RID, _IP, _left("glorfindel-block-a"), [], _RID)
    (a,) = _left_cards("pending")
    give_back = _store_full(monkeypatch)
    with pytest.raises(OSError):
        say_left("vm", _RID, _IP, _left("glorfindel-block-b"), [], _RID)
    give_back()
    assert _left_cards("pending") == [a]
    say_left("vm", _RID, _IP, _left("glorfindel-block-b"), [], _RID)
    (b,) = _left_cards("pending")
    assert "glorfindel-block-b" in b["reason"] and _left_cards("resolved")[0]["id"] == a["id"]


def test_an_unreadable_set_changed_on_a_full_store_keeps_its_former_card(monkeypatch):
    """Another set of state files unreadable, its card refused: the former card still waits; the
    files all read again, it closes — no new card to write (L1A)."""
    from glorfindel import actions
    from glorfindel.reassert_cards import say_unreadable_states
    _broken("a--00000000.json")
    say_unreadable_states([])
    (a,) = _state_cards("pending")
    _broken("b--00000000.json")
    give_back = _store_full(monkeypatch)
    with pytest.raises(OSError):
        say_unreadable_states([])
    give_back()
    assert _state_cards("pending") == [a]
    say_unreadable_states([])
    (b,) = _state_cards("pending")
    assert b["id"] != a["id"] and _state_cards("resolved")[0]["id"] == a["id"]
    for name in ("a--00000000.json", "b--00000000.json"):
        (actions._ISOLATION_STATE_DIR / name).unlink()
    say_unreadable_states([])
    assert not _state_cards("pending")


def test_a_quarantine_changed_on_a_full_store_keeps_its_former_card(monkeypatch):
    """A quarantine NSG's change A said; B's card refused — by the store's write, not a mock of
    `record`: A still waits; B said next, A closed in its write, with its note (L1A)."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(*[("altered", d) for d in (_DENY_IN, _FORENSIC, _FORENSIC)])
    reassert_pass(c, _ACT)
    (a,) = _cards("pending")
    give_back = _store_full(monkeypatch)
    with pytest.raises(OSError):
        reassert_pass(c, _ACT)
    give_back()
    assert _cards("pending") == [a]
    reassert_pass(c, _ACT)
    (b,) = _cards("pending")
    assert b["id"] != a["id"] and "forensic" in b["reason"]
    assert [e["resolution"] for e in _cards("resolved")] == [reassert_quarantine._CHANGED]


def test_a_quarantine_whole_again_then_back_is_said_while_its_record_is_kept(monkeypatch):
    """A change said; the NSG whole again — its card closed by Glorfindel, with its note — while
    quarantine_alerts.json can't be written (it keeps the change). The same change back: said,
    never read as the operator's acknowledgement (L2Q; M1861, realigned by L1A)."""
    from glorfindel.reassert import reassert_pass
    c = _quarantines(("altered", _DENY_IN), ("whole", []), ("altered", _DENY_IN))
    reassert_pass(c, _ACT)
    (a,) = _cards("pending")
    give_back = _alerts_unwritable(monkeypatch)
    reassert_pass(c, _ACT)
    give_back()
    assert not _cards("pending") and _cards("resolved")[0]["resolution"] == reassert_quarantine._SETTLED
    reassert_pass(c, _ACT)
    (card,) = _cards("pending")
    assert card["signal_id"] == a["signal_id"] and card["id"] != a["id"]


# ── L1H (#483): the pair the card read turned, written again by another perimeter ──

_PAIR_TURNED = {"verified": False, "missing_rules": ["pair", "pair-out", "r", "r-out"], "open_nics": ["nic"],
                "rules_seen": {"rg/nsg-subnet/pair": "turned", "rg/nsg-subnet/pair-out": "turned-out", **_VM_SEEN}}


@pytest.mark.parametrize("acknowledged", [True, False], ids=["acknowledged", "pending"])
def test_a_turned_pair_written_again_after_an_acknowledged_card_ends_its_episode(acknowledged):
    """Seed 5 at 500's cause (L1H): a merged entry's pair turned into an allow — on Azure, « gone » by what
    it does — and its VM's rules deleted: said, acknowledged; then another VM's perimeter block wrote the
    pair over the turned one, a deny again, the VM's rules still gone. The card had read the pair there,
    so nothing read « back » by presence alone: « better than the card, not worse », in silence. Said
    anew now, as for a pair absent at the card (L1G); under a pending card, nothing more (L1Q)."""
    c, card, after = _said_then(_PAIR_TURNED, _PAIR_BACK, acknowledged)
    if acknowledged:
        (new,) = after
        assert new["id"] != card["id"] and "reste bloquée" in new["reason"], new["reason"]
        assert "r, r-out" in new["reason"], new["reason"]               # what is still gone, by name
    else:
        assert [e["id"] for e in after] == [card["id"]]
    c.block_suspicious_ip.assert_not_called()                  # human_only: said, never written


def test_a_turned_pair_written_again_after_an_acknowledged_card_is_put_back_outside_human_only():
    """The same outside human_only, never put back before: a new episode — the VM's rules written once."""
    c, card, after = _said_then(_PAIR_TURNED, _PAIR_BACK, True, mode="non_disruptive")
    assert "vm" in [k.kwargs.get("scope") for k in c.block_suspicious_ip.call_args_list], \
        c.block_suspicious_ip.call_args_list                   # the VM's rules written again
    assert [e for e in after if e["id"] != card["id"]], [e["reason"] for e in after]


@pytest.mark.parametrize("then", ["turned otherwise", "a vm rule set right", "a pair held, changed"])
def test_an_acknowledged_drift_whose_pair_did_not_come_back_says_nothing(then):
    """Only the pair, only from « gone » to holding (L1H): the pair turned at the card and turned
    otherwise since — still gone, no worse —; a VM's own rule turned, set right in place, the pair held
    both times (RB1: its own block alone writes it, and ends the episode on its own, L1Q); the pair held
    at the card, changed since and holding still — it was never said gone. Nothing said again."""
    if then == "turned otherwise":
        first, now = _PAIR_TURNED, {**_PAIR_TURNED, "rules_seen": {
            "rg/nsg-subnet/pair": "turned-to-udp", "rg/nsg-subnet/pair-out": "turned-out", **_VM_SEEN}}
    elif then == "a vm rule set right":
        held = {"verified": True, "held_by_perimeter": ["nic"], "perimeter_rule": "pair"}
        first = {**held, "held_missing": ["r", "r-out"],
                 "rules_seen": {"rg/nsg-subnet/pair": "a1", "rg/nsg-subnet/pair-out": "a2",
                                "rg/nsg/r": "turned", "rg/nsg/r-out": None}}
        now = {**held, "held_missing": ["r-out"],
               "rules_seen": {"rg/nsg-subnet/pair": "a1", "rg/nsg-subnet/pair-out": "a2",
                              "rg/nsg/r": "set-right", "rg/nsg/r-out": None}}
    else:
        first = _PAIR_BACK
        now = {**_PAIR_BACK, "rules_seen": {**_PAIR_BACK["rules_seen"], "rg/nsg-subnet/pair": "a1-moved"}}
    _, _, after = _said_then(first, now, True)
    assert not after, [e["reason"] for e in after]


def test_the_pair_of_an_entry_is_named_by_its_nsg_and_rule():
    """`_pair_keys`: the keys `rules_seen` gives the entry's perimeter pair — in lowercase, as the check
    writes them —, none for a VM block nor for an entry that doesn't say where its pair is."""
    from glorfindel.reassert_said import _pair_keys
    assert _pair_keys({"scoped": False, "nsg": "rg/NSG-Subnet", "rule": "Pair"}) == {
        "rg/nsg-subnet/pair", "rg/nsg-subnet/pair-out"}
    assert _pair_keys({"scoped": True, "nsg": "rg/nsg-subnet", "rule": "pair"}) == set()
    assert _pair_keys({"nsg": "rg/nsg-subnet", "rule": "pair"}) == set()
    assert _pair_keys({"scoped": False, "nsg": "nsg-subnet", "rule": "pair"}) == set()
    assert _pair_keys({"scoped": False, "nsg": "rg/nsg-subnet"}) == set()


def test_the_first_time_decides_on_a_turned_pair_written_again_as_the_second():
    """The first time decides as the second (L1Qs, `_to_write`): the acknowledged card read the pair
    turned; written again since, the episode is over — what is gone is written."""
    from glorfindel.reassert_cards import new_pass
    from glorfindel.reassert_perimeters import _to_write

    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)
    reassert_active(_connector(verify_blk=_PAIR_TURNED), AutonomyConfig(default="human_only"))
    (card,) = _block_cards()
    escalations.resolve(card["id"])
    new_pass()
    b = _load_block_entries(_RID)[0]
    assert _to_write(b, _PAIR_BACK, _ACT, "vm", _RID, _IP, _RID)
    assert not _to_write(b, _PAIR_TURNED, _ACT, "vm", _RID, _IP, _RID)


# ── L1O (#507): « reposé une fois » ends its episode — gone again before the next pass, said ──

def _l1o_writes(c) -> list:
    """The scopes the reassertion wrote, in order."""
    return [k.kwargs.get("scope") for k in c.block_suspicious_ip.call_args_list]


def _l1o_merged() -> None:
    """One merged entry (RB1): its perimeter pair and its VM's own rules."""
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                      threat_port=22)


# The VM's own block alone (no first time: `_rewrite_block` writes it all): both rules gone; then its
# inbound rule written again by someone, read there (`_back`), its outbound still gone.
_L1O_VM_GONE = {"verified": False, "missing_rules": ["r", "r-out"], "open_nics": ["nic"], "rules_seen": dict(_VM_SEEN)}
_L1O_VM_BACK = {"verified": False, "missing_rules": ["r-out"], "open_nics": ["nic"],
                "rules_seen": {"rg/nsg/r": "a", "rg/nsg/r-out": None}}
# kind → (the first read, everything gone; the read after, something back, something still gone)
_L1O_KINDS = {"vm": (_L1O_VM_GONE, _L1O_VM_BACK), "merged": (_GONE_BOTH, _PAIR_BACK)}


def _l1o_failed_then_acknowledged(kind: str = "merged"):
    """The way of L1G, without the journal, its first half: the entry — the VM's own block (`vm`: written by
    `_rewrite_block` alone) or merged with its perimeter (`merged`: the pair by the first time) — read with
    everything gone, outside human_only; putting it back fails — said, marked (`drift_alerted_at`,
    `drift_said`), the episode open —; the operator acknowledges the card. Then a rule of it is written
    again by someone (merged: another VM's perimeter block writes the pair), the rest still gone: the
    connector reads that from now on. The connector, the card, what it reads now."""
    first, then = _L1O_KINDS[kind]
    if kind == "merged":
        _l1o_merged()
    else:
        _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)
    c = _connector(verify_blk=first)
    blocked = c.block_suspicious_ip.side_effect
    c.block_suspicious_ip.side_effect = RuntimeError("429 Too Many Requests")
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["failed"], report
    (card,) = _block_cards()
    escalations.resolve(card["id"])
    c.block_suspicious_ip.side_effect = blocked
    c.block_suspicious_ip.reset_mock()
    c.verify_block_ip.return_value = then
    return c, card, then


def _l1o_put_back_once(kind: str = "merged"):
    """The way of L1G, whole: after the acknowledged failure, the rule read back ends that episode
    (`_back`, L1G), what is still gone put back once, read whole — « reposé une fois ». The mocked
    connector never rewrites the entry (the Azure adapter's own state write does, see
    `docs/design/preuves.md`): what the reassertion itself writes is what is tested. The connector, the
    card « reposé une fois », the read before the put-back."""
    c, _, then = _l1o_failed_then_acknowledged(kind)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["reapplied"], report
    (put_back,) = _block_cards()
    assert "reposé une fois" in put_back["reason"], put_back["reason"]
    assert _l1o_writes(c) == (["vm"] if kind == "vm" else ["subnet", "vm"])
    c.block_suspicious_ip.reset_mock()
    return c, put_back, then


_L1O_KIND = pytest.mark.parametrize("kind", ["vm", "merged"])


@_L1O_KIND
@pytest.mark.parametrize("acknowledged", [False, True], ids=["pending", "acknowledged"])
@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
def test_l1o_put_back_after_an_acknowledged_failure_then_gone_again_is_said_a_second_time(mode, acknowledged,
                                                                                           kind):
    """L1O (#507), the way of L1G: put back once after an acknowledged failure, then gone again before the
    next pass — as it was read when it was put back. The entry kept the marks of the failure, the episode
    stayed open, the card « reposé une fois » pending or acknowledged: « already said, no worse », in
    silence — yet that card says « s'il disparaît encore, Glorfindel alertera sans le reposer ». The
    episode ends in the write of `reasserted_at` — `_rewrite_block`'s (`vm`), the first time's too
    (`merged`): said « une deuxième fois », never written again, in either mode (L1Q: put back once at
    most; nothing in human_only)."""
    c, put_back, then = _l1o_put_back_once(kind)
    if acknowledged:
        escalations.resolve(put_back["id"])
    c.verify_block_ip.return_value = then                       # gone again, as read when it was put back
    reassert_active(c, AutonomyConfig(default=mode))
    after = [e for e in _block_cards() if e["id"] != put_back["id"]]
    assert after, "gone again after « reposé une fois », unsaid"
    (new,) = after
    assert "une deuxième fois" in new["reason"] and "ne le repose pas" in new["reason"], new["reason"]
    assert _l1o_writes(c) == []


@_L1O_KIND
def test_l1o_the_put_back_takes_the_marks_off_in_the_write_of_reasserted_at(kind):
    """The episode over on disk too: `reasserted_at` written, `drift_alerted_at` and `drift_said` taken off
    in the same write — a restart, or a reader of the state, never sees a « said » episode over."""
    _l1o_put_back_once(kind)
    (b,) = _load_block_entries(_RID)
    assert b.get("reasserted_at")
    assert not b.get("drift_alerted_at") and not b.get("drift_said"), b


@_L1O_KIND
def test_l1o_said_a_second_time_once_then_nothing_never_written_again(kind):
    """No loop: said « une deuxième fois » once; the passes after read the same — its card pending,
    nothing; acknowledged, nothing more, pass after pass. Never written again outside human_only (L1Q)."""
    c, put_back, then = _l1o_put_back_once(kind)
    c.verify_block_ip.return_value = then
    reassert_active(c, _ACT)
    (second,) = [e for e in _block_cards() if e["id"] != put_back["id"]]
    for _ in range(2):
        reassert_active(c, _ACT)
        assert [e["id"] for e in _block_cards() if e["id"] != put_back["id"]] == [second["id"]]
    escalations.resolve(second["id"])
    escalations.resolve(put_back["id"])
    for _ in range(2):
        reassert_active(c, _ACT)
        assert not _block_cards(), [e["reason"] for e in _block_cards()]
    assert _l1o_writes(c) == []


@_L1O_KIND
def test_l1o_the_episode_is_over_even_when_the_write_of_its_end_is_refused(monkeypatch, kind):
    """Over first, in memory, whatever the write does: the write of `reasserted_at` refused (a full disk),
    the failure's marks stay on disk — read alone, with the episode still open, the pass after said
    nothing of rules still gone. Said again (the put-back unrecorded, `unrecorded` says it may be)."""
    c, card, then = _l1o_failed_then_acknowledged(kind)
    undo = _l1o_refuse_reasserted_at(monkeypatch)
    report = reassert_active(c, _ACT)
    assert report and all(r["outcome"] == "failed" for r in report), report     # unrecorded, said
    (b,) = _load_block_entries(_RID)
    assert b.get("drift_alerted_at") and not b.get("reasserted_at")             # the marks of the failure
    undo()
    c.verify_block_ip.return_value = then
    reassert_active(c, _ACT)
    assert [e for e in _block_cards() if e["id"] != card["id"]], "the rules still gone, unsaid"


def _l1o_refuse_reasserted_at(monkeypatch):
    """The write of `reasserted_at` refused (a full disk), every other write let through: undone by the
    returned function."""
    import glorfindel.actions as actions
    real = actions._update_block_entry

    def refused(vm_ref, ip, **fields):
        if "reasserted_at" in fields:
            raise OSError(28, "No space left on device")
        return real(vm_ref, ip, **fields)
    monkeypatch.setattr(actions, "_update_block_entry", refused)
    return lambda: monkeypatch.setattr(actions, "_update_block_entry", real)


def test_l1o_a_partial_put_back_still_marks_its_episode():
    """Ended in the write of `reasserted_at`, the episode opens again with the card of a put-back that does
    not hold whole (`partial`): its marks written after that card. The pass after reads the same — one
    card, nothing more, nothing written; never « une deuxième fois » every pass."""
    _l1o_merged()
    c = _connector(verify_blk=_GONE_BOTH)

    def half(ip, rid, scope="vm", threat_port=None):
        if scope == "vm":
            raise RuntimeError("429 Too Many Requests")
        c.verify_block_ip.return_value = _PAIR_BACK              # the pair written, the VM's rules not
        return {"status": "blocked"}
    c.block_suspicious_ip.side_effect = half
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"], report
    (card,) = _block_cards()
    (b,) = _load_block_entries(_RID)
    assert b.get("reasserted_at") and b.get("drift_alerted_at") and b.get("drift_said"), b
    c.block_suspicious_ip.reset_mock()
    for _ in range(2):
        reassert_active(c, _ACT)
        assert [e["id"] for e in _block_cards()] == [card["id"]], [e["reason"] for e in _block_cards()]
    assert _l1o_writes(c) == []


def test_l1o_after_a_restart_the_episode_ended_in_memory_is_never_reopened(monkeypatch):
    """The closure in memory (`_EPISODE_OPEN`), alone (L1O's review): a merged entry, everything gone,
    the put-back fails (429), its card acknowledged; the watch restarts (its memory empty: the
    disappearance is no longer « said »); the pass after puts the block back, the write of
    `reasserted_at` refused — the failure's marks stay on disk. Gone again: with the episode left open
    in memory (`over=False`), the acknowledged card and the marks read « already said », no card and no
    write. Over: said, or put back again (`reasserted_at` never written, as `unrecorded` warns)."""
    from glorfindel import reassert_cards

    _l1o_merged()
    c = _connector(verify_blk=_GONE_BOTH)
    blocked = c.block_suspicious_ip.side_effect
    c.block_suspicious_ip.side_effect = RuntimeError("429 Too Many Requests")
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["failed"]
    (card,) = _block_cards()
    escalations.resolve(card["id"])
    reassert_active(c, _ACT)
    assert not _block_cards()                                   # acknowledged, the same: nothing
    reassert_cards._EPISODE_OPEN.clear()                        # the watch restarted
    reassert_cards._HISTORY.clear()
    c.block_suspicious_ip.side_effect = blocked
    c.verify_block_ip.return_value = _GONE_BOTH
    undo = _l1o_refuse_reasserted_at(monkeypatch)
    report = reassert_active(c, _ACT)
    assert report and all(r["outcome"] == "failed" for r in report), report     # unrecorded, said
    undo()
    (b,) = _load_block_entries(_RID)
    assert b.get("drift_alerted_at") and not b.get("reasserted_at"), b
    c.block_suspicious_ip.reset_mock()
    c.verify_block_ip.return_value = _GONE_BOTH                 # gone again
    reassert_active(c, _ACT)
    assert _block_cards() or _l1o_writes(c), "gone again, nothing said nor written"


@pytest.mark.parametrize("write", ["written", "refused"])
def test_l1o_a_pass_cut_between_its_two_times_ends_the_episode_too(monkeypatch, write):
    """The first time (L1Qs) ends the episode in its write of `reasserted_at`, as `_rewrite_block` does —
    the core whole, whatever the connector writes of the entry (MC0, L1O's review). A merged entry said
    after a failed put-back, its card acknowledged; the pair written again by another VM (`_back`): the
    first time puts it back, the second time skipped (its lock held). Then everything gone again, as the
    card read it. Marks kept and the episode open, the acknowledged card read « already said »: silent.
    Written: marks off on disk, said « une deuxième fois », never written again; the write refused: over
    in memory all the same, said (and put back, `reasserted_at` never written)."""
    from glorfindel import reassert

    c, card, _ = _l1o_failed_then_acknowledged("merged")
    real_block = reassert._reassert_block
    monkeypatch.setattr(reassert, "_reassert_block", lambda *a, **k: None)     # the second time skipped
    undo = _l1o_refuse_reasserted_at(monkeypatch) if write == "refused" else (lambda: None)
    reassert_active(c, _ACT)
    undo()
    monkeypatch.setattr(reassert, "_reassert_block", real_block)
    assert _l1o_writes(c) == ["subnet"]
    (b,) = _load_block_entries(_RID)
    if write == "written":
        assert b.get("reasserted_at") and not b.get("drift_alerted_at") and not b.get("drift_said"), b
    c.block_suspicious_ip.reset_mock()
    c.verify_block_ip.return_value = _GONE_BOTH                 # gone again, as the card read it
    reassert_active(c, _ACT)
    after = [e for e in _block_cards() if e["id"] != card["id"]]
    assert after, "the pair put back by the first time, gone again: unsaid"
    if write == "written":
        (new,) = after
        assert "une deuxième fois" in new["reason"], new["reason"]
        assert _l1o_writes(c) == []


# ── L1W (#492): a perimeter pair another VM wrote again, gone again before any pass ──

_L1W_PAIR_GONE = {"verified": False, "missing_rules": ["pair", "pair-out"], "open_nics": ["nic"],
              "rules_seen": dict(_PAIR_SEEN)}
_L1W_PAIR_HELD = {"verified": True, "held_missing": ["r", "r-out"], "held_by_perimeter": ["nic"],
                      "perimeter_rule": "pair",
                      "rules_seen": {"rg/nsg-subnet/pair": "a1", "rg/nsg-subnet/pair-out": "a2", **_VM_SEEN}}


def _another_vms_perimeter(pair: str = "pair") -> None:
    """Another VM blocked on the same subnet: the pair, one per IP and subnet, written by Glorfindel."""
    from glorfindel.response.pair_journal import note_pair_write
    note_pair_write("rg/NSG-Subnet", pair)


def _pair_said(first: dict, acknowledged: bool, written: str, mode: str = "human_only", merged: bool = False):
    """A perimeter entry (merged with the VM's own rules or not) read `first` — said, in human_only —, the
    card acknowledged or left pending; the pair written by another VM's perimeter block `written`
    (« after » the acknowledgement, « before » it, « never »), gone again before any pass: read `first`
    again, in `mode`. The connector, the card, the cards pending after."""
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    if merged:
        _save_block_state("vm", _IP, _RID, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}],
                          threat_port=22)
    c = _connector(verify_blk=first)
    reassert_active(c, AutonomyConfig(default="human_only"))
    (card,) = _block_cards()
    if written == "before":
        _another_vms_perimeter()
    if acknowledged:
        escalations.resolve(card["id"])
    if written == "after":
        _another_vms_perimeter()
    c.verify_block_ip.return_value = first
    reassert_active(c, AutonomyConfig(default=mode))
    return c, card, _block_cards()


@pytest.mark.parametrize("acknowledged", [True, False], ids=["acknowledged", "pending"])
def test_a_pair_written_again_by_another_vm_then_gone_after_an_acknowledged_card_is_said(acknowledged):
    """L1W (#492): web of rg-app2 blocked on its subnet, the pair taken off, said in human_only, the
    card acknowledged; web of rg-app1 blocked on the same subnet writes the pair again, taken off again
    before any pass. The reading is the card's — no pass saw it back —, and rg-app2/web's entry stayed
    silent behind its acknowledged card. Glorfindel's journal of its pair writes ends the episode: said
    anew, nothing written in human_only. Under a pending card, the card still says what is: nothing more."""
    c, card, after = _pair_said(_L1W_PAIR_GONE, acknowledged, "after")
    if acknowledged:
        (new,) = after
        assert new["id"] != card["id"] and "a disparu" in new["reason"], new["reason"]
    else:
        assert [e["id"] for e in after] == [card["id"]]
    c.block_suspicious_ip.assert_not_called()                  # human_only: said, never written


def test_a_pair_written_again_by_another_vm_then_gone_is_said_once_not_in_a_loop():
    """Said anew once: the pass after reads the same, its card pending — nothing; acknowledged in turn,
    no write of the pair since — nothing, pass after pass."""
    c, _, after = _pair_said(_L1W_PAIR_GONE, True, "after")
    (new,) = after
    reassert_active(c, AutonomyConfig(default="human_only"))
    assert [e["id"] for e in _block_cards()] == [new["id"]]
    escalations.resolve(new["id"])
    for _ in range(2):
        reassert_active(c, AutonomyConfig(default="human_only"))
        assert not _block_cards(), [e["reason"] for e in _block_cards()]
    c.block_suspicious_ip.assert_not_called()


def test_a_pair_written_again_by_another_vm_then_gone_is_put_back_once_outside_human_only():
    """The same outside human_only, never put back before: a new episode — the pair written once (the
    first time, L1Qs), said « reposé une fois »."""
    c, card, after = _pair_said(_L1W_PAIR_GONE, True, "after", mode="non_disruptive")
    assert [k.kwargs.get("scope") for k in c.block_suspicious_ip.call_args_list] == ["subnet"]
    assert [e for e in after if e["id"] != card["id"] and "reposé une fois" in e["reason"]], \
        [e["reason"] for e in after]
    assert _load_block_entries(_RID)[0].get("reasserted_at")


@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
@pytest.mark.parametrize("case", ["written before the acknowledgement", "never written", "another pair written",
                                  "the pair held at the card"])
def test_an_acknowledged_drift_whose_pair_was_not_written_since_says_nothing(case, mode):
    """Only a write after the acknowledgement, only of the entry's pair, only of a pair the card said
    gone (L1W): written between the card and its acknowledgement — gone again when the operator closed
    it, the card still said what was —; never written; another IP's pair (another rule) written; the
    pair held at the card, the VM's own rules gone, the pair written again since — never said gone,
    nothing over. Nothing said, nothing written."""
    if case == "written before the acknowledgement":
        c, _, after = _pair_said(_L1W_PAIR_GONE, True, "before", mode=mode)
    elif case == "never written":
        c, _, after = _pair_said(_L1W_PAIR_GONE, True, "never", mode=mode)
    elif case == "another pair written":
        c, _, _ = _pair_said(_L1W_PAIR_GONE, True, "never", mode=mode)
        _another_vms_perimeter("glorfindel-block-another-ip")
        reassert_active(c, AutonomyConfig(default=mode))
        after = _block_cards()
    else:
        c, _, after = _pair_said(_L1W_PAIR_HELD, True, "after", mode=mode, merged=True)
    assert not after, [e["reason"] for e in after]
    c.block_suspicious_ip.assert_not_called()


def test_the_first_time_decides_on_a_pair_written_again_then_gone_as_the_second():
    """The first time decides as the second (L1Qs, `_to_write`): the acknowledged card's pair written
    since, gone again — the episode is over, the pair written; not written since: nothing."""
    from glorfindel.reassert_cards import new_pass
    from glorfindel.reassert_perimeters import _to_write

    _save_block_state("vm", _IP, _RID, nsg="rg/nsg-subnet", nsg_scope="subnet", rule="pair", scoped=False,
                      threat_port=22)
    reassert_active(_connector(verify_blk=_L1W_PAIR_GONE), AutonomyConfig(default="human_only"))
    (card,) = _block_cards()
    escalations.resolve(card["id"])
    new_pass()
    b = _load_block_entries(_RID)[0]
    assert not _to_write(b, _L1W_PAIR_GONE, _ACT, "vm", _RID, _IP, _RID)
    _another_vms_perimeter()
    new_pass()
    assert _to_write(b, _L1W_PAIR_GONE, _ACT, "vm", _RID, _IP, _RID)


def test_the_journal_of_pair_writes_says_a_write_at_or_after_a_time():
    """`pair_written_since`: a write of one of the pairs at the time or after it; before it, another pair,
    a line cut (a full disk), a journal absent — no. Beside the blocks' states, wherever they go."""
    import json

    import glorfindel.actions as actions
    from glorfindel.response.pair_journal import _pair_journal, note_pair_write, pair_written_since

    pairs = {"rg/nsg-subnet/pair", "rg/nsg-subnet/pair-out"}
    assert _pair_journal().parent == actions._BLOCK_STATE_DIR.parent
    assert not pair_written_since(pairs, "")                         # no journal
    _pair_journal().parent.mkdir(parents=True, exist_ok=True)
    _pair_journal().write_text('{"pair": "rg/nsg-subnet/pair", "at": "2026-11-0')   # cut by a full disk
    note_pair_write("rg/NSG-Subnet", "Pair")                         # on a line of its own all the same
    at = json.loads(_pair_journal().read_text().splitlines()[-1])["at"]
    assert pair_written_since(pairs, at) and pair_written_since(pairs, "")
    assert not pair_written_since(pairs, "2999-01-01T00:00:00+00:00")
    assert not pair_written_since({"rg/nsg-subnet/other"}, "")
    assert pair_written_since(pairs, "not a time")                   # an unknown acknowledgement: any write


def test_a_perimeter_block_notes_its_pair_before_writing_it(monkeypatch):
    """The Azure adapter notes the pair before its write: a write that reached Azure and then raised
    (a 429 after it, a crash) is noted too — a card more, never one less (L1W)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    from glorfindel.response.pair_journal import pair_written_since

    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "Subnet-NSG"))
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.side_effect = RuntimeError("429 after the write")
    connector._network = net
    with pytest.raises(RuntimeError):
        connector.block_suspicious_ip("192.31.196.47", _RID, scope="subnet")
    assert pair_written_since({"rg/subnet-nsg/glorfindel-block-192-31-196-47"}, "")


def test_a_journal_that_cannot_be_written_never_stops_the_block(monkeypatch, caplog):
    """The journal refused (a directory in its place, a full disk): the perimeter block is written all the
    same, the refusal logged — never in the way of the block (L1W)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    from glorfindel.response.pair_journal import _pair_journal

    _pair_journal().mkdir(parents=True)
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "subnet-nsg"))
    net = MagicMock()
    net.security_rules.list.return_value = []
    connector._network = net
    with caplog.at_level("WARNING"):
        out = connector.block_suspicious_ip("192.31.196.47", _RID, scope="subnet")
    assert out["status"].startswith("blocked"), out               # partial: the mock's NICs unread
    assert net.security_rules.begin_create_or_update.call_count == 2
    assert "written unnoted" in caplog.text


def test_a_line_out_of_utf8_never_silences_the_journal():
    """L1W's review: one line forged out of UTF-8 made the whole read raise — every write unseen, L1W's
    case silent again. Read line by line, the byte replaced: that line is no pair of ours, the others
    still read."""
    from glorfindel.response.pair_journal import _pair_journal, note_pair_write, pair_written_since

    _pair_journal().parent.mkdir(parents=True, exist_ok=True)
    _pair_journal().write_bytes(b'{"pair": "rg/nsg-subnet/\xff\xfe", "at": "2026-11-04T00:00:00+00:00"}')
    note_pair_write("rg/nsg-subnet", "pair")
    assert pair_written_since({"rg/nsg-subnet/pair"}, "")


@pytest.mark.parametrize("what", ["a link", "a pipe"])
def test_a_journal_that_is_not_a_regular_file_is_never_followed(monkeypatch, caplog, what):
    """L1W's review: a link (or a pipe) in the journal's place is never followed — opened `O_NOFOLLOW`,
    then `fstat`, as `eregion_core/channel_reader.py`: its target untouched, nothing read from it, the
    perimeter block written all the same, the journal said refused."""
    import os

    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    from glorfindel.response.pair_journal import _pair_journal, pair_written_since

    journal = _pair_journal()
    journal.parent.mkdir(parents=True, exist_ok=True)
    target = journal.parent / "elsewhere.jsonl"
    target.write_text('\n{"pair": "rg/subnet-nsg/glorfindel-block-192-31-196-47", "at": "2026-11-04T00:00:00+00:00"}')
    before = target.read_bytes()
    reader = None
    if what == "a link":
        journal.symlink_to(target)
    else:
        os.mkfifo(journal)
        reader = os.open(journal, os.O_RDONLY | os.O_NONBLOCK)    # someone reads it: a write would pass
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "subnet-nsg"))
    net = MagicMock()
    net.security_rules.list.return_value = []
    connector._network = net
    with caplog.at_level("WARNING"):
        out = connector.block_suspicious_ip("192.31.196.47", _RID, scope="subnet")
    assert out["status"].startswith("blocked"), out
    assert net.security_rules.begin_create_or_update.call_count == 2
    assert "written unnoted" in caplog.text
    assert target.read_bytes() == before                             # never written through the link
    assert not pair_written_since({"rg/subnet-nsg/glorfindel-block-192-31-196-47"}, "")   # nor read
    if reader is not None:
        try:
            assert os.read(reader, 4096) == b""                          # nothing went into the pipe
        finally:
            os.close(reader)


@pytest.mark.parametrize(("now_seen", "back"), [("turned", False), ("a deny again", True)],
                         ids=["read the same", "written again"])
def test_a_turned_pair_holding_now_is_back_only_if_it_reads_otherwise(now_seen, back):
    """`_back` (L1H's review, L1W): the pair the card said gone while it read it there — turned —, holding
    now, was written again only if it reads otherwise: read the same, what tells « gone » from « holds »
    changed beside it."""
    from glorfindel.reassert_said import _back, _pair_keys, _situation

    out = "turned-out" if now_seen == "turned" else "a2"
    now = {**_L1W_PAIR_HELD,
           "rules_seen": {"rg/nsg-subnet/pair": now_seen, "rg/nsg-subnet/pair-out": out, **_VM_SEEN}}
    pair = _pair_keys({"scoped": False, "nsg": "rg/nsg-subnet", "rule": "pair"})
    assert _back(_situation(_PAIR_TURNED), _situation(now), pair) is back


# ── L1O (#507), the way of L1W: put back once, written again by another perimeter, gone before the next pass ──

@pytest.mark.parametrize("order", ["pending", "written, then acknowledged", "acknowledged, then written"])
def test_l1o_the_way_of_l1w_put_back_once_then_written_again_and_gone_is_said_once(order):
    """L1O (#507), the way of L1W: the pair said gone, the card acknowledged, written again by another VM's
    perimeter block (`perimeter_writes.jsonl`) and gone again — L1W ends that episode, the first time puts
    the pair back once outside human_only, « reposé une fois ». Then another VM's perimeter block writes
    the pair again (noted in the journal), and it goes again before the next pass, as the put-back read it.
    The card « reposé une fois » pending, or acknowledged after that write: the journal says nothing (L1W
    reads a write after an acknowledgement only), the marks of the first card kept and its episode open
    read « already said » — silent before L1O. Said « une deuxième fois », never written again; and never
    twice: the passes after, its card pending then acknowledged, nothing more. Acknowledged before the
    write, L1W's journal says it too: a guard."""
    c, card, _ = _pair_said(_L1W_PAIR_GONE, True, "after", mode="non_disruptive")
    (put_back,) = [e for e in _block_cards() if e["id"] != card["id"]]
    assert "reposé une fois" in put_back["reason"], put_back["reason"]
    if order == "acknowledged, then written":
        escalations.resolve(put_back["id"])
    _another_vms_perimeter()                                    # another VM's perimeter block: the pair again
    if order == "written, then acknowledged":
        escalations.resolve(put_back["id"])
    c.block_suspicious_ip.reset_mock()
    c.verify_block_ip.return_value = _L1W_PAIR_GONE             # gone again before the next pass
    reassert_active(c, _ACT)
    seen = {card["id"], put_back["id"]}
    after = [e for e in _block_cards() if e["id"] not in seen]
    assert after, "put back once, written again by another VM, gone again: unsaid"
    (second,) = after
    assert "une deuxième fois" in second["reason"] and "ne le repose pas" in second["reason"], second["reason"]
    for _ in range(2):
        reassert_active(c, _ACT)
        assert [e["id"] for e in _block_cards() if e["id"] not in seen] == [second["id"]]
    escalations.resolve(second["id"])
    for _ in range(2):
        reassert_active(c, _ACT)
        assert [e["id"] for e in _block_cards() if e["id"] not in seen] == [], [e["reason"] for e in _block_cards()]
    assert _l1o_writes(c) == []
