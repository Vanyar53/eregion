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
    c.isolate_vm.side_effect = lambda rid: _isolated() or {"status": "isolated"}

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


def test_vanished_block_is_put_back_once_with_its_threat_port():
    _save_block_state("vm", "203.0.113.9", _RID, nsg="rg/nsg", nsg_scope="subnet", rule="r",
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "r"}], threat_port=22)
    c = _connector(verify_blk={"verified": False, "missing_rules": ["r"]})
    report = reassert_active(c, _ACT)
    c.block_suspicious_ip.assert_called_once_with("203.0.113.9", _RID, scope="vm", threat_port=22)
    assert report[0]["outcome"] == "reapplied"
    assert _load_block_entries("vm")[0]["reasserted_at"]


def test_second_removal_is_a_new_card_not_folded_into_the_first():
    """The store merged the second alert into the 're-applied once' card, which kept
    its text and sent no notification (validation run, 2026-10-06)."""
    _isolated()
    c = _connector({"verified": False, "uncovered_nics": ["nic-a"]})
    reassert_active(c, _ACT)                       # first removal: re-applied
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
