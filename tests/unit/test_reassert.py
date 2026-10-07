"""Reassertion of isolations and blocks whose rules vanished from Azure (lot L5)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from glorfindel import escalations, readiness
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
    """Re-applying doesn't fix an allow evaluated before the deny: verify reports it."""
    _isolated()
    c = _connector({"verified": False, "shadowed_by": [{"rule": "allow-ssh"}]})
    assert reassert_active(c, _ACT) == []
    c.isolate_vm.assert_not_called()


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
