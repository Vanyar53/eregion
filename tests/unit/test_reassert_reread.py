"""RW3 (#575): the put-back of an isolation reads its effect again (`verify_isolation`), as a block's does.

`isolate_vm` answers as it writes: on Azure, each deny is confirmed at its write, never what holds once
written. A rule taken off between two writes (an apply in a loop), an allow placed after the plan, a
read refused: the card said « reposée une fois. Si elle disparaît encore, Glorfindel alertera » of an
isolation that does not hold. Now the put-back is read again; a re-read that does not hold, or cannot be
read, is a put-back that does not hold: `partial`, said as it is, nothing promised — and put back once
(RW2): gone again, it is « une deuxième fois », escalated alone, never written again.

The cost, measured here: one `verify_isolation` more per put-back — as many reads as the check before
it (on Azure 1 + 4 per NIC for an isolation by rules) — and none on a pass where everything holds.
Measured on the in-memory Azure (tests/unit/fake_azure.py) and the AWS world (tests/unit/fake_aws.py):
no cloud call, no model call.
"""
from __future__ import annotations

from collections import Counter

import pytest

from glorfindel import escalations
from glorfindel.actions import _load_isolation_state
from glorfindel.reassert import _reread_said, reassert_active

from .fake_azure import FakeAzure, _rule_record, key, open_flows, throttled
from .test_invariants import _rule
from .test_reassert_verified import _ACT, _AZ_WEB, _WEB, _azure, _cards, _ours_gone, _terraform_apply, aws  # noqa: F401


def _flows(f: FakeAzure) -> frozenset:
    return open_flows({"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}, _AZ_WEB)


def _ours(f: FakeAzure) -> dict:
    return {(k, name): dict(r) for k, n in f.nsgs.items() for name, r in n["rules"].items()
            if name.startswith("glorfindel-iso")}


def _after_the_put_back(f: FakeAzure, then) -> None:
    """`then(f)` once the put-back's two rules are written (one NIC), before anything reads them:
    another writer between the write and the re-read, not through the API (no journal entry)."""
    written = []

    def chaos(op, phase, write):
        if op == "rule.write" and phase == "after":
            written.append(1)
            if len(written) == 2:
                then(f)
    f.chaos = chaos


def _inbound_taken_off(f: FakeAzure) -> None:
    for n in f.nsgs.values():
        for name in [k for k in n["rules"] if k.startswith("glorfindel-iso") and not k.endswith("-out")]:
            del n["rules"][name]


def _isolated_then_gone(monkeypatch, **world):
    f, c, nsgs = _azure(monkeypatch, **world)
    out = c.isolate_vm(_AZ_WEB)
    assert out["status"] == "isolated" and not out.get("bypass"), out
    whole = _ours(f)
    _ours_gone(f, "glorfindel-iso")
    return f, c, nsgs, whole


def _iso(report: list[dict]) -> list[dict]:
    return [r for r in report if r["kind"] == "isolation"]


def test_a_rule_taken_off_after_its_write_is_not_reposed(monkeypatch):
    """An apply in a loop takes the inbound deny off right after the put-back wrote it: `isolate_vm`
    answers `isolated`, nothing in `bypass`. Before, « reposée une fois »; the re-read reads the NIC
    uncovered: the card says it does not hold, names the NIC, promises nothing; put back once all the
    same (`reasserted_at`, the original `isolated_at` kept), marked said."""
    f, c, _, _ = _isolated_then_gone(monkeypatch)
    since = _load_isolation_state(_AZ_WEB)["isolated_at"]
    _after_the_put_back(f, _inbound_taken_off)
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["partial"], report
    (card,) = _cards("isolate_vm")
    assert card["reason"] == report[0]["detail"]
    assert "ne tient pas en entier : relue, elle ne tient pas (sans isolation : web-nic-0)" in card["reason"], card
    assert "reposée une fois" not in card["reason"] and "alertera" not in card["reason"]
    state = _load_isolation_state(_AZ_WEB)
    assert state.get("reasserted_at") and state.get("drift_alerted_at") and state["isolated_at"] == since
    assert any(fl[2] == "in" for fl in _flows(f)), "the card says it does not hold: inbound is open"
    # Gone as the card said: the next pass says nothing more, writes nothing (one card per episode).
    f.chaos = lambda *a: None
    written = len(f.journal)
    assert _iso(reassert_active(c, _ACT)) == [] and len(_cards("isolate_vm")) == 1
    assert f.journal[written:] == []


def test_a_put_back_its_re_read_found_short_is_put_back_once(monkeypatch):
    """« Une fois » (RW2) for a put-back its re-read found short: back in place (the apply's loop
    stops), then gone again — « une deuxième fois », escalated alone, nothing written."""
    f, c, _, whole = _isolated_then_gone(monkeypatch)
    _after_the_put_back(f, _inbound_taken_off)
    reassert_active(c, _ACT)
    f.chaos = lambda *a: None
    for (k, name), rec in whole.items():                    # put back by someone else, whole
        f.nsgs[k]["rules"][name] = dict(rec)
    assert _iso(reassert_active(c, _ACT)) == []
    assert not _load_isolation_state(_AZ_WEB).get("drift_alerted_at")
    _ours_gone(f, "glorfindel-iso")
    written = len(f.journal)
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["escalated"], report
    assert "une deuxième fois" in report[0]["detail"] and "ne les repose pas" in report[0]["detail"]
    assert f.journal[written:] == [], "written again after a put-back that did not hold"


def test_an_allow_placed_after_the_plan_is_read_again_and_said(monkeypatch):
    """The customer's deny-telnet at 100 turned into an allow of SSH while the put-back writes: its
    plan read no allow before the deny (no `bypass`), the deny at 101 lands behind it. The re-read
    reads the bypass: the card says it, and the bypass has its own card at once, as a block's re-read
    does — never a write over the customer's rule."""
    f, c, nsgs = _azure(monkeypatch)
    telnet = _rule("deny-telnet", 100, dict(access="Deny", direction="Inbound", source_address_prefix="*",
                                            destination_address_prefix="*", destination_port_range="23"))
    FakeAzure._put_rule(f.nsgs[key(nsgs[0])], _rule_record(telnet))
    assert not c.isolate_vm(_AZ_WEB).get("bypass")
    _ours_gone(f, "glorfindel-iso")

    armed = []

    def chaos(op, phase, write):                     # once, before the first rule of the put-back
        if op == "rule.write" and phase == "before" and not armed:
            armed.append(1)
            f.nsgs[key(nsgs[0])]["rules"]["deny-telnet"].update(access="Allow", destination_port_range="22")
    f.chaos = chaos
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["partial", "bypassed"], report
    (card,) = _cards("isolate_vm")
    assert "ne tient pas en entier : relue, elle ne tient pas (isolation contournée" in card["reason"], card
    assert "deny-telnet" in card["reason"] and "reposée une fois" not in card["reason"]
    (bypass,) = _cards("review_bypass")
    assert "deny-telnet" in bypass["reason"]
    assert _load_isolation_state(_AZ_WEB).get("bypass_said") == bypass["signal_id"]
    assert f.nsgs[key(nsgs[0])]["rules"]["deny-telnet"]["access"] == "Allow"        # never touched (I2)
    assert any(fl[2] == "in" and fl[4] == 22 for fl in _flows(f))


def test_a_re_read_that_raises_is_never_holds(monkeypatch):
    """The re-read refused (every `vm.get` throttled once the rules are written): unreadable, said
    with the error — never « reposée une fois »."""
    f, c, _, _ = _isolated_then_gone(monkeypatch)
    armed = []

    def chaos(op, phase, write):
        if op == "rule.write" and phase == "after":
            armed.append(1)
        elif op == "vm.get" and phase == "before" and len(armed) >= 2:
            raise throttled(op)
    f.chaos = chaos
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["partial"], report
    (card,) = _cards("isolate_vm")
    assert "relue, elle n'est pas lisible (relecture impossible : (TooManyRequests) vm.get" in card["reason"], card
    assert "reposée une fois" not in card["reason"] and "alertera" not in card["reason"]
    assert _load_isolation_state(_AZ_WEB).get("drift_alerted_at")


def test_a_re_read_that_cannot_read_the_rules_is_never_holds(monkeypatch):
    """The NSG's rules unreadable once written (a 403 on the listing): `verified` None — said
    « n'est pas lisible » with the NIC, never « ne tient pas » as if read, never « reposée »."""
    f, c, nsgs, _ = _isolated_then_gone(monkeypatch)
    _after_the_put_back(f, lambda f: f.unreadable.add(key(nsgs[0])))
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["partial"], report
    (card,) = _cards("isolate_vm")
    assert "relue, elle n'est pas lisible (isolation non vérifiable : règles illisibles sur web-nic-0)" in \
        card["reason"], card
    assert "ne tient pas (" not in card["reason"]


@pytest.mark.parametrize("nics", [1, 2])
def test_the_re_read_costs_one_check_per_put_back_and_none_otherwise(monkeypatch, nics):
    """The cost: a put-back that holds reads Azure again once — as many reads as the check before it
    (1 + 4 per NIC: the VM, each NIC, its subnet, its NSG and the NSG's rules) — and is « reposée une
    fois », as before. A pass where everything holds reads it once, as before."""
    f, c, _, _ = _isolated_then_gone(monkeypatch, nics=nics)
    real_iso, real_verify = c.isolate_vm, c.verify_isolation
    phase, reads, verifies = ["check"], Counter(), []

    def iso(rid):
        phase[0] = "write"
        try:
            return real_iso(rid)
        finally:
            phase[0] = "re-read"

    def verify(rid):
        verifies.append(phase[0])
        try:
            return real_verify(rid)
        finally:
            phase[0] = "after" if phase[0] == "re-read" else phase[0]
    c.isolate_vm, c.verify_isolation = iso, verify
    f.chaos = lambda op, ph, w: reads.update([phase[0]]) if ph == "before" and not w else None
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["reapplied"], report
    assert "reposée une fois" in report[0]["detail"]
    assert verifies == ["check", "re-read"]
    assert reads["re-read"] == reads["check"] == 1 + 4 * nics, reads
    verifies.clear()
    phase[0] = "check"
    assert _iso(reassert_active(c, _ACT)) == [] and verifies == ["check"]


# ── AWS: the re-read beside the write's own read-back ─────────────────────────────────────────────

def test_aws_a_put_back_undone_before_its_re_read_is_said(aws):  # noqa: F811  (the imported fixture)
    """The swap lands and its own read-back holds (`verified` True); an apply puts the ENI's groups
    back before the reassertion reads it again: the re-read says it, the provider's word alone said
    « reposée une fois »."""
    f, c = aws
    _terraform_apply(f)
    real = c.isolate_vm
    c.isolate_vm = lambda rid: (real(rid), _terraform_apply(f))[0]
    report = _iso(reassert_active(c, _ACT))
    assert [r["outcome"] for r in report] == ["partial"], report
    assert "ne tient pas en entier : relue, elle ne tient pas (sans isolation : eni-web1)" in report[0]["detail"]
    assert "ne la relit pas entière" not in report[0]["detail"] and "alertera" not in report[0]["detail"]
    state = _load_isolation_state(_WEB)
    assert state.get("reasserted_at") and state.get("drift_alerted_at")


def test_aws_the_card_says_both_the_provider_and_the_re_read(aws):  # noqa: F811  (the imported fixture)
    """The swap undone at its own check and still undone at the re-read: both say it, the provider's
    word first, then the re-read's."""
    from .test_reassert_verified import _swapped_back_at_the_check
    f, c = aws
    _terraform_apply(f)
    _swapped_back_at_the_check(f)
    (r,) = _iso(reassert_active(c, _ACT))
    assert ("ne tient pas en entier : le fournisseur ne la relit pas entière (eni-web1) ; relue, elle ne "
            "tient pas (sans isolation : eni-web1)") in r["detail"], r["detail"]


# ── what the re-read says, each answer ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("after,said", [
    ({"verified": True, "method": "nsg_check"}, ""),
    ({"verified": None, "error": "isolation non vérifiable : règles illisibles sur nic-a"},
     "relue, elle n'est pas lisible (isolation non vérifiable : règles illisibles sur nic-a)"),
    ({"verified": None, "method": "quarantine_sg", "unknown": ["eni-1", "eni-2"]},
     "relue, elle n'est pas lisible (eni-1, eni-2)"),
    ({"verified": None, "reason": "instance introuvable"}, "relue, elle n'est pas lisible (instance introuvable)"),
    ({"verified": None}, "relue, elle n'est pas lisible (vérification non concluante)"),
    ({"verified": "?"}, "relue, elle n'est pas lisible (vérification non concluante)"),
    (None, "relue, elle n'est pas lisible (vérification non concluante)"),
    ({"verified": False, "uncovered_nics": ["nic-a", "nic-b"]}, "relue, elle ne tient pas (sans isolation : nic-a, nic-b)"),
    ({"verified": False, "uncovered_nics": [], "missing_rules": ["sg-q: egress 0.0.0.0/0 ajoutée"]},
     "relue, elle ne tient pas (règles absentes ou altérées : sg-q: egress 0.0.0.0/0 ajoutée)"),
    ({"verified": False, "uncovered_nics": ["nic-a"], "error": "NSG de quarantaine modifié : nic-a (x)."},
     "relue, elle ne tient pas (sans isolation : nic-a ; NSG de quarantaine modifié : nic-a (x))"),
    ({"verified": False}, "relue, elle ne tient pas (non vérifiée)"),
])
def test_what_the_re_read_says(after, said):
    assert _reread_said(after) == said


def test_no_re_read_when_nothing_is_put_back(monkeypatch):
    """human_only: the disappearance said, nothing written — and nothing read again."""
    from glorfindel.config import AutonomyConfig
    f, c, _, _ = _isolated_then_gone(monkeypatch)
    verifies = []
    real = c.verify_isolation
    c.verify_isolation = lambda rid: (verifies.append(rid), real(rid))[1]
    report = _iso(reassert_active(c, AutonomyConfig(default="human_only")))
    assert [r["outcome"] for r in report] == ["escalated"] and len(verifies) == 1
    assert escalations.pending()
