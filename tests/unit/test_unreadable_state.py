"""SEC4b: a local state that can't be read is an unknown — never "nothing" — for every
reader that concludes from an absence (SEC3 closed the orphan sweep only), and the
reassertion says it; an allow of someone else's before our deny is said, never removed.

On the invariant machine's fake Azure (tests/unit/fake_azure.py): no Azure, no LLM.
"""
from __future__ import annotations

import json
import shutil

import pytest

from glorfindel import actions, escalations, reassert

from .fake_azure import _rule_record, key
from .test_invariant_regressions import API, WEB1, _net, _nic
from .test_invariants import IsolationMachine, _rule, invariant_env

_BROKEN = "{\"resource_id\": "                        # a state cut short: not JSON


@pytest.fixture
def world(monkeypatch):
    invariant_env(monkeypatch)
    machines = []

    def build(net):
        m = IsolationMachine()
        machines.append(m)
        m.build(net)
        return m
    yield build
    for m in machines:
        shutil.rmtree(m.home, ignore_errors=True)


def _break_state(text: str = _BROKEN) -> list:
    """Every isolation state file made unreadable, as a disk or a hand would."""
    files = sorted(actions._ISOLATION_STATE_DIR.glob("*.json"))
    assert files
    for f in files:
        f.write_text(text)
    return files


def _quarantined(m, nic: str) -> tuple[str, str]:
    """web isolated by quarantine: (its own NSG, the quarantine NSG)."""
    own = m.fake.nics[nic]["nsg"]
    assert m.connector.isolate_vm(WEB1)["status"] == "isolated"
    q = m.fake.nics[nic]["nsg"]
    assert key(q) != key(own or "")
    return own, q


# ── point 1: each reader of the state ─────────────────────────────────────────────────

@pytest.mark.parametrize("text", [
    _BROKEN, json.dumps([1]), json.dumps({"resource_id": WEB1, "placements": "x"}),
    json.dumps({"placements": []}), json.dumps({"resource_id": "", "placements": []}),
    json.dumps({"resource_id": 5, "placements": []})],
    ids=["cut-short", "a-list", "placements-not-a-list", "no-resource-id", "empty-resource-id",
         "resource-id-not-text"])
def test_verify_release_never_says_released_on_an_unreadable_state(world, text):
    """_held_in_quarantine, read by verify_release (I3F): web in quarantine, its state
    unreadable, our tag lost, left bare by hand. The state may hold it — it read as "not
    in quarantine", and verify_release said verified, the NIC without its NSG."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    _, q = _quarantined(m, nic)
    _break_state(text)
    m.fake.nsgs[key(q)]["tags"].pop(actions.AzureConnector._orig_tag(m.fake.nics[nic]["id"]))
    m.fake.nics[nic]["nsg"] = None
    check = m.connector.verify_release(WEB1)
    assert check["verified"] is not True, check
    assert any("web-nic" in u and "illisible" in u for u in check["unreadable"]), check


def test_release_takes_nothing_off_on_an_unreadable_state(world):
    """_recorded_original, read by the release: the state may record the original — our tag
    read in its place put back what it says, and the release said released. Now nothing
    is taken off, it says why, and the unreadable file is left as it is (written over, the
    next release read the tag in its place)."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    _, q = _quarantined(m, nic)
    (f,) = _break_state()
    out = m.connector.release_isolation(WEB1)
    assert out["status"] == "release_partial", out
    assert any("web-nic" in e and "illisible" in e for e in out["failed"]), out
    assert key(m.fake.nics[nic]["nsg"]) == key(q)                       # still in quarantine
    assert f.read_text() == _BROKEN
    assert m.connector.release_isolation(WEB1)["status"] == "release_partial"   # and again
    f.unlink()                                                           # the operator's way out
    assert m.connector.release_isolation(WEB1)["status"] == "released"


def test_a_bare_nic_is_not_released_on_an_unreadable_state(world):
    """The release's sweep: a bare NIC, no tag — bare by design, or held for a state that
    can't be read. Unknown: not released on a guess."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    _, q = _quarantined(m, nic)
    _break_state()
    m.fake.nsgs[key(q)]["tags"].pop(actions.AzureConnector._orig_tag(m.fake.nics[nic]["id"]))
    m.fake.nics[nic]["nsg"] = None
    out = m.connector.release_isolation(WEB1)
    assert out["status"] == "release_partial" and any("illisible" in e for e in out["failed"]), out


@pytest.mark.parametrize("bare", [False, True])
def test_reset_takes_nothing_off_on_an_unreadable_state(world, bare):
    """_recorded_original, read by `reset --from-azure`, in quarantine and left bare."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    _, q = _quarantined(m, nic)
    (f,) = _break_state()
    if bare:
        m.fake.nics[nic]["nsg"] = None                   # our tag kept: it names the original
    out = m.connector.sweep_vm_rules(WEB1)
    assert out["status"] == "swept_partial", out
    assert any("web-nic" in e and "illisible" in e for e in out["failed"]), out
    assert m.fake.nics[nic]["nsg"] == (None if bare else m.fake.nics[nic]["nsg"])
    if not bare:
        assert key(m.fake.nics[nic]["nsg"]) == key(q)
    assert f.read_text() == _BROKEN


def test_the_fixed_names_of_an_nsg_are_nobodys_on_an_unreadable_state(world):
    """`tied` (_tied_while_away, I4S): an older version's fixed names on api's own NSG, api
    away from it, our tag lost — only api's state ties it. That state unreadable, the NSG
    read as the new VM's alone, and its reset took the old isolation for its own. Unknown
    now: the fixed names are left and said."""
    m = world(_net(legacy=("api-nic", False), api_nic={"own": "dedicated"}))
    own = m.fake.nics[_nic("rg-edge", "api-nic")]["nsg"]
    assert m.connector._tied_while_away(m.fake.nsg_view(m.fake.nsgs[key(own)]), []) is False
    actions._ISOLATION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    (actions._ISOLATION_STATE_DIR / "api--00000000.json").write_text(_BROKEN)
    assert m.connector._tied_while_away(m.fake.nsg_view(m.fake.nsgs[key(own)]), []) is None


def test_the_readers_still_answer_from_a_readable_state_beside_an_unreadable_one(world):
    """A state that records the NIC answers for it, whatever another file holds."""
    from glorfindel.response.state import StateUnreadable, _held_in_quarantine, _recorded_original
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    own, _ = _quarantined(m, nic)
    (actions._ISOLATION_STATE_DIR / "other--00000000.json").write_text(_BROKEN)
    nic_id = m.fake.nics[nic]["id"]
    assert key(_recorded_original(nic_id)) == key(own) and _held_in_quarantine(nic_id) is True
    with pytest.raises(StateUnreadable, match="other--00000000"):
        _held_in_quarantine(API.replace("virtualMachines/api", "networkInterfaces/nope"))


# ── relecture : l'isolation n'est jamais arrêtée par un état illisible ─────────────────

def _other_broken() -> None:
    actions._ISOLATION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    (actions._ISOLATION_STATE_DIR / "other--00000000.json").write_text(_BROKEN)


@pytest.mark.parametrize("subnet_nsg", [None, []], ids=["no-subnet-nsg", "subnet-nsg"])
def test_a_bare_nic_isolates_beside_another_vms_unreadable_state(world, subnet_nsg):
    """Review of SEC4b: a NIC with no NSG, another VM's state unreadable — isolate_vm raised
    StateUnreadable (refused, or fell back to rules with `quarantine_error`): containment
    lost. It isolates by quarantine now; the original, unknown, is left unwritten (no tag),
    so the release keeps the NIC in quarantine until it is known — the tag it names."""
    m = world(_net(quarantine=True, subnet_nsg=subnet_nsg))
    nic = _nic("rg-app1", "web-nic")
    _other_broken()
    out = m.connector.isolate_vm(WEB1)
    assert out["status"] == "isolated" and not out.get("quarantine_refused"), out
    # Said now, not first at the release (second review): the result, the state, the card.
    assert out["original_unknown"] == ["web-nic"] and "glorfindel-orig-" in out["original_note"], out
    assert actions._load_isolation_state(WEB1)["original_unknown"] == ["web-nic"]
    from eregion_console import api
    assert api._original_unknown_nics(actions._load_isolation_state(WEB1)["placements"]) == ["web-nic"]
    q = m.fake.nics[nic]["nsg"]
    assert q and "quarantine" in q
    tag = actions.AzureConnector._orig_tag(m.fake.nics[nic]["id"])
    assert tag not in m.fake.nsgs[key(q)]["tags"]                       # unknown: not written
    assert (actions._ISOLATION_STATE_DIR / "other--00000000.json").read_text() == _BROKEN
    assert m.connector.release_isolation(WEB1)["status"] == "release_partial"
    (actions._ISOLATION_STATE_DIR / "other--00000000.json").unlink()
    out = m.connector.release_isolation(WEB1)
    assert out["status"] == "release_partial" and any(tag in e for e in out["failed"]), out
    assert key(m.fake.nics[nic]["nsg"]) == key(q)                       # still contained
    m.fake.nsgs[key(q)]["tags"][tag] = "none"                           # the operator says it
    assert m.connector.release_isolation(WEB1)["status"] == "released"
    assert m.fake.nics[nic]["nsg"] is None


def test_a_reisolation_beside_its_own_unreadable_state_sets_it_aside(world):
    """Review of SEC4b: a VM in quarantine, its own state unreadable, isolated again —
    StateUnreadable escaped isolate_vm. It isolates (the original from our tag); the
    unreadable file is set aside, never written over, and still said."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    own, q = _quarantined(m, nic)
    (f,) = _break_state()
    out = m.connector.isolate_vm(WEB1)
    assert out["status"] == "isolated" and "original_unknown" not in out    # our tag said it
    aside = actions._ISOLATION_STATE_DIR / "aside" / f.name
    assert aside.read_text() == _BROKEN
    from glorfindel.response.state import unreadable_states
    assert unreadable_states() == [f"isolation/aside/{aside.name}"]
    assert actions._load_isolation_state(WEB1)["resource_id"]            # the new state, readable
    aside.unlink()
    assert m.connector.release_isolation(WEB1)["status"] == "released"
    assert key(m.fake.nics[nic]["nsg"]) == key(own)


def test_a_file_set_aside_then_repaired_is_never_a_state_again(world):
    """Second review of SEC4b: set aside as `<file>.unreadable.json`, the file stayed in the
    states' `*.json`. Repaired, as the card asked, it was a second active isolation of
    the VM (two reassertions, two TTL cards), it left the unreadable list, and the start-up
    migration put the old state back over the current one. In `isolation/aside/` now: never
    read as a state, listed while it exists, untouched by the migration; the card asks to
    report what it holds into the current state, then to remove it."""
    from glorfindel.response.state import migrate_state_files, unreadable_states
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    _quarantined(m, _nic("rg-app1", "web-nic"))
    (f,) = _break_state()
    assert m.connector.isolate_vm(WEB1)["status"] == "isolated"
    current = json.loads(f.read_text())
    aside = actions._ISOLATION_STATE_DIR / "aside" / f.name
    good = {**current, "marker": "repaired-old"}
    aside.write_text(json.dumps(good))                                    # the operator repairs it
    assert [i["state_key"] for i in actions.active_isolations()] == [f.stem]
    assert "marker" not in actions._load_isolation_state(WEB1)
    assert unreadable_states() == [f"isolation/aside/{f.name}"]
    assert migrate_state_files() == 0
    assert json.loads(aside.read_text())["marker"] == "repaired-old"
    assert json.loads(f.read_text()) == current
    reassert.reassert_pass(m.connector, None)
    (card,) = _state_cards("pending")
    steps = " ".join(card["suggested_steps"])
    assert "reporter à la main" in steps and "le retirer" in steps and "les réparer" not in steps, steps
    assert "glorfindel-orig-" in steps
    aside.unlink()
    reassert.reassert_pass(m.connector, None)
    assert not _state_cards("pending")


def test_an_unblock_behind_the_quarantine_says_an_unreadable_state(world):
    """Review of SEC4b: blocked, then isolated by quarantine, the state unreadable —
    StateUnreadable escaped unblock_ip after its deletions, `unblocking_at` left and no
    `unblock_failed`. It ends unblock_partial now, naming the file."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    ip = "203.0.113.7"
    assert m.connector.block_suspicious_ip(ip, WEB1)["status"] == "blocked"
    _quarantined(m, _nic("rg-app1", "web-nic"))
    _break_state()
    out = m.connector.unblock_ip(ip, WEB1)
    assert out["status"] == "unblock_partial", out
    assert any("illisible" in e and "web--" in e for e in out["failed"]), out
    (entry,) = actions._load_block_entries(WEB1)
    assert entry.get("unblock_failed")


def test_the_card_says_what_waits_for_which_file(world):
    """Only a block file unreadable: the orphan sweep waits, not the release."""
    from glorfindel.reassert_cards import say_unreadable_states
    world(_net())
    blocks = actions._ISOLATION_STATE_DIR.parent / "blocks"
    blocks.mkdir(parents=True, exist_ok=True)
    (blocks / "db--00000000.json").write_text("{}")
    say_unreadable_states([])
    (card,) = _state_cards("pending")
    assert "orpheline" in card["reason"] and "levée" not in card["reason"], card["reason"]
    _other_broken()
    say_unreadable_states([])
    (card,) = _state_cards("pending")
    assert "levée" in card["reason"] and "isolation se fait quand même" in card["reason"]


# ── point 1: the reassertion says it ──────────────────────────────────────────────────

def _state_cards(status=None):
    return [e for e in escalations.all_escalations() if e["escalation_type"] == "state_unreadable"
            and (status is None or e["status"] == status)]


def test_the_reassertion_says_an_unreadable_state_once_per_change(world):
    """reassert_pass read "no isolation" from an unreadable file — nothing checked, nothing
    said. Said now: one card per set of files, not at every pass, not again once
    acknowledged; closed once everything reads again; a new break, a new card."""
    m = world(_net(quarantine=True, web_nic={"own": "dedicated"}))
    _quarantined(m, _nic("rg-app1", "web-nic"))
    (f,) = _break_state()
    for _ in range(3):
        report = reassert.reassert_pass(m.connector, None)
    (card,) = _state_cards()
    assert card["status"] == "pending" and f.name in card["reason"] and card["severity"] == "high"
    assert card["occurrences"] == 1 and card["action"] == "repair_local_state"
    escalations.resolve(card["id"])
    assert not any(r["kind"] == "state" for r in reassert.reassert_pass(m.connector, None))
    assert not _state_cards("pending")
    (actions._ISOLATION_STATE_DIR.parent / "blocks").mkdir(parents=True, exist_ok=True)
    (actions._ISOLATION_STATE_DIR.parent / "blocks" / "db--00000000.json").write_text("{}")
    report = reassert.reassert_pass(m.connector, None)          # another file: another card
    assert [r["kind"] for r in report].count("state") == 1
    (now,) = _state_cards("pending")
    assert "blocks/db--00000000.json" in now["reason"]
    f.unlink()
    (actions._ISOLATION_STATE_DIR.parent / "blocks" / "db--00000000.json").unlink()
    reassert.reassert_pass(m.connector, None)
    assert not _state_cards("pending")
    f.write_text(_BROKEN)
    reassert.reassert_pass(m.connector, None)
    assert len(_state_cards("pending")) == 1


# ── V-16 on the fake Azure: someone else's allow before our deny ──────────────────────

def test_a_third_partys_allow_before_our_deny_is_said_and_left(world):
    """web isolated by rules on its own NSG; someone moves our deny behind an allow of
    theirs (priority 150 before 200). The reassertion said nothing (V-16). Said now, on
    one card naming the rule and its NSG; nothing written to Azure, the allow still there
    (I2); acknowledged, not said again; gone, the card closes."""
    m = world(_net(web_nic={"own": "dedicated"}))
    nic = _nic("rg-app1", "web-nic")
    assert m.connector.isolate_vm(WEB1)["status"] == "isolated"
    nsg = m.fake.nsgs[key(m.fake.nics[nic]["nsg"])]
    ours = [r for r in nsg["rules"].values() if r["name"].startswith("glorfindel-iso")]
    assert ours
    for r in ours:
        r["priority"] = 200 + (r["direction"].lower() == "outbound")
    m.fake._put_rule(nsg, _rule_record(_rule("allow-ssh", 150, dict(
        access="Allow", direction="Inbound", source_address_prefix="*",
        destination_address_prefix="*", destination_port_range="22"))))
    writes = len(m.fake.journal)
    for _ in range(2):
        report = reassert.reassert_pass(m.connector, None)
    assert len(m.fake.journal) == writes and "allow-ssh" in nsg["rules"]
    (card,) = [e for e in escalations.all_escalations() if e["escalation_type"] == "bypassed"]
    assert card["status"] == "pending" and key(card["resource_id"]) == key(WEB1)
    assert "allow-ssh" in card["reason"] and "nsg-web-nic" in card["reason"]
    assert report == []                                    # said once
    del nsg["rules"]["allow-ssh"]
    reassert.reassert_pass(m.connector, None)
    assert [e["status"] for e in escalations.all_escalations() if e["escalation_type"] == "bypassed"] == [
        "resolved"]
