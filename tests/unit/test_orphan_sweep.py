"""A3 — the orphan sweep (U1, retrait après alerte).

A rule Glorfindel left for a NIC that no longer exists, aimed at an address Azure has
given to another VM since, cuts that VM off. The watch's reassertion pass, every minute
and discovery on or off (D-B), takes the rule off — only that rule, only when it cuts a
live VM behind its own NSG, only when nothing says its NIC may still exist or that VM is
one Glorfindel isolates, and only when that VM runs in non_disruptive or full_auto; in
human_only, a card says what to run (D-A). On the in-memory Azure (fake_azure.py): no
Azure call.
"""
from __future__ import annotations

import hashlib

import pytest

from glorfindel import actions, escalations
from glorfindel.actions import AzureConnector
from glorfindel.config import GlorfindelConfig
from glorfindel.posture import PostureChecker

from .fake_azure import ATTACKER, FakeAzure, _rule_record, key, nic_id, open_flows, vm_id
from .test_invariants import _rule

WEB = vm_id("rg-app1", "web")
APP = vm_id("rg-app2", "app")


def _world(monkeypatch, web_nsg=None, app_nsg=None):
    """Two VMs on one subnet whose NSG they share; isolation by rules (no quarantine)."""
    monkeypatch.setenv("GLORFINDEL_QUARANTINE_NSG", "0")
    f = FakeAzure()
    subnet_nsg = f.add_nsg("rg-net", "nsg-subnet")
    subnet = f.add_subnet("rg-net", "vnet-hub", "app", subnet_nsg)
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": "web-nic", "ips": ["10.0.0.4"], "subnet": subnet,
                                 "nsg": web_nsg}])
    f.add_vm("rg-app2", "app", [{"rg": "rg-app2", "name": "app-nic", "ips": ["10.0.0.5"], "subnet": subnet,
                                 "nsg": app_nsg}])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    return f, c, subnet


def _world_view(f):
    return {"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}


def _delete(f, vm, lose_state=True):
    for n in f.vms.pop(key(vm))["nics"]:
        f.nics.pop(key(n))
    if lose_state:
        actions._clear_isolation_state(vm)


def _new_vm_at(f, subnet, ip, nsg=None, rg="rg-new", name="batch"):
    return f.add_vm(rg, name, [{"rg": rg, "name": f"{name}-nic", "ips": [ip], "subnet": subnet, "nsg": nsg}])


def _designed(f, vm):
    bare = {**_world_view(f), "nsgs": {k: {**g, "rules": {n: r for n, r in g["rules"].items()
                                                          if not n.startswith("glorfindel-")}}
                                       for k, g in f.nsgs.items()}}
    return open_flows(bare, vm)


def _posture_pass(c):
    PostureChecker(GlorfindelConfig(), c).check_and_escalate([])


def _watch_pass(c, mode="non_disruptive"):
    """The watch's reassertion pass, as its thread runs it (cli.py), `--mode` pinning
    the default mode — the configuration is the default one (conftest)."""
    from glorfindel.cli import _watch_reassert_pass
    return _watch_reassert_pass(c, mode_override=mode)


def _orphan_cards():
    return [e for e in escalations.all_escalations() if e.get("escalation_type") == "orphan_rule"]


def _glorfindel_rules(f):
    return {(k, n) for k, g in f.nsgs.items() for n in g["rules"] if n.startswith("glorfindel-")}


def test_a_vm_given_a_deleted_vms_address_is_not_left_cut_off(monkeypatch):
    """The criterion of A3: `web` isolated, deleted with its state lost; a new VM gets
    10.0.0.4 behind the same subnet NSG — cut off by web's rule. The posture pass says
    so, takes the rule off, and the new VM is back to its design. `app` is untouched."""
    f, c, subnet = _world(monkeypatch)
    assert c.isolate_vm(WEB)["status"] == "isolated"
    assert c.isolate_vm(APP)["status"] == "isolated"          # its rules share the NSG
    app_rules = _glorfindel_rules(f)
    _delete(f, WEB)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    assert open_flows(_world_view(f), new) != _designed(f, new)          # cut off
    app_before = open_flows(_world_view(f), APP)
    _watch_pass(c)
    assert open_flows(_world_view(f), new) == _designed(f, new)
    assert open_flows(_world_view(f), APP) == app_before
    assert c.verify_isolation(APP)["verified"] is True
    assert _glorfindel_rules(f) == {r for r in app_rules if "-web-" not in r[1]}   # web's only went
    cards = _orphan_cards()                      # one per rule (in, out): alerted, then resolved
    assert len(cards) == 2
    assert all(e["status"] == "resolved" and "retirée" in e["resolution"] for e in cards)
    assert all(e["severity"] == "high" and "batch" in e["reason"] for e in cards)


def test_a_block_left_by_a_deleted_vm_goes_too(monkeypatch):
    f, c, subnet = _world(monkeypatch)
    assert c.block_suspicious_ip(ATTACKER, WEB, scope="vm", threat_port=None)["status"] == "blocked"
    _delete(f, WEB, lose_state=False)              # its block state stays: the NIC is gone (404)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    assert any(fl[3] == ATTACKER for fl in _designed(f, new) - open_flows(_world_view(f), new))
    _watch_pass(c)
    assert open_flows(_world_view(f), new) == _designed(f, new)


def test_an_orphan_behind_an_nsg_that_doesnt_govern_the_holder_stays(monkeypatch):
    """web's rule sits on web's own NSG; the new VM at its address has no NSG: nothing
    is cut. Alerted (medium: not cut), not removed — a rule that cuts no one is not worth
    the risk of taking a live isolation off."""
    f, c, subnet = _world(monkeypatch)
    own = f.add_nsg("rg-app1", "nsg-web")
    f.nics[key(nic_id("rg-app1", "web-nic"))]["nsg"] = own
    f.subnets[key(subnet)]["nsg"] = None
    assert c.isolate_vm(WEB)["status"] == "isolated"
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    before = _glorfindel_rules(f)
    assert before
    (orphan,) = [o for o in c.find_orphan_rules() if not o["rule"].endswith("-out")]
    assert orphan["now_on"] and not orphan["cut"] and orphan["removable"] is False
    _watch_pass(c)
    assert _glorfindel_rules(f) == before
    cards = _orphan_cards()
    assert cards and all(e["status"] == "pending" and e["severity"] == "medium" for e in cards)
    assert "ne gouverne pas" in cards[0]["reason"]
    assert "Gardée : ne coupe aucune carte vivante derrière ce NSG" in cards[0]["reason"]


@pytest.mark.parametrize("aimed, kept", [("*", True), ("10.0.0.0/24", True), ("VirtualNetwork", True),
                                         ("10.0.0.99", False)])
def test_an_orphan_deny_behind_our_rule_turned_into_an_allow_stays(monkeypatch, aimed, kept):
    """I5Q (#327): web blocked on its subnet and isolated there by rules, deleted with its
    state lost; a new VM at its address. Someone turned the perimeter block into an
    allow: web's inbound deny is the last thing holding back what that allow lets pass —
    kept, said with the turned rule, never taken off. Aimed at the new VM's address (`*`,
    a prefix holding it, a tag read as holding it); aimed elsewhere, it doesn't hold
    anything back and goes. The outbound deny goes either way: the turned rule is inbound."""
    f, c, subnet = _world(monkeypatch)
    assert c.block_suspicious_ip(ATTACKER, WEB, scope="subnet")["status"] == "blocked"
    assert c.isolate_vm(WEB)["status"] == "isolated"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    perimeter = next(n for n in g["rules"] if n.startswith("glorfindel-block-") and not n.endswith("-out"))
    g["rules"][perimeter].update(access="Allow", destination_address_prefix=aimed)
    _delete(f, WEB)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    _watch_pass(c)
    iso = {n for n in g["rules"] if n.startswith("glorfindel-iso-")}
    assert any(not n.endswith("-out") for n in iso) is kept, iso
    assert not any(n.endswith("-out") for n in iso), iso
    if kept:
        assert not {fl for fl in open_flows(_world_view(f), new) if fl[2] == "in"}
        (card,) = [e for e in _orphan_cards() if e["status"] == "pending"]
        assert perimeter in card["reason"] and "retournée en autorisation" in card["reason"], card["reason"]


def test_a_card_two_rules_share_stays_open_while_one_stands(monkeypatch):
    """I5Q, seed 101 at 500 after RB1: the in and out denies of a deleted VM cut the same
    VM, said on one card in human_only (the store merges by VM). Given non_disruptive,
    the outbound one goes, the inbound one stays behind the turned rule — the removal
    resolved the card they share: the deny kept, no longer said. It stays pending."""
    f, c, subnet = _world(monkeypatch)
    assert c.block_suspicious_ip(ATTACKER, WEB, scope="subnet")["status"] == "blocked"
    assert c.isolate_vm(WEB)["status"] == "isolated"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    perimeter = next(n for n in g["rules"] if n.startswith("glorfindel-block-") and not n.endswith("-out"))
    g["rules"][perimeter]["access"] = "Allow"
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    _watch_pass(c, "human_only")
    (card,) = _orphan_cards()
    assert card["status"] == "pending"
    _watch_pass(c, "non_disruptive")
    iso = {n for n in g["rules"] if n.startswith("glorfindel-iso-")}
    assert iso and not any(n.endswith("-out") for n in iso), iso
    assert [e["status"] for e in _orphan_cards()] == ["pending"], _orphan_cards()


def _held_world(monkeypatch, out: bool = False):
    """web blocked on its subnet and isolated there by rules, deleted with its state lost;
    `batch` at its address, cut off by web's denies (in and out). `out`: the perimeter's
    outbound rule is the one to turn."""
    f, c, subnet = _world(monkeypatch)
    assert c.block_suspicious_ip(ATTACKER, WEB, scope="subnet")["status"] == "blocked"
    assert c.isolate_vm(WEB)["status"] == "isolated"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    perimeter = next(n for n in g["rules"] if n.startswith("glorfindel-block-") and n.endswith("-out") is out)
    _delete(f, WEB)
    return f, c, g, perimeter, _new_vm_at(f, subnet, "10.0.0.4")


@pytest.mark.parametrize("side", ["in", "out"])
@pytest.mark.parametrize("then", ["human_only", "non_disruptive"])
def test_a_card_said_before_the_turn_is_replaced_by_one_naming_it(monkeypatch, then, side):
    """I5Q, the review: the in and out denies said first in human_only, on one card — its
    only step the delete. Then someone turns a perimeter rule into an allow: the deny on
    its side is now the last thing keeping the attacker out. The card said before was
    never written again — it still said to delete it, which would open the VM. It is
    replaced: the pending card names the turned rule, and says first to put it back as a
    deny; the delete only after. `out`: the kept deny is the outbound one, listed after
    the inbound — the card the two share must still name the turned rule."""
    f, c, g, perimeter, new = _held_world(monkeypatch, out=side == "out")
    _watch_pass(c, "human_only")
    (old,) = _orphan_cards()
    assert old["suggested_steps"][0].startswith("az network nsg rule delete")
    g["rules"][perimeter]["access"] = "Allow"
    _watch_pass(c, then)
    assert not {fl for fl in open_flows(_world_view(f), new) if fl[2] == side and fl[3] == ATTACKER}
    (card,) = [e for e in _orphan_cards() if e["status"] == "pending"]
    assert card["id"] != old["id"]
    assert perimeter in card["reason"] and "retournée en autorisation" in card["reason"], card["reason"]
    assert card["suggested_steps"][0].startswith(f"Remettre {perimeter} en refus") \
        and "--access Deny" in card["suggested_steps"][0], card["suggested_steps"]
    assert not any(s.startswith("az network nsg rule delete") for s in card["suggested_steps"])
    _watch_pass(c, then)                                    # said once: no new card
    assert [e["id"] for e in _orphan_cards() if e["status"] == "pending"] == [card["id"]]


def test_the_card_of_a_vm_names_every_rule_its_kept_denies_wait_behind(monkeypatch):
    """I5Q, seed 31337 at 500 (the review's fixes): the inbound and outbound denies of the
    deleted VM, kept behind two different turned rules — the perimeter's in, and its out.
    The store merges the cards of a VM: the card named the first only, the other deny
    kept unsaid. It names both, and puts both back first."""
    f, c, g, perimeter, new = _held_world(monkeypatch)
    g["rules"][perimeter]["access"] = "Allow"
    g["rules"][f"{perimeter}-out"]["access"] = "Allow"
    _watch_pass(c, "non_disruptive")
    assert {n for n in g["rules"] if n.startswith("glorfindel-iso-")}, "a kept deny went"
    (card,) = [e for e in _orphan_cards() if e["status"] == "pending"]
    for rule in (perimeter, f"{perimeter}-out"):
        assert f"notre règle {rule} (" in card["reason"], card["reason"]
    assert all(s.startswith("Remettre ") for s in card["suggested_steps"][:2]), card["suggested_steps"]


def test_a_card_naming_a_vm_rule_of_the_ip_is_no_card_naming_the_perimeter(monkeypatch):
    """I5Q, seed 31337: the perimeter's name begins every VM rule of its IP. web blocked for
    itself and on its subnet, deleted; its own block deny, said in human_only, names
    `glorfindel-block-<ip>-web-…` — read as a substring, that card « named » the turned
    perimeter, and was kept: still telling to delete the deny. It is replaced."""
    f, c, subnet = _world(monkeypatch)
    for scope in ("vm", "subnet"):
        assert c.block_suspicious_ip(ATTACKER, WEB, scope=scope, threat_port=22)["status"] == "blocked"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    perimeter = "glorfindel-block-" + ATTACKER.replace(".", "-")
    assert perimeter in g["rules"]
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    _watch_pass(c, "human_only")
    (old,) = _orphan_cards()
    assert perimeter in old["reason"] and f"notre règle {perimeter} (" not in old["reason"]
    g["rules"][perimeter]["access"] = "Allow"
    _watch_pass(c, "non_disruptive")
    (card,) = [e for e in _orphan_cards() if e["status"] == "pending"]
    assert f"notre règle {perimeter} (" in card["reason"], card["reason"]
    assert card["suggested_steps"][0].startswith(f"Remettre {perimeter} en refus"), card["suggested_steps"]


def test_a_new_kept_deny_never_merges_into_a_stale_card_of_its_vm(monkeypatch):
    """I5Q, its second review (the reviewer's probe): the VM has a pending card for an
    orphan rule that is not kept (web's outbound deny, said in human_only). A new deny
    of a gone NIC appears, kept behind the perimeter someone turned — no card of its own
    yet: the store folded it into the VM's pending card, which keeps its first reason.
    The operator saw only the delete of a deny already gone, the kept one named nowhere
    for a pass. That card is read too, and replaced."""
    f, c, subnet = _world(monkeypatch)
    assert c.block_suspicious_ip(ATTACKER, WEB, scope="subnet")["status"] == "blocked"
    assert c.isolate_vm(WEB)["status"] == "isolated"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    perimeter = "glorfindel-block-" + ATTACKER.replace(".", "-")
    iso_in = next(n for n in g["rules"] if n.startswith("glorfindel-iso-") and not n.endswith("-out"))
    del g["rules"][iso_in]
    _delete(f, WEB)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    _watch_pass(c, "human_only")
    (old,) = _orphan_cards()
    FakeAzure._put_rule(g, _rule_record(_rule("glorfindel-iso-ghost-ghost-nic-abcdef", 150, dict(
        access="Deny", direction="Inbound", source_address_prefix="*", destination_address_prefix="10.0.0.4",
        destination_port_range="*"))))
    g["rules"][perimeter]["access"] = "Allow"
    _watch_pass(c, "non_disruptive")
    assert "glorfindel-iso-ghost-ghost-nic-abcdef" in g["rules"]
    assert not {fl for fl in open_flows(_world_view(f), new) if fl[2] == "in" and fl[3] == ATTACKER}
    (card,) = [e for e in _orphan_cards() if e["status"] == "pending"]
    assert card["id"] != old["id"]
    assert f"notre règle {perimeter} (" in card["reason"], card["reason"]
    assert card["suggested_steps"][0].startswith(f"Remettre {perimeter} en refus"), card["suggested_steps"]


def test_a_rule_turned_after_the_listing_stops_the_removal(monkeypatch):
    """I5Q, the review: the pass lists the NSGs, then someone turns the perimeter block
    before the removal — the guard is played again on the NSGs that govern the VM cut,
    read by their id just before the delete. One that can't be read keeps the rule."""
    f, c, g, perimeter, new = _held_world(monkeypatch)
    (orphan,) = [o for o in c.find_orphan_rules() if not o["rule"].endswith("-out")]
    assert orphan["removable"] is True and orphan["cut"][0]["governed_by"]
    g["rules"][perimeter]["access"] = "Allow"
    out = c.remove_orphan_rule(orphan)
    assert out["removed"] is False and perimeter in out["why"], out
    assert orphan["rule"].lower() in {n.lower() for n in g["rules"]}
    g["rules"][perimeter]["access"] = "Deny"
    real = f.network.network_security_groups.get

    def refused(*a, **k):
        raise RuntimeError("(AuthorizationFailed) no read")
    monkeypatch.setattr(f.network.network_security_groups, "get", refused)
    out = c.remove_orphan_rule(orphan)
    assert out["removed"] is False and "non relu" in out["why"], out
    monkeypatch.setattr(f.network.network_security_groups, "get", real)
    assert c.remove_orphan_rule(orphan)["removed"] is True


def _twin_vnet(f, subnet_nsg):
    """A second VNet whose address space overlaps the hub's, its subnet behind the same NSG."""
    return f.add_subnet("rg-net", "vnet-twin", "app", subnet_nsg)


def _hide(f, monkeypatch, *nics):
    """The listing misses these NICs (no read right on their resource group)."""
    real = f.network.network_interfaces.list_all
    monkeypatch.setattr(f.network.network_interfaces, "list_all",
                        lambda: [n for n in real() if key(n.id) not in {key(x) for x in nics}])


def test_a_nic_of_our_state_missing_from_the_listing_is_no_orphan(monkeypatch):
    """web is isolated and alive, but the listing misses it; another VM, in a VNet that
    overlaps, holds the same address behind the same NSG. The state names web's NIC:
    Azure still has it, so its rule is web's isolation, not an orphan — never lifted."""
    f, c, subnet = _world(monkeypatch)
    nsg = f.subnets[key(subnet)]["nsg"]
    twin = _new_vm_at(f, _twin_vnet(f, nsg), "10.0.0.4", name="twin")
    assert c.isolate_vm(WEB)["status"] == "isolated"
    _hide(f, monkeypatch, nic_id("rg-app1", "web-nic"))
    assert twin and c.find_orphan_rules() == []
    before = _glorfindel_rules(f)
    _watch_pass(c)
    assert _glorfindel_rules(f) == before and c.verify_isolation(WEB)["verified"] is True


def test_an_nsg_whose_attached_nic_is_missing_from_the_listing_keeps_its_orphans(monkeypatch):
    """The same, the state lost: nothing names web's NIC any more. Its NSG says a NIC is
    attached that the listing doesn't have — the listing is incomplete: kept, said."""
    f, c, subnet = _world(monkeypatch)
    own = f.add_nsg("rg-net", "nsg-tier")
    f.nics[key(nic_id("rg-app1", "web-nic"))]["nsg"] = own
    twin_subnet = f.add_subnet("rg-net", "vnet-twin", "app", None)
    _new_vm_at(f, twin_subnet, "10.0.0.4", nsg=own, name="twin")
    assert c.isolate_vm(WEB)["status"] == "isolated"
    actions._clear_isolation_state(WEB)
    _hide(f, monkeypatch, nic_id("rg-app1", "web-nic"))
    orphans = c.find_orphan_rules()
    assert orphans and all(o["cut"] and o["removable"] is False and "manque" in o["kept"] for o in orphans)
    before = _glorfindel_rules(f)
    _watch_pass(c)
    assert _glorfindel_rules(f) == before
    assert _orphan_cards() and all("Gardée : une carte attachée à ce NSG manque" in e["reason"]
                                   for e in _orphan_cards())


def test_older_names_of_a_live_nic_are_not_orphans(monkeypatch):
    """Before the NIC hash (L24), names ended with the NIC's (or VM's) name, or — long —
    a hash of the id as Azure wrote it: a live NIC's rule, never an orphan to remove."""
    f, c, subnet = _world(monkeypatch)
    mixed = "/subscriptions/s/resourceGroups/RG-App3/providers/Microsoft.Network/networkInterfaces/Long-Nic"
    f.nics[key(mixed)] = {"id": mixed, "location": "westeurope", "nsg": None, "design_nsg": None,
                          "ips": ["10.0.0.6"], "subnet": subnet, "policy": False}
    f.add_vm("rg-app1", "cafe", [{"rg": "rg-app1", "name": "web-cafe01", "ips": ["10.0.0.7"], "subnet": subnet}])
    legacy_long = "glorfindel-iso-" + "x" * 40 + "-" + hashlib.sha1(mixed.encode()).hexdigest()[:8]
    nsg = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    for i, (name, ip) in enumerate((("glorfindel-iso-cafe-web-cafe01", "10.0.0.7"), (legacy_long, "10.0.0.6"))):
        FakeAzure._put_rule(nsg, _rule_record(_rule(name, 200 + i, dict(
            access="Deny", direction="Inbound", source_address_prefix="*",
            destination_address_prefix=ip, destination_port_range="*"))))
    assert c.find_orphan_rules() == []


def test_read_only_credentials_leave_it_at_the_alert(monkeypatch):
    f, c, subnet = _world(monkeypatch)
    c.isolate_vm(WEB)
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    before = _glorfindel_rules(f)
    c.read_only = True
    tried = []
    monkeypatch.setattr(c, "remove_orphan_rule", lambda o: tried.append(o) or {"removed": False})
    _posture_pass(c)
    assert _glorfindel_rules(f) == before and not tried
    assert _orphan_cards() and all(e["status"] == "pending" for e in _orphan_cards())
    # The watch's pass doesn't run on read-only credentials; were it to, the VM's mode
    # wouldn't make it write either.
    from glorfindel.config import AutonomyConfig
    from glorfindel.orphans import sweep_orphan_rules
    escalations._STORE.unlink()
    (actions._ISOLATION_STATE_DIR.parent / "orphan_alerts.json").unlink()
    sweep_orphan_rules(c, AutonomyConfig(default="non_disruptive"))
    assert _glorfindel_rules(f) == before and not tried
    assert _orphan_cards() and all("lecture seule" in e["reason"] for e in _orphan_cards())


def test_a_removal_that_fails_keeps_the_card(monkeypatch):
    f, c, subnet = _world(monkeypatch)
    c.isolate_vm(WEB)
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    f.write_denied = True
    _watch_pass(c)
    cards = _orphan_cards()
    assert cards and all(e["status"] == "pending" and e["severity"] == "high" for e in cards)
    assert "az network nsg rule delete" in cards[0]["suggested_steps"][0]
    assert "Glorfindel n'a pas pu la retirer" in cards[0]["reason"]


def test_remove_orphan_rule_refuses_what_find_kept():
    c = AzureConnector(dry_run=False, read_only=False)
    out = c.remove_orphan_rule({"nsg_id": "x", "rule": "glorfindel-iso-a-b-0d0228", "removable": False,
                                "kept": "ne coupe aucune carte vivante derrière ce NSG"})
    assert out == {"removed": False, "why": "ne coupe aucune carte vivante derrière ce NSG"}


def test_remove_orphan_rule_on_read_only_credentials_raises():
    c = AzureConnector(dry_run=False, read_only=True)
    with pytest.raises(PermissionError):
        c.remove_orphan_rule({"nsg_id": "x", "rule": "r", "removable": True})


# ── A3, after its first review: the mode, the watch's pass, the held VMs ─────────────

def _cut_new_vm(monkeypatch):
    """web isolated, deleted with its state lost; `batch` gets 10.0.0.4 and is cut off."""
    f, c, subnet = _world(monkeypatch)
    assert c.isolate_vm(WEB)["status"] == "isolated"
    _delete(f, WEB)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    assert open_flows(_world_view(f), new) != _designed(f, new)
    return f, c, new


@pytest.mark.parametrize("mode", ["non_disruptive", "full_auto"])
def test_the_rule_goes_alone_when_the_cut_vm_may_act_alone(monkeypatch, mode):
    """D-A: taking off a rule of ours that cuts a VM by mistake disrupts nothing —
    in non_disruptive and full_auto, the watch's pass does it."""
    f, c, new = _cut_new_vm(monkeypatch)
    _watch_pass(c, mode)
    assert open_flows(_world_view(f), new) == _designed(f, new)
    assert _orphan_cards() and all(e["status"] == "resolved" for e in _orphan_cards())


def test_in_human_only_the_card_says_what_to_run_and_nothing_is_written(monkeypatch):
    """D-A: human_only only reads (glorfindel-config.yaml.example) — the card, no write;
    it says the command and the mode that lets the watch do it. Said once: the next pass
    adds no card, nor once the card is acknowledged. Given the mode, the next pass
    takes the rule off."""
    f, c, new = _cut_new_vm(monkeypatch)
    before = _glorfindel_rules(f)
    _watch_pass(c, "human_only")
    assert _glorfindel_rules(f) == before
    (card,) = _orphan_cards()                   # the in and out rules cut the same VM: one card
    assert card["status"] == "pending" and card["severity"] == "high"
    assert "Mode batch (human_only)" in card["reason"] and "az network nsg rule delete" in card["reason"]
    assert any("non_disruptive" in step for step in card["suggested_steps"])
    _watch_pass(c, "human_only")
    assert [e["occurrences"] for e in _orphan_cards()] == [card["occurrences"]]
    escalations.resolve(card["id"])             # acknowledged: it stays closed
    _watch_pass(c, "human_only")
    assert len(_orphan_cards()) == 1 and _glorfindel_rules(f) == before
    _watch_pass(c, "non_disruptive")
    assert open_flows(_world_view(f), new) == _designed(f, new)
    assert all(e["status"] == "resolved" for e in _orphan_cards())


def _config_file(monkeypatch, text):
    from glorfindel import config
    path = actions._ISOLATION_STATE_DIR.parent / "glorfindel-config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [path])
    return path


def test_the_mode_is_the_cut_vms(monkeypatch):
    """The mode that counts is the one of the VM the rule cuts, from the configuration
    the watch reads at each pass."""
    f, c, new = _cut_new_vm(monkeypatch)
    before = _glorfindel_rules(f)
    path = _config_file(monkeypatch, "autonomy:\n  default: non_disruptive\n"
                                     "  assets:\n    - match: batch\n      mode: human_only\n")
    _watch_pass(c, None)
    assert _glorfindel_rules(f) == before
    path.write_text("autonomy:\n  default: human_only\n  assets:\n    - match: batch\n      mode: non_disruptive\n")
    _watch_pass(c, None)
    assert open_flows(_world_view(f), new) == _designed(f, new)


def test_the_watch_frees_the_vm_with_discovery_off(monkeypatch):
    """D-B: the sweep is the watch's, every minute, whatever discovery does —
    `discovery.enabled: false` doesn't stop it."""
    from glorfindel import config
    f, c, new = _cut_new_vm(monkeypatch)
    _config_file(monkeypatch, "monitoring_backends:\n  - name: law\n    type: azure_monitor\n"
                              "    workspace_id: ws\n    discovery:\n      enabled: false\n"
                              "autonomy:\n  default: non_disruptive\n")
    assert config.load_glorfindel_config().monitoring_backends[0].discovery.enabled is False
    report = _watch_pass(c, None)
    assert open_flows(_world_view(f), new) == _designed(f, new)
    assert {r["outcome"] for r in report if r["kind"] == "orphan"} == {"removed"}


def test_the_pass_lists_the_nsgs_once_for_the_quarantines_and_the_orphans(monkeypatch):
    f, c, new = _cut_new_vm(monkeypatch)
    calls = []
    real = f.network.network_security_groups.list_all
    monkeypatch.setattr(f.network.network_security_groups, "list_all", lambda: calls.append(1) or real())
    _watch_pass(c)
    assert len(calls) == 1
    assert open_flows(_world_view(f), new) == _designed(f, new)


def test_a_card_closes_once_its_rule_is_no_longer_an_orphan(monkeypatch):
    f, c, new = _cut_new_vm(monkeypatch)
    _watch_pass(c, "human_only")
    for g in f.nsgs.values():                   # the operator ran the command
        for n in [n for n in g["rules"] if "-web-" in n]:
            g["rules"].pop(n)
    _watch_pass(c, "human_only")
    assert _orphan_cards() and all(e["status"] == "resolved" for e in _orphan_cards())


def _recreate_nic(f, vm, old_name, new_name):
    """A `terraform apply` recreates the NIC: a new id, the same static address, the
    same subnet; the VM keeps running."""
    rec = f.nics.pop(key(nic_id("rg-app1", old_name)))
    new = nic_id("rg-app1", new_name)
    f.nics[key(new)] = {**rec, "id": new}
    f.vms[key(vm)]["nics"] = [new]
    return new


@pytest.mark.parametrize("rid", [WEB, WEB.lower(), WEB.replace("rg-app1", "RG-APP1").replace("web", "Web")],
                         ids=["azure-case", "lowercase", "other-case"])
@pytest.mark.parametrize("what", ["isolate", "block"])
def test_the_rule_of_a_recreated_nic_of_a_vm_glorfindel_holds_stays(monkeypatch, what, rid):
    """First review of A3 (high): web isolated (or blocked), its NIC recreated under it.
    The old NIC's rule has a hash no NIC has, and still holds what the state wants: it
    is web's isolation, not an orphan to take off — kept, and the card says why. The
    state keeps the id it was given (Log Analytics' _ResourceId is lowercase), the
    listing Azure's case: compared whatever the case (second review)."""
    f, c, subnet = _world(monkeypatch)
    if what == "isolate":
        assert c.isolate_vm(rid)["status"] == "isolated"
    else:
        assert c.block_suspicious_ip(ATTACKER, rid, scope="vm", threat_port=None)["status"] == "blocked"
    _recreate_nic(f, WEB, "web-nic", "web-nic-v2")
    held = open_flows(_world_view(f), WEB)
    assert held != _designed(f, WEB)                # the old NIC's rule holds it still
    orphans = c.find_orphan_rules()
    assert orphans and all(o["cut"] and o["removable"] is False
                           and o["kept"] == "la VM visée (web) est isolée ou bloquée par Glorfindel" for o in orphans)
    _watch_pass(c, "full_auto" if rid != WEB.lower() else "non_disruptive")
    assert open_flows(_world_view(f), WEB) == held
    assert _orphan_cards() and all("Gardée : la VM visée (web) est isolée" in e["reason"] for e in _orphan_cards())


def test_a_pre_l24_name_hashed_on_another_case_is_held_by_the_vm(monkeypatch):
    """Before L24, a long name ended with the sha1 of the NIC's id as Azure wrote it then;
    in another case than today's listing, no live mark matches, nor the state's. The VM
    it cuts is isolated: held by the VM, not by the hash."""
    f, c, subnet = _world(monkeypatch)
    assert c.isolate_vm(WEB)["status"] == "isolated"
    other_case = nic_id("RG-APP1", "Web-Nic")
    legacy = "glorfindel-iso-" + "w" * 40 + "-" + hashlib.sha1(other_case.encode()).hexdigest()[:8]
    nsg = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    FakeAzure._put_rule(nsg, _rule_record(_rule(legacy, 300, dict(
        access="Deny", direction="Inbound", source_address_prefix="*",
        destination_address_prefix="10.0.0.4", destination_port_range="*"))))
    (orphan,) = [o for o in c.find_orphan_rules() if o["rule"] == legacy]
    assert orphan["removable"] is False and "isolée ou bloquée" in orphan["kept"]


def test_an_isolation_recorded_after_the_listing_stops_the_removal(monkeypatch):
    """Read again just before the write (first review of A3): the new VM isolated
    between the listing and the removal — the rule stays."""
    f, c, new = _cut_new_vm(monkeypatch)
    orphans = [o for o in c.find_orphan_rules() if o["removable"]]
    assert orphans
    assert c.isolate_vm(new)["status"] == "isolated"
    before = _glorfindel_rules(f)
    out = c.remove_orphan_rule(orphans[0])
    assert out["removed"] is False and "isolée ou bloquée" in out["why"]
    assert _glorfindel_rules(f) == before


@pytest.mark.parametrize("status", [403, 429])
def test_a_nic_of_our_state_unreadable_is_no_proof_it_is_gone(monkeypatch, status):
    """Only a 404 says a NIC of our state is gone: a 403 (no right on its group) or a
    429 (throttled) says nothing — the rule is kept, and why (first review of A3)."""
    from azure.core.exceptions import HttpResponseError

    from .fake_azure import _error
    f, c, subnet = _world(monkeypatch)
    nsg = f.subnets[key(subnet)]["nsg"]
    _new_vm_at(f, _twin_vnet(f, nsg), "10.0.0.4", name="twin")
    assert c.isolate_vm(WEB)["status"] == "isolated"
    listed = [n for n in f.network.network_interfaces.list_all() if n.id != nic_id("rg-app1", "web-nic")]
    monkeypatch.setattr(f.network.network_interfaces, "list_all", lambda: list(listed))
    real = f.network.network_interfaces.get

    def refused(rg, name):
        if name == "web-nic":
            raise _error(HttpResponseError, status, f"({status}) refused")
        return real(rg, name)
    monkeypatch.setattr(f.network.network_interfaces, "get", refused)
    orphans = c.find_orphan_rules()
    assert orphans and all(o["removable"] is False and "illisible" in o["kept"] for o in orphans)
    before = _glorfindel_rules(f)
    _watch_pass(c, "full_auto")
    assert _glorfindel_rules(f) == before


# ── A3, second review: the guards locked ─────────────────────────────────────────────

def test_an_unreadable_config_writes_nothing(monkeypatch):
    """D-A with the configuration unreadable (a key nobody reads): no mode can be read —
    human_only, the card only, never a removal on a mode guessed (second review)."""
    f, c, new = _cut_new_vm(monkeypatch)
    before = _glorfindel_rules(f)
    _config_file(monkeypatch, "autonomy:\n  default: non_disruptive\n  quarantaine: 1\n")
    _watch_pass(c, None)
    assert _glorfindel_rules(f) == before
    assert _orphan_cards() and all(e["status"] == "pending" for e in _orphan_cards())


def test_with_the_reassertion_off_the_posture_still_says_them(monkeypatch):
    """GLORFINDEL_REASSERT_INTERVAL_S=0: the watch's pass doesn't run. The posture pass
    keeps L28's alert — the card only, nothing written, write rights or not (second
    review). With the reassertion on, the posture leaves them to the watch."""
    f, c, new = _cut_new_vm(monkeypatch)
    before = _glorfindel_rules(f)
    monkeypatch.setenv("GLORFINDEL_REASSERT_INTERVAL_S", "60")
    _posture_pass(c)
    assert not _orphan_cards()
    monkeypatch.setenv("GLORFINDEL_REASSERT_INTERVAL_S", "0")
    _posture_pass(c)
    assert _glorfindel_rules(f) == before
    assert _orphan_cards() and all(e["status"] == "pending" for e in _orphan_cards())


def test_a_rule_cutting_vms_of_different_modes_waits_for_every_one(monkeypatch):
    """A rule of a gone NIC aimed at two live VMs' addresses: removed alone only when
    every VM it cuts may act alone — one in human_only keeps it (second review)."""
    f, c, subnet = _world(monkeypatch)
    gone = nic_id("rg-old", "gone-nic")
    name = "glorfindel-iso-gone-gone-nic-" + hashlib.sha1(gone.lower().encode()).hexdigest()[:6]
    nsg = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    FakeAzure._put_rule(nsg, _rule_record(_rule(name, 300, dict(
        access="Deny", direction="Inbound", source_address_prefix="*",
        destination_address_prefixes=["10.0.0.4", "10.0.0.5"], destination_port_range="*"))))
    (orphan,) = [o for o in c.find_orphan_rules() if o["rule"] == name]
    assert orphan["removable"] is True and len(orphan["cut"]) == 2
    path = _config_file(monkeypatch, "autonomy:\n  default: non_disruptive\n"
                                     "  assets:\n    - match: app\n      mode: human_only\n")
    _watch_pass(c, None)
    assert (key(nsg["id"]), name) in {(k, n) for k, g in f.nsgs.items() for n in g["rules"]}
    (card,) = _orphan_cards()
    assert "app (human_only)" in card["reason"]
    path.write_text("autonomy:\n  default: non_disruptive\n")
    _watch_pass(c, None)
    assert name not in nsg["rules"]


# ── SEC3 (#274): an unreadable state never frees a VM ────────────────────────────────

def _corrupt_states(directory, text="{not json"):
    files = sorted(directory.glob("*.json"))
    assert files
    for f in files:
        f.write_text(text)
    return files


@pytest.mark.parametrize("text", ["{not json", "wrong-shape", "\"x\""], ids=["truncated", "wrong-shape", "scalar"])
@pytest.mark.parametrize("what", ["isolate", "block"])
def test_an_unreadable_state_keeps_the_rule_of_a_recreated_nic(monkeypatch, what, text):
    """N-06: web isolated (or blocked), its NIC recreated under it — the old NIC's rule
    holds what the state wants. Its state file unreadable, the state is unknown, not
    empty: the sweep keeps every orphan, says why on the card, and writes nothing — in
    full_auto too. The VM stays held."""
    f, c, subnet = _world(monkeypatch)
    if what == "isolate":
        assert c.isolate_vm(WEB)["status"] == "isolated"
        directory = actions._ISOLATION_STATE_DIR
    else:
        assert c.block_suspicious_ip(ATTACKER, WEB, scope="vm", threat_port=None)["status"] == "blocked"
        directory = actions._BLOCK_STATE_DIR
    if text == "wrong-shape":               # a list for an isolation, an object for blocks
        text = "[1]" if what == "isolate" else '{"ip": "x"}'
    _recreate_nic(f, WEB, "web-nic", "web-nic-v2")
    held = open_flows(_world_view(f), WEB)
    assert held != _designed(f, WEB)
    _corrupt_states(directory, text)
    before = _glorfindel_rules(f)
    _watch_pass(c, "full_auto")
    assert _glorfindel_rules(f) == before
    assert open_flows(_world_view(f), WEB) == held
    orphans = c.find_orphan_rules()
    assert orphans and all(o["removable"] is False and "état local illisible" in o["kept"] for o in orphans)
    cards = _orphan_cards()
    assert cards and all(e["status"] == "pending" and "état local illisible" in e["reason"] for e in cards)


def test_a_state_unreadable_after_the_listing_stops_the_removal(monkeypatch):
    """Read again before the write: a state that turned unreadable between the listing
    and the removal stops it, as a state recorded since does."""
    f, c, new = _cut_new_vm(monkeypatch)
    orphans = [o for o in c.find_orphan_rules() if o["removable"]]
    assert orphans
    assert c.isolate_vm(APP)["status"] == "isolated"
    _corrupt_states(actions._ISOLATION_STATE_DIR)
    before = _glorfindel_rules(f)
    out = c.remove_orphan_rule(orphans[0])
    assert out["removed"] is False and "état local illisible" in out["why"]
    assert _glorfindel_rules(f) == before


def test_remove_orphan_rule_is_a_guarded_write(monkeypatch):
    """N-07: remove_orphan_rule takes the locks of the VMs it cuts and refuses an NSG of
    another subscription, as every other write of the connector does."""
    from glorfindel.response.policy import WrongSubscriptionError
    f, c, new = _cut_new_vm(monkeypatch)
    (orphan, *_) = [o for o in c.find_orphan_rules() if o["removable"]]
    other = {**orphan, "nsg_id": orphan["nsg_id"].replace("/subscriptions/s/", "/subscriptions/other/")}
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "s")
    before = _glorfindel_rules(f)
    with pytest.raises(WrongSubscriptionError):
        c.remove_orphan_rule(other)
    assert _glorfindel_rules(f) == before
    taken: list[str] = []
    import glorfindel.providers.azure.connector as connector_module
    real = connector_module._vm_lock

    def spy(vm, timeout=None):
        taken.append(vm)
        return real(vm, timeout=timeout)
    monkeypatch.setattr(connector_module, "_vm_lock", spy)
    assert c.remove_orphan_rule(orphan)["removed"] is True
    assert taken == ["batch"]
