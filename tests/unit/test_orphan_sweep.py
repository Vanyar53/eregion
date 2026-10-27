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


@pytest.mark.parametrize("what", ["isolate", "block"])
def test_the_rule_of_a_recreated_nic_of_a_vm_glorfindel_holds_stays(monkeypatch, what):
    """First review of A3 (high): web isolated (or blocked), its NIC recreated under it.
    The old NIC's rule has a hash no NIC has, and still holds what the state wants: it
    is web's isolation, not an orphan to take off — kept, and the card says why."""
    f, c, subnet = _world(monkeypatch)
    if what == "isolate":
        assert c.isolate_vm(WEB)["status"] == "isolated"
    else:
        assert c.block_suspicious_ip(ATTACKER, WEB, scope="vm", threat_port=None)["status"] == "blocked"
    _recreate_nic(f, WEB, "web-nic", "web-nic-v2")
    held = open_flows(_world_view(f), WEB)
    assert held != _designed(f, WEB)                # the old NIC's rule holds it still
    orphans = c.find_orphan_rules()
    assert orphans and all(o["cut"] and o["removable"] is False
                           and o["kept"] == "la VM visée (web) est isolée ou bloquée par Glorfindel" for o in orphans)
    _watch_pass(c, "full_auto")
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
