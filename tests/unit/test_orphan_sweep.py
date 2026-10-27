"""A3 — the orphan sweep (U1, retrait après alerte).

A rule Glorfindel left for a NIC that no longer exists, aimed at an address Azure has
given to another VM since, cuts that VM off. The posture pass alerts, then takes the rule
off — only that rule, only when it cuts a live VM behind its own NSG, and only when
nothing says its NIC may still exist. On the in-memory Azure (fake_azure.py): no Azure
call.
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
    _delete(f, WEB)
    new = _new_vm_at(f, subnet, "10.0.0.4")
    assert open_flows(_world_view(f), new) != _designed(f, new)          # cut off
    app_before = open_flows(_world_view(f), APP)
    _posture_pass(c)
    assert open_flows(_world_view(f), new) == _designed(f, new)
    assert open_flows(_world_view(f), APP) == app_before
    assert not _glorfindel_rules(f)
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
    _posture_pass(c)
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
    _posture_pass(c)
    assert _glorfindel_rules(f) == before
    cards = _orphan_cards()
    assert cards and all(e["status"] == "pending" and e["severity"] == "medium" for e in cards)
    assert "ne gouverne pas" in cards[0]["reason"]


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
    _posture_pass(c)
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
    _posture_pass(c)
    assert _glorfindel_rules(f) == before


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


def test_a_removal_that_fails_keeps_the_card(monkeypatch):
    f, c, subnet = _world(monkeypatch)
    c.isolate_vm(WEB)
    _delete(f, WEB)
    _new_vm_at(f, subnet, "10.0.0.4")
    f.write_denied = True
    _posture_pass(c)
    cards = _orphan_cards()
    assert cards and all(e["status"] == "pending" and e["severity"] == "high" for e in cards)
    assert "az network nsg rule delete" in cards[0]["suggested_steps"][0]


def test_remove_orphan_rule_refuses_what_find_kept():
    c = AzureConnector(dry_run=False, read_only=False)
    out = c.remove_orphan_rule({"nsg_id": "x", "rule": "glorfindel-iso-a-b-0d0228", "removable": False,
                                "kept": "ne coupe aucune carte vivante derrière ce NSG"})
    assert out == {"removed": False, "why": "ne coupe aucune carte vivante derrière ce NSG"}


def test_remove_orphan_rule_on_read_only_credentials_raises():
    c = AzureConnector(dry_run=False, read_only=True)
    with pytest.raises(PermissionError):
        c.remove_orphan_rule({"nsg_id": "x", "rule": "r", "removable": True})
