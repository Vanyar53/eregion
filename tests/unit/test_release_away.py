"""D80 (#380) — the release looks for a bare NIC's isolation rules away from it.

A NIC of the VM left with no NSG of its own (someone took its NSG off, its quarantine
lifted to « none »): the release's sweep saw only the NSGs that govern a NIC now, and a
rule of its isolation an earlier release kept on the NSG it carried (I4C) was out of
sight once the state was lost — `released`, or a partial release that didn't name it.
Its rules, by the NIC's hash, are looked for on every NSG of the subscription
(`glorfindel/providers/azure/away.py`). On the in-memory Azure (fake_azure.py): no Azure
call.
"""
from __future__ import annotations

from glorfindel.actions import AzureConnector

from .fake_azure import FakeAzure, key, nic_id, vm_id
from .test_invariants import _rule

WEB = vm_id("rg-app1", "web")
WEB_NIC = nic_id("rg-app1", "web-nic")


def _world(monkeypatch, subnet_nsg: bool = False):
    """web, its NIC bare (its NSG nsg-web taken off by someone); batch on nsg-web at
    10.0.0.5. Isolation by rules; no state for web (lost)."""
    monkeypatch.setenv("GLORFINDEL_QUARANTINE_NSG", "0")
    f = FakeAzure()
    own = f.add_nsg("rg-app1", "nsg-web")
    s_nsg = f.add_nsg("rg-net", "nsg-subnet") if subnet_nsg else None
    subnet = f.add_subnet("rg-net", "vnet-hub", "app", s_nsg)
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": "web-nic", "ips": ["10.0.0.4"], "subnet": subnet,
                                 "nsg": None}])
    f.add_vm("rg-new", "batch", [{"rg": "rg-new", "name": "batch-nic", "ips": ["10.0.0.5"], "subnet": subnet,
                                  "nsg": own}])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    return f, c, own, s_nsg


def _iso_name() -> str:
    return AzureConnector()._placement_rule_bases("glorfindel-iso", "web", "web-nic", WEB_NIC)[0]


def _turned_toward_batch(f, nsg: str) -> str:
    """web's isolation rule turned into an allow by someone, aimed at 10.0.0.5 — batch's
    address now: taken off, batch loses what it opens (I4B)."""
    name = _iso_name()
    f._put_rule(f.nsgs[key(nsg)], {**_record(name, "Allow", "Inbound", "*", "10.0.0.5")})
    return name


def _record(name, access, direction, src, dst) -> dict:
    from .fake_azure import _rule_record
    return _rule_record(_rule(name, 100, dict(access=access, direction=direction, source_address_prefix=src,
                                               destination_address_prefix=dst, destination_port_range="*")))


def test_a_bare_nics_rule_kept_on_the_nsg_it_carried_is_never_released(monkeypatch):
    """The NSG web's NIC carried governs none of web's NICs now: the rule kept there was
    out of sight, the release said `released` (#380). Kept, and said « gardée »."""
    f, c, own, _ = _world(monkeypatch)
    name = _turned_toward_batch(f, own)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert any(name in s and "gardée" in s for s in out["failed"]), out
    assert name in f.nsgs[key(own)]["rules"]


def test_a_bare_nics_leftover_on_the_nsg_it_carried_is_taken_off(monkeypatch):
    """A deny pair of web's isolation on the NSG its NIC carried, aimed at web's own
    address — nothing of another VM waits behind it: taken off, as for a gone VM (I7S)."""
    f, c, own, _ = _world(monkeypatch)
    name = _iso_name()
    f._put_rule(f.nsgs[key(own)], _record(name, "Deny", "Inbound", "*", "10.0.0.4"))
    f._put_rule(f.nsgs[key(own)], _record(f"{name}-out", "Deny", "Outbound", "10.0.0.4", "*"))
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert not [n for n in f.nsgs[key(own)]["rules"] if n.startswith("glorfindel-")]


def test_a_bare_nics_rules_unlooked_for_are_said(monkeypatch):
    """The subscription's NSGs can't be listed by the search away from the NIC: nothing found
    is not nothing there (A0) — never `released`, and the NIC is said. Only that listing is
    refused (the first, the search for the bare NIC's original, reads): its failure is the
    only one (D80's review — refused from the first, the original's failed too and hid it)."""
    f, c, own, _ = _world(monkeypatch)
    listing, calls = f.network.network_security_groups.list_all, []

    def refused_after_the_first():
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("AuthorizationFailed")
        return listing()
    monkeypatch.setattr(f.network.network_security_groups, "list_all", refused_after_the_first)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert len(calls) == 2, calls
    assert len(out["failed"]) == 1 and "web-nic" in out["failed"][0] and "non cherchées" in out["failed"][0], out


def test_a_bare_nics_rule_under_its_second_name_is_kept_and_said(monkeypatch):
    """The NIC's second name (`-b-`, I4B): its `-out` rule turned into an allow toward batch's
    address, on the NSG the NIC carried — looked for too, kept and said (D80's review: the
    first name alone was pinned)."""
    f, c, own, _ = _world(monkeypatch)
    second = AzureConnector()._placement_rule_bases("glorfindel-iso", "web", "web-nic", WEB_NIC)[1]
    f._put_rule(f.nsgs[key(own)], _record(f"{second}-out", "Allow", "Outbound", "10.0.0.5", "*"))
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert f"{second}-out" in f.nsgs[key(own)]["rules"]
    assert any(second in s and "gardée" in s for s in out["failed"]), out


def test_a_rule_on_the_bare_nics_subnet_nsg_is_said_once(monkeypatch):
    """The NSG of the bare NIC's subnet is swept for it already: the search away from the
    NIC skips it — the kept rule named once, not twice."""
    f, c, _, s_nsg = _world(monkeypatch, subnet_nsg=True)
    name = _turned_toward_batch(f, s_nsg)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert sum(name in s and "gardée" in s for s in out["failed"]) == 1, out
