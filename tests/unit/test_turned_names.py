"""I4G (#460): an older version's deny-all someone turned into an allow is one of our turned rules.

The guard every removal by name asks (`_held_by_turned`, glorfindel/providers/azure/turned.py)
knew our rules by two prefixes, `glorfindel-iso-` and `glorfindel-block-`. An older version's
isolation is named `glorfindel-isolation-deny-all` (`-out`, or VM-suffixed): turned into an
allow, it was no turned rule of ours, the guard returned at once, and the release of that VM
took it off by its name. A VM given that NSG since lost what the allow let in — an operation on
one VM cut off another (I4, the machine, seed 73). On the in-memory Azure (fake_azure.py): no
Azure call. The oracles are flows on the fake, never the code's markers (A0).
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from glorfindel import actions
from glorfindel.actions import AzureConnector
from glorfindel.providers.azure.turned import _turned_allows

from .fake_azure import FakeAzure, key, open_flows, vm_id
from .test_invariants import _rule

WEB = vm_id("rg-app1", "web")
API = vm_id("rg-app1", "api")
FIXED = AzureConnector.ISOLATION_RULE_NAME


def _deny_all(name: str, priority: int, direction: str):
    return _rule(name, priority, dict(access="Deny", direction=direction, source_address_prefix="*",
                                      destination_address_prefix="*", destination_port_range="*"))


def _world(monkeypatch, base: str):
    """web on its own NSG, isolated there by an older version (a deny-all pair under `base`,
    its single-NSG state kept); then api given that NSG — what a pipeline does once the NSG
    outlives its first VM. Isolation by rules (no quarantine)."""
    monkeypatch.setenv("GLORFINDEL_QUARANTINE_NSG", "0")
    f = FakeAzure()
    subnet = f.add_subnet("rg-net", "vnet-hub", "app", None)
    nsg = f.add_nsg("rg-app1", "nsg-web-nic", [_deny_all(base, 100, "Inbound"),
                                               _deny_all(f"{base}-out", 100, "Outbound")])
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": "web-nic", "ips": ["10.0.0.4"], "subnet": subnet,
                                 "nsg": nsg}])
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / "web.json").write_text(json.dumps({
        "resource_id": WEB, "nsg_rg": "rg-app1", "nsg_name": "nsg-web-nic", "rule_names": [base, f"{base}-out"],
        "bumped": [], "isolated_at": "2026-05-01T00:00:00+00:00"}))
    f.add_vm("rg-app1", "api", [{"rg": "rg-app1", "name": "api-nic", "ips": ["10.0.0.5"], "subnet": subnet,
                                 "nsg": nsg}])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    return f, c, f.nsgs[key(nsg)]


def _flows(f, vm):
    return open_flows({"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}, vm)


def _turn(g: dict, name: str) -> None:
    """Someone turns our deny into an allow, by hand — never through the API."""
    g["rules"][name] = {**g["rules"][name], "access": "Allow"}


_NAMES = [FIXED, f"{FIXED}-out", f"{FIXED}-web"]


@pytest.mark.parametrize("name", _NAMES + [f"{FIXED}-web-out"])
def test_an_older_versions_deny_all_turned_into_an_allow_is_a_turned_rule_of_ours(name):
    """The guard's list: an older version's name turned into an allow is on it — fixed, `-out`,
    VM-suffixed — as today's names are; a deny under that name, or a customer's allow, is not."""
    def nsg(*rules):
        return SimpleNamespace(id="/x/nsg-a", subnets=[], security_rules=list(rules))

    def rule(n, access):
        return SimpleNamespace(name=n, access=access, direction="Outbound" if n.endswith("-out") else "Inbound",
                               source_address_prefix="*", destination_address_prefix="*")
    assert [t[3] for t in _turned_allows([nsg(rule(name, "Allow"))])] == [name]
    assert _turned_allows([nsg(rule(name, "Deny"), rule("allow-ssh", "Allow"))]) == []


@pytest.mark.parametrize("op", ["release", "reset"])
@pytest.mark.parametrize("base, turned", [(FIXED, FIXED), (FIXED, f"{FIXED}-out"),
                                          (f"{FIXED}-web", f"{FIXED}-web")])
def test_an_older_deny_all_turned_into_an_allow_stays_for_the_vm_given_its_nsg(monkeypatch, base, turned, op):
    """The seed: web's older deny-all on the NSG api was given since, one rule of the pair
    turned into an allow by someone. web's release — its reset too — took it off by its name,
    and api lost what it let in. Now it stays, said with why (« retournée en autorisation »),
    never `released`; api loses none of its flows. The deny of the pair goes: nothing hangs on
    it — what only that leftover of web's closed opens again for api, as I4 admits."""
    f, c, g = _world(monkeypatch, base)
    _turn(g, turned)
    before = _flows(f, API)
    assert before, "the turned allow lets api be reached"
    out = c.release_isolation(WEB) if op == "release" else c.sweep_vm_rules(WEB)
    lost = before - _flows(f, API)
    assert not lost, f"an operation on web cut off api: {sorted(lost)}"
    assert turned in g["rules"], f"the turned allow {turned} was taken off"
    pair = turned[:-4] if turned.endswith("-out") else f"{turned}-out"
    assert pair not in g["rules"], f"the deny {pair} kept, nothing hangs on it"
    assert out["status"] == ("release_partial" if op == "release" else "swept_partial"), out
    said = " ".join(out.get("failed") or [])
    assert turned in said and "retournée en autorisation" in said, out


def test_an_older_deny_all_still_a_deny_goes_with_its_release(monkeypatch):
    """Nothing turned: the older version's pair goes with web's release, as it always did —
    the guard keeps only what someone turned (no rule of ours kept for nothing, A0)."""
    f, c, g = _world(monkeypatch, FIXED)
    assert c.release_isolation(WEB)["status"] == "released"
    assert not {n for n in g["rules"] if n.startswith("glorfindel-")}, g["rules"]
