"""I4P (#466): the promotion of a block to the perimeter never cuts off another VM.

A VM's block promoted to its subnet (`block_suspicious_ip(scope="subnet", replace=True)`,
glorfindel/providers/azure/blocks.py and perimeter.py) took its per-NIC rules off by their
names, the guard every other removal by name asks never asked (`turned._held_by_turned`, I4B).
One of them someone turned into an allow, which lets the attacker reach another VM — the
address it names taken up since, or every address on a NIC's NSG another VM of ANOTHER subnet
joined —, went: that VM, off the perimeter, was cut off. Now the pair stays whole, said, its
placement in the state for the unblock (which asks again). On the in-memory Azure
(fake_azure.py): no Azure call. The oracles are flows on the fake, never the code's markers (A0).
"""
from __future__ import annotations

import pytest

from glorfindel import actions
from glorfindel.actions import AzureConnector

from .fake_azure import ATTACKER, FakeAzure, key, open_flows, vm_id
from .test_invariants import _TEMPLATES, _rule

WEB = vm_id("rg-app1", "web")
BATCH = vm_id("rg-new", "batch")
PREFIX = "glorfindel-block-" + ATTACKER.replace(".", "-")


def _ssh():
    return [_rule("allow-ssh", 100, _TEMPLATES["allow-ssh"])]


def _world(monkeypatch, shared: bool):
    """web on the app subnet, batch on the data subnet, each subnet behind an NSG that lets
    SSH in. `shared`: both NICs on one NSG of theirs (a tier), web's block on it scoped to
    web's address; otherwise web on an NSG of its own (its block on every address), batch
    given it later (`_join`). Isolation by rules (no quarantine)."""
    monkeypatch.setenv("GLORFINDEL_QUARANTINE_NSG", "0")
    f = FakeAzure()
    app = f.add_subnet("rg-net", "vnet-hub", "app", f.add_nsg("rg-net", "nsg-subnet", _ssh()))
    data = f.add_subnet("rg-net", "vnet-hub", "data", f.add_nsg("rg-net", "nsg-data", _ssh()))
    nic_nsg = f.add_nsg("rg-net", "nsg-tier") if shared else f.add_nsg("rg-app1", "nsg-web-nic")
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": "web-nic", "ips": ["10.0.0.4"], "subnet": app,
                                 "nsg": nic_nsg}])
    if shared:
        f.add_vm("rg-new", "batch", [{"rg": "rg-new", "name": "batch-nic", "ips": ["10.0.0.9"], "subnet": data,
                                      "nsg": nic_nsg}])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    return f, c, f.nsgs[key(nic_nsg)], data


def _join(f, nsg: dict, subnet: str, ip: str = "10.0.0.9"):
    """batch created on the data subnet, given web's NSG — a pipeline reuses what outlives a VM."""
    f.add_vm("rg-new", "batch", [{"rg": "rg-new", "name": "batch-nic", "ips": [ip], "subnet": subnet,
                                  "nsg": nsg["id"]}])


def _flows(f, vm):
    return {x for x in open_flows({"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}, vm)
            if x[3] == ATTACKER}


def _ours(g: dict) -> dict:
    return {n: r["access"] for n, r in g["rules"].items() if n.startswith(PREFIX)}


def _inbound(g: dict) -> str:
    return next(n for n, r in g["rules"].items() if n.startswith(PREFIX) and r["direction"].lower() == "inbound")


def _turn(g: dict, name: str) -> None:
    """Someone turns our deny into an allow, by hand — never through the API."""
    g["rules"][name] = {**g["rules"][name], "access": "Allow"}


def _taken_up(f):
    """web's address changed, batch given it: the turned rule now lets the attacker reach batch."""
    f.nics[key(f.vms[key(WEB)]["nics"][0])]["ips"] = ["10.0.0.20"]
    f.nics[key(f.vms[key(BATCH)]["nics"][0])]["ips"] = ["10.0.0.4"]


def _entry():
    return next(e for e in actions._load_block_entries(WEB) if e.get("ip") == ATTACKER)


@pytest.mark.parametrize("case", ["a tier NSG", "web's own NSG, given to batch since"])
def test_the_promotion_keeps_a_turned_rule_that_lets_the_attacker_reach_a_vm_off_the_perimeter(monkeypatch, case):
    """The lot's case: web blocked for itself, its inbound deny turned into an allow by someone,
    web's address given to batch since, which the allow now lets the attacker reach — batch on
    the data subnet, on web's NIC NSG (a tier both share, or web's own a pipeline gave batch),
    out of the perimeter's reach. The
    promotion took the rule off: batch lost SSH from the attacker, an operation on web changed
    batch's flows (I4). Now the pair stays whole, said as the unblock says it, its placement in
    the state; the status is web's — the perimeter cuts the attacker off it."""
    shared = case == "a tier NSG"
    f, c, g, data = _world(monkeypatch, shared)
    assert c.block_suspicious_ip(ATTACKER, WEB)["status"] == "blocked"
    rule = _inbound(g)
    _turn(g, rule)
    if not shared:
        _join(f, g, data)
    _taken_up(f)
    before = _flows(f, BATCH)
    assert before, "the turned allow lets the attacker reach batch"
    out = c.block_suspicious_ip(ATTACKER, WEB, scope="subnet", replace=True)
    assert not before - _flows(f, BATCH), f"the promotion of web cut off batch: {sorted(before - _flows(f, BATCH))}"
    assert _ours(g) == {rule: "Allow", f"{rule}-out": "Deny"}, "the pair kept whole"
    assert out["status"] == "blocked", out
    assert not _flows(f, WEB), "the perimeter cuts the attacker off web"
    said = " ".join(out.get("kept_rules") or [])
    assert f"nsg-{'tier' if shared else 'web-nic'}/{rule} gardée" in said and "retournée en autorisation" in said, out
    assert "10.0.0.4" in said and "batch-nic" in said, said
    assert rule in out["note"] and "promoted_from" not in out, out
    entry = _entry()
    assert entry["scoped"] is False and [p["rule"] for p in entry["placements"]] == [rule], entry
    # The unblock finds it and asks again: kept, said, never `unblocked`.
    un = c.unblock_ip(ATTACKER, WEB)
    assert un["status"] == "unblock_partial" and any(rule in x for x in un["failed"]), un
    assert rule in g["rules"] and not before - _flows(f, BATCH), "the unblock cut off batch"


def test_the_promotion_drops_the_pair_when_nothing_was_turned(monkeypatch):
    """Nothing turned: the pair goes with the promotion, as it always did — named in
    `promoted_from`, the state's placements empty, nothing said kept (A0: no rule of ours kept
    for nothing). Green on `main`: it holds the correction to its case."""
    f, c, g, _ = _world(monkeypatch, True)
    c.block_suspicious_ip(ATTACKER, WEB)
    rule = _inbound(g)
    _taken_up(f)
    out = c.block_suspicious_ip(ATTACKER, WEB, scope="subnet", replace=True)
    assert _ours(g) == {}, g["rules"]
    assert out["status"] == "blocked" and out["promoted_from"] == [rule] and "kept_rules" not in out, out
    assert _entry()["placements"] == []


def test_a_turned_rule_on_the_vms_own_address_goes_with_the_promotion(monkeypatch):
    """Turned, but aimed at web's own address still: nothing of another VM hangs on it — it
    goes, the perimeter cuts the attacker off web (the guard keeps only what opens another)."""
    f, c, g, _ = _world(monkeypatch, True)
    c.block_suspicious_ip(ATTACKER, WEB)
    _turn(g, _inbound(g))
    out = c.block_suspicious_ip(ATTACKER, WEB, scope="subnet", replace=True)
    assert _ours(g) == {} and "kept_rules" not in out and not _flows(f, WEB), out


def test_a_delete_that_fails_keeps_the_placement_said(monkeypatch):
    """A delete refused (a lock, a 429 that outlasts the retries): before, swallowed — the rule
    left on Azure, its placement dropped from the state, the unblock blind to it. Kept now, said
    with its error, in the state for the unblock."""
    f, c, g, _ = _world(monkeypatch, True)
    c.block_suspicious_ip(ATTACKER, WEB)
    rule = _inbound(g)
    real = c._delete_rule
    monkeypatch.setattr(c, "_delete_rule", lambda rg, nsg, name: (
        f"{rg}/{nsg}/{name}: (ScopeLocked) refused" if name == rule else real(rg, nsg, name)))
    out = c.block_suspicious_ip(ATTACKER, WEB, scope="subnet", replace=True)
    assert rule in g["rules"] and "ScopeLocked" in " ".join(out["kept_rules"]), out
    assert [p["rule"] for p in _entry()["placements"]] == [rule]


def test_a_legacy_entry_turned_rule_stays_with_its_placement(monkeypatch):
    """An entry of the single-rule form (no placements): the same guard — kept, recorded as a
    placement of the primary NIC for the unblock."""
    f, c, g, _ = _world(monkeypatch, True)
    c.block_suspicious_ip(ATTACKER, WEB)
    rule = _inbound(g)
    entry = _entry()
    actions._clear_block_state(WEB, ATTACKER)
    actions._save_block_state("web", ATTACKER, WEB, nsg="rg-net/nsg-tier", nsg_scope="nic", rule=rule)
    assert _entry()["placements"] == [] and entry["placements"]
    _turn(g, rule)
    _taken_up(f)
    before = _flows(f, BATCH)
    out = c.block_suspicious_ip(ATTACKER, WEB, scope="subnet", replace=True)
    assert not before - _flows(f, BATCH) and rule in g["rules"], out
    assert [(p["nsg_name"], p["rule"]) for p in _entry()["placements"]] == [("nsg-tier", rule)]
    assert c.unblock_ip(ATTACKER, WEB)["status"] == "unblock_partial"
