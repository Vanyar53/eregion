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
from glorfindel.providers.azure.turned import _OLDER_NAMES, _turned_allows

from .fake_azure import FakeAzure, _rule_record, key, open_flows, vm_id
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
def test_an_older_versions_deny_all_turned_into_an_allow_is_ours_for_its_own_removal_only(name):
    """Two lists (I4G's review): an older version's name turned into an allow — fixed, `-out`,
    VM-suffixed — is found among those a removal by that name asks about (`_OLDER_NAMES`),
    never among the turned rules a deny holds back (I5Q, `_TURNED_NAMES`, the default) — a name
    homonyms and customers share there kept a true orphan. A deny under that name, or a
    customer's allow, is on neither."""
    def nsg(*rules):
        return SimpleNamespace(id="/x/nsg-a", subnets=[], security_rules=list(rules))

    def rule(n, access):
        return SimpleNamespace(name=n, access=access, direction="Outbound" if n.endswith("-out") else "Inbound",
                               source_address_prefix="*", destination_address_prefix="*")
    assert [t[3] for t in _turned_allows([nsg(rule(name, "Allow"))], _OLDER_NAMES)] == [name]
    assert _turned_allows([nsg(rule(name, "Allow"))]) == []
    assert _turned_allows([nsg(rule(name, "Deny"), rule("allow-ssh", "Allow"))], _OLDER_NAMES) == []


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
    # Put back as a deny-all, it would cut api too (I4G's review): never advised.
    assert "remettre en refus" not in said and "recréer sous un nom à elle" in said, said


def test_an_older_deny_all_still_a_deny_goes_with_its_release(monkeypatch):
    """Nothing turned: the older version's pair goes with web's release, as it always did —
    the guard keeps only what someone turned (no rule of ours kept for nothing, A0)."""
    f, c, g = _world(monkeypatch, FIXED)
    assert c.release_isolation(WEB)["status"] == "released"
    assert not {n for n in g["rules"] if n.startswith("glorfindel-")}, g["rules"]


@pytest.mark.parametrize("name", [FIXED, f"{FIXED}-web", f"{FIXED}-customer-thing"])
def test_a_true_orphan_goes_whatever_allow_an_older_name_carries_behind_it(monkeypatch, name):
    """U1 kept (I4G's review): web isolated by rules on its subnet's NSG, an allow on `*` there
    under an older version's name (its own, or a customer's that begins alike), web deleted with
    its state lost, batch given 10.0.0.4, a pass in non_disruptive. The orphan `glorfindel-iso-web-…`
    cuts batch: it goes, as on `main` before I4G — the older name is no turned rule a deny holds
    back (I5Q). With it counted there (the first form of I4G), the orphan was kept, batch cut."""
    from .test_orphan_sweep import _delete, _new_vm_at, _watch_pass
    from .test_orphan_sweep import _world as _sweep_world
    f, c, subnet = _sweep_world(monkeypatch)
    sweep_web = vm_id("rg-app1", "web")
    assert c.isolate_vm(sweep_web)["status"] == "isolated"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    g["rules"][name] = _rule_record(_rule(name, 4000, dict(
        access="Allow", direction="Inbound", source_address_prefix="*", destination_address_prefix="*",
        destination_port_range="*")))
    _delete(f, sweep_web)
    batch = _new_vm_at(f, subnet, "10.0.0.4")
    cut = _flows(f, batch)
    _watch_pass(c)
    assert not sorted(n for n in g["rules"] if n.startswith("glorfindel-iso-")), "U1: the orphan kept"
    assert cut < _flows(f, batch), "batch still cut off"


_BLOCK = "glorfindel-block-192-31-196-7-web-web-nic-8b70f2"


@pytest.mark.parametrize("name, to, back", [
    # A block's deny on one address: put back, it cuts only the attacker off the VM there.
    (_BLOCK, "10.0.0.5", True),
    (f"{_BLOCK}-out", "10.0.0.5", True),
    # A block's on every address: every NIC behind the NSG would lose the attacker's flows it opens.
    (_BLOCK, "*", False),
    # An isolation's deny on one address cuts EVERY flow of the VM holding it now (I4P): never put back.
    ("glorfindel-iso-web-web-nic-8b70f2", "10.0.0.5", False),
    ("glorfindel-iso-web-web-nic-8b70f2-out", "10.0.0.5", False),
    ("glorfindel-iso-web-web-nic-8b70f2", "*", False),           # every NIC behind the NSG would be cut
    (FIXED, "10.0.0.5", False),                                  # an older version's deny-all, never put back
    (f"{FIXED}-out", "*", False)])
def test_a_turned_allow_kept_says_what_to_do_without_cutting_the_vm_it_opens(name, to, back):
    """I4G's review: « la remettre en refus », said of a rule on `*` or of an older version's
    deny-all on an NSG shared since, would cut every NIC behind it — the VM it opens too. I4P:
    said of an isolation's rule aimed at another live NIC's address, it would cut every flow of
    that VM — it is advised for a block's rule on one address only (it denies the attacker, no
    more). Said otherwise: take it off by hand if no longer wanted; if another VM needs that flow,
    recreate it under a name of its own, then run again."""
    from glorfindel.providers.azure.turned import _opens_text
    said = _opens_text(name, to, "toutes les cartes derrière ce NSG, dont api-nic")
    assert ("la remettre en refus" in said) is back, said
    assert "la retirer à la main si elle n'est plus voulue" in said and "recréer sous un nom à elle" in said, said


@pytest.mark.parametrize("name, values, back", [
    (f"{_BLOCK}", ["10.0.0.5"], True),                          # a block's on its address: the attacker alone
    (f"{_BLOCK}-out", ["10.0.0.5"], True),
    (_BLOCK, ["*"], False),                                     # every NIC behind its NSG
    ("glorfindel-iso-web-web-nic-8b70f2", ["10.0.0.5"], False),  # every flow of the VM that holds 10.0.0.5
    ("glorfindel-iso-web-web-nic-8b70f2-out", ["10.0.0.5"], False),
    ("glorfindel-iso-web-web-nic-8b70f2", ["*"], False)])
def test_a_deny_kept_for_a_turned_rule_behind_it_says_what_to_do_without_cutting_that_vm(name, values, back):
    """I4P's review (`_turned_text`, I5Q): an orphan deny — a deleted VM's block, the attacker alone —
    on the address of a live NIC, kept for one of our rules turned into an allow behind it, aimed
    there. Its advice said « la remettre en refus » whatever that rule was: an isolation's, put
    back, cut every flow of that VM on its side. Said for a block's rule on its addresses only;
    otherwise: take it off by hand, or recreate the flow under a name of its own."""
    from glorfindel.providers.azure.turned import _turned_text
    said = _turned_text(("/x/nsg-subnet", name, "10.0.0.5", values))
    assert ("la remettre en refus" in said) is back, said
    assert back or ("la retirer à la main si elle n'est plus voulue" in said and "recréer sous un nom à elle" in said), said
    assert name in said and "10.0.0.5" in said, said


def test_the_orphan_sweep_never_advises_putting_back_an_isolations_rule(monkeypatch):
    """The case end to end: web blocked for itself on its subnet's NSG (aimed at 10.0.0.4), web
    deleted, its state lost; batch given 10.0.0.4 on that subnet, isolated, its isolation's inbound
    deny there turned into an allow by someone, batch's state lost. The orphan block of web is kept for
    that rule (I5Q) — its advice no longer says to put the isolation's rule back as a deny."""
    from .fake_azure import ATTACKER
    from .test_orphan_sweep import _delete, _new_vm_at, _watch_pass
    from .test_orphan_sweep import _world as _sweep_world
    f, c, subnet = _sweep_world(monkeypatch)
    web = vm_id("rg-app1", "web")
    assert c.block_suspicious_ip(ATTACKER, web)["status"] == "blocked"
    g = f.nsgs[key(f.subnets[key(subnet)]["nsg"])]
    _delete(f, web)
    for d in (actions._BLOCK_STATE_DIR,):
        for p in (d.glob("*.json") if d.exists() else []):
            p.unlink()
    batch = _new_vm_at(f, subnet, "10.0.0.4")
    c.isolate_vm(batch)
    iso = next((n for n, r in g["rules"].items() if n.startswith("glorfindel-iso-")
                and r["direction"].lower() == "inbound"), None)
    if iso is None:
        pytest.skip("batch isolated by quarantine: no rule of its own on the subnet's NSG")
    _turn(g, iso)
    actions._clear_isolation_state(batch)     # its state lost: not a VM Glorfindel holds
    said = " ".join(str(x) for x in (c.find_orphan_rules() or []))
    _watch_pass(c)
    blocks = [n for n in g["rules"] if n.startswith("glorfindel-block-")]
    assert blocks, "the orphan block is kept: the turned isolation rule waits behind it"
    from glorfindel import escalations
    cards = " ".join(e.get("reason") or "" for e in escalations.pending()) + said
    assert iso in cards and "la remettre en refus" not in cards, cards
