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

import pytest

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


def test_the_reset_says_a_bare_nics_rule_kept_on_the_nsg_it_carried(monkeypatch):
    """`reset --from-azure` had the same blind spot (the macOS job of PR #391, D80): the NSG
    the bare NIC carried, out of its sight. Kept by the guard, said « gardée »; never `swept`."""
    f, c, own, _ = _world(monkeypatch)
    name = _turned_toward_batch(f, own)
    out = c.sweep_vm_rules(WEB)
    assert out["status"] == "swept_partial", out
    assert any(name in s and "gardée" in s for s in out["failed"]), out
    assert name in f.nsgs[key(own)]["rules"]


def test_the_reset_takes_off_a_bare_nics_block_left_on_the_nsg_it_carried(monkeypatch):
    """The reset takes blocks off too: a block of web's NIC left on the NSG it carried, aimed
    at the attacker, nothing of another VM behind it — found by its name and taken off."""
    f, c, own, _ = _world(monkeypatch)
    block = AzureConnector()._placement_rule_bases("glorfindel-block-192-31-196-7", "web", "web-nic", WEB_NIC)[0]
    f._put_rule(f.nsgs[key(own)], _record(block, "Deny", "Inbound", "192.31.196.7", "10.0.0.4"))
    f._put_rule(f.nsgs[key(own)], _record(f"{block}-out", "Deny", "Outbound", "10.0.0.4", "192.31.196.7"))
    out = c.sweep_vm_rules(WEB)
    assert out["status"] == "swept", out
    assert not [n for n in f.nsgs[key(own)]["rules"] if n.startswith("glorfindel-")]


# I3R (#431): the rules of a NIC on our quarantine NSG it leaves with the release.

def _in_quarantine(monkeypatch, other: bool = False, turned: bool = False, bare: bool = False):
    """web isolated by our quarantine NSG (its own, nsg-web, away); our denies there stripped,
    then its isolation written again while that NSG had lost our tag — not ours, so web-nic's
    deny pair went on the NSG it carries, the quarantine NSG (what the reassertion did in the
    night's seed 67). The tag back. `other`: batch, beside it in the same quarantine, a rule
    of its own there too. `turned`: web's inbound deny turned by someone into an allow toward
    batch's address (I4B; batch in the quarantine too). `bare`: web-nic has no NSG of its own."""
    monkeypatch.delenv("GLORFINDEL_QUARANTINE_NSG", raising=False)
    other = other or turned
    f = FakeAzure()
    own = None if bare else f.add_nsg("rg-app1", "nsg-web")
    subnet = f.add_subnet("rg-net", "vnet-hub", "app", None)
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": "web-nic", "ips": ["10.0.0.4"], "subnet": subnet,
                                 "nsg": own}])
    batch = f.add_vm("rg-app1", "batch", [{"rg": "rg-app1", "name": "batch-nic", "ips": ["10.0.0.5"],
                                           "subnet": subnet, "nsg": f.add_nsg("rg-app1", "nsg-batch")}])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    for vm in (WEB, batch) if other else (WEB,):
        assert c.isolate_vm(vm)["status"] == "isolated"
    q = f.nics[key(WEB_NIC)]["nsg"]
    assert "quarantine" in q
    rules = f.nsgs[key(q)]["rules"]
    for ours in ("glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out"):
        rules.pop(ours)
    name = _iso_name()
    if turned:
        f._put_rule(f.nsgs[key(q)], _record(name, "Allow", "Inbound", "*", "10.0.0.5"))
    else:
        f._put_rule(f.nsgs[key(q)], _record(name, "Deny", "Inbound", "*", "10.0.0.4"))
    f._put_rule(f.nsgs[key(q)], _record(f"{name}-out", "Deny", "Outbound", "10.0.0.4", "*"))
    if other:
        assert key(f.nics[key(nic_id("rg-app1", "batch-nic"))]["nsg"]) == key(q)
        b = AzureConnector()._placement_rule_bases("glorfindel-iso", "batch", "batch-nic",
                                                   nic_id("rg-app1", "batch-nic"))[0]
        f._put_rule(f.nsgs[key(q)], {**_record(b, "Deny", "Inbound", "*", "10.0.0.5"), "priority": 101})
    return f, c, own, q


def _iso_on(f, nsg: str) -> list[str]:
    return sorted(n for n in f.nsgs[key(nsg)]["rules"] if n.startswith("glorfindel-iso"))


def test_a_nics_rules_on_the_quarantine_nsg_it_leaves_go_with_a_stateless_release(monkeypatch):
    """The state lost: the sweep puts web-nic's NSG back from our tag, then looked only at the
    NSGs that govern it now — `released`, its pair left on the quarantine NSG (seed 67, I3R)."""
    from glorfindel.actions import _clear_isolation_state
    f, c, own, q = _in_quarantine(monkeypatch)
    _clear_isolation_state(WEB)
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(own)
    assert _iso_on(f, q) == []


def test_a_nics_rules_on_the_quarantine_nsg_it_leaves_go_with_a_release_by_its_state(monkeypatch):
    """The state kept, its quarantine placement undone first — the sweep then reads the NIC
    off the quarantine NSG all the same: the NSG it leaves comes from the placement."""
    f, c, own, q = _in_quarantine(monkeypatch)
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(own)
    assert _iso_on(f, q) == []


def test_a_nic_held_in_the_quarantine_keeps_its_rules_there(monkeypatch):
    """Its original unknown (state and our tag lost), web-nic stays in quarantine and the
    release says so: its rules there stay — with our denies taken off, they may be all
    that cuts it off."""
    from glorfindel.actions import _clear_isolation_state
    f, c, _, q = _in_quarantine(monkeypatch)
    _clear_isolation_state(WEB)
    f.nsgs[key(q)]["tags"] = {k: v for k, v in f.nsgs[key(q)]["tags"].items() if not k.startswith("glorfindel-orig-")}
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(q)
    assert _iso_on(f, q) == sorted([_iso_name(), f"{_iso_name()}-out"])


def test_only_the_leaving_nics_rules_go_from_the_quarantine_nsg(monkeypatch):
    """batch stays in the same quarantine, a rule of its own there: web's release takes off
    web-nic's, never batch's (its hash, I4)."""
    f, c, _, q = _in_quarantine(monkeypatch, other=True)
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert [n for n in _iso_on(f, q) if "batch" in n] and not [n for n in _iso_on(f, q) if "-web-" in n]


def test_a_rule_turned_toward_a_vm_still_in_the_quarantine_stays_and_is_said(monkeypatch):
    """web-nic's inbound rule on the quarantine NSG turned into an allow toward batch, still
    in it: taken off with web's release, batch would lose what it opens (I4B) — kept, said
    « gardée », never `released`. Its deny pair's other half goes."""
    f, c, _, q = _in_quarantine(monkeypatch, turned=True)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert any(_iso_name() in s and "gardée" in s for s in out["failed"]), out
    assert _iso_name() in f.nsgs[key(q)]["rules"] and f"{_iso_name()}-out" not in f.nsgs[key(q)]["rules"]


def test_a_bare_nics_rule_kept_on_the_quarantine_nsg_it_left_is_said_once(monkeypatch):
    """web-nic had no NSG of its own: back to none, it is bare, and its rules are looked for
    on every NSG of the subscription (D80) — the quarantine NSG it left among them. The rule
    kept there is said once, not by both searches."""
    f, c, _, q = _in_quarantine(monkeypatch, turned=True, bare=True)
    out = c.release_isolation(WEB)
    assert f.nics[key(WEB_NIC)]["nsg"] is None
    assert out["status"] == "release_partial", out
    assert sum(_iso_name() in s and "gardée" in s for s in out["failed"]) == 1, out


def test_a_quarantine_nsg_left_that_cant_be_read_is_said(monkeypatch):
    """web-nic put back on its NSG, the quarantine NSG it left can't be listed any more (its
    role removed meanwhile): nothing found is not nothing there (A0) — never `released`."""
    f, c, own, q = _in_quarantine(monkeypatch)
    real = f.network.security_rules.list

    def refused(rg, name):
        if key(f"/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}") \
                == key(q):
            raise RuntimeError("AuthorizationFailed")
        return real(rg, name)
    monkeypatch.setattr(f.network.security_rules, "list", refused)
    out = c.release_isolation(WEB)
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(own)
    assert out["status"] == "release_partial", out
    assert any("règles illisibles" in s for s in out["failed"]), out


def test_a_nic_held_in_the_quarantine_by_its_state_keeps_its_rules_there(monkeypatch):
    """The state kept, its original gone (the customer deleted nsg-web meanwhile): the
    placement's undo fails, web-nic stays in quarantine — the NSG its placement names is
    not one it leaves, its rules there stay."""
    f, c, own, q = _in_quarantine(monkeypatch)
    assert f.delete_nsg(own)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(q)
    assert _iso_on(f, q) == sorted([_iso_name(), f"{_iso_name()}-out"])


def _refuse_listing(monkeypatch, f, q):
    """The quarantine NSG's rules can't be listed (its role removed meanwhile); returns the
    real listing, to give it back."""
    real = f.network.security_rules.list

    def refused(rg, name):
        if key(f"/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}") \
                == key(q):
            raise RuntimeError("AuthorizationFailed")
        return real(rg, name)
    monkeypatch.setattr(f.network.security_rules, "list", refused)
    return real


@pytest.mark.parametrize("with_state", [False, True])
def test_the_retry_of_a_release_that_couldnt_read_the_quarantine_nsg_looks_there_again(monkeypatch, with_state):
    """I3R's review: the quarantine NSG unreadable, the release puts web-nic's NSG back and says
    `release_partial`; the retry finds the NIC on its own NSG — its quarantine placement undone,
    or no state at all: it no longer knew to look there and said `released`, the pair still
    there. The partial state keeps the NSG left unswept (`quarantines_left`)."""
    from glorfindel.actions import _clear_isolation_state, _load_isolation_state
    f, c, own, q = _in_quarantine(monkeypatch)
    if not with_state:
        _clear_isolation_state(WEB)
    real = _refuse_listing(monkeypatch, f, q)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert key(f.nics[key(WEB_NIC)]["nsg"]) == key(own) and _iso_on(f, q)
    assert [x.lower() for x in _load_isolation_state(WEB)["quarantines_left"][WEB_NIC]] == \
        [q.split("/")[4].lower(), q.rsplit("/", 1)[-1].lower()]
    monkeypatch.setattr(f.network.security_rules, "list", real)
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert _iso_on(f, q) == [] and _load_isolation_state(WEB) is None


def test_the_retry_of_a_release_whose_delete_failed_on_the_quarantine_nsg_takes_it_off(monkeypatch):
    """A 429 on the delete of web-nic's rule on the quarantine NSG: `release_partial`; the retry,
    the NIC on its own NSG and no state but the partial one, takes it off — never `released`
    with the rule there."""
    from glorfindel.actions import _clear_isolation_state
    f, c, own, q = _in_quarantine(monkeypatch)
    _clear_isolation_state(WEB)
    real, calls = f.network.security_rules.begin_delete, []

    def throttled_once(rg, nsg, name):
        if name.startswith("glorfindel-iso") and not calls:
            calls.append(name)
            raise RuntimeError("(TooManyRequests) 429")
        return real(rg, nsg, name)
    monkeypatch.setattr(f.network.security_rules, "begin_delete", throttled_once)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial" and calls, out
    assert calls[0] in _iso_on(f, q)
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert _iso_on(f, q) == []


def test_a_rule_its_placement_kept_on_the_quarantine_nsg_is_said_once(monkeypatch):
    """The state as the reassertion wrote it in seed 67: web-nic's isolation placed by rules on
    the quarantine NSG (it had lost our tag), the inbound one turned toward batch, still in it.
    The placement's undo keeps it and says so; the search on the quarantine NSG the NIC then
    leaves skips what the placements just failed (`stuck`): said once."""
    from glorfindel.actions import _load_isolation_state, _save_isolation_state
    f, c, _, q = _in_quarantine(monkeypatch, turned=True)
    st = _load_isolation_state(WEB)
    q_rg, q_name = q.split("/")[4], q.rsplit("/", 1)[-1]
    _save_isolation_state(WEB, {**st, "placements": [{
        "nic_id": WEB_NIC, "nsg_rg": q_rg, "nsg_name": q_name, "scope": "nic", "shared_nsg": True,
        "ips": ["10.0.0.4"], "priority": 100, "rule_in": _iso_name(), "rule_out": f"{_iso_name()}-out",
        "bumped": [], "applied": [_iso_name(), f"{_iso_name()}-out"]}]})
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert sum(_iso_name() in s and "gardée" in s for s in out["failed"]) == 1, out
    assert _iso_name() in f.nsgs[key(q)]["rules"]


# ── I3U (#440) : un état devenu illisible ne dit jamais « levée faite » ────────────────────

_BROKEN = '{"resource_id": '                     # a write cut short: not JSON


def _partial_then_unreadable(monkeypatch, with_state: bool):
    """I3R's retry, the double fault of its review's probe: the quarantine NSG unreadable, the
    release gives web-nic its NSG back and keeps that NSG in its partial state; the NSG reads
    again, then the state turns unreadable (a disk, a write cut short). Returns the world, the
    state file and its readable text (what the operator repairs it to)."""
    from glorfindel.actions import _clear_isolation_state
    from glorfindel.response.state import _ISOLATION_STATE_DIR, _isolation_unreadable, _state_file
    f, c, own, q = _in_quarantine(monkeypatch)
    if not with_state:
        _clear_isolation_state(WEB)
    real = _refuse_listing(monkeypatch, f, q)
    assert c.release_isolation(WEB)["status"] == "release_partial"
    monkeypatch.setattr(f.network.security_rules, "list", real)
    sf = _state_file(_ISOLATION_STATE_DIR, WEB)
    text = sf.read_text()
    assert "quarantines_left" in text and _iso_on(f, q)
    sf.write_text(_BROKEN)
    assert _isolation_unreadable(WEB)
    return f, c, own, q, sf, text


@pytest.mark.parametrize("with_state", [False, True])
def test_a_partial_release_whose_state_turns_unreadable_never_says_released(monkeypatch, with_state):
    """The probe of I3R's review: the retry read an empty state, found web-nic on its own NSG,
    said `released` and deleted the unreadable file — the pair left on the quarantine NSG, the
    only record of where to look gone. Now `release_partial`, the reason said, the file kept as
    it is, again and again; repaired by the operator, the retry takes the normal path."""
    f, c, own, q, sf, text = _partial_then_unreadable(monkeypatch, with_state)
    for _ in range(2):
        out = c.release_isolation(WEB)
        assert out["status"] == "release_partial", out
        assert [s for s in out["failed"] if f"isolation/{sf.name}" in s and "illisible" in s
                and "levée non vérifiée" in s], out
        assert sf.read_text() == _BROKEN and _iso_on(f, q)
    sf.write_text(text)                                                   # the operator repairs it
    out = c.release_isolation(WEB)
    assert out["status"] == "released", out
    assert _iso_on(f, q) == [] and not sf.exists()


def test_a_release_by_rules_on_an_unreadable_state_takes_them_off_and_keeps_the_file(monkeypatch):
    """No quarantine: the rules are found by their names and taken off, as before — but what the
    unreadable state may name besides is unknown: `release_partial`, the file kept. Removed by
    the operator, the retry says `released`."""
    from glorfindel.response.state import _ISOLATION_STATE_DIR, _state_file
    f, c, own, _ = _world(monkeypatch)
    f.nics[key(WEB_NIC)]["nsg"] = own
    assert c.isolate_vm(WEB)["status"] == "isolated" and _iso_on(f, own)
    sf = _state_file(_ISOLATION_STATE_DIR, WEB)
    sf.write_text(_BROKEN)
    out = c.release_isolation(WEB)
    assert out["status"] == "release_partial", out
    assert len([s for s in out["failed"] if "illisible" in s]) == 1, out
    assert _iso_on(f, own) == [] and sf.read_text() == _BROKEN
    sf.unlink()                                                           # the operator removes it
    assert c.release_isolation(WEB)["status"] == "released"


def test_the_verification_of_a_release_on_an_unreadable_state_is_never_verified(monkeypatch):
    """`glorfindel release` asks verify_release first: « verified » — web-nic on its own NSG, the
    quarantine NSG out of its sight — and it cleared the state file, « No active isolation
    found ». Its own state unreadable: unknown."""
    f, c, *_ = _partial_then_unreadable(monkeypatch, with_state=True)
    v = c.verify_release(WEB)
    assert v["verified"] is False and any("illisible" in u for u in v["unreadable"]), v


def test_the_cli_release_keeps_an_unreadable_state_and_exits_2(monkeypatch):
    """The CLI path of the same: never « state cleared », the file kept, exit 2."""
    from click.testing import CliRunner

    from glorfindel import cli
    f, c, own, q, sf, _ = _partial_then_unreadable(monkeypatch, with_state=False)
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **_k: c)
    monkeypatch.setattr(cli, "_record_manual_action", lambda *a, **k: None)     # runs/: not the test's
    res = CliRunner().invoke(cli.cli, ["release", WEB, "--yes"])
    assert res.exit_code == 2, res.output
    assert "state cleared" not in res.output and "illisible" in res.output
    assert sf.read_text() == _BROKEN and _iso_on(f, q)


@pytest.mark.parametrize("dry_run", [True, False])
def test_reset_from_azure_on_an_unreadable_state_never_says_swept(monkeypatch, dry_run):
    """`reset --from-azure` reads the state too (its older record, its originals): unreadable, it
    said `swept` and deleted the file. Now `swept_partial`, said in the preview too, the file
    kept; the rules it finds by name are taken off all the same."""
    from glorfindel.response.state import _ISOLATION_STATE_DIR, _state_file
    f, c, own, _ = _world(monkeypatch)
    f.nics[key(WEB_NIC)]["nsg"] = own
    assert c.isolate_vm(WEB)["status"] == "isolated"
    sf = _state_file(_ISOLATION_STATE_DIR, WEB)
    sf.write_text(_BROKEN)
    out = c.sweep_vm_rules(WEB, dry_run=dry_run)
    assert out["status"] == ("dry_run" if dry_run else "swept_partial"), out
    assert [s for s in out["failed"] if "illisible" in s and "reset non vérifié" in s], out
    assert sf.read_text() == _BROKEN
    assert bool(_iso_on(f, own)) is dry_run


def test_a_plain_reset_on_an_unreadable_state_is_not_nothing_to_reset(monkeypatch):
    """`glorfindel reset` read the readable states only: « Nothing to reset », exit 0. The
    release runs, says what it can't verify, exit 2, the file kept."""
    from click.testing import CliRunner

    from glorfindel import cli
    f, c, own, q, sf, _ = _partial_then_unreadable(monkeypatch, with_state=True)
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **_k: c)
    monkeypatch.setattr(cli, "_record_manual_action", lambda *a, **k: None)     # runs/: not the test's
    res = CliRunner().invoke(cli.cli, ["reset", WEB, "--yes"])
    assert res.exit_code == 2 and "Nothing to reset" not in res.output, res.output
    assert "illisible" in res.output and sf.read_text() == _BROKEN


def test_clearing_a_state_never_deletes_an_unreadable_file(monkeypatch):
    """Whoever asks (a provider's release, the CLI): an unreadable file is the operator's to
    repair or remove — what it held is unknown (A0)."""
    from glorfindel.actions import _clear_isolation_state
    *_, sf, text = _partial_then_unreadable(monkeypatch, with_state=True)
    _clear_isolation_state(WEB)
    assert sf.read_text() == _BROKEN
    sf.write_text(text)
    _clear_isolation_state(WEB)
    assert not sf.exists()
