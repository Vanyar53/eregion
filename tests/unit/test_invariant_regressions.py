"""Sequences the invariant machine found failing (L26), replayed as fixed examples on
every push: each one broke a property before its fix. A rule's draws are given in the
order it makes them — `_draw` takes the VM, the id it is reached with, the fault.
"""
from __future__ import annotations

import pytest

from .fake_azure import ATTACKER, FakeAzure, _rule_record, key
from .test_invariants import IsolationMachine, _rule, invariant_env

WEB1 = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web"
WEB2 = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web"
API = "/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api"
DB = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01"


def _nic(rg: str, name: str) -> str:
    return key(f"/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{name}")


class Script:
    """Feeds the rules their draws, in order."""

    def __init__(self, *values):
        self.values = list(values)

    def draw(self, strategy, label=None):
        return self.values.pop(0)


def _net(quarantine=False, subnet_nsg=None, quarantine_rg="", tier_rules=(), legacy=None, **nics):
    plain = {"own": None, "rules": [], "policy": False}
    return {"subnet_nsg": subnet_nsg, "edge_nsg": None, "tier_rules": list(tier_rules),
            "nics": {n: {**plain, **nics.get(n.replace("-", "_"), {})}
                     for n in ("web-nic", "db-nic-0", "db-nic-1", "api-nic")},
            "windows": None,
            "config": {"quarantine": quarantine, "rg": quarantine_rg, "forensic": [], "readable": True},
            "legacy": legacy}


def _run(monkeypatch, net, *steps):
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(net)
        for rule, *draws in steps:
            getattr(m, rule)(**({"data": Script(*draws)} if draws else {}))
            m.never_more_open_than_designed()
            m.customer_configuration_untouched()
            m.one_vm_one_state_file()
    finally:
        m.teardown()


def test_the_old_ip_rule_goes_with_a_stateless_release(monkeypatch):
    """Isolated by rules, then the customer changes the NIC's IP: the rule still denies
    the old address. Without state, the release looked for this NIC's rules by content,
    skipped it — `released`, and the rule waited for whoever got the old IP."""
    _run(monkeypatch, _net(web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("customer_changes_ip", _nic("rg-app1", "web-nic"), 0, 20),
         ("lose_state", WEB1),
         ("release", WEB1, WEB1, None))


def test_a_block_is_checked_against_the_nic_as_it_is_now(monkeypatch):
    """A block, then the customer changes an IP of the VM: the verification compared the
    rules with the IPs recorded at block time and said blocked — the new address open."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block", DB, DB, None, 22),
         ("customer_changes_ip", _nic("rg-app1", "db-nic-0"), 0, 20),
         ("verify", DB, DB, None))


def test_a_nic_given_back_its_nsg_releases_without_its_original(monkeypatch):
    """Quarantine, state and tags lost, re-isolated, then a redeploy puts the customer's
    NSG back. The release asked for the (unknown, unneeded) original before looking at
    the NIC, and failed forever."""
    _run(monkeypatch, _net(quarantine=True),
         ("lose_everything", WEB1, WEB1, None, WEB1,
          "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/"
          "nsg-glorfindel-quarantine-westeurope", "stop"),
         ("isolate", WEB1, WEB1, None),
         ("redeploy_nic", _nic("rg-app1", "web-nic")),
         ("recover",))


def test_a_block_hidden_behind_the_quarantine_is_not_a_block(monkeypatch):
    """A block on the NIC's own NSG, then an isolation by quarantine: the NIC no longer
    carries that NSG. Someone empties the quarantine NSG — the attacker gets through,
    and the verification read the block's rules, present on an NSG that no longer
    governs the NIC, as a block."""
    _run(monkeypatch, _net(web_nic={"own": "dedicated"}),
         ("block", WEB1, WEB1, None, 22),
         ("config_changes", {"quarantine": True, "rg": "", "forensic": [], "readable": True}, True),
         ("isolate", WEB1, WEB1, None),
         ("strip_quarantine_nsg",
          "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/"
          "nsg-glorfindel-quarantine-westeurope"))


def test_a_second_release_never_empties_the_shared_quarantine_nsg(monkeypatch):
    """Two VMs in one quarantine NSG (a central quarantine group). A release that fails
    partway (a subnet it can't read)
    keeps a state with no placements left, next to the flat fields that name the
    shared quarantine NSG and its deny rules. The next release read that as a legacy
    single-NSG state and deleted those rules: the other VM was open again."""
    _run(monkeypatch, _net(quarantine=True, quarantine_rg="rg-sec"),
         ("isolate", WEB2, WEB2, None),
         ("isolate", WEB1, WEB1, None),
         ("release", WEB1, WEB1, ("subnet.get", "always-429")),
         ("release", WEB1, WEB1, None))


def test_an_unblock_in_quarantine_finds_the_block_behind_it(monkeypatch):
    """A block on the NIC's own NSG, the VM isolated by quarantine, the block's state
    lost (a crash before it was written): the unblock looked only at the NSGs on the
    NIC, said `not_found`, and the IP was blocked again when the isolation was released."""
    from glorfindel import actions
    from .fake_azure import ATTACKER
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, web_nic={"own": "dedicated"}))
        m.block(Script(WEB1, WEB1, None, 22))
        m.isolate(Script(WEB1, WEB1, None))
        actions._clear_block_state(WEB1, ATTACKER)
        m.unblock(Script(WEB1, WEB1, None))
        m.customer_configuration_untouched()
    finally:
        m.teardown()


def test_a_reset_reads_the_original_from_the_state_and_marks_what_it_left(monkeypatch):
    """Blocked, isolated by quarantine, then the quarantine NSG's tags replaced. The
    reset read the original NIC NSG from the tag only, stopped on it although the state
    knew it, deleted the block's rules anyway and kept the block's state unmarked — the
    reassertion would have put back what the operator had asked to remove."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, subnet_nsg=[]))
        m.block(Script(WEB1, WEB1, None, 22))
        m.isolate(Script(WEB1, WEB1, None))
        m.tags_lost(Script("/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/"
                           "networksecuritygroups/nsg-glorfindel-quarantine-westeurope"))
        m.reset_from_azure(Script(WEB1, WEB1, None))
        # The state knew the original: the reset finishes. Since A0 it records its intent
        # first, so stopping on the lost tag no longer shows as a state that isn't Azure's:
        # it shows here, as a reset that didn't do what it could (M24).
        assert m._state(WEB1) is None and m._nics_as_designed(WEB1), m._state(WEB1)
    finally:
        m.teardown()


def test_a_nic_left_without_an_nsg_gets_its_original_back(monkeypatch):
    """Someone takes the quarantine NSG off a NIC and leaves it with none. The release
    moved on (the NIC no longer carried ours), deleted the tag of the original, and said
    `released` — the NIC kept no NSG (seventh review, U2)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("release", WEB1, WEB1, None))


def test_an_emptied_quarantine_is_seen_with_an_unreadable_config(monkeypatch):
    """The config can't be read and someone empties the quarantine NSG: the check of
    the quarantine read the forensic sources from the config, raised, and the
    reassertion only logged it — the VM open, nobody told (seventh review, U4). Our
    denies don't depend on the config: an emptied NSG reads as altered."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True))
        m.isolate(Script(WEB1, WEB1, None))
        m.config["readable"] = False
        m._write_config()
        assert m.connector.verify_isolation(WEB1)["verified"] is None      # denies intact, forensic unknown
        m._strip_quarantine_nsg(Script(
            "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/"
            "nsg-glorfindel-quarantine-westeurope"))
        assert m.connector.verify_isolation(WEB1)["verified"] is False
        m.config["readable"] = True
        m._write_config()
    finally:
        m.teardown()


def test_a_deleted_vms_block_on_a_reused_ip_is_reported(monkeypatch):
    """Seventh review, V-1 and U1: `web` (group 1) gets a new IP and is blocked, then
    deleted; its homonym in group 2 is given that IP. The deleted VM's block rule now
    applies to the live one: an unblock of the live one has nothing of its own to
    remove, and the orphan — cutting the live VM off — is reported."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        m.customer_changes_ip(Script(_nic("rg-app1", "web-nic"), 0, 20))
        m.block(Script(WEB1, WEB1, None, 22))
        m.delete_vm(Script(WEB1))
        m.customer_changes_ip(Script(_nic("rg-app2", "web-nic"), 0, 20))
        m.unblock(Script(WEB2, WEB2, None))
        m.orphans_are_reported()
        orphans = m.connector.find_orphan_rules()
        assert any(o["now_on"] and o["now_on"][0]["ip"] == "10.0.0.20" for o in orphans), orphans
        assert m.fake.nics[_nic("rg-app2", "web-nic")]["ips"] == ["10.0.0.20"]
    finally:
        m.teardown()


def test_a_bare_nic_isolated_again_keeps_its_recorded_original(monkeypatch):
    """Isolated by quarantine, taken off it and left bare by someone, isolated again:
    the second isolation saw no NSG and recorded "none" over the original the first one
    had recorded — the release then left the NIC without its NSG (seventh review, U2)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("isolate", WEB1, WEB1, None),
         ("release", WEB1, WEB1, None))


def _moved_behind_a_customer_allow(monkeypatch, net, act, prefix):
    """Act, then move Glorfindel's OUTBOUND deny to 4000, behind a customer allow at
    1200: each direction must be judged against its own deny (A0)."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(net)
        act(m)
        (nsg, name), = [(k, n) for k, g in m.fake.nsgs.items() for n in g["rules"]
                        if n.startswith(prefix) and n.endswith("-out")]
        m.tamper_with_our_rule(Script("priority", (nsg, name)))   # claims checked after
        m.never_more_open_than_designed()
    finally:
        m.teardown()


def test_an_isolation_moved_behind_a_customer_allow_is_bypassed(monkeypatch):
    """The outbound isolation deny moved to 4000 by hand, the tier NSG allowing the
    VNet out at 1200: verify_isolation used the INBOUND deny's priority (100) for both
    directions and said isolated — lateral movement open."""
    lateral = _rule("allow-lateral-out", 1200, dict(
        access="Allow", direction="Outbound", source_address_prefix="*",
        destination_address_prefix="VirtualNetwork", destination_port_range="*"))
    _moved_behind_a_customer_allow(
        monkeypatch, _net(tier_rules=[lateral], web_nic={"own": "tier"}),
        lambda m: m.isolate(Script(WEB1, WEB1, None)), "glorfindel-iso-")


def test_a_block_moved_behind_a_customer_allow_is_bypassed(monkeypatch):
    """Same for a block: its outbound deny moved behind an allow-all out."""
    out_all = _rule("allow-all-out", 1200, dict(
        access="Allow", direction="Outbound", source_address_prefix="*",
        destination_address_prefix="*", destination_port_range="*"))
    _moved_behind_a_customer_allow(
        monkeypatch, _net(web_nic={"own": "dedicated", "rules": [out_all]}),
        lambda m: m.block(Script(WEB1, WEB1, None, 22)), "glorfindel-block-")


def test_an_isolation_undone_by_another_host_is_not_reported_isolated(monkeypatch):
    """Another host puts the NIC back right after the quarantine swap: nothing read the
    NIC back, and isolate_vm said isolated on a NIC carrying no NSG at all (A0, M30)."""
    _run(monkeypatch, _net(quarantine=True),
         ("another_host_writes", WEB1, WEB1, None, "after-foreign", False))


def test_a_release_undone_by_another_host_is_not_reported_released(monkeypatch):
    """Another host keeps putting the quarantine back during the release: only the
    read-back after the write tells (A0, M14 — the sweep re-reads too, once)."""
    _run(monkeypatch, _net(quarantine=True),
         ("another_host_writes", WEB1, WEB1, None, "always-foreign", True))


def _legacy_world(monkeypatch, legacy, *steps, check):
    """An older version's isolation in the world, steps, then the claims of `check`."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(legacy=legacy, web_nic={"own": "dedicated"}, api_nic={"own": "dedicated"}))
        for rule, *draws in steps:
            getattr(m, rule)(Script(*draws))
        check(m)
    finally:
        m.teardown()


_NEW_VM_ON = "/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/nsg-{nic}"


def test_an_old_isolation_is_not_released_when_its_nsg_cant_be_read(monkeypatch):
    """Old fixed names, state lost, and the NSG's associations unreadable: placed as
    shared, the fixed names didn't count — verify_release said released, the VM still
    cut off by the old deny any/any (A0)."""
    _legacy_world(monkeypatch, ("api-nic", False),
                  check=lambda m: m._check_claims(API, API, ("nsg.get", "always-429")))


def test_an_old_isolation_on_an_nsg_shared_since_is_not_released(monkeypatch):
    """Same, the NSG now shared with a new VM: whose the old deny is can't be told —
    not "released" while it cuts the VM off (A0)."""
    _legacy_world(monkeypatch, ("web-nic", False),
                  ("create_vm", "westeurope", "rg-app1", "api", _NEW_VM_ON.format(rg="rg-app1", nic="web-nic"), "Linux"),
                  check=lambda m: m._check_claims(WEB1, WEB1))


def test_an_old_state_names_its_rules_for_the_verification_too(monkeypatch):
    """The old single-NSG state kept, the NSG shared since: the release deletes the
    recorded rules, verify_release ignored the record and said released (A0)."""
    _legacy_world(monkeypatch, ("api-nic", True),
                  ("create_vm", "northeurope", "rg-new", "web", _NEW_VM_ON.format(rg="rg-edge", nic="api-nic"), "Linux"),
                  check=lambda m: m._check_claims(API, API))


def test_an_interrupted_reset_is_a_release_under_way(monkeypatch):
    """`reset --from-azure` cut off right after it removed something from Azure: with no
    marker of the reset's intent, the reassertion took the half-removed isolation for one
    removed outside Glorfindel and put it back, mid-release (A0, I9). Its second write is
    the first one on Azure when the intent is recorded (the first is the marker)."""
    _legacy_world(monkeypatch, ("api-nic", True),
                  ("reset_from_azure", API, API, (2, "after-crash")),
                  ("reassert", "non_disruptive", None),
                  check=lambda m: None)


def test_a_reset_with_unreadable_sharing_doesnt_skip_an_old_isolation(monkeypatch):
    """`reset --from-azure` on an older version's isolation, the NSG's associations
    unreadable: placed as shared, the fixed names didn't count — "swept", the VM still
    cut off (state lost); state kept, its record was ignored and cleared (A0)."""
    for keep in (False, True):
        _legacy_world(monkeypatch, ("api-nic", keep),
                      ("reset_from_azure", API, API, ("nsg.get", "always-429")),
                      check=lambda m: None)


_NSG = "/subscriptions/s/resourcegroups/{rg}/providers/microsoft.network/networksecuritygroups/{name}"


def test_a_homonyms_alert_doesnt_close_the_other_card(monkeypatch):
    """Two `web` blocked, both blocks removed by a `terraform apply`, reassertion in
    human_only: the alert was keyed by the VM's NAME — the second one closed the first
    card, and that block stayed "already alerted" with no card at all (A0, L1)."""
    _run(monkeypatch, _net(web_nic={"own": "dedicated"}),
         ("block", WEB1, WEB1, None, 22),
         ("block", WEB2, WEB2, None, 22),
         ("terraform_apply", _NSG.format(rg="rg-app1", name="nsg-web-nic")),
         ("terraform_apply", _NSG.format(rg="rg-app2", name="nsg-web-nic")),
         ("reassert", "human_only", None))


def test_a_block_gone_behind_the_quarantine_is_said(monkeypatch):
    """Blocked, then isolated by quarantine, then the block's rules removed from the NIC's
    own NSG: the quarantine holds the attacker out, so the block read as verified — and
    nothing was said until the release let the attacker back in (A0, L1)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("block", WEB1, WEB1, None, 22),
         ("isolate", WEB1, WEB1, None),
         ("terraform_apply", _NSG.format(rg="rg-app1", name="nsg-web-nic")),
         ("reassert", "human_only", None))


def test_a_release_never_takes_an_old_isolation_on_a_shared_nsg(monkeypatch):
    """An older version's isolation of `web` (fixed names, any/any, its state kept), then a
    new VM attached to the same NSG — shared since. Releasing the NEW VM must leave web's
    rule: fixed names only count on an NSG that governs one VM (M02, observable since the
    machine has older versions' rules — A0)."""
    new_vm = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/api"
    _legacy_world(monkeypatch, ("web-nic", True),
                  ("create_vm", "westeurope", "rg-app1", "api", _NEW_VM_ON.format(rg="rg-app1", nic="web-nic"), "Linux"),
                  ("release", new_vm, new_vm, None),
                  check=lambda m: None)


_Q1 = _NSG.format(rg="rg-app1", name="nsg-glorfindel-quarantine-westeurope")


def test_a_reset_puts_a_bare_nics_original_back_from_the_state(monkeypatch):
    """Isolated, our NSG taken off the NIC by someone, our tags lost: the reset read a bare
    NIC's original from the tag only — skipped it, said `swept` and cleared the state that
    knew it: the NIC left without its NSG, in silence (A0, seed 3)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("tags_lost", _Q1),
         ("reset_from_azure", WEB1, WEB1, None))


def test_a_block_on_a_deleted_nsg_is_gone_not_unreadable(monkeypatch):
    """Blocked on the NIC's own NSG, isolated by quarantine, then the customer deletes that
    NSG (it governs nothing any more): the listing failed (404) and read as "unreadable" —
    the block gone and never said (A0, L1, seed 3)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("block", WEB1, WEB1, None, 22),
         ("isolate", WEB1, WEB1, None),
         ("customer_deletes_nsg", _NSG.format(rg="rg-app1", name="nsg-web-nic")),
         ("reassert", "human_only", None))


def test_a_reset_sweeps_the_original_it_puts_back(monkeypatch):
    """An older version's isolation of `web` on its own NSG, then a quarantine, our NSG
    taken off the NIC by someone, and a reset: it put the NIC's NSG back but never read
    that NSG's rules — the old isolation stayed, the VM still cut off after `swept`, with
    no state (A0, seed 20)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", True), web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("reset_from_azure", WEB1, WEB1, None))


def test_a_vm_given_an_isolated_deleted_vms_address_is_freed_by_the_sweep(monkeypatch):
    """A3, the criterion of the lot: `web` (group 1) isolated by rules on the subnet NSG,
    deleted after losing its state; a new VM gets 10.0.0.4 behind that NSG and is cut off
    by web's rule. The watch's pass takes it off in non_disruptive — nothing else; in
    human_only first, it only says so — and teardown checks every live VM is back to its
    design in full."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        m.address_reused(Script(WEB1, WEB1, None, True, True, "rg-new", "batch", None, "Linux", False))
        assert m._cutting_orphans(), "the new VM should be cut off by web's rule"
        m.orphan_sweep(Script(None, "human_only"))
        assert m._cutting_orphans(), "human_only only reads (D-A)"
        m.orphan_sweep(Script(None, "non_disruptive"))
        assert not m._cutting_orphans()
        m.orphans_are_reported()
    finally:
        m.teardown()


def test_the_teardown_frees_the_vms_whatever_mode_the_last_rule_left(monkeypatch):
    """Found at 2 000 sequences (A3, after its first review): `api` isolated, its state
    lost, deleted; a new `api` gets its address behind its NSG. The teardown's sweep ran
    in the mode an earlier rule — or an earlier sequence — left: in human_only, only a
    card, and the new VM stayed cut off. The teardown gives the VMs their mode."""
    from . import test_invariants
    monkeypatch.setattr(test_invariants._CURRENT, "mode", "human_only")
    nsg_api = ("/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Network/"
               "networkSecurityGroups/nsg-api-nic")
    _run(monkeypatch, _net(api_nic={"own": "dedicated"}),
         ("address_reused", WEB1, WEB1, None, False, 22, False, "rg-app1", "web", False),
         ("address_reused", API, API, None, True, True, "rg-app1", "api", nsg_api, "Linux", False))


BATCH = "/subscriptions/s/resourceGroups/rg-new/providers/Microsoft.Compute/virtualMachines/batch"


def test_a_deleted_vms_rule_on_a_vm_glorfindel_isolates_waits_for_its_release(monkeypatch):
    """A3, first review: the VM given web's address is isolated in its turn. web's rule
    cuts a VM Glorfindel holds: kept, not swept from under the isolation. Once that VM
    is released, the rule is an orphan cutting it off — the next pass takes it off, and
    teardown finds every live VM back to its design."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        m.address_reused(Script(WEB1, WEB1, None, True, True, "rg-new", "batch", None, "Linux", False))
        cutting = m._cutting_orphans()
        m.isolate(Script(BATCH, BATCH, None))
        m.orphan_sweep(Script(None, "non_disruptive"))
        assert m._cutting_orphans() == cutting, "a rule cutting a VM Glorfindel isolates was swept"
        m.release(Script(BATCH, BATCH, None))
        m.orphan_sweep(Script(None, "non_disruptive"))
        assert not m._cutting_orphans()
    finally:
        m.teardown()


def test_a_block_that_could_not_be_put_back_is_said_even_after_a_crash(monkeypatch):
    """Blocked on the subnet's NSG, the role removed, then a `terraform apply` deletes the
    block's rule. The reassertion tries to put it back (refused, 403) and dies right after
    writing "already alerted" — before the card. Every later pass returned on that marker:
    the attacker back in, and nothing said (L1F, seed of I8F)."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block", WEB1, WEB1, None, 22),
         ("access_changes", True),
         ("terraform_apply", _NSG.format(rg="rg-net", name="nsg-subnet")),
         ("reassert", "non_disruptive", (1, "after-crash")),
         ("reassert", "human_only", None))


# I1F (#226): web's own NSG denies the VNet in (deny-lateral-in) — the quarantine NSG that
# replaces it must too. Its deny turned to Udp, TCP from the VNet falls to Azure's default
# AllowVnetInBound: 10.9.9.9 reaches :22.
_SEC_Q = _NSG.format(rg="rg-sec", name="nsg-glorfindel-quarantine-westeurope")
_LATERAL_RULES = [
    _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                         destination_address_prefix="VirtualNetwork", destination_port_range="*")),
    _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                       destination_address_prefix="*", destination_port_range="*")),
]
_TURNED_TO_UDP = ("tamper_with_our_rule", "protocol", (_SEC_Q, "glorfindel-quarantine-deny-in"))


def test_a_quarantine_deny_turned_to_udp_is_someone_elses_opening(monkeypatch):
    """The sequence of the deep run (27/10, 10 000 sequences), as it shrank: isolated by a
    quarantine whose state and tags are lost (twice), the customer narrows a rule, then
    someone turns our quarantine deny to Udp. I1 fell at that very step — before
    Glorfindel could do anything: the test read a deny of one protocol as a deny-all
    (`_quarantine_intact`), so the opening was not taken for that someone's (I1F)."""
    edit = ("customer_edits_rule", _NSG.format(rg="rg-app1", name="nsg-web-nic"), "allow-lateral-out",
            ("source_address_prefix", "10.9.0.0/16"))
    _run(monkeypatch, _net(quarantine=True, quarantine_rg="rg-sec", legacy=("web-nic", False),
                           web_nic={"own": "dedicated", "rules": _LATERAL_RULES}),
         ("lose_everything", WEB1, WEB1, ("nic.get", "always-429"), WEB1, _SEC_Q, "stop"),
         ("lose_everything", WEB1, WEB1, (1, "before-429"), WEB1, _SEC_Q, "stop"),
         edit, edit, edit, edit, edit,
         _TURNED_TO_UDP)


def test_an_altered_quarantine_whose_state_is_lost_is_said(monkeypatch):
    """The same opening, then a reassertion: the isolation's state and our NSG's tags lost,
    nothing read that NSG again — web reachable from the VNet on TCP, and nothing said
    (I1F, L2). The reassertion now lists our quarantine NSGs and says the altered one."""
    _run(monkeypatch, _net(quarantine=True, quarantine_rg="rg-sec", web_nic={"own": "dedicated",
                                                                         "rules": _LATERAL_RULES}),
         ("lose_everything", WEB1, WEB1, None, WEB1, _SEC_Q, "stop"),
         _TURNED_TO_UDP,
         ("reassert", "human_only", None),
         ("reassert", "non_disruptive", None))


def test_an_altered_quarantine_card_closes_once_it_is_whole(monkeypatch):
    """L2's card is one per change, and closes itself: said once over two passes, then
    gone when an isolation in the region put the NSG's rules back (I1F)."""
    from glorfindel import escalations
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, quarantine_rg="rg-sec", web_nic={"own": "dedicated",
                                                                    "rules": _LATERAL_RULES}))
        m.lose_everything(Script(WEB1, WEB1, None, WEB1, _SEC_Q, "stop"))
        m.tamper_with_our_rule(Script(*_TURNED_TO_UDP[1:]))
        for _ in range(2):
            m.reassert(Script("human_only", None))
        cards = [e for e in escalations.all_escalations() if e["escalation_type"] == "quarantine_altered"]
        assert len(cards) == 1 and cards[0]["status"] == "pending", cards
        assert key(cards[0]["resource_id"]) == key(_SEC_Q) and "nsg-glorfindel-quarantine-westeurope" in \
            cards[0]["reason"] and "web-nic" in cards[0]["reason"], cards
        m.isolate(Script(DB, DB, None))             # same region: the NSG's rules put back
        m.reassert(Script("human_only", None))
        assert not [e for e in escalations.pending() if e["escalation_type"] == "quarantine_altered"]
    finally:
        m.teardown()


@pytest.mark.parametrize("how", ["role removed", "untagged", "both"])
def test_a_said_quarantine_out_of_the_listing_stays_said(monkeypatch, how):
    """L2's card, then the NSG out of the listing — the role removed on its group (a
    listing that leaves it out without an error: our hypothesis), our tag taken off with
    our rules, or both: its card closed on the mere absence, silence until the role came
    back (I1S, #231; third and fourth reviews of I1F). Two passes, the second autonomous."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, quarantine_rg="rg-sec", web_nic={"own": "dedicated",
                                                                    "rules": _LATERAL_RULES}))
        m.lose_everything(Script(WEB1, WEB1, None, WEB1, _SEC_Q, "stop"))
        m.tamper_with_our_rule(Script(*_TURNED_TO_UDP[1:]))
        m.reassert(Script("human_only", None))
        assert m.l2_held_on == {key(_SEC_Q)}
        m._out_of_sight(Script(how, key(_SEC_Q), 2, "human_only", "non_disruptive"))
        assert not m.fake.unreadable and m.fake.nsgs[key(_SEC_Q)]["tags"]["managed-by"] == "glorfindel"
    finally:
        m.teardown()


@pytest.mark.parametrize("alteration", [
    ("strip_quarantine_nsg", _Q1),
    ("tamper_with_our_rule", "protocol", (_Q1, "glorfindel-quarantine-deny-in")),
])
def test_a_quarantine_made_before_the_group_was_set_is_still_read(monkeypatch, alteration):
    """Isolated while `quarantine_rg` was empty (our NSG in the VM's group), the state
    lost, the setting then naming another group, our NSG altered: listed in that group
    only, it was never read — the hole of I1F open again (second review of I1F, seen
    once in 11 runs at 500 sequences). The whole subscription is listed."""
    _run(monkeypatch, _net(quarantine=True),
         ("isolate", WEB1, WEB1, None),
         ("lose_state", WEB1),
         ("config_changes", {"quarantine": True, "rg": "rg-sec", "forensic": [], "readable": True}, True),
         alteration,
         ("reassert", "human_only", None))


def test_a_bare_nic_whose_original_is_unknown_stays_unknown(monkeypatch):
    """An older version's isolation of `web` on its own NSG; a quarantine whose state and
    tags are lost, re-isolated (its original unknown); our NSG taken off the NIC by
    someone, then isolated again: that isolation recorded "none" over the unknown — the
    release put no NSG back, said `released` and cleared the state, the old isolation
    still on the NIC's own NSG with nothing recording it (I8). Reduced from 186 steps of
    A3's run (27/10, I8F, #227): its faults (429 on the NIC and the NSGs) were leftovers."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("lose_everything", WEB1, WEB1, None, WEB1, _Q1, "reisolate"),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("isolate", WEB1, WEB1, None),
         ("release", WEB1, WEB1, None))


def test_a_bare_nic_isolated_again_under_a_429_keeps_its_original_unknown(monkeypatch):
    """The same, a single 429 on the second isolation, as it reads our tag: the error read
    as "none", and "none" was written — released bare, the old isolation left without
    state (I8F, relecture)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("lose_everything", WEB1, WEB1, None, WEB1, _Q1, "reisolate"),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("isolate", WEB1, WEB1, (5, "before-429")),
         ("release", WEB1, WEB1, None))


def test_a_failed_release_keeps_the_placement_it_couldnt_undo(monkeypatch):
    """Original unknown, the NIC left bare: the first release can't put an NSG back and
    keeps the placement. A release that dropped it (M862) wrote a state without the NIC —
    the second said `released`, the old isolation left without state. The oracle's
    exemption for a bare NIC must not reward that: it is the test's journal that says
    the state was lost, not the state the code left (A0, I8F relecture)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("lose_everything", WEB1, WEB1, None, WEB1, _Q1, "reisolate"),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("release", WEB1, WEB1, None),
         ("release", WEB1, WEB1, None))


def test_a_bare_nic_isolated_after_its_state_is_lost_doesnt_carry_its_rules(monkeypatch):
    """The other side of the test above (2 000 sequences, seed 302): the NIC left bare,
    both releases kept it — then the test loses the state. Isolated again, bare, nothing
    says it was ever ours: "none" is all Glorfindel can know, and its release can't reach
    the old isolation on the NIC's own NSG. A state held the NIC after the loss, but
    never while it was bare: the exemption holds (I8F, relecture)."""
    q = _NSG.format(rg="rg-edge", name="nsg-glorfindel-quarantine-northeurope")
    _run(monkeypatch, _net(quarantine=True, legacy=("api-nic", False), api_nic={"own": "dedicated"}),
         ("lose_everything", API, API, None, API, q, "reisolate"),
         ("someone_detaches_the_quarantine", _nic("rg-edge", "api-nic")),
         ("release", API, API, None),
         ("release", API, API, None),
         ("lose_state", API),
         ("isolate", API, API, None),
         ("release", API, API, None))


def test_our_rules_on_an_nsg_nothing_ties_to_a_bare_nic_any_more(monkeypatch):
    """I3 had the same defect as I8 (500 sequences, seed 34): db-nic-1, isolated by rules on
    the tier NSG then by quarantine, left bare, its state lost by the test after a state
    saw it bare — Glorfindel's own rules named for it stay on the tier NSG, off the NIC,
    and nothing says where to look. The release said `released`; I3 counted them. The
    same journal exemption (_untied); the operator puts the NSG back, the release then
    sweeps them (I7)."""
    ssh = _rule("allow-ssh", 100, dict(access="Allow", direction="Inbound", source_address_prefix="*",
                                       destination_address_prefix="*", destination_port_range="22"))
    out = _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                               destination_address_prefix="VirtualNetwork", destination_port_range="*"))
    deny = _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                              destination_address_prefix="*", destination_port_range="*"))
    https = _rule("allow-https", 110, dict(access="Allow", direction="Inbound", source_address_prefix="Internet",
                                           destination_address_prefix="*", destination_port_range="443"))
    # db-nic-0 can't take the quarantine (a policy): isolated by rules on the subnet's NSG.
    _run(monkeypatch, _net(subnet_nsg=[ssh, out, deny], tier_rules=[ssh, https],
                           web_nic={"own": "dedicated", "rules": [out, deny], "policy": True},
                           db_nic_0={"rules": [out], "policy": True}, db_nic_1={"own": "tier"},
                           api_nic={"policy": True}),
         ("another_host_writes", DB, DB, None, "after-foreign", False),
         ("bare_with_an_unknown_original", DB, DB, None, _nic("rg-app1", "db-nic-1"), "reset"),
         ("access_changes", True),
         ("bare_with_an_unknown_original", DB, DB, None, _Q1, "release twice"))


def test_a_state_is_azures_without_an_nsg_nothing_ties_to_a_bare_nic(monkeypatch):
    """The third place of the same defect (2 000 sequences, seed 303): web left bare in our
    quarantine's state, then the test loses that state (lose_state, drawn for web while
    another VM is isolated). _consistent (I8 of the reset, I11) counted the old isolation
    on the NSG the NIC lost, against a state the code can't have. Same exemption (_untied)."""
    _run(monkeypatch, _net(web_nic={"own": "dedicated"}),
         ("bare_with_an_unknown_original", WEB1, WEB1, None, _nic("rg-app1", "web-nic"), "isolate+release",
          (1, "before-429")),
         ("lose_everything", WEB2, WEB2, None, WEB1, _Q1, "stop"),
         ("race", WEB1, ("release", "reassert"), 0))


def test_a_reset_doesnt_skip_a_bare_nic_whose_original_is_unknown(monkeypatch):
    """The same, a reset in place of the second isolation: the bare NIC, in quarantine for
    the state but its original unknown there and on no tag, was skipped — `swept`, the
    state cleared, the old isolation left on the NIC's own NSG (I8, I8F)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("lose_everything", WEB1, WEB1, None, WEB1, _Q1, "reisolate"),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("reset_from_azure", WEB1, WEB1, None))


def test_a_bare_nic_nothing_ties_to_its_nsg_doesnt_carry_its_rules(monkeypatch):
    """The other side of I8F, met by its composite rule: our NSG taken off the NIC by
    someone, then the state and the tags lost — nothing ties the NIC to its own NSG any
    more, and the release can't know it, nor the old isolation there. I8 counted it
    against the release; I3 and the blocks did not (_untraceable): the oracle's defect.
    It counts again as soon as a state held the NIC in quarantine (the two tests above)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("lose_state", WEB1),
         ("tags_lost", _Q1),
         ("release", WEB1, WEB1, None))


def test_a_429_on_our_tag_doesnt_overwrite_a_valid_original(monkeypatch):
    """The state lost but our tag intact, someone leaves the NIC bare, and a single 429 as
    the next isolation reads the tag: the error read as "none" — and, no state holding the
    NIC, "none" was written over the valid tag. The original was gone from Azure, the
    release said `released`, the NIC left without its NSG (I3; I8F, second relecture)."""
    _run(monkeypatch, _net(quarantine=True, web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         ("lose_state", WEB1),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("isolate", WEB1, WEB1, (5, "before-429")),
         ("release", WEB1, WEB1, None))


def _retagged(monkeypatch, lose_tags: bool):
    _run(monkeypatch, _net(quarantine=True, legacy=("web-nic", False), web_nic={"own": "dedicated"}),
         ("isolate", WEB1, WEB1, None),
         *([("tags_lost", _Q1)] if lose_tags else []),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("writes_only_its_own",),
         ("isolate", WEB1, WEB1, None),
         ("lose_state", WEB1),
         ("someone_detaches_the_quarantine", _nic("rg-app1", "web-nic")),
         ("release", WEB1, WEB1, None))


def test_a_tag_written_again_ties_the_nic_back(monkeypatch):
    """Our tags lost by the test, the NIC left bare, isolated again: the state knew the
    original, the isolation wrote the tag again (U2). Then the state lost, the NIC bare
    again: the tag says where its NSG is — a release that ignored it (M865) left the NIC
    bare and the old isolation there. The oracle took the NIC for untraceable: the test's
    journal now sees the tag written again (I8F, second relecture)."""
    _retagged(monkeypatch, lose_tags=True)


def test_a_tag_never_lost_ties_the_nic(monkeypatch):
    """The same without the tags lost: the tag was never gone (I8F, second relecture)."""
    _retagged(monkeypatch, lose_tags=False)

_BATCH = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/batch"


@pytest.mark.parametrize("then", [
    [("reset_from_azure", _BATCH, _BATCH, None)],
    # As the machine found it (I4F, #235: 2 000 sequences, seed 101), shrunk: a release
    # and a reset of the new VM at once.
    [("race", _BATCH, ("release", "reset"), 0)],
    # The NIC bare (our NSG taken off it): its original is read the same way.
    [("someone_detaches_the_quarantine", _nic("rg-app1", "batch-nic-4")), ("reset_from_azure", _BATCH, _BATCH, None)],
])
def test_a_reset_never_takes_an_old_isolation_on_an_nsg_shared_since(monkeypatch, then):
    """An older version's isolation of `api` (fixed names, any/any, state lost), then a new
    VM attached to the same NSG and isolated by quarantine: its NIC away, the NSG governed
    api's NIC alone — read as the new VM's own, the reset took the fixed names for its
    isolation and deleted api's (I4). A NIC away in quarantine still counts among the
    NSG's (I4F)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("api-nic", False), api_nic={"own": "dedicated"}),
         ("create_vm", "northeurope", "rg-app1", "batch", _NEW_VM_ON.format(rg="rg-edge", nic="api-nic"), "Linux"),
         ("isolate", _BATCH, _BATCH, None),
         *then)


_QUARANTINE_EDGE = _NSG.format(rg="rg-edge", name="nsg-glorfindel-quarantine-northeurope")


@pytest.mark.parametrize("then", [
    [("reset_from_azure", _BATCH, _BATCH, None)],
    # The release of the new VM sweeps the same names on the same NSG.
    [("release", _BATCH, _BATCH, None)],
    # api's NIC left bare (our NSG taken off it): our tag still ties it to its NSG.
    [("someone_detaches_the_quarantine", _nic("rg-edge", "api-nic")), ("reset_from_azure", _BATCH, _BATCH, None)],
    # The tags of the quarantine lost: api's state still says where its NIC belongs.
    [("tags_lost", _QUARANTINE_EDGE), ("reset_from_azure", _BATCH, _BATCH, None)],
    # api's state lost: our tag still says it.
    [("lose_state", API), ("reset_from_azure", _BATCH, _BATCH, None)],
    # api's NIC bare, the NICs can't be listed: unknown, not "no NIC away".
    [("someone_detaches_the_quarantine", _nic("rg-edge", "api-nic")),
     ("reset_from_azure", _BATCH, _BATCH, ("nic.list", "always-429"))],
])
def test_a_reset_never_takes_the_old_isolation_of_a_vm_in_quarantine(monkeypatch, then):
    """The symmetric case of I4F (#239): an older version's isolation of `api` (fixed names,
    any/any, state lost), `api` isolated by quarantine — its NIC away —, then a new VM
    attached to the same NSG, alone there now. Counted from what is attached, the NSG read
    as the new VM's, the fixed names as its own: its reset deleted api's older isolation.
    No flow opened (the quarantine holds api), but back on its NSG outside Glorfindel (an
    ARM redeploy), api's NIC would have found it gone. A NIC tied to the NSG by our tag
    (or by the state when the tag is lost) counts among its NICs (I4S)."""
    _run(monkeypatch, _net(quarantine=True, legacy=("api-nic", False), api_nic={"own": "dedicated"}),
         ("isolate", API, API, None),
         ("create_vm", "northeurope", "rg-app1", "batch", _NEW_VM_ON.format(rg="rg-edge", nic="api-nic"), "Linux"),
         *then)


_GONE_NIC = "/subscriptions/s/resourceGroups/rg-old/providers/Microsoft.Network/networkInterfaces/old-nic"
_API_NSG = _NEW_VM_ON.format(rg="rg-edge", nic="api-nic")


def _alone_with_a_stale_tag(m, fault=None):
    """api alone on its NSG with its older isolation; our quarantine NSG keeps the tag of
    a NIC gone since, naming that NSG (deleted in quarantine: nobody took the tag off).
    The reset of api, under `fault`."""
    m.fake.add_nsg("rg-edge", "nsg-glorfindel-quarantine-northeurope", location="northeurope",
                   tags={"managed-by": "glorfindel", m.connector._orig_tag(_GONE_NIC): _API_NSG})
    m.chaos.arm(fault)
    try:
        return m.connector.sweep_vm_rules(API)
    finally:
        m.chaos.arm(None)


def _old_names_on(m) -> set:
    return {n for n in m.fake.nsgs[key(_API_NSG)]["rules"] if n.startswith("glorfindel-isolation-deny-all")}


def test_a_vm_alone_on_its_nsg_still_takes_its_old_isolation(monkeypatch):
    """No eternal rule (I4S): the VM alone on its NSG, the reset still deletes its older
    isolation — a stale tag (its NIC gone) ties nothing."""
    def check(m):
        out = _alone_with_a_stale_tag(m)
        assert out["status"] == "swept", out
        assert not _old_names_on(m)
    _legacy_world(monkeypatch, ("api-nic", False), check=check)


def test_an_unreadable_quarantine_listing_leaves_the_old_isolation_and_says_it(monkeypatch):
    """Whose the fixed names are can't be read (the NSG listing throttled): unknown, not
    "nobody else" — left, and said (I4S)."""
    def check(m):
        out = _alone_with_a_stale_tag(m, ("nsg.list", "always-429"))
        assert out["status"] == "swept_partial", out
        assert _old_names_on(m) == {"glorfindel-isolation-deny-all", "glorfindel-isolation-deny-all-out"}
        assert any("partage illisible" in f and "ancienne version" in f for f in out["failed"]), out
    _legacy_world(monkeypatch, ("api-nic", False), check=check)


def _quarantine_world(monkeypatch, *steps, check):
    """api's older isolation (fixed names, state lost), the quarantine on, steps, then
    `check`."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, legacy=("api-nic", False), api_nic={"own": "dedicated"}))
        for rule, *draws in steps:
            getattr(m, rule)(Script(*draws))
        check(m)
    finally:
        m.teardown()


def test_a_vm_in_quarantine_alone_on_its_nsg_still_takes_its_old_isolation(monkeypatch):
    """The VM of the older isolation in quarantine itself, alone on its NSG: its own NIC,
    away and tied by our tag, is not another VM's — its reset deletes the fixed names
    (I4S: no eternal rule)."""
    def check(m):
        assert m._in_quarantine(API)
        out = m.connector.sweep_vm_rules(API)
        assert out["status"] == "swept", out
        assert not _old_names_on(m)
    _quarantine_world(monkeypatch, ("isolate", API, API, None), check=check)


def test_the_nic_away_of_the_reset_itself_needs_no_listing(monkeypatch):
    """I4F's case — the new VM's own NIC away from api's NSG —, the subscription's NSGs
    and NICs unreadable: the NIC of the reset, away, makes the NSG shared, known without
    reading anything else. The older isolation is left as another VM's, not as unknown."""
    def check(m):
        m.chaos.arm(("nsg.list", "always-429"))
        try:
            out = m.connector.sweep_vm_rules(_BATCH)
        finally:
            m.chaos.arm(None)
        assert _old_names_on(m) == {"glorfindel-isolation-deny-all", "glorfindel-isolation-deny-all-out"}
        assert any("NSG nsg-api-nic partagé :" in f for f in out["failed"]), out
    _quarantine_world(monkeypatch,
                      ("create_vm", "northeurope", "rg-app1", "batch", _API_NSG, "Linux"),
                      ("isolate", _BATCH, _BATCH, None), check=check)


_PLAIN = "glorfindel-block-" + ATTACKER.replace(".", "-")


def _plain_block_world(monkeypatch, *steps, check):
    """An older version's block of the attacker on api's own NSG, under the IP's name
    alone (no VM in it), its state lost — and no older isolation: the plain block name
    is the only fixed name on the NSG. The quarantine on, steps, then `check`."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, api_nic={"own": "dedicated"}))
        nsg = m.fake.nsgs[key(_API_NSG)]
        taken = {r["priority"] for r in nsg["rules"].values()}
        prio = next(p for p in range(200, 4096) if p not in taken)
        for name, direction, src, dst in ((_PLAIN, "Inbound", ATTACKER, "*"), (f"{_PLAIN}-out", "Outbound", "*", ATTACKER)):
            FakeAzure._put_rule(nsg, _rule_record(_rule(name, prio, dict(
                access="Deny", direction=direction, source_address_prefix=src,
                destination_address_prefix=dst, destination_port_range="*"))))
            m.fake.authored.add((key(_API_NSG), name.lower()))
        for rule, *draws in steps:
            getattr(m, rule)(Script(*draws))
        check(m)
    finally:
        m.teardown()


def _plain_on(m) -> set:
    return {n for n in m.fake.nsgs[key(_API_NSG)]["rules"] if n.startswith(_PLAIN)}


def test_an_unblock_never_takes_the_old_block_of_a_vm_in_quarantine(monkeypatch):
    """The issue's world with a block: api's older block under the IP's name alone, api
    isolated by quarantine, a new VM attached alone to api's NSG. Read as the new VM's
    alone, the NSG's plain block name was its own: its unblock deleted api's block. The
    plain block name is a fixed name too: the NIC away is looked for (I4S)."""
    def check(m):
        out = m.connector.unblock_ip(ATTACKER, _BATCH)
        assert out["status"] == "not_found", out
        assert _plain_on(m) == {_PLAIN, f"{_PLAIN}-out"}
    _plain_block_world(monkeypatch, ("isolate", API, API, None),
                       ("create_vm", "northeurope", "rg-app1", "batch", _API_NSG, "Linux"), check=check)


@pytest.mark.parametrize("fault", [("nsg.get", "always-429"), ("nsg.list", "always-429")])
def test_an_unblock_says_the_old_block_it_cant_attribute(monkeypatch, fault):
    """api alone on its NSG with its older plain-named block, whose sharing can't be read
    (the NSG, or the subscription's NSGs where a NIC away would show): unknown. The
    block is left — the IP stays blocked — and said: `not_found` was answered while the
    rules stayed (I4S, review). Readable again, the unblock takes it."""
    def check(m):
        m.chaos.arm(fault)
        try:
            out = m.connector.unblock_ip(ATTACKER, API)
        finally:
            m.chaos.arm(None)
        assert out["status"] == "unblock_partial", out
        assert any("partage illisible" in f and _PLAIN in f for f in out["failed"]), out
        assert _plain_on(m) == {_PLAIN, f"{_PLAIN}-out"}
        out = m.connector.unblock_ip(ATTACKER, API)
        assert out["status"] == "unblocked" and not _plain_on(m), out
    _plain_block_world(monkeypatch, check=check)


# I8S (#245): two Glorfindel hosts, each its own state directory — the machine has one.
# A case: how host 1 finds the NIC (re-isolated by host 1, bare, or still in host 2's
# quarantine), host 2's quarantine group (the same as host 1's, or another), the lift (release
# or reset), where the 429 falls (in the re-isolation or in the lift), its kind and position.
_LIFTS = ("release", "reset")
_TWO_HOSTS = (
    # The issue's sequence: a 429 at each call of host 1's re-isolation, then its release.
    [("reisolated", "same", "release", "isolate", "before-429", k) for k in range(1, 27)]
    + [("reisolated", "same", "release", "isolate", "after-429", k) for k in range(1, 9)]
    # The 429 in the lift itself (re-isolated cleanly), then the operator's retry; the reset.
    + [("reisolated", "same", "release", "lift", "before-429", k) for k in range(1, 16)]
    + [("reisolated", "same", "reset", where, "before-429", k)
       for where in ("isolate", "lift") for k in range(1, 16)]
    # No re-isolation: the NIC bare, or still in host 2's quarantine; host 1's state says
    # "none"; a 429 before or after each call of the lift.
    + [(nic, "same", lift, "lift", kind, k) for nic in ("bare", "in-quarantine") for lift in _LIFTS
       for kind in ("before-429", "after-429") for k in range(1, 16)]
    # Host 2's configuration names another quarantine group: its tag X is there, host 1's
    # "none" in the VM's group (I8S, review).
    + [(nic, "other", lift, "lift", "before-429", k) for nic in ("reisolated", "bare", "in-quarantine")
       for lift in _LIFTS for k in range(1, 11)])


@pytest.mark.parametrize("nic_is,group,lift_with,where,kind,k", _TWO_HOSTS)
def test_two_hosts_a_stale_none_never_leaves_the_nic_bare(monkeypatch, nic_is, group, lift_with, where, kind, k):
    """Two hosts with separate states. A bare NIC; host 1 isolates it (state and tag:
    "none"); someone takes our NSG off, then the customer gives the NIC an NSG X; host 2
    isolates it (tag: X); our NSG taken off again; host 1 isolates it again — a 429 at
    call k — then releases it. Its state's "none" was followed over the tag: 10 positions
    of 26 ended `released` with the NIC without any NSG (I8S, #245); the reset, and a
    lift with no re-isolation, the same. The tag that names X wins over the state's
    "none" — found in another quarantine group too; a 429 never writes "none" over it,
    nor puts the NIC back bare; a tag that can't be read fails the lift, never "none" on a
    guess; verify_release doesn't say released while X is off the NIC. After the
    operator's retry the NIC is on X, and verify_release agrees."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    host1 = actions._ISOLATION_STATE_DIR
    try:
        m.build(_net(quarantine=True))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        assert f.nics[nic]["nsg"] is None
        assert c.isolate_vm(WEB1)["status"] == "isolated"                  # host 1: "none"
        f.nics[nic]["nsg"] = None                                         # someone, by hand
        https = _rule("allow-https", 110, dict(access="Allow", direction="Inbound",
                                               source_address_prefix="Internet",
                                               destination_address_prefix="*", destination_port_range="443"))
        x = f.add_nsg("rg-app1", "nsg-web-x", [https])                     # the customer's new design
        f.nics[nic]["nsg"] = f.nics[nic]["design_nsg"] = x
        m.design = f.snapshot()                                           # the oracles judge by it
        m.design["nsgs"] = {k: g for k, g in m.design["nsgs"].items() if g["tags"].get("managed-by") != "glorfindel"}
        actions._ISOLATION_STATE_DIR = m.home / "host2" / "isolation"
        if group == "other":                                              # host 2's configuration
            m.config = {**m.config, "rg": "rg-sec"}
            m._write_config()
        assert c.isolate_vm(WEB1)["status"] == "isolated"                  # host 2: tag X
        if group == "other":
            m.config = {**m.config, "rg": ""}
            m._write_config()
        if nic_is != "in-quarantine":
            f.nics[nic]["nsg"] = None                                     # by hand, again
            m.detached.add(nic)
        actions._ISOLATION_STATE_DIR = host1
        lift = (lambda: c.sweep_vm_rules(WEB1)) if lift_with == "reset" else (lambda: c.release_isolation(WEB1))
        if nic_is == "reisolated":
            m._run((k, kind) if where == "isolate" else None, lambda: c.isolate_vm(WEB1))
        else:
            assert c.verify_release(WEB1)["verified"] is not True, "verify_release True, X off the NIC"
        out, _ = m._run((k, kind) if where == "lift" else None, lift)
        m.customer_configuration_untouched()
        m.never_more_open_than_designed()
        done = ("swept",) if lift_with == "reset" else ("released",)
        if (out or {}).get("status") in done:
            assert key(f.nics[nic]["nsg"] or "") == key(x), (
                f"{out['status']}, the NIC on {f.nics[nic]['nsg'] or 'no NSG'} — its NSG is X")
        else:
            # Not done: the NIC kept as it was (bare) or in quarantine, never put back bare
            # on a guess; the retry, the 429 gone, puts X back.
            now = f.nics[nic]["nsg"]
            assert (now is None and nic_is != "in-quarantine") or (now and actions._is_quarantine_nsg(now)) \
                or key(now or "") == key(x), f"{(out or {}).get('status')}: the NIC on {now or 'no NSG'}"
            if key(now or "") != key(x):
                assert c.verify_release(WEB1)["verified"] is not True, "verify_release True, X off the NIC"
            out = lift()
            assert out["status"] in done, out
        assert key(f.nics[nic]["nsg"] or "") == key(x), f"the NIC on {f.nics[nic]['nsg'] or 'no NSG'}, not X"
        assert c.verify_release(WEB1)["verified"] is True
        m.customer_configuration_untouched()
        m.never_more_open_than_designed()
    finally:
        actions._ISOLATION_STATE_DIR = host1
        shutil.rmtree(m.home, ignore_errors=True)


# ISU (#264): the small follow-ups of the reviews of I1S, I8S and I4S.

def _host_dirs():
    from glorfindel import actions
    return actions._ISOLATION_STATE_DIR, actions._BLOCK_STATE_DIR


def _set_host_dirs(dirs) -> None:
    from glorfindel import actions
    actions._ISOLATION_STATE_DIR, actions._BLOCK_STATE_DIR = dirs


@pytest.mark.parametrize("tag", ["readable", "unreadable"])
def test_two_hosts_an_unblock_behind_the_quarantine_finds_the_block_on_x(monkeypatch, tag):
    """Host 1 isolates a bare NIC (state and tag: "none"); our NSG is taken off by hand and
    the customer gives the NIC an NSG X; host 2 blocks the attacker (on X), then isolates
    the NIC (tag: X). Host 1 unblocks: its state's "none" hid X, `not_found` was answered
    while the IP stayed blocked on X, put back with X at the release (ISU, #264; I8S). The
    tag that names X wins, as at the release; a tag that can't be read is
    `unblock_partial`, never "none" on a guess — and the retry unblocks."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    host1 = _host_dirs()
    try:
        m.build(_net(quarantine=True))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        assert f.nics[nic]["nsg"] is None
        assert c.isolate_vm(WEB1)["status"] == "isolated"                  # host 1: "none"
        f.nics[nic]["nsg"] = None                                         # someone, by hand
        x = f.add_nsg("rg-app1", "nsg-web-x")
        f.nics[nic]["nsg"] = f.nics[nic]["design_nsg"] = x
        _set_host_dirs((m.home / "host2" / "isolation", m.home / "host2" / "blocks"))
        assert c.block_suspicious_ip(ATTACKER, WEB1)["status"] == "blocked"   # on X
        assert c.isolate_vm(WEB1)["status"] == "isolated"                  # host 2: tag X
        _set_host_dirs(host1)

        def on_x():
            return {n for n in f.nsgs[key(x)]["rules"] if n.startswith("glorfindel-block-")}
        assert on_x()
        if tag == "unreadable":
            m.chaos.arm(("nsg.get", "always-429"))
            try:
                out = m.connector.unblock_ip(ATTACKER, WEB1)
            finally:
                m.chaos.arm(None)
            assert out["status"] == "unblock_partial" and on_x(), out
            assert any("NSG d'origine" in e for e in out["failed"]), out
        out = c.unblock_ip(ATTACKER, WEB1)
        assert out["status"] == "unblocked" and not on_x(), out
    finally:
        _set_host_dirs(host1)
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("bare", [False, True])
@pytest.mark.parametrize("lift_with", ["release", "reset"])
@pytest.mark.parametrize("known_by", ["state", "tag"])
def test_an_original_gone_says_how_to_get_out(monkeypatch, known_by, lift_with, bare):
    """The NIC's own NSG deleted while it is in quarantine (or left bare by hand): the lift
    fails and keeps the NIC as it is — wanted — but said only that the NSG wasn't found
    (ISU, #264; I8S). It says how to get out: recreate it, put by hand on the NIC the NSG
    it must carry — or, when only our tag names it, set the tag to "none" (the state's
    original wins over the tag: never offered then). Each way out taken, the retry lifts."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, web_nic={"own": "dedicated"}))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        x = f.nics[nic]["nsg"]
        assert c.isolate_vm(WEB1)["status"] == "isolated"
        q = f.nics[nic]["nsg"]
        assert actions._is_quarantine_nsg(q)
        if known_by == "tag":
            for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
                p.unlink()                                                # the state lost
        if bare:
            f.nics[nic]["nsg"] = None                                     # ours taken off by hand
        assert f.delete_nsg(x)                                           # the customer's NSG gone
        lift = (lambda: c.sweep_vm_rules(WEB1)) if lift_with == "reset" else (lambda: c.release_isolation(WEB1))
        done = "swept" if lift_with == "reset" else "released"
        out = lift()
        assert out["status"] == ("swept_partial" if lift_with == "reset" else "release_partial"), out
        said = [e for e in out["failed"] if "n'existe plus" in e]
        assert said and "rg-app1/nsg-web-nic" in said[0], out
        assert "recréer" in said[0] and "poser à la main" in said[0], said
        tag = actions.AzureConnector._orig_tag(f.nics[nic]["id"])
        assert (f"{tag}=none" in said[0]) == (known_by == "tag"), said
        assert f.nics[nic]["nsg"] == (None if bare else q)                # kept as it was
        assert lift()["status"] == out["status"]                          # nothing changed: again
        if known_by == "tag":
            f.nsgs[key(q)]["tags"][tag] = "none"                            # the tag set to none
            assert lift()["status"] == done
            assert f.nics[nic]["nsg"] is None
        elif bare:
            f.add_nsg("rg-app1", "nsg-web-nic")                              # recreated
            assert lift()["status"] == done
            assert key(f.nics[nic]["nsg"] or "") == key(x)
        else:
            y = f.add_nsg("rg-app1", "nsg-web-y")                            # another, by hand
            f.nics[nic]["nsg"] = y
            assert lift()["status"] == done
            assert key(f.nics[nic]["nsg"] or "") == key(y)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_an_original_that_cant_be_read_is_not_called_gone(monkeypatch):
    """The original refused (403), not deleted: the lift fails as it did, and never says
    it no longer exists — only a 404 on its id does (ISU, #264). Readable again, lifted."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, web_nic={"own": "dedicated"}))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        x = f.nics[nic]["nsg"]
        assert c.isolate_vm(WEB1)["status"] == "isolated"
        f.unreadable.add(key(x))
        out = c.release_isolation(WEB1)
        assert out["status"] == "release_partial", out
        assert out["failed"] and not any("n'existe plus" in e for e in out["failed"]), out
        f.unreadable.discard(key(x))
        assert c.release_isolation(WEB1)["status"] == "released"
        assert key(f.nics[nic]["nsg"] or "") == key(x)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("subnet_too", [False, True])
def test_an_unblock_says_a_plain_block_may_be_a_perimeter_one(monkeypatch, subnet_too):
    """api's older plain-named block on its own NSG, whose sharing can't be read. When that
    NSG is its subnet's too, the plain name is also a perimeter block's: the unblock says
    "d'une ancienne version ou de périmètre", not only "d'une ancienne version" (ISU,
    #264; I4S)."""
    def check(m):
        if subnet_too:
            m.fake.subnets[key(m.fake.nics[_nic("rg-edge", "api-nic")]["subnet"])]["nsg"] = _API_NSG
        m.chaos.arm(("nsg.get", "always-429"))
        try:
            out = m.connector.unblock_ip(ATTACKER, API)
        finally:
            m.chaos.arm(None)
        said = [f for f in out["failed"] if _PLAIN in f]
        assert len(said) == 2, out                                        # in and out
        for s in said:
            assert "partage illisible" in s and "blocage d'une ancienne version" in s, out
            assert ("ou de périmètre" in s) == subnet_too, s
        assert _plain_on(m) == {_PLAIN, f"{_PLAIN}-out"}
    _plain_block_world(monkeypatch, check=check)


_API_OWN = _NSG.format(rg="rg-edge", name="nsg-api-nic")
_API_LOW = key(API)
_NEW_API = "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.compute/virtualmachines/api"


def test_a_bare_nic_held_in_quarantine_with_an_unknown_original_is_not_released(monkeypatch):
    """SEC3's harness, frozen (I3F, #287): an older version's isolation on api's own NSG;
    api isolated by quarantine, the tags lost, left bare; a new VM on that NSG reset.
    The quarantine group then turns into the VM's own: api, re-isolated into a second
    quarantine NSG (its original read from the state), loses its state and that NSG's
    tags, is isolated again — its original unknown now (Q7) — and is left bare. Until
    then verify_release said "api-nic : sans NSG, nsg-api-nic non remis"; from there it
    said verified, the NIC without its NSG and the old isolation still on it."""
    _run(monkeypatch, _net(quarantine=True, quarantine_rg="rg-sec", legacy=("api-nic", True),
                           api_nic={"own": "dedicated"}),
         ("an_old_isolations_vm_goes_away", (_API_OWN, API), True, True, "rg-app1", "api", "Linux", True,
          _NEW_API),
         ("config_changes", {"quarantine": True, "rg": "", "readable": True, "forensic": []}, True),
         ("bare_with_an_unknown_original", API, _API_LOW, None, _nic("rg-edge", "api-nic"), "isolate+release",
          (4, "before-429")))


@pytest.mark.parametrize("way_out", ["nsg", "tag"])
def test_a_bare_nic_whose_original_is_unknown_is_said_bare(monkeypatch, way_out):
    """The same, said (I3F, #287): web isolated by quarantine, its state and our tag lost,
    isolated again — its original unknown (Q7) — then left bare by hand. verify_release
    says the original is unknown, never released; the release keeps the placement and
    says the NIC carries no NSG — it said "La carte reste en quarantaine" and "NSG de
    quarantaine non détaché", of a NIC with no NSG at all. Each way out it names (the
    NSG put back on the NIC, or our tag) lets the retry finish."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, web_nic={"own": "dedicated"}))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        own = f.nics[nic]["nsg"]
        assert c.isolate_vm(WEB1)["status"] == "isolated"
        q = f.nics[nic]["nsg"]
        for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
            p.unlink()                                                    # the state lost
        tag = actions.AzureConnector._orig_tag(f.nics[nic]["id"])
        f.nsgs[key(q)]["tags"].pop(tag)                                   # and our tag
        assert c.isolate_vm(WEB1)["status"] == "isolated"                 # original unknown now
        f.nics[nic]["nsg"] = None                                         # ours taken off by hand
        check = c.verify_release(WEB1)
        assert check["verified"] is False, check
        assert any("web-nic" in u and "inconnu" in u for u in check["original_unknown"]), check
        out = c.release_isolation(WEB1)
        assert out["status"] == "release_partial", out
        said = [e for e in out["failed"] if e.startswith("web-nic")]
        assert said and "carte sans NSG" in said[0] and "inconnu" in said[0], out
        assert "reste en quarantaine" not in said[0] and "non détaché" not in said[0], said
        assert tag in said[0] and "poser sur la carte" in said[0].lower(), said
        assert f.nics[nic]["nsg"] is None and actions._load_isolation_state(WEB1), out   # kept as it was
        if way_out == "tag":
            f.nsgs[key(q)]["tags"][tag] = own                              # the tag, by hand
        else:
            f.nics[nic]["nsg"] = own                                       # the NSG, by hand
        assert c.release_isolation(WEB1)["status"] == "released"
        assert key(f.nics[nic]["nsg"] or "") == key(own)
        assert c.verify_release(WEB1)["verified"] is True
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_race_whose_two_operations_rewrite_the_escalations_store(monkeypatch):
    """Two operations of a race that each rewrite the escalations store (two reassertions
    whose sweeps both leave a card). The store's lock (SEC3) was not the scheduler's: one
    operation stopped at its write, inside that lock, left the other blocked in it out of
    the scheduler's sight — I11 « op-2 never came back » ({'op-1': 'wait', 'op-2': 'run'},
    #292), then the teardown's sweep waiting behind it forever (the macOS job of I3F, 29/10).
    Each lock the code takes in a race is the scheduler's (_scheduled)."""
    import json
    from glorfindel import escalations
    from .test_invariants import _CURRENT, _Chaos, _Scheduler
    invariant_env(monkeypatch)
    monkeypatch.setattr(_CURRENT, "chaos", _Chaos())

    @escalations._locked
    def rewrite(n):
        escalations._write_lines([json.dumps({"n": n})])

    try:
        for seed in range(8):           # each order of the two: one stopped inside, then the other
            _CURRENT.scheduler = _Scheduler(seed)
            out = _CURRENT.scheduler.run([("op-1", lambda: rewrite(1)), ("op-2", lambda: rewrite(2))])
            assert all(exc is None for _, exc in out.values()), out
    finally:
        _CURRENT.scheduler = None


@pytest.mark.parametrize("k", [7, 8])
def test_an_unblock_looks_behind_a_quarantine_taken_off(monkeypatch, k):
    """Seed 210 at 500 sequences, shrunk by hand (U3F, #293): api blocked, the block cut
    off before its state (after its inbound rule, or after both), then isolated by
    quarantine, and someone takes our NSG off the NIC, left bare. The block lies on the
    NIC's own NSG, away from it; the unblock looked behind a quarantine only — `not_found`
    while the rules stayed, and the release then put the NSG back with the IP blocked."""
    _run(monkeypatch, _net(quarantine=True, api_nic={"own": "dedicated"}),
         ("block", API, API, (k, "before-crash"), 22),
         ("isolate", API, API, None),
         ("someone_detaches_the_quarantine", _nic("rg-edge", "api-nic")),
         ("unblock", API, API, None),
         ("release", API, API, None))


@pytest.mark.parametrize("known_by", ["state", "tag", "nothing"])
def test_an_unblock_of_a_bare_nic_takes_the_block_or_says_it(monkeypatch, known_by):
    """The same, said (U3F): the NIC's own NSG known by the state, or by our tag (the
    state lost), the block on it goes — `unblocked`. Known by nothing (state and tags
    lost before a re-isolation, Q7), the NSG the block may lie on can't be named: never
    `not_found` — `unblock_partial`, the NIC named, the rules as they were."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, api_nic={"own": "dedicated"}))
        f, c, nic = m.fake, m.connector, _nic("rg-edge", "api-nic")
        own = key(f.nics[nic]["nsg"])
        assert c.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)["status"] == "blocked"
        for p in actions._BLOCK_STATE_DIR.glob("*.json"):
            p.unlink()                                            # the block's state never written
        ours = {n for n in f.nsgs[own]["rules"] if n.startswith("glorfindel-block-")}
        assert len(ours) == 2, ours
        assert c.isolate_vm(API)["status"] == "isolated"
        q = key(f.nics[nic]["nsg"])
        if known_by != "state":
            for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
                p.unlink()
        if known_by == "nothing":
            f.nsgs[q]["tags"].pop(actions.AzureConnector._orig_tag(f.nics[nic]["id"]))
            assert c.isolate_vm(API)["status"] == "isolated"       # its original unknown now
        f.nics[nic]["nsg"] = None                                  # ours taken off by hand
        out = c.unblock_ip(ATTACKER, API)
        left = {n for n in f.nsgs[own]["rules"] if n.startswith("glorfindel-block-")}
        if known_by == "nothing":
            assert out["status"] == "unblock_partial", out
            assert any(e.startswith("api-nic") and "inconnu" in e for e in out["failed"]), out
            assert left == ours
        else:
            assert out["status"] == "unblocked" and {r.lower() for r in out["deleted_rules"]} == ours, out
            assert not left
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_stuck_race_fails_and_lets_the_teardown_through(monkeypatch):
    """A race that blocks on purpose: op-1 holds the VM's lock and waits for its turn;
    op-2 waits, out of the scheduler's sight, for op-1 to be gone — and never comes back.
    I11 failed, but op-1 stayed in its wait, the lock held, and the teardown that takes
    it next waited forever: the job hung instead of failing (I3F's review). Now the
    waiting thread unwinds, its lock goes with it, and the failure is what is seen."""
    import threading
    from glorfindel import actions
    from .test_invariants import _CURRENT, _Abandoned, _Chaos, _Scheduler
    invariant_env(monkeypatch)
    monkeypatch.setattr(_CURRENT, "chaos", _Chaos())
    gone = threading.Event()

    def holder():
        ev = gone
        try:
            with actions._vm_lock("u3f-vm"):              # the scheduler's: turns inside
                for _ in range(4):
                    _CURRENT.scheduler.point()
        finally:
            ev.set()

    def outside():
        ev = gone
        _CURRENT.scheduler.point()
        ev.wait(30)                                       # out of the scheduler's sight

    stuck = 0
    try:
        for seed in range(8):
            gone = threading.Event()
            _CURRENT.scheduler = sched = _Scheduler(seed, timeout=0.3)
            try:
                out = sched.run([("op-1", holder), ("op-2", outside)])
            except AssertionError as exc:
                assert "I11" in str(exc), exc
                stuck += 1
            else:
                assert all(exc is None for _, exc in out.values()), out
            _CURRENT.scheduler = None
            with actions._vm_lock("u3f-vm", timeout=3):   # the teardown's turn
                pass
            gone.set()                                    # a thread still out of sight goes
    finally:
        _CURRENT.scheduler = None
    assert stuck, "no seed made the race stick: the test proves nothing"
    assert issubclass(_Abandoned, BaseException) and not issubclass(_Abandoned, Exception)


def test_two_driven_locks_taken_in_reverse_order_fail_fast(monkeypatch):
    """A deadlock between two driven locks: op-1 holds A and wants B, op-2 holds B and
    wants A. Each gives its turn away at every try, so every turn comes back in time and
    I11 never fell — the race ran forever (U3F review). Turns that only find taken locks
    are counted: past the limit, the race fails as a livelock, its threads unwound, and
    the locks are free for whoever comes next."""
    import threading
    import time
    from glorfindel import actions
    from .test_invariants import _CURRENT, _Chaos, _Scheduler
    invariant_env(monkeypatch)
    monkeypatch.setattr(_CURRENT, "chaos", _Chaos())

    def one_then_other(first, second):
        def op():
            with actions._vm_lock(first):
                with actions._vm_lock(second):
                    pass
        return op

    locked = 0
    try:
        for seed in range(8):
            _CURRENT.scheduler = sched = _Scheduler(seed, timeout=5)
            t0, got = time.monotonic(), {}

            def race():
                try:
                    got["out"] = sched.run([("op-1", one_then_other("u3f-a", "u3f-b")),
                                            ("op-2", one_then_other("u3f-b", "u3f-a"))])
                except AssertionError as exc:
                    got["exc"] = exc
            th = threading.Thread(target=race, daemon=True)
            th.start()
            th.join(15)
            if th.is_alive():                              # the race never ends: free it, then fail
                with sched.cv:
                    sched.abandoned = True
                    sched.cv.notify_all()
                th.join(10)
                pytest.fail("two driven locks taken crosswise: the race never ended")
            if "exc" in got:
                assert "I11: livelock" in str(got["exc"]), got["exc"]
                assert time.monotonic() - t0 < 5, "a livelock must fail before a turn's timeout"
                assert not sched.hung, sched.hung
                locked += 1
            else:
                assert all(exc is None for _, exc in got["out"].values()), got
            _CURRENT.scheduler = None
            for name in ("u3f-a", "u3f-b"):
                with actions._vm_lock(name, timeout=3):    # the teardown's turn
                    pass
    finally:
        _CURRENT.scheduler = None
    assert locked, "no seed took the locks crosswise: the test proves nothing"


def test_a_thread_out_of_sight_holding_a_lock_does_not_hang_the_teardown(monkeypatch):
    """A race whose thread blocks out of the scheduler's sight while it holds a driven
    lock — web's: it never unwinds. I11 fails, and the teardown's recovery, which takes
    web's lock, used to wait behind it forever. The failure names the thread, and the
    teardown skips the recovery behind it (I11 has failed already). The next example —
    Hypothesis replays one while shrinking — then wrote on web behind the same lock, a
    process-wide object: it gets registries of its own now, and the thread's name is
    never one of a later race's."""
    import functools
    import threading
    from glorfindel import actions
    from . import test_invariants
    invariant_env(monkeypatch)
    monkeypatch.setattr(test_invariants, "_Scheduler", functools.partial(test_invariants._Scheduler, timeout=0.5))
    gone = threading.Event()

    def holder():
        with actions._vm_lock("web"):
            gone.wait(60)                                   # out of the scheduler's sight

    m = IsolationMachine()
    done = threading.Event()
    try:
        m.build(_net())
        with pytest.raises(AssertionError, match="never unwound"):
            m._race(Script(0), (WEB1, "hold", holder), (WEB1, "hold", lambda: None))
        assert m.hung == ["op-1"], m.hung
        th = threading.Thread(target=lambda: (m.teardown(), done.set()), daemon=True)
        th.start()
        th.join(10)
        assert done.is_set(), "the teardown waited behind the thread that never unwound"
        # The next example: a new machine, a write on web, one call after the other.
        m2, out = IsolationMachine(), {}
        m2.build(_net(quarantine=True))
        def write():
            try:
                out["isolate"] = m2.connector.isolate_vm(WEB1)
            except BaseException as exc:
                out["isolate"] = {"status": repr(exc)}
        th = threading.Thread(target=write, daemon=True)
        th.start()
        th.join(10)
        assert not th.is_alive(), "the next example's write on web waited behind the thread that never unwound"
        assert out["isolate"]["status"] == "isolated", out
        m2.teardown()
        sched = test_invariants._Scheduler(0, timeout=0.5)
        sched.run([("op-1", lambda: None)])
        assert set(sched.state) != {"op-1"} and set(sched._seen()) == {"op-1"}, sched.state
    finally:
        gone.set()
        if not done.is_set():
            done.wait(30)


def test_a_deleted_vm_leaves_no_isolation_on_a_shared_nsg(monkeypatch):
    """Seed 322 at 500, reduced (I7S, #303): web, on a tier NSG it shares, isolated by
    rules there (the quarantine off), then by quarantine — its state and tags lost, its
    NIC left bare, released twice (its original unknown). Isolated again while every
    NSG read is throttled: the bare NIC's isolation falls back on the subnet's NSG, and
    the state, written again, names only that one. web is then deleted. Its release
    found the VM gone, undid the subnet's rules and said `released`: the first
    isolation's rules stayed on the tier NSG, aimed at web's old address — the next VM
    given it behind that NSG is cut off."""
    _run(monkeypatch, _net(web_nic={"own": "tier"}, subnet_nsg=[]),
         ("block_then_isolate", WEB1, WEB1, None, 22, None, False, False),
         ("bare_with_an_unknown_original", WEB1, WEB1, None, _nic("rg-app1", "web-nic"), "release twice"),
         ("address_reused", WEB1, WEB1, ("nsg.get", "always-429"), True, False, "rg-app1", "web", False))


@pytest.mark.parametrize("known_by", ["state", "block"])
@pytest.mark.parametrize("listing", ["readable", "throttled"])
def test_a_deleted_vms_rules_go_with_its_release_or_are_said(monkeypatch, listing, known_by):
    """The same, said (I7S): web isolated by rules on the tier NSG, its state lost; then
    its NIC left bare and isolated again on the subnet's NSG (the state names the NIC),
    or only its block's state left (it names the NIC too). web is deleted; a new VM gets
    its address behind the tier NSG — cut off, and said (the orphan's card). The release
    of web looks for the rules named for its NIC on every NSG and takes them off; when
    the NSGs can't be listed, it says so and keeps a state — never `released` — and the
    retry finishes. The new VM is back to its design."""
    import copy
    import shutil

    from glorfindel import actions

    from .fake_azure import nic_id

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(web_nic={"own": "tier"}, subnet_nsg=[]))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        tier, ip, subnet = f.nics[nic]["nsg"], f.nics[nic]["ips"][0], f.nics[nic]["subnet"]
        if known_by == "block":
            assert c.block_suspicious_ip(ATTACKER, WEB1, scope="vm", threat_port=22)["status"] == "blocked"
        assert c.isolate_vm(WEB1)["status"] == "isolated"                 # by rules, on the tier NSG
        ours = sorted(n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-"))
        assert len(ours) == 2, ours
        for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
            p.unlink()                                                    # the state lost
        if known_by == "state":
            f.nics[nic]["nsg"] = None                                     # the NIC left bare
            out = c.isolate_vm(WEB1)
            assert out["status"] == "isolated" and "nsg-subnet" in out["nsg"], out
        m._delete_vm(WEB1)
        new = f.add_vm("rg-new", "web", [{"rg": "rg-new", "name": "web-nic-9", "ips": [ip], "subnet": subnet,
                                          "nsg": tier, "policy": False, "location": "westeurope"}])
        m.vms.append(new)
        m.design["vms"][key(new)] = copy.deepcopy(f.vms[key(new)])
        m.design["nics"][key(nic_id("rg-new", "web-nic-9"))] = copy.deepcopy(f.nics[key(nic_id("rg-new", "web-nic-9"))])
        assert not m._back_to_design(new)                                 # cut off by web's rules
        said = {o["rule"].lower() for o in c.find_orphan_rules()}
        assert set(ours) <= said, said                                    # never in silence
        if listing == "throttled":
            m.chaos.arm(("nsg.list", "always-429"))
            try:
                out = c.release_isolation(WEB1)
            finally:
                m.chaos.plan = None
            assert out["status"] == "release_partial", out
            assert any("supprimée" in e and "non vérifiée" in e for e in out["failed"]), out
            assert actions._load_isolation_state(WEB1), "the state of what is left was cleared"
            assert set(ours) <= set(f.nsgs[key(tier)]["rules"]), "rules gone though the listing failed"
        out = c.release_isolation(WEB1)
        assert out["status"] == "released", out
        assert not [n for n in f.nsgs[key(tier)]["rules"] if n in ours], f.nsgs[key(tier)]["rules"]
        assert m._back_to_design(new), "the VM given web's address is still cut off"
        assert actions._load_isolation_state(WEB1) is None
    finally:
        shutil.rmtree(m.home, ignore_errors=True)
