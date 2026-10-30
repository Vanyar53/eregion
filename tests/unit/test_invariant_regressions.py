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


def _net(quarantine=False, subnet_nsg=None, quarantine_rg="", tier_rules=(), legacy=None, data_subnet=None,
         **nics):
    plain = {"own": None, "rules": [], "policy": False}
    return {"subnet_nsg": subnet_nsg, "edge_nsg": None, "tier_rules": list(tier_rules),
            "nics": {n: {**plain, **nics.get(n.replace("-", "_"), {})}
                     for n in ("web-nic", "db-nic-0", "db-nic-1", "api-nic")},
            "windows": None,
            "config": {"quarantine": quarantine, "rg": quarantine_rg, "forensic": [], "readable": True},
            "legacy": legacy, "data_subnet": data_subnet}


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


@pytest.mark.parametrize("known_by", ["state", "block", "unreadable state", "unreadable block"])
@pytest.mark.parametrize("listing", ["readable", "throttled"])
def test_a_deleted_vms_rules_go_with_its_release_or_are_said(monkeypatch, listing, known_by):
    """The same, said (I7S): web isolated by rules on the tier NSG, its state lost; then
    its NIC left bare and isolated again on the subnet's NSG (the state names the NIC),
    or only its block's state left (it names the NIC too). web is deleted; a new VM gets
    its address behind the tier NSG — cut off, and said (the orphan's card). The release
    of web looks for the rules named for its NIC on every NSG and takes them off; when
    the NSGs can't be listed, it says so and keeps a state — never `released` — and the
    retry finishes. The new VM is back to its design.
    A state of web's that can't be read (its isolation's, or its block's, which named
    the NIC) may name NICs nothing else does: `released` used to clear that file, the
    rules left (review). Now `release_partial`, the file kept as it is; repaired, the
    release finishes."""
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
        if known_by in ("block", "unreadable block"):
            assert c.block_suspicious_ip(ATTACKER, WEB1, scope="vm", threat_port=22)["status"] == "blocked"
        assert c.isolate_vm(WEB1)["status"] == "isolated"                 # by rules, on the tier NSG
        ours = sorted(n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-"))
        assert len(ours) == 2, ours
        if known_by != "unreadable state":
            for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
                p.unlink()                                                # the state lost
        if known_by == "state":
            f.nics[nic]["nsg"] = None                                     # the NIC left bare
            out = c.isolate_vm(WEB1)
            assert out["status"] == "isolated" and "nsg-subnet" in out["nsg"], out
        where = {"unreadable state": actions._ISOLATION_STATE_DIR,
                 "unreadable block": actions._BLOCK_STATE_DIR}.get(known_by)
        kept = {p: p.read_text() for p in where.glob("*.json")} if where else {}
        assert kept or not where
        for p in kept:
            p.write_text("{not json")                                     # can't be read
        m._delete_vm(WEB1)
        new = f.add_vm("rg-new", "web", [{"rg": "rg-new", "name": "web-nic-9", "ips": [ip], "subnet": subnet,
                                          "nsg": tier, "policy": False, "location": "westeurope"}])
        m.vms.append(new)
        m.design["vms"][key(new)] = copy.deepcopy(f.vms[key(new)])
        m.design["nics"][key(nic_id("rg-new", "web-nic-9"))] = copy.deepcopy(f.nics[key(nic_id("rg-new", "web-nic-9"))])
        assert not m._back_to_design(new)                                 # cut off by web's rules
        said = {o["rule"].lower() for o in c.find_orphan_rules()}
        assert set(ours) <= said, said                                    # never in silence
        if kept:
            out = c.release_isolation(WEB1)
            assert out["status"] == "release_partial", out
            assert any("supprimée, état illisible" in e and "non vérifiée" in e for e in out["failed"]), out
            assert all(p.read_text() == "{not json" for p in kept), "the unreadable file was not kept as it was"
            assert set(ours) <= set(f.nsgs[key(tier)]["rules"]), "rules gone though the state was unknown"
            for p, text in kept.items():
                p.write_text(text)                                        # repaired
        if listing == "throttled":
            m.chaos.arm(("nsg.list", "always-429"))
            try:
                out = c.release_isolation(WEB1)
            finally:
                m.chaos.plan = None
            assert out["status"] == "release_partial", out
            assert any("supprimée" in e and "non vérifiée" in e for e in out["failed"]), out
            assert actions._load_isolation_state(WEB1), "the state of what is left was cleared"
            if known_by != "unreadable state":                            # there, undone by its placements
                assert set(ours) <= set(f.nsgs[key(tier)]["rules"]), "rules gone though the listing failed"
        out = c.release_isolation(WEB1)
        assert out["status"] == "released", out
        assert not [n for n in f.nsgs[key(tier)]["rules"] if n in ours], f.nsgs[key(tier)]["rules"]
        assert m._back_to_design(new), "the VM given web's address is still cut off"
        assert actions._load_isolation_state(WEB1) is None
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("nic_is", ["detached", "on another name", "on a namesake", "unreadable"])
def test_a_deleted_vms_nic_that_azure_kept_is_read_first(monkeypatch, nic_is):
    """The review's probe (I7S): `az vm delete` and Terraform keep a VM's NIC by default,
    detached. web, isolated by rules on the tier NSG, is deleted, its NIC kept; its state
    names only the NIC. Detached, or attached since to a VM of another name (our names
    carry `web`): its rules go. Attached to another `web` (another group) that Glorfindel
    isolates: that isolation has the same names — the release took them, the other web
    open again until the next pass. Now they stay and the release says so; the other
    web's own release takes them. A NIC that can't be read: never `released`."""
    import shutil

    from glorfindel import actions

    from .fake_azure import vm_id

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(web_nic={"own": "tier"}, subnet_nsg=[]))
        f, c, nic = m.fake, m.connector, _nic("rg-app1", "web-nic")
        tier = f.nics[nic]["nsg"]
        assert c.isolate_vm(WEB1)["status"] == "isolated"
        ours = sorted(n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-"))
        assert len(ours) == 2, ours
        for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
            p.unlink()
        actions._save_isolation_state(WEB1, {"resource_id": WEB1, "placements": [],
                                             "known_nics": [f.nics[nic]["id"]]})
        vm = f.vms.pop(key(WEB1))                                         # deleted, its NIC kept
        other = None
        if nic_is in ("on another name", "on a namesake"):
            other = vm_id("rg-other", "web") if nic_is == "on a namesake" else vm_id("rg-app1", "batch")
            f.vms[key(other)] = {**vm, "id": other}
        if nic_is == "on a namesake":
            assert c.isolate_vm(other)["status"] == "isolated"            # the same names
        if nic_is == "unreadable":
            m.chaos.arm(("nic.get", "always-429"))
        try:
            out = c.release_isolation(WEB1)
        finally:
            m.chaos.plan = None
        left = sorted(n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-"))
        if nic_is in ("detached", "on another name"):
            assert out["status"] == "released", out
            assert not left, left
            return
        assert out["status"] == "release_partial", out
        assert left == ours, left
        assert actions._load_isolation_state(WEB1), "the state that named the NIC was cleared"
        if nic_is == "unreadable":
            assert any("web-nic illisible" in e and "non vérifiée" in e for e in out["failed"]), out
            assert c.release_isolation(WEB1)["status"] == "released"       # readable again
            assert not [n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-")]
            return
        assert any("rg-other/web" in e and "laissés" in e for e in out["failed"]), out
        assert c.verify_isolation(other)["verified"] is True              # the other web still cut off
        assert c.release_isolation(other)["status"] == "released"         # its own release takes them
        assert not [n for n in f.nsgs[key(tier)]["rules"] if n.startswith("glorfindel-iso-")]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


_SUBNET = _NSG.format(rg="rg-net", name="nsg-subnet")
_WEB2_BLOCK = "glorfindel-block-192-31-196-7-web-web-nic-80ab3c"     # web2's NIC, in the IP's block


def test_a_perimeter_block_put_back_keeps_its_place(monkeypatch):
    """Found by the machine during I7S, shrunk to four steps (I5R, #311): web2 blocked on
    the perimeter (200), then for itself (210); someone turns the VM's rule into an allow;
    the reassertion puts the block back — the perimeter rule rewritten at the first number
    free, 220, under that allow: the attacker reached web2 on every port. A rewrite now
    keeps its place."""
    _run(monkeypatch, _net(quarantine=True, subnet_nsg=[]),
         ("block_perimeter", WEB2, WEB2, None, False),
         ("block", WEB2, WEB2, None, 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         ("reassert", "non_disruptive", None))


def test_the_sequence_the_machine_found_on_i5(monkeypatch):
    """The same, as the machine drew it (I7S's run, shrunk): a crash drawn in the
    perimeter block, a 429 under the VM's, the reassertion inside a quarantine altered
    on another VM."""
    _run(monkeypatch, _net(quarantine=True, quarantine_rg="rg-sec", subnet_nsg=[]),
         ("block_perimeter", WEB2, WEB2, (11, "before-crash"), False),
         ("block", WEB2, key(WEB2), (10, "before-429"), 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         ("quarantine_altered_then_reasserted", API, key(API), (8, "before-crash"), False, False,
          "protocol", (key(_NSG.format(rg="rg-sec", name="nsg-glorfindel-quarantine-northeurope")),
                       "glorfindel-quarantine-deny-in"), "non_disruptive", "no"))


def _allow_from_attacker(m, nsg: str, priority: int, direction: str = "Inbound"):
    FakeAzure._put_rule(m.fake.nsgs[key(nsg)], _rule_record(_rule(
        f"customer-allow-{priority}-{direction.lower()}", priority, dict(
            access="Allow", direction=direction,
            source_address_prefix=ATTACKER if direction == "Inbound" else "*",
            destination_address_prefix="*" if direction == "Inbound" else ATTACKER,
            destination_port_range="*"))))


def _reached_in(m, vm: str) -> set:
    return {f for f in m._open(vm, forensic=None) if f[3] == ATTACKER and f[2] == "in"}


@pytest.mark.parametrize("scope", ["vm", "subnet"])
@pytest.mark.parametrize("split", [False, True])
def test_a_block_written_again_never_moves_down(monkeypatch, scope, split):
    """A block written again — the reassertion, or the operator blocking twice — rewrites
    its rules under their names: each keeps the number it holds, or a smaller one. An
    allow put since, after the deny, stays after it. `split`: our outbound rule moved
    away by hand, and its number taken by another outbound rule — the inbound one keeps
    its own; the pair no longer shares a number."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        c, g = m.connector, m.fake.nsgs[key(_SUBNET)]
        assert c.block_suspicious_ip(ATTACKER, WEB2, scope=scope, threat_port=22)["status"] == "blocked"
        ours = {n: r["priority"] for n, r in g["rules"].items() if n.startswith("glorfindel-block-")}
        assert set(ours.values()) == {200}, ours
        if split:
            g["rules"][next(n for n in ours if n.endswith("-out"))]["priority"] = 4000
            _allow_from_attacker(m, _SUBNET, 200, "Outbound")
        _allow_from_attacker(m, _SUBNET, 205)
        assert not _reached_in(m, WEB2)
        c.block_suspicious_ip(ATTACKER, WEB2, scope=scope, threat_port=22)
        assert not _reached_in(m, WEB2), "the rewrite fell behind the allow at 205"
        now = {n: r["priority"] for n, r in g["rules"].items() if n.startswith("glorfindel-block-")}
        inbound = next(n for n in ours if not n.endswith("-out"))
        assert now[inbound] == 200, now
        if not split:
            assert all(now[n] <= ours[n] for n in ours), (ours, now)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)       # the allows aren't the machine's


def test_an_isolation_written_again_never_moves_down(monkeypatch):
    """The same for an isolation by rules (no quarantine): our outbound rule moved away by
    hand, its number taken by another outbound rule, an allow put after our inbound deny —
    isolated again, the inbound deny kept its number; moved to the first one free, it fell
    behind the allow."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        c, g = m.connector, m.fake.nsgs[key(_SUBNET)]
        assert c.isolate_vm(WEB2)["status"] == "isolated"
        ours = {n: r["priority"] for n, r in g["rules"].items() if n.startswith("glorfindel-iso")}
        p = c.ISOLATION_PRIORITY
        assert set(ours.values()) == {p}, ours
        g["rules"][next(n for n in ours if n.endswith("-out"))]["priority"] = 4000
        _allow_from_attacker(m, _SUBNET, p, "Outbound")
        _allow_from_attacker(m, _SUBNET, p + 1)
        assert not _reached_in(m, WEB2)
        c.isolate_vm(WEB2)
        assert not _reached_in(m, WEB2), "the rewrite fell behind the allow"
        now = {n: r["priority"] for n, r in g["rules"].items() if n.startswith("glorfindel-iso")}
        assert now[next(n for n in ours if not n.endswith("-out"))] == p, now
    finally:
        shutil.rmtree(m.home, ignore_errors=True)       # the allows aren't the machine's


def _gone_world(monkeypatch, *, isolated: bool, nic_to_web1: bool = False):
    """web2 (maybe isolated by rules, no quarantine) blocked, its block's entry lost — a
    crash before it was written, or written over —, then web2 deleted. `nic_to_web1`: its
    NIC kept and given to web1 (another VM named web), which blocks the attacker too —
    under the same names, the NIC's and the VM's name being the same."""
    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    m.build(_net(subnet_nsg=[]))
    c = m.connector
    if isolated:
        assert c.isolate_vm(WEB2)["status"] == "isolated"
    assert c.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)["status"] == "blocked"
    for f in actions._BLOCK_STATE_DIR.glob("*.json"):
        f.unlink()
    web2 = m.fake.vms.pop(key(WEB2))
    if nic_to_web1:
        m.fake.vms[key(WEB1)]["nics"] += web2["nics"]
        assert c.block_suspicious_ip(ATTACKER, WEB1, scope="vm", threat_port=22)["status"] == "blocked"
    else:
        for n in web2["nics"]:
            m.fake.nics.pop(key(n))
    return m


def _block_rules(m) -> set:
    return {n for n in m.fake.nsgs[key(_SUBNET)]["rules"] if n.startswith(_WEB2_BLOCK)}


def test_an_unblock_of_a_deleted_vm_takes_the_block_its_records_name(monkeypatch):
    """I7S's cause on the unblock's side (I5R): the VM gone, the unblock answered
    `not_found` without looking (`return [], []`), the block left on the subnet's NSG for
    whoever gets the address. The NIC its isolation's state still names: the block goes,
    the isolation's rules stay."""
    import shutil

    m = _gone_world(monkeypatch, isolated=True)
    try:
        iso = {n for n in m.fake.nsgs[key(_SUBNET)]["rules"] if n.startswith("glorfindel-iso")}
        assert _block_rules(m) and iso
        out = m.connector.unblock_ip(ATTACKER, WEB2)
        assert out["status"] == "unblocked", out
        assert not _block_rules(m)
        assert {n for n in m.fake.nsgs[key(_SUBNET)]["rules"] if n.startswith("glorfindel-iso")} == iso
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_an_unblock_of_a_deleted_vm_says_the_block_nothing_names(monkeypatch):
    """Nothing names its NIC any more: the rules can't be told from a deleted homonym's —
    left, and said; never `not_found`."""
    import shutil

    m = _gone_world(monkeypatch, isolated=False)
    try:
        left = _block_rules(m)
        out = m.connector.unblock_ip(ATTACKER, WEB2)
        assert out["status"] == "unblock_partial", out
        assert all(any(r in f for f in out["failed"]) for r in left), out
        assert _block_rules(m) == left
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_an_unblock_of_a_deleted_vm_leaves_its_old_nic_on_another_vm(monkeypatch):
    """Its NIC given to another VM named web, blocked there under the same names: that
    block is the other VM's — the unblock of the deleted one leaves it, and says so
    (I7S's `_gone_nic_check`: they may be the deleted VM's, if the other isn't blocked)."""
    import shutil

    m = _gone_world(monkeypatch, isolated=True, nic_to_web1=True)
    try:
        left = _block_rules(m)
        assert left
        out = m.connector.unblock_ip(ATTACKER, WEB2)
        assert out["status"] == "unblock_partial", out
        assert any("rg-app1/web" in f and "le blocage porte les mêmes noms" in f for f in out["failed"]), out
        assert _block_rules(m) == left
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("which", ["blocks", "isolation"])
def test_an_unblock_of_a_deleted_vm_with_a_state_unreadable_says_it(monkeypatch, which):
    """Its block or isolation state can't be read: the NICs it may name are unknown —
    `unblock_partial`, the file named."""
    import shutil

    from glorfindel import actions

    m = _gone_world(monkeypatch, isolated=True)
    try:
        d = actions._BLOCK_STATE_DIR if which == "blocks" else actions._ISOLATION_STATE_DIR
        if which == "blocks":
            d.mkdir(parents=True, exist_ok=True)
            (d / f"web--{actions._rid_hash(WEB2)}.json").write_text("{not json")
        else:
            next(d.glob("*.json")).write_text("{not json")
        out = m.connector.unblock_ip(ATTACKER, WEB2)
        assert out["status"] == "unblock_partial", out
        assert any(f"{d.name}/" in f and "illisible" in f for f in out["failed"]), out
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


# ── RB1 (#321): the reassertion of a merged block, the unblock of a deleted VM ─────────

_DATA = _NSG.format(rg="rg-net", name="nsg-data")
_PERIMETER = "glorfindel-block-" + ATTACKER.replace(".", "-")


def _block_name(vm: str, nic: str, nic_key: str) -> str:
    """The VM block's rule of this NIC, by the naming convention (restated)."""
    import hashlib
    mark = hashlib.sha1(nic_key.rstrip("/").lower().encode()).hexdigest()[:6]
    return f"{_PERIMETER}-{vm}-{nic}-{mark}".lower()


_DB0_BLOCK = _block_name("db--01", "db-nic-0", _nic("rg-app1", "db-nic-0"))
_DB1_BLOCK = _block_name("db--01", "db-nic-1", _nic("rg-app1", "db-nic-1"))


@pytest.mark.parametrize("modes", [("human_only",), ("non_disruptive", "non_disruptive")])
def test_a_merged_block_never_says_the_ip_unblocked_while_the_perimeter_holds(monkeypatch, modes):
    """RB1, finding 1, one subnet: web2 blocked on the perimeter (200), then for itself
    (210), in one entry (`scoped: false`); someone turns the VM's rule into an allow. The
    perimeter still cuts the attacker off. The reassertion put back the perimeter alone
    — the VM's rule stayed an allow — then said « disparu une deuxième fois — l'IP n'est
    plus bloquée »; in human_only, at once. False, on the prudent side."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block_perimeter", WEB2, WEB2, None, False),
         ("block", WEB2, WEB2, None, 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         *[("reassert", mode, None) for mode in modes])


def test_a_merged_block_puts_back_the_vms_rules_on_every_subnet(monkeypatch):
    """RB1, finding 1, two subnets: Db--01's second NIC on a subnet of its own. The
    perimeter covers the primary NIC's subnet only, and the second NIC's rule was turned
    into an allow: the attacker reaches it. The reassertion put back the perimeter and
    said « reposé une fois » — db-nic-1 open."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block_perimeter", DB, DB, None, False),
         ("block", DB, DB, None, 22),
         ("tamper_with_our_rule", "access", (key(_DATA), _DB1_BLOCK)),
         ("reassert", "non_disruptive", None))


def _cards(m) -> list[str]:
    from glorfindel import escalations
    return [e["reason"] for e in escalations.pending()
            if e.get("action") == "block_suspicious_ip" and e["signal_id"].startswith("reassert-")]


def test_a_merged_block_card_says_what_is_back_and_what_still_holds(monkeypatch):
    """The card of a merged block, both NICs' rules turned: in human_only it says where the
    IP is no longer blocked (db-nic-1) and where the perimeter still blocks it (db-nic-0)
    — never « reposé »; outside it, both rules are written again, the perimeter kept, and
    only then « reposé une fois »."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        c = m.connector
        out = c.block_suspicious_ip(ATTACKER, DB, scope="subnet")       # db-nic-1 not behind it
        assert out["status"] == "blocked_partial" and out["uncovered_nics"] == ["db-nic-1"], out
        assert c.block_suspicious_ip(ATTACKER, DB, scope="vm", threat_port=22)["status"] == "blocked"
        for nsg, name in ((_SUBNET, _DB0_BLOCK), (_DATA, _DB1_BLOCK)):
            m.fake.nsgs[key(nsg)]["rules"][name]["access"] = "Allow"
        m.reassert(Script("human_only", None))
        (card,) = _cards(m)
        assert "n'est plus bloquée sur db-nic-1" in card and "db-nic-0" in card and "périmètre" in card, card
        assert "reposé" not in card, card
        from glorfindel import actions
        actions._update_block_entry(DB, ATTACKER, drift_alerted_at=None)      # the operator acknowledged it
        m.reassert(Script("non_disruptive", None))
        (card,) = _cards(m)
        assert "reposé une fois" in card, card
        for nsg, name in ((_SUBNET, _DB0_BLOCK), (_DATA, _DB1_BLOCK), (_SUBNET, _PERIMETER)):
            assert m.fake.nsgs[key(nsg)]["rules"][name]["access"] == "Deny", (nsg, name)
        assert not m._attacker_flows(DB, None)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)      # the rules turned by hand aren't the machine's


def test_an_unblock_of_a_deleted_vm_says_how_to_take_what_it_leaves(monkeypatch):
    """RB1, finding 2: the rules it can't attribute are left — the message now says how
    to take them off, and that the unblock says them again while they stay: once taken
    off by hand, the next unblock is done."""
    import shutil

    m = _gone_world(monkeypatch, isolated=False)
    try:
        left = sorted(_block_rules(m))
        for _ in range(2):
            out = m.connector.unblock_ip(ATTACKER, WEB2)
            assert out["status"] == "unblock_partial", out
            for r in left:
                said = [f for f in out["failed"] if r in f]
                assert said and f"az network nsg rule delete -g rg-net --nsg-name nsg-subnet -n {r}" in said[0], out
                assert "tant qu'elle reste" in said[0], said
        for r in left:
            del m.fake.nsgs[key(_SUBNET)]["rules"][r]
        assert m.connector.unblock_ip(ATTACKER, WEB2)["status"] == "not_found"
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("case", ["entry lost", "tied elsewhere", "entry kept"])
def test_an_unblock_of_a_deleted_vm_says_a_perimeter_block_nothing_ties_elsewhere(monkeypatch, case):
    """RB1, finding 2: a perimeter block of the deleted VM's, its entry lost: neither looked
    for nor said — `not_found`, the IP blocked for the whole subnet. Now said, left (it
    covers every VM of the subnet), with how to take it off. One another VM's entry
    records (web1 blocked the IP on the same subnet) is that VM's; and with its own entry
    kept (a VM block), the deleted VM's entry says what was its own — nothing else said."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        c = m.connector
        perimeter_of = WEB1 if case == "entry kept" else WEB2
        assert c.block_suspicious_ip(ATTACKER, perimeter_of, scope="subnet")["status"] == "blocked"
        if case == "tied elsewhere":
            assert c.block_suspicious_ip(ATTACKER, WEB1, scope="subnet")["status"] == "blocked"
        if case == "entry kept":
            assert c.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)["status"] == "blocked"
        (actions._BLOCK_STATE_DIR / f"web--{actions._rid_hash(perimeter_of)}.json").unlink()
        web2 = m.fake.vms.pop(key(WEB2))
        for n in web2["nics"]:
            m.fake.nics.pop(key(n))
        out = c.unblock_ip(ATTACKER, WEB2)
        assert {_PERIMETER, f"{_PERIMETER}-out"} <= set(m.fake.nsgs[key(_SUBNET)]["rules"])
        if case != "entry lost":
            assert out["status"] == ("unblocked" if case == "entry kept" else "not_found"), out
            return
        assert out["status"] == "unblock_partial", out
        said = [f for f in out["failed"] if _PERIMETER in f]
        assert said and "périmètre" in said[0], out
        assert f"az network nsg rule delete -g rg-net --nsg-name nsg-subnet -n {_PERIMETER}" in said[0], said
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_our_outbound_rule_turned_inbound_never_collides_with_the_rewrite(monkeypatch):
    """RB1, finding 3: someone turns our `-out` rule into an Inbound one, at a number below
    the first free (here its own, 200, the inbound one deleted). Our names don't count
    among the numbers taken: 200 read as free, the inbound deny written there met the
    turned rule — Azure refuses two rules of one direction at one number, and nothing
    was put back. Only a rule of ours in its own direction frees its number."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[]))
        c, g = m.connector, m.fake.nsgs[key(_SUBNET)]["rules"]
        assert c.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)["status"] == "blocked"
        del g[_WEB2_BLOCK]
        g[f"{_WEB2_BLOCK}-out"]["direction"] = "Inbound"
        out = c.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)
        assert out["status"] == "blocked", out
        assert g[_WEB2_BLOCK]["direction"] == "Inbound" and g[f"{_WEB2_BLOCK}-out"]["direction"] == "Outbound"
        assert not m._attacker_flows(WEB2, None)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def _merged_world(monkeypatch, net, rid=WEB2):
    """`rid` blocked on the perimeter, then for itself: one merged entry."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    m.build(net)
    assert m.connector.block_suspicious_ip(ATTACKER, rid, scope="subnet")["status"] == "blocked"
    m.connector.block_suspicious_ip(ATTACKER, rid, scope="vm", threat_port=22)
    return m


@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
def test_a_merged_blocks_perimeter_gone_is_put_back_or_said(monkeypatch, mode):
    """The perimeter of a merged entry deleted (a `terraform apply` on the subnet's NSG),
    the VM's own rules in place: the verification looked at the VM's rules only — the
    block read whole, its perimeter gone in silence for every other VM of the subnet.
    Now its own pair is checked: put back once, or said — the IP still blocked for this
    VM, by its own rules."""
    import shutil

    m = _merged_world(monkeypatch, _net(subnet_nsg=[]))
    try:
        rules = m.fake.nsgs[key(_SUBNET)]["rules"]
        for n in (_PERIMETER, f"{_PERIMETER}-out"):
            del rules[n]
        m.reassert(Script(mode, None))
        (card,) = _cards(m)
        if mode == "human_only":
            assert _PERIMETER in card and "l'IP reste bloquée" in card, card
            assert _PERIMETER not in rules
        else:
            assert "reposé une fois" in card, card
            assert {_PERIMETER, f"{_PERIMETER}-out"} <= set(rules)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_merged_block_whose_perimeter_cant_be_read_is_never_said_held(monkeypatch):
    """web2's own rule on its NIC's NSG turned into an allow, the subnet's NSG — where the
    perimeter lies — unreadable (403): the perimeter may hold or not. Never read as held
    (« reste bloquée »), nor as gone (« n'est plus bloquée »): unknown, said so."""
    import shutil

    m = _merged_world(monkeypatch, _net(subnet_nsg=[], web_nic={"own": "dedicated"}))
    try:
        own = _NSG.format(rg="rg-app2", name="nsg-web-nic")
        name = next(n for n in m.fake.nsgs[key(own)]["rules"] if n.startswith(_PERIMETER) and not n.endswith("-out"))
        m.fake.nsgs[key(own)]["rules"][name]["access"] = "Allow"
        m.fake.unreadable.add(key(_SUBNET))
        v = m.connector.verify_block_ip(ATTACKER, WEB2)
        assert v["verified"] is not True and v.get("perimeter_unread") == ["web-nic"], v
        m.reassert(Script("human_only", None))
        (card,) = _cards(m)
        assert "on ne sait pas si l'IP est encore bloquée sur web-nic" in card, card
        assert "n'est plus bloquée" not in card and "reste bloquée" not in card, card
    finally:
        m.fake.unreadable.discard(key(_SUBNET))
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_merged_block_whose_perimeter_is_bypassed_is_never_said_held(monkeypatch):
    """A customer allow for SSH (100) before every deny of ours on the subnet's NSG: the
    perimeter lets the threat through. The VM's rule turned too: the IP is not blocked on
    22 — never « reste bloquée » because the perimeter is there."""
    from .test_invariants import _TEMPLATES

    _run(monkeypatch, _net(subnet_nsg=[_rule("allow-ssh", 100, _TEMPLATES["allow-ssh"])]),
         ("block_perimeter", WEB2, WEB2, None, False),
         ("block", WEB2, WEB2, None, 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         ("reassert", "human_only", None))


def test_a_vm_block_never_says_the_ip_unblocked_while_another_vms_perimeter_holds(monkeypatch):
    """Found by the machine on RB1's first fix (seed 1 at 500): web1 blocked on the
    perimeter, web2 for itself only — its entry not merged — and web2's rule turned into an
    allow. The perimeter is one rule for the whole subnet: web2 stays blocked, and its card
    said « l'IP n'est plus bloquée ». Any perimeter block of the IP on a NSG that governs
    the NIC counts, whoever's entry records it."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block_perimeter", WEB1, WEB1, None, False),
         ("block", WEB2, WEB2, None, 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         ("reassert", "human_only", None))


# ── RB1, review (5.5): a perimeter block covers its subnet only ─────────────────────────

def test_a_perimeter_block_never_says_blocked_with_a_nic_left_open(monkeypatch):
    """The review's sequence: Db--01's second NIC on a subnet of its own, a perimeter block
    of Db--01 — on the primary NIC's subnet. It said `blocked`, db-nic-1 open to the
    attacker; the machine's I3, cut down to that subnet, didn't see it. Now
    `blocked_partial`, db-nic-1 named."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block_perimeter", DB, DB, None, False))


def test_a_promotion_keeps_the_block_of_a_nic_the_perimeter_doesnt_cover(monkeypatch):
    """Db--01 blocked for itself on both its subnets, then promoted to the perimeter: the
    promotion took the block off both NICs — db-nic-1 open, `blocked` said,
    `verify_block_ip` true, no card. A NIC off the perimeter's subnet keeps its own."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block", DB, DB, None, 22),
         ("block_perimeter", DB, DB, None, True),
         ("verify", DB, DB, None))


def test_a_perimeter_block_alone_is_verified_on_every_nic(monkeypatch):
    """A perimeter block alone was verified on its rule pair only: true, db-nic-1 open.
    Now its verification reads the VM's NICs it doesn't cover — false, and the
    reassertion's card names it: never covered, not gone (second review: « a disparu
    d'Azure — l'IP n'est plus bloquée sur db-nic-1 », and the perimeter written again for
    nothing) — said once, nothing written, in either mode."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        c = m.connector
        c.block_suspicious_ip(ATTACKER, DB, scope="subnet")
        v = c.verify_block_ip(ATTACKER, DB)
        assert v["verified"] is False and v["uncovered_nics"] == ["db-nic-1"], v
        writes = len(m.fake.journal)
        m.reassert(Script("non_disruptive", None))
        (card,) = _cards(m)
        assert "ne couvre pas db-nic-1" in card and "scope vm" in card and "disparu" not in card, card
        assert not [e for e in m.fake.journal[writes:] if e["op"].endswith((".write", ".delete"))]
        m.reassert(Script("non_disruptive", None))
        assert len(_cards(m)) == 1 and not [e for e in m.fake.journal[writes:] if e["op"].endswith(".write")]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_perimeter_block_whose_nics_cant_be_read_takes_no_block_off(monkeypatch):
    """The VM's NICs unreadable while it is promoted: what the perimeter covers is unknown
    — no NIC's own block is taken off, and `blocked` is not said."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        c = m.connector
        assert c.block_suspicious_ip(ATTACKER, DB, scope="vm", threat_port=22)["status"] == "blocked"

        def unreadable(*a, **k):
            raise RuntimeError("(TooManyRequests) networkInterfaces")
        monkeypatch.setattr(c, "_off_perimeter", unreadable)
        out = c.block_suspicious_ip(ATTACKER, DB, scope="subnet", replace=True)
        assert out["status"] == "blocked_partial" and out.get("nics_unread"), out
        entry = next(e for e in actions._load_block_entries(DB) if e["ip"] == ATTACKER)
        assert len(entry["placements"]) == 2, entry
        assert {_DB0_BLOCK, _DB1_BLOCK} <= set(m.fake.nsgs[key(_SUBNET)]["rules"]) | set(
            m.fake.nsgs[key(_DATA)]["rules"])
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_write_that_failed_is_never_said_put_back(monkeypatch):
    """The review's second case: a merged entry on web2, its own rule turned into an
    allow, the subnet's NSG unreadable (403). Putting back the perimeter fails, the VM's
    rule is written; the verification read the perimeter's unknown pair as nothing to
    say — « reposé une fois », the error swallowed. Now the pair unread is unknown, and a
    failed write never « reposé »: the card says what failed."""
    import shutil

    m = _merged_world(monkeypatch, _net(subnet_nsg=[], web_nic={"own": "dedicated"}))
    try:
        own = _NSG.format(rg="rg-app2", name="nsg-web-nic")
        name = next(n for n in m.fake.nsgs[key(own)]["rules"] if n.startswith(_PERIMETER) and not n.endswith("-out"))
        m.fake.nsgs[key(own)]["rules"][name]["access"] = "Allow"
        m.fake.unreadable.add(key(_SUBNET))
        m.reassert(Script("non_disruptive", None))
        (card,) = _cards(m)
        assert "reposé" not in card and "échec" in card, card
        assert m.fake.nsgs[key(own)]["rules"][name]["access"] == "Deny"
        v = m.connector.verify_block_ip(ATTACKER, WEB2)
        assert v["verified"] is None, v
    finally:
        m.fake.unreadable.discard(key(_SUBNET))
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_perimeter_block_reads_the_other_nics_own_block_on_azure(monkeypatch):
    """Found by the machine on the review's fix (seed 777 at 500): Db--01 blocked for
    itself, db-nic-1's rules removed since (a `terraform apply` on its subnet's NSG), then
    a perimeter block. The state still named db-nic-1's block: `blocked` said, db-nic-1
    open. What blocks a NIC off the perimeter's subnet is read on Azure."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block", DB, DB, None, 22),
         ("terraform_apply", key(_DATA)),
         ("block_perimeter", DB, DB, None, False))


@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
def test_a_promotion_is_no_drift_for_the_next_pass(monkeypatch, mode):
    """RB1, second review: Db--01 blocked for itself on its two subnets, then promoted —
    db-nic-0 left to the perimeter, db-nic-1 keeping its own block. The next pass read
    db-nic-0, absent from the placements, as a NIC added since whose rules are gone: « a
    disparu d'Azure en partie (db-nic-0) » in human_only; outside it, the VM's rules written
    again on db-nic-0 — the promotion undone — and `reasserted_at` set, the next real drift
    escalated without being put back. A NIC the entry's perimeter covers is covered by
    design: no card, no write (and the machine's oracle on an untouched block)."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block", DB, DB, None, 22),
         ("block_perimeter", DB, DB, None, True),
         ("reassert", mode, None))


def test_a_promotion_leaves_the_next_pass_silent_and_writes_nothing(monkeypatch):
    """The same, said by the cards and the journal: two passes outside human_only, no card,
    no write, no `reasserted_at`."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        c = m.connector
        assert c.block_suspicious_ip(ATTACKER, DB, scope="vm", threat_port=22)["status"] == "blocked"
        assert c.block_suspicious_ip(ATTACKER, DB, scope="subnet", replace=True)["status"] == "blocked"
        writes = len(m.fake.journal)
        for _ in range(2):
            m.reassert(Script("non_disruptive", None))
        assert not _cards(m)
        assert not [e for e in m.fake.journal[writes:] if e["op"].endswith((".write", ".delete"))]
        entry = next(e for e in actions._load_block_entries(DB) if e["ip"] == ATTACKER)
        assert not entry.get("reasserted_at") and c.verify_block_ip(ATTACKER, DB)["verified"] is True
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_nic_left_to_a_perimeter_someone_turned_is_open(monkeypatch):
    """A NIC a promotion left to the perimeter is covered by design only while the
    perimeter holds: turned into an allow, it is open — never « reste bloquée »."""
    _run(monkeypatch, _net(subnet_nsg=[], data_subnet=[]),
         ("block", DB, DB, None, 22),
         ("block_perimeter", DB, DB, None, True),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _PERIMETER)),
         ("reassert", "human_only", None))


@pytest.mark.parametrize("mode", ["human_only", "non_disruptive"])
def test_a_perimeter_gone_after_its_uncovered_card_is_acknowledged_is_put_back_or_said(monkeypatch, mode):
    """RB1, third review: a perimeter block alone on Db--01 (db-nic-1 on another subnet),
    the pass says it doesn't cover db-nic-1, the operator acknowledges that card, then
    someone deletes the perimeter pair. The card had set `drift_alerted_at`, cleared only on
    a verification that holds — never, for this entry: every later pass stopped there, the
    perimeter (the IP cut off for the whole subnet) neither put back nor said. Its own mark
    now: the disappearance follows the usual way."""
    import shutil

    from glorfindel import escalations

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        assert m.connector.block_suspicious_ip(ATTACKER, DB, scope="subnet")["status"] == "blocked_partial"
        m.reassert(Script(mode, None))
        (card,) = _cards(m)
        assert "ne couvre pas db-nic-1" in card, card
        for e in escalations.pending():
            escalations.resolve(e["id"])                       # the operator acknowledges it
        rules = m.fake.nsgs[key(_SUBNET)]["rules"]
        for n in (_PERIMETER, f"{_PERIMETER}-out"):
            del rules[n]
        m.reassert(Script(mode, None))
        if mode == "non_disruptive":
            assert {_PERIMETER, f"{_PERIMETER}-out"} <= set(rules), "the perimeter was not put back"
            # Whole again, the episode is over: deleted once more, it is said (put back once).
            m.reassert(Script(mode, None))
            for e in escalations.pending():
                escalations.resolve(e["id"])
            for n in (_PERIMETER, f"{_PERIMETER}-out"):
                del rules[n]
            m.reassert(Script(mode, None))
            (card,) = _cards(m)
            assert "deuxième fois" in card, card
        else:
            (card,) = _cards(m)
            assert "disparu" in card and _PERIMETER in card, card
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_an_uncovered_card_is_said_again_when_the_uncovered_nics_change(monkeypatch):
    """Said once per set of NICs: a third NIC of Db--01 on the other subnet — the card says
    the two; the same set, nothing more."""
    import shutil

    from .fake_azure import nic_id

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        m.connector.block_suspicious_ip(ATTACKER, DB, scope="subnet")
        m.reassert(Script("human_only", None))
        assert len(_cards(m)) == 1
        m.reassert(Script("human_only", None))
        assert len(_cards(m)) == 1                              # the same NICs: not said again
        f = m.fake
        extra = nic_id("rg-app1", "db-nic-2")
        f.nics[key(extra)] = {**f.nics[_nic("rg-app1", "db-nic-1")], "id": extra, "ips": ["10.0.0.9"]}
        f.vms[key(DB)]["nics"].append(extra)
        m.design = f.snapshot()                                  # the customer's design, a NIC more
        m.reassert(Script("human_only", None))
        (card,) = _cards(m)
        assert "db-nic-1, db-nic-2" in card, card
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("then", ["perimeter deleted", "nothing", "better"])
def test_a_drift_card_acknowledged_is_said_again_only_when_it_worsens(monkeypatch, then):
    """RB1, fourth review: a merged entry on web2 (one subnet), its own rules turned into
    allows; in human_only the card says the IP stays blocked on web-nic, by the perimeter
    — true. The operator acknowledges it; someone deletes the perimeter pair: the attacker
    reaches web2, and every pass returned on `drift_alerted_at` — silent. The card now
    keeps what it said, and is said again when it worsens (a NIC held turned open, a rule
    more gone); the same, or better, says nothing: one card per disappearance."""
    import shutil

    from glorfindel import escalations

    m = _merged_world(monkeypatch, _net(subnet_nsg=[]))
    try:
        rules = m.fake.nsgs[key(_SUBNET)]["rules"]
        for n in (_WEB2_BLOCK, f"{_WEB2_BLOCK}-out"):
            rules[n]["access"] = "Allow"
        m.reassert(Script("human_only", None))
        (card,) = _cards(m)
        assert "l'IP reste bloquée sur web-nic" in card, card
        for e in escalations.pending():
            escalations.resolve(e["id"])                       # the operator acknowledges it
        if then == "perimeter deleted":
            for n in (_PERIMETER, f"{_PERIMETER}-out"):
                del rules[n]
        elif then == "better":
            rules[_WEB2_BLOCK]["access"] = "Deny"               # one of the two set right by hand
        m.reassert(Script("human_only", None))
        cards = _cards(m)
        if then == "perimeter deleted":
            assert len(cards) == 1 and "n'est plus bloquée" in cards[0] and _PERIMETER in cards[0], cards
            assert m._attacker_flows(WEB2, None)
        else:
            assert not cards, cards
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_the_machine_finds_a_perimeter_deleted_after_its_card_is_acknowledged(monkeypatch):
    """The same through the machine's rules: L1 holds an acknowledged card for said only
    while the entry's rules — its perimeter pair included — are as they were when it was
    acknowledged."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block_perimeter", WEB2, WEB2, None, False),
         ("block", WEB2, WEB2, None, 22),
         ("tamper_with_our_rule", "access", (key(_SUBNET), _WEB2_BLOCK)),
         ("reassert", "human_only", None),
         ("operator_acknowledges", 0),
         ("terraform_apply", key(_SUBNET)),
         ("reassert", "human_only", None))


_EDGE = _NSG.format(rg="rg-edge", name="nsg-edge")


def test_a_block_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address(monkeypatch):
    """I4A (#328), found by RB1's machine (seed 8675 at 500), present on main before it: api
    blocked on its subnet's NSG, its inbound rule turned into an allow by someone, its IP
    changed, a new VM given the old address — the turned rule now lets the attacker reach
    that VM. api blocked again: the block rewrote its rule by name, a deny for api's new
    address — the allow gone, the new VM cut off from flows an operation on api must not
    touch. Now the block leaves that rule as it is, writes its deny under the NIC's second
    name, and says what it left."""
    net = _net()
    net["edge_nsg"] = []
    _run(monkeypatch, net,
         ("block_turned_then_reasserted", API, API, None, "vm", 22,
          (key(_EDGE), "glorfindel-block-192-31-196-7-api-api-nic-c272f2"), "human_only"),
         ("customer_changes_ip", _nic("rg-edge", "api-nic"), 0, 4),
         ("create_vm", "northeurope", "rg-app1", "api", None, "Linux"),
         ("address_reused", API, API, None, False, 22, False, "rg-new", "x", None, "Linux", False))


def test_the_same_perimeter_gone_twice_is_said_twice(monkeypatch):
    """RB1, fifth review: a perimeter block alone on Db--01 (two subnets) — « ne couvre pas »,
    acknowledged; its pair deleted — « disparu », acknowledged; blocked again by the
    operator, the pair back: the next pass reads it whole but for db-nic-1, the episode is
    over; the same pair deleted a second time must be said again — the same rules gone, so
    no « rule more » tells it worse: only the episode closed does."""
    import shutil

    from glorfindel import escalations

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(subnet_nsg=[], data_subnet=[]))
        c, rules = m.connector, m.fake.nsgs[key(_SUBNET)]["rules"]

        def drop():
            for n in (_PERIMETER, f"{_PERIMETER}-out"):
                rules.pop(n, None)

        def ack():
            for e in escalations.pending():
                escalations.resolve(e["id"])
        c.block_suspicious_ip(ATTACKER, DB, scope="subnet")
        m.reassert(Script("human_only", None))
        ack()
        drop()
        m.reassert(Script("human_only", None))
        assert any("disparu" in x for x in _cards(m)), _cards(m)
        ack()
        c.block_suspicious_ip(ATTACKER, DB, scope="subnet")
        m.reassert(Script("human_only", None))
        ack()
        drop()
        m.reassert(Script("human_only", None))
        (card,) = _cards(m)
        assert "disparu" in card, card
        assert m._attacker_flows(WEB1, None)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


_API_BASE = "glorfindel-block-192-31-196-7-api-api-nic-c272f2"
_API_SECOND = "glorfindel-block-192-31-196-7-api-api-nic-b-c272f2"
_NEW_API_VM = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/api"


def _address_taken(monkeypatch, turn=True, reuse=True):
    """api blocked on nsg-edge (no NSG of its own), its inbound rule turned into an allow
    (or not), its IP changed, a new VM api in rg-app1 given the old address (or not)."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    net = _net()
    net["edge_nsg"] = []
    m.build(net)
    assert m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)["status"] == "blocked"
    rules = m.fake.nsgs[key(_EDGE)]["rules"]
    old = rules[_API_BASE]["destination_address_prefixes"]
    if turn:
        rules[_API_BASE]["access"] = "Allow"
    m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 4))
    if reuse:
        m.create_vm(data=Script("northeurope", "rg-app1", "api", None, "Linux"))
        assert m.fake.nics[_nic("rg-app1", "api-nic-4")]["ips"] == old
    return m, rules, old


def test_a_turned_rule_on_an_address_handed_to_another_vm_is_left_and_said(monkeypatch):
    """I4A: the block written again leaves the turned rule (it lets the attacker reach the
    new VM — an operation on api never changes that VM's flows), writes api's deny under
    the NIC's second name, for api's address only; the reassertion says what was left, on
    one card, once."""
    import shutil

    from glorfindel import escalations

    m, rules, old = _address_taken(monkeypatch)
    try:
        reach = m._attacker_flows(_NEW_API_VM, None)
        assert reach
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert out["status"] == "blocked", out
        assert rules[_API_BASE]["access"] == "Allow" and rules[_API_BASE]["destination_address_prefixes"] == old
        now = m.fake.nics[_nic("rg-edge", "api-nic")]["ips"]
        for name, side in ((_API_SECOND, "destination"), (f"{_API_SECOND}-out", "source")):
            assert rules[name]["access"] == "Deny" and rules[name][f"{side}_address_prefixes"] == now, rules[name]
        # Our -out deny, on the old address, cut the new VM's way out: taken off, given back.
        assert f"{_API_BASE}-out" not in rules
        assert not m._attacker_flows(API, None)
        assert reach < m._attacker_flows(_NEW_API_VM, None)
        reach = m._attacker_flows(_NEW_API_VM, None)
        (left,) = out["left_rules"]
        assert left["rule"] == _API_BASE and left["to"] == old[0] and left["on"] == "api", left
        assert m.connector.verify_block_ip(ATTACKER, API)["verified"] is True
        for _ in range(2):
            m.reassert(Script("human_only", None))
            cards = [e for e in escalations.pending() if e["escalation_type"] == "rule_left"]
            assert len(cards) == 1, cards
        assert _API_BASE in cards[0]["reason"] and old[0] in cards[0]["reason"], cards[0]["reason"]
        escalations.resolve(cards[0]["id"])                  # acknowledged: not said again
        m.reassert(Script("human_only", None))
        assert not [e for e in escalations.pending() if e["escalation_type"] == "rule_left"]
        # Blocked a third time, the same: nothing more written over the turned rule.
        assert m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)["status"] == "blocked"
        assert rules[_API_BASE]["access"] == "Allow"
        assert m._attacker_flows(_NEW_API_VM, None) == reach
    finally:
        shutil.rmtree(m.home, ignore_errors=True)       # the rule turned by hand isn't the machine's


def test_a_turned_rule_on_an_address_nobody_has_is_written_again_as_before(monkeypatch):
    """The old address handed to nobody: the turned rule changes no VM's flows — written
    again under its own name, for api's new address (I7S), nothing left, nothing said."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch, reuse=False)
    try:
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert out["status"] == "blocked" and "left_rules" not in out, out
        now = m.fake.nics[_nic("rg-edge", "api-nic")]["ips"]
        assert rules[_API_BASE]["access"] == "Deny" and rules[_API_BASE]["destination_address_prefixes"] == now
        assert _API_SECOND not in rules
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_our_deny_on_an_address_handed_to_another_vm_is_written_for_the_vm_it_blocks(monkeypatch):
    """Our deny, never turned, left on the old address: it cuts the new VM off. Written
    again by name, for api's address, it gives the new VM back what it cut — as before."""
    m, rules, old = _address_taken(monkeypatch, turn=False)
    try:
        assert not m._attacker_flows(_NEW_API_VM, None)
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert out["status"] == "blocked" and "left_rules" not in out, out
        assert rules[_API_BASE]["destination_address_prefixes"] != old and _API_SECOND not in rules
        assert m._attacker_flows(_NEW_API_VM, None) and not m._attacker_flows(API, None)
    finally:
        m.teardown()


def test_the_reset_preview_says_what_it_keeps(monkeypatch):
    """`glorfindel reset --from-azure` shows the preview before the confirmation: it said
    « supprimer …/glorfindel-block-…-c272f2 » — the turned allow aimed at the VM given the
    old address —, the operator confirmed, and got `swept_partial … gardée` (I4B, review:
    the guard was skipped in preview). It only reads: the preview says it is kept."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch)
    try:
        journal = len(m.fake.journal)
        out = m.connector.sweep_vm_rules(API, dry_run=True)
        assert len(m.fake.journal) == journal, "a preview wrote"
        assert out["status"] == "dry_run" and not any(_API_BASE == d.rsplit("/", 1)[-1] for d in out["deleted"]), out
        assert any(_API_BASE in f and "gardée" in f for f in out["failed"]), out
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("aim", ["any", "range"])
@pytest.mark.parametrize("lift", ["unblock", "reset"])
def test_a_turned_rule_aimed_at_any_or_a_range_stays_at_the_unblock(monkeypatch, aim, lift):
    """I4B: the turned allow the unblock or the reset would take off, aimed at any address
    on the subnet's NSG a new VM sits behind, or at a range (who it takes in is not read,
    A0): it lets the attacker reach that VM — kept, said."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch, reuse=aim == "range")
    try:
        if aim == "any":
            m.create_vm(data=Script("northeurope", "rg-app1", "api", None, "Linux"))
            rules[_API_BASE].pop("destination_address_prefixes")
            rules[_API_BASE]["destination_address_prefix"] = "*"
        else:
            rules[_API_BASE]["destination_address_prefixes"] = ["10.1.0.0/24"]
        reach = m._attacker_flows(_NEW_API_VM, None)
        assert reach
        out = m.connector.unblock_ip(ATTACKER, API) if lift == "unblock" else m.connector.sweep_vm_rules(API)
        assert rules[_API_BASE]["access"] == "Allow" and m._attacker_flows(_NEW_API_VM, None) >= reach
        said = [f for f in out["failed"] if _API_BASE in f and "gardée" in f]
        assert said and ("toutes les cartes" if aim == "any" else "inconnu") in said[0], out
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("turned", ["isolation", "another NIC's block"])
def test_any_turned_rule_of_ours_behind_our_deny_keeps_it_at_the_block(monkeypatch, turned):
    """I4B, the lot's fourth point: one guard. api blocked on nsg-edge, its IP changed, a new
    VM at the old address. Behind api's inbound deny on that address waits one of our rules
    someone turned into an allow, aimed at it — not one of api's block rules (all I4A read)
    but its isolation's, or a rule named for another NIC. Blocked again, the deny was
    rewritten for api's new address and the turned rule let the attacker reach the new VM.
    Now every turned rule of ours on an NSG that governs the holder is read (_waits_for):
    the deny stays, said (`left_rules`, kind deny)."""
    import shutil

    m, rules, old = _address_taken(monkeypatch, turn=False)
    try:
        name = ("glorfindel-iso-api-api-nic-c272f2" if turned == "isolation"
                else "glorfindel-block-192-31-196-7-db--01-db-nic-0-0d0228")
        FakeAzure._put_rule(m.fake.nsgs[key(_EDGE)], _rule_record(_rule(name, 300, dict(
            access="Allow", direction="Inbound", source_address_prefix=ATTACKER,
            destination_address_prefixes=list(old), destination_port_range="*"))))
        assert not {f for f in m._attacker_flows(_NEW_API_VM, None) if f[2] == "in"}
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert out["status"] == "blocked", out
        assert rules[_API_BASE]["access"] == "Deny" and rules[_API_BASE]["destination_address_prefixes"] == old
        assert any(x["rule"] == _API_BASE and x["kind"] == "deny" for x in out["left_rules"]), out
        assert not {f for f in m._attacker_flows(_NEW_API_VM, None) if f[2] == "in"}
        assert not m._attacker_flows(API, None)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_whose_the_old_address_is_unknown_the_turned_rule_is_left(monkeypatch):
    """The NICs unreadable: who holds the old address is unknown — never read as nobody
    (A0): the turned rule is left, and said as unknown. And our -out deny on that address:
    whether a turned rule of ours waits behind it for its holder can't be read either —
    kept too, said (I4B: the guard reads every turned rule; keeping a deny never opens)."""
    import shutil

    from .fake_azure import throttled

    m, rules, _ = _address_taken(monkeypatch)
    try:
        def unreadable():
            raise throttled("nic.list")
        monkeypatch.setattr(m.connector._network.network_interfaces, "list_all", unreadable)
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert out["status"] == "blocked", out
        assert rules[_API_BASE]["access"] == "Allow"
        left = {x["rule"]: x for x in out["left_rules"]}
        assert set(left) == {_API_BASE, f"{_API_BASE}-out"}, out["left_rules"]
        assert left[_API_BASE]["on"].startswith("inconnu") and left[_API_BASE]["kind"] == "turned", left
        assert left[f"{_API_BASE}-out"]["on"].startswith("inconnu") and left[f"{_API_BASE}-out"]["kind"] == "deny"
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("lift", ["verify", "unblock", "unblock after an ip change", "reset"])
def test_a_block_under_its_second_name_is_found_without_its_state(monkeypatch, lift):
    """Under its second name, the block is still the NIC's (same hash): its state lost, the
    verification finds it, the unblock and the reset take it off — the unblock by the
    NIC's mark too, the NIC's IP changed again since (the deny on an address no longer
    its own, L26). The first pair's turned allow, aimed at the VM given the old address,
    stays — said, the outcome partial (I4B: taken off, that VM lost the flows it gave it;
    `unblocked` was said, the test asked for it)."""
    import shutil

    from glorfindel import actions

    m, rules, _ = _address_taken(monkeypatch)
    try:
        m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        if lift == "unblock after an ip change":
            m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 20))
        for f in actions._BLOCK_STATE_DIR.glob("api--*.json"):
            f.unlink()
        if lift == "verify":
            assert m.connector.verify_block_ip(ATTACKER, API)["verified"] is True
            return
        reach = m._attacker_flows(_NEW_API_VM, None)
        out = (m.connector.sweep_vm_rules(API) if lift == "reset"
               else m.connector.unblock_ip(ATTACKER, API))
        assert out["status"] in ("unblock_partial", "swept_partial"), out
        assert any(_API_BASE in f and "gardée" in f for f in out["failed"]), out
        assert rules[_API_BASE]["access"] == "Allow" and m._attacker_flows(_NEW_API_VM, None) >= reach
        assert _API_SECOND not in rules and f"{_API_SECOND}-out" not in rules, sorted(rules)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_turned_rule_widened_to_any_on_a_shared_nsg_is_left(monkeypatch):
    """Turned into an allow and widened to any address by hand, on the subnet's NSG a new VM
    sits behind: it lets the attacker reach that VM. Blocked again, the block leaves it as
    it is — and says the bypass it makes for api: never « blocked » alone."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch, reuse=False)
    try:
        m.create_vm(data=Script("northeurope", "rg-app1", "api", None, "Linux"))
        rules[_API_BASE].pop("destination_address_prefixes")
        rules[_API_BASE]["destination_address_prefix"] = "*"
        reach = m._attacker_flows(_NEW_API_VM, None)
        assert reach
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert rules[_API_BASE]["access"] == "Allow" and rules[_API_BASE]["destination_address_prefix"] == "*"
        (left,) = out["left_rules"]
        assert left["to"] == "*" and "derrière ce NSG" in left["on"], left
        assert out.get("bypass"), out
        assert m._attacker_flows(_NEW_API_VM, None) >= reach
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_turned_rule_aimed_at_a_range_is_left(monkeypatch):
    """Turned into an allow and aimed at a range by hand: who is in it is unknown — never
    read as nobody (A0): left, said as unknown."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch)
    try:
        rules[_API_BASE]["destination_address_prefixes"] = ["10.1.0.0/24"]
        reach = m._attacker_flows(_NEW_API_VM, None)
        out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        assert rules[_API_BASE]["access"] == "Allow", out
        (left,) = out["left_rules"]
        assert left["to"] == "10.1.0.0/24" and left["on"].startswith("inconnu"), left
        assert m._attacker_flows(_NEW_API_VM, None) >= reach
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_an_isolation_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address(monkeypatch):
    """Found at I4A's work, the isolation's side of the same defect (I4B): api isolated by
    rules on nsg-edge, its inbound isolation rule turned into an allow by someone, its IP
    changed, a new VM given the old address, api isolated again — the isolation, written
    again by name for api's new address, took the allow off and cut the new VM off (I4).
    Now the rewrite reads its rules first (_plan_isolation): the turned allow stays, said
    (`left_rules`), the isolation is written under the NIC's second name."""
    net = _net()
    net["edge_nsg"] = []
    _run(monkeypatch, net,
         ("isolate", API, API, None),
         ("tamper_with_our_rule", "access", (key(_EDGE), "glorfindel-iso-api-api-nic-c272f2")),
         ("customer_changes_ip", _nic("rg-edge", "api-nic"), 0, 4),
         ("create_vm", "northeurope", "rg-app1", "api", None, "Linux"),
         ("isolate", API, API, None))


_API_ISO = "glorfindel-iso-api-api-nic-c272f2"
_API_ISO_SECOND = "glorfindel-iso-api-api-nic-b-c272f2"


@pytest.mark.parametrize("state", ["kept", "lost"])
def test_an_isolation_written_again_leaves_the_turned_rule_said_under_its_second_name(monkeypatch, state):
    """I4B, what the sequence above holds, said: the turned allow on the old address stays
    as it is, named in `left_rules` and the note; api's isolation is written under the
    NIC's second name, for its new address; the first pair's -out deny on the old address
    (the new VM's way out cut off) goes. The release keeps the turned allow and says it
    (`release_partial`); once the operator puts it back, the release takes it off — its
    state kept (the placements, _held_by_turned) or lost (the sweep of the NIC's NSGs)."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    net = _net()
    net["edge_nsg"] = []
    try:
        m.build(net)
        assert m.connector.isolate_vm(API)["status"] == "isolated"
        rules = m.fake.nsgs[key(_EDGE)]["rules"]
        old = rules[_API_ISO]["destination_address_prefixes"]
        rules[_API_ISO]["access"] = "Allow"
        m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 4))
        m.create_vm(data=Script("northeurope", "rg-app1", "api", None, "Linux"))
        reach = m._open(_NEW_API_VM)
        out = m.connector.isolate_vm(API)
        assert out["status"] == "isolated", out
        assert rules[_API_ISO]["access"] == "Allow" and rules[_API_ISO]["destination_address_prefixes"] == old
        (left,) = out["left_rules"]
        assert left["rule"] == _API_ISO and "gardée" in left["why"] and old[0] in left["why"], left
        assert _API_ISO in out["left_note"]
        now = m.fake.nics[_nic("rg-edge", "api-nic")]["ips"]
        assert rules[_API_ISO_SECOND]["access"] == "Deny" and rules[_API_ISO_SECOND]["destination_address_prefixes"] == now
        assert rules[f"{_API_ISO_SECOND}-out"]["source_address_prefixes"] == now
        assert f"{_API_ISO}-out" not in rules
        assert m._open(_NEW_API_VM) >= reach and not m._attacker_flows(API, None)
        assert m.connector.verify_isolation(API)["verified"] is True
        if state == "lost":
            m._lose_state(API)
        rel = m.connector.release_isolation(API)
        assert rel["status"] == "release_partial" and any(_API_ISO in f and "gardée" in f for f in rel["failed"]), rel
        assert _API_ISO_SECOND not in rules and m._open(_NEW_API_VM) >= reach
        rules[_API_ISO]["access"] = "Deny"                       # the operator, from what was said
        assert m.connector.release_isolation(API)["status"] == "released"
        assert not [n for n in rules if n.startswith("glorfindel-iso-api-")]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_reassertion_says_what_the_isolation_left(monkeypatch):
    """I4B: the isolation under the second name disappears (someone deletes it); the
    reassertion puts it back — and its card names the turned allow it left as it was, as
    the outcome of the isolation did."""
    import shutil

    from glorfindel import escalations

    invariant_env(monkeypatch)
    m = IsolationMachine()
    net = _net()
    net["edge_nsg"] = []
    try:
        m.build(net)
        assert m.connector.isolate_vm(API)["status"] == "isolated"
        rules = m.fake.nsgs[key(_EDGE)]["rules"]
        rules[_API_ISO]["access"] = "Allow"
        m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 4))
        m.create_vm(data=Script("northeurope", "rg-app1", "api", None, "Linux"))
        assert m.connector.isolate_vm(API)["left_rules"]
        for n in (_API_ISO_SECOND, f"{_API_ISO_SECOND}-out"):
            del rules[n]
        m.reassert(Script("non_disruptive", None))
        assert _API_ISO_SECOND in rules
        said = [e["reason"] for e in escalations.pending() if e.get("action") == "isolate_vm"]
        assert any("reposée une fois" in r and _API_ISO in r and "gardée" in r for r in said), said
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


_NSG_WEB2 = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Network/networkSecurityGroups/nsg-web-nic"
_BATCH_APP2 = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/batch"


_TURNED_TO = {"exact": None, "range": ["10.0.0.0/16"], "tag": ["VirtualNetwork"]}


def _turned_behind_world(monkeypatch, target="exact"):
    """web2 blocked on its own NSG (allow-ssh after our deny), its rule on the subnet's NSG
    too — an earlier placement there — turned into an allow, aimed at web2's address, a
    range holding it or a tag (`target`); web2's IP changed, batch created on web2's NSG,
    given the old address: our deny there cuts it off, the turned allow on the subnet's
    NSG waits behind it."""
    invariant_env(monkeypatch)
    m = IsolationMachine()
    ssh = _rule("allow-ssh", 1000, dict(access="Allow", direction="Inbound", source_address_prefix="*",
                                        destination_address_prefix="*", destination_port_range="22"))
    m.build(_net(subnet_nsg=[], web_nic={"own": "dedicated", "rules": [ssh]}))
    assert m.connector.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)["status"] == "blocked"
    own = m.fake.nsgs[key(_NSG_WEB2)]["rules"]
    old = own[_WEB2_BLOCK]["destination_address_prefixes"]
    FakeAzure._put_rule(m.fake.nsgs[key(_SUBNET)], _rule_record(_rule(_WEB2_BLOCK, 300, dict(
        access="Allow", direction="Inbound", source_address_prefix=ATTACKER,
        destination_address_prefixes=_TURNED_TO[target] or list(old), destination_port_range="*"))))
    # The turned rule is the test's own, not one the machine turned: its claims not judged here.
    m._customer_changes_ip(Script(_nic("rg-app2", "web-nic"), 0, 20))
    m.create_vm(data=Script("westeurope", "rg-app2", "batch", _NSG_WEB2, "Linux"))
    assert m.fake.nics[_nic("rg-app2", "batch-nic-4")]["ips"] == old
    return m, own, old


@pytest.mark.parametrize("target", ["exact", "range", "tag"])
@pytest.mark.parametrize("subnet_nsg", ["readable", "unreadable"])
def test_our_deny_a_turned_rule_waits_behind_is_kept_for_the_new_owner(monkeypatch, subnet_nsg, target):
    """I4A, seed 42 at 2 000 (the machine's new rule), present on main: the block written
    again rewrote our deny on web2's NSG for web2's new address — and the turned allow on
    the subnet's NSG let the attacker reach batch on 22: an operation on web2 opened
    another VM. Now that deny stays (its pair under the second name), said; the subnet's
    NSG unreadable, whether an allow waits is unknown — kept too (A0). The turned allow
    aimed at a range holding the address, or at a tag, waits behind it as well (review:
    compared as strings, `10.0.0.0/16` and `VirtualNetwork` opened batch on 22)."""
    import shutil

    from .fake_azure import throttled

    m, own, old = _turned_behind_world(monkeypatch, target)
    try:
        rules = m.connector._network.security_rules
        listing = rules.list

        def partly(rg, name):
            if name == "nsg-subnet" and subnet_nsg == "unreadable":
                raise throttled("rule.list")
            return listing(rg, name)
        rules.list = partly
        try:
            out = m.connector.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)
        finally:
            rules.list = listing
        assert out["status"] == "blocked", out
        assert own[_WEB2_BLOCK]["access"] == "Deny" and own[_WEB2_BLOCK]["destination_address_prefixes"] == old
        # Unknown, the -out deny on the old address is kept as well: keeping one never opens.
        assert len(out["left_rules"]) == (1 if subnet_nsg == "readable" else 2), out["left_rules"]
        left = next(x for x in out["left_rules"] if x["rule"] == _WEB2_BLOCK)
        assert left["kind"] == "deny" and left["on"] == "batch" and left["to"] == old[0], left
        assert not {f for f in m._attacker_flows(_BATCH_APP2, None) if f[2] == "in"}
        assert not m._attacker_flows(WEB2, None)
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_failed_take_off_of_the_first_pairs_rule_is_said(monkeypatch):
    """I4A, review: the first pair's -out deny, on the old address — the new VM's now —, to
    take off once the block holds under the second name. Its delete fails: it stays and
    cuts that VM off. `blocked` was said, the failure written where nothing read it; now
    the outcome says it (`drop_failed`, the note), and the card with what the block left."""
    import shutil

    from glorfindel import escalations

    from .fake_azure import throttled

    m, rules, old = _address_taken(monkeypatch)
    try:
        api_rules = m.connector._network.security_rules
        delete = api_rules.begin_delete

        def refused(rg, nsg, name):
            if name.lower() == f"{_API_BASE}-out":
                raise throttled("rule.delete")
            return delete(rg, nsg, name)
        api_rules.begin_delete = refused
        try:
            out = m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        finally:
            api_rules.begin_delete = delete
        assert f"{_API_BASE}-out" in rules
        (failed,) = out["drop_failed"]
        assert failed["rule"] == f"{_API_BASE}-out" and old[0] in failed["to"], failed
        assert "n'a pas pu être retirée" in out["note"], out["note"]
        m.reassert(Script("human_only", None))
        (card,) = [e for e in escalations.pending() if e["escalation_type"] == "rule_left"]
        assert f"{_API_BASE}-out" in card["reason"] and "n'a pas pu être retirée" in card["reason"], card["reason"]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_the_verification_without_state_reads_the_pair_that_blocks_the_nic_now(monkeypatch):
    """I4A, review: two pairs of web2's on its NSG — the first kept on the old address
    (batch's now, a turned rule behind it, unknown), the second for web2's address — and an
    allow before the second for the threat. Its state lost, the verification took the
    first pair present by name: no allow precedes it, verified — while the attacker
    reached web2 (the subnet's NSG lets it through: the turned rule aims at a range). Now
    it reads the pair that blocks the NIC as it is now: bypassed."""
    import shutil

    from glorfindel import actions

    from .fake_azure import throttled

    m, own, old = _turned_behind_world(monkeypatch, "range")
    try:
        rules = m.connector._network.security_rules
        listing = rules.list

        def partly(rg, name):
            if name == "nsg-subnet":
                raise throttled("rule.list")
            return listing(rg, name)
        rules.list = partly
        try:
            assert m.connector.block_suspicious_ip(ATTACKER, WEB2, scope="vm", threat_port=22)["status"] == "blocked"
        finally:
            rules.list = listing
        nic = m.fake.vms[key(WEB2)]["nics"][0]
        second = m.connector._placement_rule_bases(m.connector._block_rule_prefix(ATTACKER), "web", "web-nic", nic)[1]
        first, then = own[_WEB2_BLOCK]["priority"], own[second]["priority"]
        assert first < then - 1, (first, then)
        FakeAzure._put_rule(m.fake.nsgs[key(_NSG_WEB2)], _rule_record(_rule("allow-threat", first + 1, dict(
            access="Allow", direction="Inbound", source_address_prefix=ATTACKER,
            destination_address_prefix="*", destination_port_range="22"))))
        for f in actions._BLOCK_STATE_DIR.glob("web--*.json"):
            f.unlink()
        assert m._attacker_flows(WEB2, 22)
        assert m.connector.verify_block_ip(ATTACKER, WEB2)["verified"] is False
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("reblock", [False, True])
@pytest.mark.parametrize("lift", ["unblock", "reset"])
def test_the_unblock_and_the_reset_leave_the_new_owner_of_the_old_address(monkeypatch, lift, reblock):
    """I4B (#333), found at I4A's review, the machine's seeds 42 and 8675 at 500 once its
    oracle compared the attacker's flows at an unblock and a reset (they were taken out of
    it): the unblock and the reset took off a rule with the NIC's hash whatever it had
    become (_nic_owns) — the turned allow the block left too, aimed at the old address: the
    VM given it lost the flows it gave it. Now asked first (_held_by_turned): it stays,
    said (`unblock_partial`, `swept_partial`, the rule named)."""
    import shutil

    m, rules, _ = _address_taken(monkeypatch)
    try:
        if reblock:
            m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)
        reach = m._attacker_flows(_NEW_API_VM, None)
        assert reach
        out = m.connector.unblock_ip(ATTACKER, API) if lift == "unblock" else m.connector.sweep_vm_rules(API)
        assert m._attacker_flows(_NEW_API_VM, None) >= reach
        assert out["status"] in ("unblock_partial", "swept_partial"), out
        said = [f for f in out["failed"] if _API_BASE in f]
        assert len(said) == 1, out["failed"]
        assert "gardée" in said[0] and "retournée en autorisation" in said[0] and "10.1.0.4" in said[0], said
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


# ── I5Q (#327): an orphan's deny that holds back one of our rules someone turned ──────

_Q_EDGE_NSG = _NSG.format(rg="rg-edge", name="nsg-edge")
_Q_API_NSG = "/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Network/networkSecurityGroups/nsg-api-nic"
_Q_API_BLOCK = "glorfindel-block-192-31-196-7-api-api-nic-c272f2"     # api's NIC, in the IP's block
_Q_API_ISO = "glorfindel-iso-api-api-nic-c272f2"
_Q_PERIMETER = "glorfindel-block-192-31-196-7"
_Q_NEW_WEB = "/subscriptions/s/resourceGroups/rg-new/providers/Microsoft.Compute/virtualMachines/web"


def _edge_net():
    """api on an NSG of its own that lets SSH in from anywhere; its subnet's NSG empty."""
    return {**_net(api_nic={"own": "dedicated", "rules": [_rule("allow-ssh", 101, dict(
        access="Allow", direction="Inbound", source_address_prefix="*",
        destination_address_prefix="*", destination_port_range="22"))]}), "edge_nsg": []}


def test_the_sequence_the_machine_found_on_i5_after_an_address_reused(monkeypatch):
    """Graine 101 at 500 sequences (RB1's fourth review; on `main` too), shrunk from 14
    steps to 4: api blocked, then blocked on its subnet as well — its own rule at 200,
    the perimeter rule at 210 —, its own rule turned into an allow; api isolated by
    rules, deleted, and a new VM given its address and its NSG. The orphan sweep of the
    reassertion took api's isolation off the new VM: the attacker, let through the
    subnet's NSG by the turned rule, reached it on 22 — the perimeter block behind.
    The reassertion inside step 2 runs in human_only: since RB1, in non_disruptive it
    puts the turned rule back as a deny, and the state is never reached (the sequence
    then passed on `main` too — the review of I5Q)."""
    _run(monkeypatch, _edge_net(),
         ("block", API, API, None, 22),
         ("block_turned_then_reasserted", API, API, None, "both", 22, (key(_Q_EDGE_NSG), _Q_API_BLOCK),
          "human_only"),
         ("address_reused", API, API, None, True, False, "rg-new", "web", _Q_API_NSG, "Linux", False),
         ("reassert", "non_disruptive", None))


@pytest.mark.parametrize("turned", [_Q_API_BLOCK, _Q_PERIMETER])
def test_an_orphan_deny_behind_a_turned_rule_stays_said_then_goes(monkeypatch, turned):
    """The deny a deleted VM left, cutting the VM that took its address and NSG, is the
    last thing keeping the attacker out: one of our rules on the subnet's NSG, turned
    into an allow by someone, lets them past the block. The reassertion keeps it and
    says why — the card names the turned rule; never the opening. Once the operator puts
    that rule back, the next pass takes the deny off: the VM is no longer cut off, the
    attacker still out. Whichever rule is turned — the VM's, or the perimeter one (aimed
    at every address of the subnet)."""
    import shutil

    from glorfindel import escalations, reassert

    from .test_invariants import _CURRENT

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_edge_net())
        c, g = m.connector, m.fake.nsgs[key(_Q_EDGE_NSG)]
        first, then = ("vm", "subnet") if turned == _Q_API_BLOCK else ("subnet", "vm")
        for scope in (first, then):
            assert c.block_suspicious_ip(ATTACKER, API, scope=scope, threat_port=22)["status"] == "blocked"
        assert g["rules"][turned]["priority"] == 200, g["rules"][turned]
        g["rules"][turned]["access"] = "Allow"
        assert c.isolate_vm(API)["status"] == "isolated"
        m._delete_vm(API)
        m._create_vm(Script("rg-new", "web", _Q_API_NSG, "Linux"), "northeurope", reuse_nsg=_Q_API_NSG)
        assert _Q_NEW_WEB in m.live and not _reached_in(m, _Q_NEW_WEB)
        _CURRENT.mode = "non_disruptive"
        reassert.reassert_pass(c, None)
        assert not _reached_in(m, _Q_NEW_WEB), "the orphan sweep let the attacker in"
        assert _Q_API_ISO in m.fake.nsgs[key(_Q_API_NSG)]["rules"]
        said = [e for e in escalations.pending() if e.get("action") == "remove_orphan_rule"
                and turned in (e.get("reason") or "")]
        assert said and "retournée en autorisation" in said[0]["reason"], escalations.pending()
        g["rules"][turned]["access"] = "Deny"                     # the operator, from the card
        reassert.reassert_pass(c, None)
        assert not _reached_in(m, _Q_NEW_WEB)
        assert _Q_API_ISO not in m.fake.nsgs[key(_Q_API_NSG)]["rules"]
        assert any(f[2] == "in" and f[4] == 22 for f in m._open(_Q_NEW_WEB)), "the new VM still cut off"
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


def test_a_card_names_the_turned_rule_by_its_whole_name(monkeypatch):
    """Seed 31337 at 500 (I5Q, after its review), as the machine drew it. Two denies of a
    deleted VM kept behind two turned rules (the perimeter's inbound, api's outbound), and
    an older card of another orphan rule of the IP, said in human_only: the perimeter's
    name begins every VM rule of its IP — read as a substring, that card « named » the
    perimeter and was kept, still telling to delete; and the VM's card named only the
    first turned rule. U1 asks a pending card naming each, by its whole name, that
    doesn't say first to delete."""
    _run(monkeypatch, {**_net(api_nic={"rules": [
        _rule("allow-https", 100, dict(access="Allow", direction="Inbound", source_address_prefix="Internet",
                                        destination_address_prefix="*", destination_port_range="443")),
        _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                              destination_address_prefix="VirtualNetwork",
                                              destination_port_range="*"))]},
        web_nic={"own": "dedicated"}), "edge_nsg": []},
         ("turned_then_address_reused", API, API, None, 22, "both", 22, (key(_Q_EDGE_NSG), _Q_API_BLOCK),
          "non_disruptive", False, 22, False, "rg-app2", "api", None, "Linux", False, "human_only"),
         ("tamper_with_our_rule", "access", (key(_Q_EDGE_NSG), _Q_PERIMETER)),
         ("time_passes",),
         ("block_turned_then_reasserted", WEB1, WEB1, (1, "before-429"), "both", 22,
          (key(_Q_EDGE_NSG), f"{_Q_API_BLOCK}-out"), "non_disruptive"),
         ("address_reused", "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/api",
          "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/api", None, True,
          False, "rg-new", "web", None, "Linux", True, None, "non_disruptive"))


@pytest.mark.parametrize("state", ["kept", "isolation lost"])
def test_a_deleted_vms_deny_behind_a_turned_rule_stays_with_its_release(monkeypatch, state):
    """The same hole on the other path that takes a deleted VM's denies off: its release
    — found by the machine once `turned_then_address_reused` was added (seed 322 at 500:
    « I4: an operation on …/rg-edge/…/api opened flows of …/rg-app2/…/api »). api blocked
    for itself (200), then on its subnet (210), isolated there by rules (100); its own
    block rule turned into an allow; api deleted, a new VM at its address on the same
    subnet. The release took the isolation off: the attacker reached the new VM through
    the turned rule. The deny stays, said (`release_partial`, the turned rule named);
    once that rule is put back, the next release takes it off. Whether the release reads
    the isolation's placements (`kept`) or looks for its names on every NSG, its state
    lost and the block's naming the NIC (I7S's `_gone_vm_rules`)."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build({**_net(), "edge_nsg": []})
        c, g = m.connector, m.fake.nsgs[key(_Q_EDGE_NSG)]
        for scope in ("vm", "subnet"):
            assert c.block_suspicious_ip(ATTACKER, API, scope=scope, threat_port=22)["status"] == "blocked"
        g["rules"][_Q_API_BLOCK]["access"] = "Allow"
        assert c.isolate_vm(API)["status"] == "isolated"
        if state == "isolation lost":
            m._lose_state(API)
        m._delete_vm(API)
        m._create_vm(Script("rg-app2", "api", None, "Linux"), "northeurope")
        new = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/api"
        assert new in m.live and not _reached_in(m, new)
        out = c.release_isolation(API)
        assert not _reached_in(m, new), "the release of the deleted VM let the attacker in"
        assert out["status"] == "release_partial", out
        assert any(_Q_API_BLOCK in f and "retournée en autorisation" in f for f in out["failed"]), out
        g["rules"][_Q_API_BLOCK]["access"] = "Deny"                 # the operator, from what was said
        out = c.release_isolation(API)
        assert out["status"] == "released", out
        assert not _reached_in(m, new)
        assert not [n for n in g["rules"] if n.startswith(_Q_API_ISO)]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


@pytest.mark.parametrize("listing", ["read", "refused", "refused, address moved"])
def test_a_live_vms_release_is_not_held_by_its_own_turned_rule(monkeypatch, listing):
    """The guard is for another VM at the address: api, alive, its own block rule turned
    into an allow, is released as usual — what that rule lets through is someone's doing
    on api's own address (I1 judges it so), not an opening of another VM. The NSGs'
    listing refused: its NIC is read, alive — released too (the review of I5Q); unless the
    NIC no longer holds every address the rule denies (its second review): another VM may
    hold it now — kept, `release_partial`."""
    import shutil

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build({**_net(), "edge_nsg": []})
        c, g = m.connector, m.fake.nsgs[key(_Q_EDGE_NSG)]
        for scope in ("vm", "subnet"):
            assert c.block_suspicious_ip(ATTACKER, API, scope=scope, threat_port=22)["status"] == "blocked"
        g["rules"][_Q_API_BLOCK]["access"] = "Allow"
        assert c.isolate_vm(API)["status"] == "isolated"
        if listing.startswith("refused"):                     # the guard's listing, once
            real, calls = m.fake.network.network_security_groups.list_all, []

            def refused(*a, **k):
                calls.append(1)
                if len(calls) == 1:
                    raise RuntimeError("(AuthorizationFailed) no list")
                return real(*a, **k)
            monkeypatch.setattr(m.fake.network.network_security_groups, "list_all", refused)
        if listing.endswith("moved"):
            m.fake.nics[_nic("rg-edge", "api-nic")]["ips"] = ["10.1.0.40"]
            out = c.release_isolation(API)
            assert out["status"] == "release_partial" and any("gardée" in f for f in out["failed"]), out
            assert [n for n in g["rules"] if n.startswith(_Q_API_ISO)]
            return
        assert c.release_isolation(API)["status"] == "released"
        assert not [n for n in g["rules"] if n.startswith(_Q_API_ISO)]
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


# ── Found on the way (I5Q), outside its cause: L2, frozen for a lot of its own ──────────

_L2_NET = {'subnet_nsg': [_rule('allow-https', 100, dict(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_address_prefix='*', destination_port_range='443')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*'))], 'edge_nsg': None, 'tier_rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'nics': {'web-nic': {'own': None, 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'policy': False}, 'db-nic-0': {'own': None, 'rules': [_rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*'))], 'policy': False}, 'db-nic-1': {'own': 'dedicated', 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*'))], 'policy': False}, 'api-nic': {'own': None, 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22'))], 'policy': False}}, 'windows': None, 'config': {'quarantine': False, 'readable': True, 'forensic': [], 'rg': ''}, 'legacy': None, 'data_subnet': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))]}
_L2_STEPS = [
    ('block_then_isolate', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', None, 22, None, True, False),
    ('config_changes', {'quarantine': False, 'rg': 'rg-sec', 'readable': True, 'forensic': []}, False),
    ('delete_vm', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web'),
    ('block', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22),
    ('block_turned_then_reasserted', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 'both', 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-80ab3c'), 'non_disruptive'),
    ('address_reused', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, True, False, 'rg-new', 'web', None, 'Linux', False),
    ('reassert', 'non_disruptive', None),
    ('bare_with_an_unknown_original', '/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api', '/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api', None, '/subscriptions/s/resourcegroups/rg-edge/providers/microsoft.network/networkinterfaces/api-nic', 'isolate+release', None),
    ('address_reused', '/subscriptions/s/resourceGroups/rg-new/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-new/providers/Microsoft.Compute/virtualMachines/web', ('nic.get', 'always-429'), True, True, 'rg-app1', 'api', None, 'Linux', False),
    ('quarantine_altered_then_reasserted', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/api', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/api', None, False, True, '/subscriptions/s/resourcegroups/rg-sec/providers/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope', 'human_only', 'role removed', '/subscriptions/s/resourcegroups/rg-sec/providers/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope', 1, 'human_only'),
    ('config_changes', {'quarantine': True, 'forensic': ['10.9.9.9'], 'readable': True, 'rg': ''}, True),
    ('reassert', 'human_only', (14, 'before-429')),
    ('config_changes', {'quarantine': False, 'rg': '', 'readable': True, 'forensic': []}, False),
    ('block_turned_then_reasserted', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01', None, 'both', 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-80ab3c-out'), 'non_disruptive'),
]


def test_an_altered_quarantine_stays_said_when_its_change_comes_back(monkeypatch):
    """Graine 101 at 500 sequences, after RB1 (I5Q's run), shrunk to 14 steps — written
    with the rules of the machine as `main` has them: it failed there too, glorfindel/ of
    171a242 and b83cb92 (« L2: the quarantine NSG …/nsg-glorfindel-quarantine-westeurope
    was altered, holds […/api-nic-5] »). The configuration is readable at every step.
    Cause (reassert_quarantine._report_altered_quarantines): step 9 strips the NSG, a card
    says change A; step 11 adds a forensic access, change B — card A closed, card B
    written, but the write of quarantine_alerts.json fails (the 14th write, a full disk):
    the file keeps A; step 12 takes the access off, the diff comes back to A; step 13's
    pass closes card B and read A in the file as « said, or acknowledged » — no card, the
    NSG still stripped. Now only the operator's word silences a change: the latest card of
    the NSG is A's, closed without Glorfindel's note (L2Q, #331)."""
    _run(monkeypatch, _L2_NET, *_L2_STEPS)


_Q_APP1 = "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope"


@pytest.mark.parametrize("readable", [True, False], ids=["access_taken_off", "config_unreadable"])
def test_a_quarantine_change_brought_back_after_a_full_disk_is_said(monkeypatch, readable):
    """The machine's own rule for it (`quarantine_change_comes_back`, L2Q): web isolated in
    our quarantine, its state lost, the NSG stripped — said (A). A forensic access added:
    change B, the disk full from the pass's third write of the local state (A's card closed,
    B's written, quarantine_alerts.json not). The access taken off, or the configuration
    unreadable and hiding it: the diff is A's again — said again."""
    _run(monkeypatch, _net(quarantine=True),
         ("quarantine_change_comes_back", WEB1, WEB1, None, True, True, _Q_APP1, "human_only", "no",
          "human_only", (3, "from-full"), readable, "human_only"))


# ── L2C (#343): the other cards of the reassertion, after a full disk ──────────────────

_NSG_WEB = "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/nsg-web-nic"


@pytest.mark.parametrize("isolation, rule", [(False, "allow-https"), (True, "deny-lateral-in")],
                         ids=["block", "isolation"])
def test_a_bypass_brought_back_after_a_full_disk_is_said(monkeypatch, isolation, rule):
    """The machine's own rule (`said_then_back_after_a_full_disk`, L2C): web blocked (port
    22), or isolated by rules, on its own NSG — our deny at 101, behind a rule of the
    customer's at 100 —; that rule widened into an allow of all: bypassed, said (A). Put
    back as it was during a pass where the disk fills up from its second write of the
    local state: our deny holds again, A's card closed (Glorfindel's note), its mark not
    taken off. Widened again: A, read « said » from the mark — no card, before L2C.
    (Back to another allow instead — a mark kept on A, B's card pending —: the stale card
    stays until L2C, tests/unit/test_reassert.py; this oracle takes any card on the VM.)"""
    tpl = (dict(access="Allow", direction="Inbound", source_address_prefix="Internet",
                destination_address_prefix="*", destination_port_range="443") if rule == "allow-https" else
           dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                destination_address_prefix="*", destination_port_range="*"))
    _run(monkeypatch, _net(web_nic={"own": "dedicated", "rules": [_rule(rule, 100, tpl)]}),
         ("said_then_back_after_a_full_disk", "bypass", WEB1, WEB1, None, isolation, *([] if isolation else [22]),
          (101, _NSG_WEB), rule, "human_only", "human_only", (2, "from-full"), "human_only"))


@pytest.mark.parametrize("another, n", [(False, 2), (True, 3)], ids=["reads_again", "another_file_too"])
def test_an_unreadable_state_brought_back_after_a_full_disk_is_said(monkeypatch, another, n):
    """The same rule for a local state file (SEC4b): one unreadable, said (A); it reads
    again — or a second one turns unreadable too (B) — during a pass where the disk fills
    up: A's card closed, state_alerts.json not written (it keeps A). The first set again:
    read « said » from the record, no card, before L2C. Found by the machine alone on
    `main` at 500 sequences, seeds 101, 202, 322, 42, 777 and 1."""
    _run(monkeypatch, _net(),
         ("said_then_back_after_a_full_disk", "unreadable state", "human_only", another, "human_only", (n, "from-full"),
          "human_only"))


@pytest.mark.parametrize("isolation", [True, False], ids=["isolation", "block"])
def test_a_disappearance_after_one_acknowledged_and_held_again_is_said_by_the_machine(monkeypatch, isolation):
    """The same rule, its branch for the review of L2C: web isolated by rules on its own
    NSG, or blocked there; our rules taken off — said; the operator acknowledges it; the
    rules put back during a pass where the disk is full from its first write of the local
    state (the drift mark not taken off); taken off again. Before the review's fix: read
    « already said » from the mark — no card, the VM open again."""
    _run(monkeypatch, _net(web_nic={"own": "dedicated"}),
         ("said_then_back_after_a_full_disk", "gone", WEB1, WEB1, None, isolation, *([] if isolation else [22]),
          (1, "from-full")))


_S101_SSH = dict(access="Allow", direction="Inbound", source_address_prefix="*", destination_address_prefix="*",
                 destination_port_range="22")
_S101_DENY = dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                  destination_address_prefix="*", destination_port_range="*")
_S101_NET = {
    "subnet_nsg": None,
    "edge_nsg": [_rule("allow-ssh", 100, _S101_SSH), _rule("deny-lateral-in", 130, _S101_DENY),
                 _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                                      destination_address_prefix="VirtualNetwork",
                                                      destination_port_range="*"))],
    "tier_rules": [],
    "nics": {"web-nic": {"own": "tier", "rules": [], "policy": True},
             "db-nic-0": {"own": "dedicated", "rules": [], "policy": False},
             "db-nic-1": {"own": None, "rules": [], "policy": False},
             "api-nic": {"own": "dedicated", "policy": False,
                         "rules": [_rule("allow-ssh", 100, _S101_SSH), _rule("deny-lateral-in", 130, _S101_DENY)]}},
    "windows": None, "config": {"quarantine": False, "rg": "", "forensic": [], "readable": True},
    "legacy": ("api-nic", False), "data_subnet": None}
_S101_NSG = "/subscriptions/s/resourcegroups/{}/providers/microsoft.network/networksecuritygroups/{}"
_S101_API2 = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/api"


@pytest.mark.xfail(strict=True, reason="L1 outside L2C (to route): present on origin/main ba657a0, without L2C's rule")
def test_a_block_put_back_on_a_new_vm_stays_said_after_an_acknowledgement(monkeypatch):
    """Seed 101 at 500 sequences on L2C's final code, shrunk: none of L2C's steps nor its
    fault, and it fails as well with glorfindel/ of origin/main (ba657a0) — « L1: the block
    on …/rg-app2/…/api vanished from Azure; the reassertion neither put it back nor said
    so ». An old isolation's VM gone, a new `api` given its NSG, blocked on its subnet and
    for itself, one of its block denies turned into an allow and reasserted; the operator
    acknowledges a card, `terraform apply` on the subnet's NSG, an IP changed, then web of
    rg-app2 blocked the same way. Cause not established; frozen for its own lot."""
    _run(monkeypatch, _S101_NET,
         ("address_reused", WEB1, WEB1, None, False, 22, False, "rg-app1", "api", None, "Linux", True, None,
          "human_only"),
         ("time_passes",), ("time_passes",),
         ("access_changes", False),
         ("terraform_apply", _S101_NSG.format("rg-app1", "nsg-db-nic-0")),
         ("an_old_isolations_vm_goes_away", (_S101_NSG.format("rg-edge", "nsg-api-nic"), API), False, False,
          "rg-app2", "api", "Linux", True, _S101_API2),
         ("block_turned_then_reasserted", _S101_API2, _S101_API2, None, "both", 22,
          (_S101_NSG.format("rg-edge", "nsg-api-nic"), "glorfindel-block-192-31-196-7-api-api-nic-5-cdd247"),
          "non_disruptive"),
         *[("time_passes",)] * 8,
         ("operator_acknowledges", 0),
         ("time_passes",),
         ("terraform_apply", _S101_NSG.format("rg-edge", "nsg-edge")),
         ("customer_changes_ip", "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/"
                                 "networkinterfaces/api-nic-4", 0, 4),
         ("time_passes",),
         ("block_turned_then_reasserted", WEB2, WEB2, None, "both", 22,
          (_S101_NSG.format("rg-net", "nsg-tier"), "glorfindel-block-192-31-196-7-web-web-nic-80ab3c"),
          "non_disruptive"))


_S42_SSH = dict(access="Allow", direction="Inbound", source_address_prefix="*", destination_address_prefix="*",
                destination_port_range="22")
_S42_NET = {
    "subnet_nsg": [], "edge_nsg": None,
    "tier_rules": [_rule("allow-ssh", 100, _S42_SSH),
                   _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound",
                                                        source_address_prefix="*",
                                                        destination_address_prefix="VirtualNetwork",
                                                        destination_port_range="*"))],
    "nics": {"web-nic": {"own": None, "rules": [], "policy": False},
             "db-nic-0": {"own": "dedicated", "rules": [], "policy": False},
             "db-nic-1": {"own": "tier", "policy": False, "rules": [
                 _rule("allow-ssh", 100, _S42_SSH),
                 _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound",
                                                    source_address_prefix="VirtualNetwork",
                                                    destination_address_prefix="*", destination_port_range="*"))]},
             "api-nic": {"own": "dedicated", "rules": [], "policy": False}},
    "windows": None, "config": {"quarantine": False, "rg": "", "forensic": [], "readable": True},
    "legacy": None, "data_subnet": None}


@pytest.mark.xfail(strict=True, reason="L1 outside L2C (to route): present on origin/main ba657a0, without L2C's rule")
def test_a_merged_block_whose_perimeter_terraform_removed_is_said(monkeypatch):
    """Seed 42 at 2 000 sequences on L2C's final code, shrunk — then its last step, L2C's
    rule, replaced by a plain pass: it fails the same, and with glorfindel/ of origin/main
    (ba657a0). Db--01 blocked on its subnet, then blocked and isolated under a throttled
    subnet read (always 429); `terraform apply` on the subnet's NSG takes our perimeter
    rules off, someone detaches the quarantine, time passes: « L1: the block on
    …/Db--01 vanished from Azure; the reassertion neither put it back nor said so ».
    Cause not established; frozen for its own lot."""
    _run(monkeypatch, _S42_NET,
         ("race", WEB1, ("release", "reassert"), 0),
         ("block_perimeter", DB, DB, None, False),
         ("access_changes", False),
         ("block_then_isolate", DB, DB, ("subnet.get", "always-429"), 22, None, False, False),
         ("terraform_apply", _S101_NSG.format("rg-net", "nsg-subnet")),
         ("someone_detaches_the_quarantine", None),
         ("time_passes",), ("time_passes",), ("time_passes",),
         ("reassert", "human_only", None))


# ── I5Q, its second review: seed 322 at 2 000 after I4A's merge ─────────────────────────

_S322_NET_KEPT = {'subnet_nsg': [], 'edge_nsg': None, 'tier_rules': [], 'nics': {'web-nic': {'own': None, 'rules': [], 'policy': False}, 'db-nic-0': {'own': None, 'rules': [], 'policy': False}, 'db-nic-1': {'own': None, 'rules': [], 'policy': False}, 'api-nic': {'own': None, 'rules': [], 'policy': False}}, 'windows': None, 'config': {'quarantine': False, 'rg': '', 'forensic': [], 'readable': True}, 'legacy': None, 'data_subnet': None}
_S322_STEPS_KEPT = [
    ('time_passes',),
    ('interrupted_release', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', (1, 'before-429'), 1, 'before-crash', False),
    ('time_passes',),
    ('address_reused_under_a_turned_rule', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-8b70f2'), '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networkinterfaces/web-nic', 0, 4, 'rg-app1', 'api', None, 'Linux'),
]


def test_a_live_vm_whose_deny_waits_before_a_turned_rule_is_released_once_it_is_put_back(monkeypatch):
    """Seed 322 at 2 000 (I5Q after I4A): web blocked, its own rule turned into an allow,
    its IP changed, a new VM at its old address (I4A's composite rule), then web's
    release: its isolation's deny on the old address now cuts the new VM, and web's
    turned rule waits behind it — the release keeps it, `release_partial`, the turned
    rule named. The teardown's operator, who put back only what deleted VMs' denies held
    back, now puts back what any deny of ours on another NIC's address holds back: I7."""
    _run(monkeypatch, _S322_NET_KEPT, *_S322_STEPS_KEPT)


_S322_NET_ISO = {'subnet_nsg': [], 'edge_nsg': None, 'tier_rules': [], 'nics': {'web-nic': {'own': None, 'rules': [], 'policy': False}, 'db-nic-0': {'own': None, 'rules': [], 'policy': False}, 'db-nic-1': {'own': None, 'rules': [], 'policy': False}, 'api-nic': {'own': None, 'rules': [], 'policy': False}}, 'windows': None, 'config': {'quarantine': False, 'rg': '', 'forensic': [], 'readable': True}, 'legacy': None, 'data_subnet': None}
_S322_STEPS_ISO = [
    ('time_passes',),
    ('interrupted_release', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 1, 'before-crash', False),
    ('time_passes',),
    ('time_passes',),
    ('address_reused_under_a_turned_rule', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-8b70f2'), '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networkinterfaces/web-nic', 0, 4, 'rg-new', 'web', None, 'Linux'),
    ('block_perimeter', '/subscriptions/s/resourceGroups/rg-new/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourcegroups/rg-new/providers/microsoft.compute/virtualmachines/web', None, False),
    ('tamper_with_our_rule', 'retarget', ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7')),
    ('turned_then_address_reused', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', (8, 'before-429'), None, 'both', 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-b-8b70f2'), 'non_disruptive',
     # The rest of the step, never reached while the sequence failed inside it (I4B): blocked,
     # its state kept, a new VM at its address, no posture pass; the reassertion outside human_only.
     False, 22, False, 'rg-app1', 'batch', None, 'Linux', False, 'non_disruptive'),
]


def test_a_reasserted_isolation_moves_off_the_old_address_a_turned_rule_waits_behind(monkeypatch):
    """Seed 322 at 2 000 (I5Q after I4A). web's IP changed under a turned block rule of its
    own (I4A's composite rule), a new VM at the old address; the reassertion puts web's
    isolation back under the same names, now on its new address — the deny that held
    the old address goes with it, and the new VM opens to the attacker through web's
    turned rule (« I5: the reassertion opened flows of …/rg-new/…/web »). The isolation's
    side of what I4A did for blocks (a second name), frozen there in
    `test_an_isolation_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address`.
    I4B: the deny on the old address stays (a turned rule of ours waits behind it, on an NSG
    that governs the new VM: _held_by_turned), the isolation goes under the second name."""
    _run(monkeypatch, _S322_NET_ISO, *_S322_STEPS_ISO)


_S322_NET_REL = {'subnet_nsg': [_rule('allow-https', 100, dict(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_address_prefix='*', destination_port_range='443')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'edge_nsg': None, 'tier_rules': [_rule('allow-https', 100, dict(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_address_prefix='*', destination_port_range='443'))], 'nics': {'web-nic': {'own': None, 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'policy': True}, 'db-nic-0': {'own': None, 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*'))], 'policy': False}, 'db-nic-1': {'own': None, 'rules': [_rule('allow-https', 100, dict(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_address_prefix='*', destination_port_range='443')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'policy': True}, 'api-nic': {'own': 'dedicated', 'rules': [_rule('allow-ssh', 100, dict(access='Allow', direction='Inbound', source_address_prefix='*', destination_address_prefix='*', destination_port_range='22')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))], 'policy': False}}, 'windows': None, 'config': {'quarantine': True, 'rg': '', 'forensic': [], 'readable': True}, 'legacy': None, 'data_subnet': [_rule('allow-https', 100, dict(access='Allow', direction='Inbound', source_address_prefix='Internet', destination_address_prefix='*', destination_port_range='443')), _rule('allow-lateral-out', 100, dict(access='Allow', direction='Outbound', source_address_prefix='*', destination_address_prefix='VirtualNetwork', destination_port_range='*')), _rule('deny-lateral-in', 130, dict(access='Deny', direction='Inbound', source_address_prefix='VirtualNetwork', destination_address_prefix='*', destination_port_range='*'))]}
_S322_STEPS_REL = [
    ('block_then_isolate', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, None, False, False),
    ('customer_edits_rule', '/subscriptions/s/resourcegroups/rg-edge/providers/microsoft.network/networksecuritygroups/nsg-api-nic', 'allow-lateral-out', ('source_address_prefix', '10.9.0.0/16')),
    ('reassert', 'human_only', None),
    ('interrupted_release', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 7, 'before-crash', True, 'human_only', None),
    ('isolate', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None),
    ('config_changes', {'quarantine': True, 'rg': '', 'forensic': [], 'readable': True}, True),
    ('time_passes',),
    ('time_passes',),
    ('customer_changes_ip', '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networkinterfaces/web-nic', 0, 4),
    ('joins_an_old_isolation', None),
    ('interrupted_release', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01', None, 1, 'before-crash', False),
    ('address_reused_under_a_turned_rule', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-8b70f2'), '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networkinterfaces/web-nic', 0, 4, 'rg-app1', 'web'),
    ('block_then_isolate', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, ('nic.get', 'always-429'), True, '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/nsg-glorfindel-quarantine-westeurope', False),
    ('release', '/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api', '/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api', None),
    ('reset_from_azure', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web', None),
    ('isolate_two', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, False),
    ('address_reused_under_a_turned_rule', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None, 22, ('/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-subnet', 'glorfindel-block-192-31-196-7-web-web-nic-8b70f2'), '/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networkinterfaces/web-nic', 0, 4, 'rg-app2', 'batch', None, 'Windows'),
    ('lose_state', '/subscriptions/s/resourceGroups/rg-edge/providers/Microsoft.Compute/virtualMachines/api'),
    ('interrupted_release', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', '/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web', None,
     # The rest of the step, never reached while its isolation failed (I4B): the release cut at
     # its first call, no reassertion.
     1, 'before-crash', False),
]


def test_an_interrupted_release_after_an_ip_change_opens_the_new_owner(monkeypatch):
    """Seed 322 at 2 000 (I5Q after I4A), 18 steps, fails with glorfindel/ of 20cb5b5 too:
    « I4: an operation on …/rg-app1/…/web opened flows of …/rg-app2/…/batch », in an
    interrupted release of web after its IP changed and another VM took the old address.
    Cause (I4B): not the release — the isolation that step begins with. web's isolation
    deny on its old address (batch's now) had one of web's block rules, turned into an
    allow, waiting behind it on the subnet's NSG; isolated again, the deny was rewritten
    for web's new address and the turned rule let the attacker reach batch. The same as
    the reassertion's case above: the deny stays, said, the isolation under the second
    name."""
    _run(monkeypatch, _S322_NET_REL, *_S322_STEPS_REL)


# ── I4B, the seventh case: the CI's macOS run (a random seed at 500), on main before I4B ──

_Q_NORTH = ("/subscriptions/s/resourcegroups/rg-edge/providers/microsoft.network/networksecuritygroups/"
            "nsg-glorfindel-quarantine-northeurope")


@pytest.mark.parametrize("entry", ["lost", "kept"])
def test_the_unblock_finds_the_block_of_a_nic_left_with_no_nsg_it_knows(monkeypatch, entry):
    """The CI's macOS run, 39 steps, shrunk by hand to these: api blocked on its own NSG
    (its entry lost: a crash after the writes), isolated by quarantine, its state and our
    tags lost, the quarantine taken off by someone — the NIC bare —, isolated again: its
    original now « none ». The teardown's release puts it back bare, as that state says;
    the unblock looked at the NSGs the NIC carries, none — `not_found` while the block's
    rules stood on nsg-api-nic, named for the NIC (« I7: block rules of …/api left after
    unblock »). Code, not the machine: those names carry the NIC's hash, no other NIC's —
    the unblock now looks for them on every NSG, as for a deleted VM's (I7S). Its entry
    kept, the placements already name that NSG: the same end."""
    steps = [("block", API, API, (2, "after-crash") if entry == "lost" else None, 22),
             ("config_changes", {"quarantine": True, "rg": "", "forensic": [], "readable": True}, True),
             ("isolate", API, API, None),
             ("lose_state", API),
             ("tags_lost", _Q_NORTH),
             ("someone_detaches_the_quarantine", _nic("rg-edge", "api-nic")),
             ("isolate", API, API, None)]
    _run(monkeypatch, _net(api_nic={"own": "dedicated"}), *steps)


def test_the_search_on_every_nsg_keeps_a_turned_rule_aimed_at_the_vm_that_took_the_address(monkeypatch):
    """The search above, asked about too (review of I4B): api blocked on its own NSG, its
    entry lost, its inbound rule turned into an allow by someone; api's IP changed, its NSG
    taken off it (the NIC bare) and given to a new VM at the old address. The unblock finds
    api's rules on that NSG by its mark — the turned allow lets the attacker reach the new
    VM: taken off, that VM lost those flows (I4). It stays, said; the -out deny on the old
    address, nothing waiting behind it, goes."""
    import shutil

    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(api_nic={"own": "dedicated"}))
        assert m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)["status"] == "blocked"
        for f in actions._BLOCK_STATE_DIR.glob("api--*.json"):
            f.unlink()
        rules = m.fake.nsgs[key(_Q_API_NSG)]["rules"]
        old = rules[_Q_API_BLOCK]["destination_address_prefixes"]
        rules[_Q_API_BLOCK]["access"] = "Allow"
        m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 20))
        m.fake.nics[_nic("rg-edge", "api-nic")]["nsg"] = None                  # someone, by hand
        m.create_vm(data=Script("northeurope", "rg-app1", "api", _Q_API_NSG, "Linux"))
        assert m.fake.nics[_nic("rg-app1", "api-nic-4")]["ips"] == old
        reach = m._attacker_flows(_NEW_API_VM, None)
        assert reach
        out = m.connector.unblock_ip(ATTACKER, API)
        assert m._attacker_flows(_NEW_API_VM, None) >= reach
        assert rules[_Q_API_BLOCK]["access"] == "Allow"
        assert out["status"] == "unblock_partial", out
        assert any(_Q_API_BLOCK in f and "gardée" in f and old[0] in f for f in out["failed"]), out
        assert f"{_Q_API_BLOCK}-out" not in rules
    finally:
        shutil.rmtree(m.home, ignore_errors=True)


# ── I4B: seed 101 at 500 once the unblock keeps what it must — a gap of the teardown's operator ──

_S101_EDGE = "/subscriptions/s/resourcegroups/rg-edge/providers/microsoft.network/networksecuritygroups/nsg-edge"
_S101_API1 = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/api"


def test_a_turned_rule_put_back_may_hold_back_another_in_its_turn(monkeypatch):
    """Seed 101 at 500 on I4B's code (« I7: block rules of …/api left after unblock: […-out] »):
    api's -out turned into an allow, its IP changed, a new VM api at the old address, blocked
    in its turn, its own -out turned as well. The teardown's operator put back api's turned
    -out (it aims at the new VM: the unblock keeps it, said) — a deny of ours on the new VM's
    address again, now holding back the new VM's turned -out, which the operator had looked
    for before and not found. The machine, not the code: the operator puts back until nothing
    said is left (`_operator_puts_turned_back`)."""
    net = {**_net(quarantine=True, db_nic_1={"own": "dedicated"}), "edge_nsg": [
        _rule("allow-https", 100, dict(access="Allow", direction="Inbound", source_address_prefix="Internet",
                                        destination_address_prefix="*", destination_port_range="443")),
        _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                              destination_address_prefix="VirtualNetwork", destination_port_range="*")),
        _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                            destination_address_prefix="*", destination_port_range="*"))]}
    net["tier_rules"] = [
        _rule("allow-ssh", 100, dict(access="Allow", direction="Inbound", source_address_prefix="*",
                                      destination_address_prefix="*", destination_port_range="22")),
        _rule("allow-lateral-out", 100, dict(access="Allow", direction="Outbound", source_address_prefix="*",
                                              destination_address_prefix="VirtualNetwork", destination_port_range="*")),
        _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                            destination_address_prefix="*", destination_port_range="*"))]
    q = ("/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/networksecuritygroups/"
         "nsg-glorfindel-quarantine-westeurope")
    _run(monkeypatch, net,
         ("customer_removes_rule", _S101_EDGE, "allow-https"),
         ("recover",), ("recover",),
         ("create_vm", "northeurope", "rg-app1", "batch", None, "Linux"),
         *[("recover",)] * 9,
         ("create_vm", "westeurope", "rg-new", "web", None, "Linux"),
         ("isolate", WEB1, WEB1, None),
         ("isolate_two", WEB1, WEB1, None, WEB1, WEB1, None, True),
         ("isolate", WEB1, WEB1, None),
         ("address_reused_under_a_turned_rule", API, API, None, 22, (_S101_EDGE, f"{_Q_API_BLOCK}-out"),
          _nic("rg-edge", "api-nic"), 0, 4, "rg-app1", "api", None, "Linux"),
         ("operator_acknowledges", 0),
         ("delete_vm", WEB1),
         ("interrupted_release", WEB2, WEB2, None, 1, "before-crash", False),
         ("access_changes", False),
         ("an_old_isolations_vm_goes_away", None),          # draws nothing here
         ("operator_acknowledges", 0),
         ("isolate_two", WEB2, WEB2, None, WEB2, WEB2, None, False),
         ("strip_quarantine_nsg", q),
         ("orphan_sweep", None, "human_only"),
         ("unblock", WEB2, WEB2, None),
         ("block_turned_then_reasserted", _S101_API1, _S101_API1, None, "vm", 22,
          (_S101_EDGE, "glorfindel-block-192-31-196-7-api-api-nic-6-c89eaa-out"), "human_only"))



# ── I4B: what the search on every NSG (_unplaced_blocks) would hide, held by its own tests ──

def test_an_unblock_reads_a_bare_nics_tag_where_its_block_lies(monkeypatch):
    """U3F's case, the subscription's NSGs unlisted: web blocked on its own NSG, its entry
    lost, isolated by quarantine, the quarantine taken off by someone — the NIC bare, the
    isolation's state lost too, our tag still naming its NSG. The unblock reads the tag and takes the block off there,
    without listing the subscription's NSGs; reading the state alone (M1345), the NIC
    looked unplaced and the search on every NSG, refused, left it said, not done."""
    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(quarantine=True, web_nic={"own": "dedicated"}))
        m.block(Script(WEB1, WEB1, None, 22))
        m.isolate(Script(WEB1, WEB1, None))
        actions._clear_block_state(WEB1, ATTACKER)
        m.someone_detaches_the_quarantine(Script(_nic("rg-app1", "web-nic")))
        m._lose_state(WEB1)                       # the isolation's too: only our tag says it

        def refused(*a, **k):
            raise RuntimeError("(AuthorizationFailed) no list")
        monkeypatch.setattr(m.fake.network.network_security_groups, "list_all", refused)
        out = m.connector.unblock_ip(ATTACKER, WEB1)
        assert out["status"] == "unblocked", out
        assert not m._named_leftovers(m.fake.vms[key(WEB1)]["nics"], "glorfindel-block-")
    finally:
        import shutil
        shutil.rmtree(m.home, ignore_errors=True)


def test_the_unblock_sweep_reads_the_second_name_on_a_nics_own_nsg(monkeypatch):
    """I4A's second name on a NIC's own NSG, its entry lost, the NIC's IP changed since:
    the deny is on an address no longer the NIC's — only its mark says it is its own. The
    sweep reads both names by the mark (M1761); the NIC has an NSG of its own, so the
    search on every NSG doesn't stand in for it."""
    from glorfindel import actions

    invariant_env(monkeypatch)
    m = IsolationMachine()
    try:
        m.build(_net(api_nic={"own": "dedicated"}))
        assert m.connector.block_suspicious_ip(ATTACKER, API, scope="vm", threat_port=22)["status"] == "blocked"
        g = m.fake.nsgs[key(_Q_API_NSG)]
        nic = m.fake.vms[key(API)]["nics"][0]
        first, second = m.connector._placement_rule_bases(m.connector._block_rule_prefix(ATTACKER), "api",
                                                          "api-nic", nic)
        for suffix in ("", "-out"):
            g["rules"][f"{second}{suffix}"] = {**g["rules"].pop(f"{first}{suffix}"), "name": f"{second}{suffix}"}
        for f in actions._BLOCK_STATE_DIR.glob("api--*.json"):
            f.unlink()
        m.customer_changes_ip(data=Script(_nic("rg-edge", "api-nic"), 0, 20))
        out = m.connector.unblock_ip(ATTACKER, API)
        assert out["status"] == "unblocked", out
        assert not [n for n in g["rules"] if n.startswith(second)], sorted(g["rules"])
    finally:
        import shutil
        shutil.rmtree(m.home, ignore_errors=True)



# ── I4B, its review: the sequence of PR #342's CI (I5), replayed draw by draw ──────────────

_PR342_LAT = _rule("deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                                 destination_address_prefix="*", destination_port_range="*"))
_PR342_NET = {"subnet_nsg": [_rule("allow-ssh", 100, dict(access="Allow", direction="Inbound", source_address_prefix="*",
                                                          destination_address_prefix="*", destination_port_range="22")),
                             _PR342_LAT],
              "edge_nsg": None, "tier_rules": [],
              "nics": {"web-nic": {"own": "tier", "rules": [], "policy": True},
                       "db-nic-0": {"own": None, "rules": [], "policy": False},
                       "db-nic-1": {"own": None, "rules": [], "policy": False},
                       "api-nic": {"own": "dedicated", "rules": [_PR342_LAT], "policy": False}},
              "windows": None, "config": {"quarantine": False, "readable": True, "forensic": [], "rg": ""},
              "legacy": ("api-nic", False), "data_subnet": [_PR342_LAT]}
_PR342_NSG = "/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/"
_PR342_DB_RULE = (_PR342_NSG + "nsg-data", "glorfindel-block-192-31-196-7-db--01-db-nic-1-1232a8")
_PR342_STEPS = [
    ("reset_from_azure", WEB1, WEB1, None),
    ("someone_detaches_the_quarantine", None),                 # draws nothing here: no NIC in quarantine
    ("isolate_two", WEB1, WEB1, ("nic.get", "always-429"), WEB2, WEB2, None, False),
    ("verify", WEB1, WEB1, None),
    ("turned_then_address_reused", DB, DB, None, 22, "both", 22, _PR342_DB_RULE, "non_disruptive", False, 22, False,
     "rg-app1", "web", False, "non_disruptive"),
    ("block_turned_then_reasserted", WEB1, WEB1, None, "both", 22, _PR342_DB_RULE, "human_only"),
    ("strip_quarantine_nsg", None),                            # draws nothing here: no quarantine NSG
    ("joins_an_old_isolation", "/subscriptions/s/resourcegroups/rg-edge/providers/microsoft.network/"
     "networksecuritygroups/nsg-api-nic", "rg-new", "web", "Linux", False, False),
    ("address_reused_under_a_turned_rule", WEB2, WEB2, None, 22,
     (_PR342_NSG + "nsg-tier", "glorfindel-block-192-31-196-7-web-web-nic-80ab3c"),
     "/subscriptions/s/resourcegroups/rg-app2/providers/microsoft.network/networkinterfaces/web-nic", 0, 4,
     "rg-app2", "api", "/subscriptions/s/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/"
     "nsg-tier", "Linux"),
    ("block_turned_then_reasserted", WEB1, WEB1, None, "both", 22,
     (_PR342_NSG + "nsg-tier", "glorfindel-block-192-31-196-7-web-web-nic-8b70f2"), "non_disruptive"),
]


def test_the_sequence_of_pr_342_reasserts_without_opening_the_vm_at_the_old_address(monkeypatch):
    """The CI of PR #342, replayed draw by draw by I4B's review; on `main` 897cd21: « I5: the
    reassertion opened flows of …/rg-app2/…/api ». web2's IP changed under a turned block rule
    of its own on the tier NSG, a new VM api at the old address; web1 blocked, its rule turned
    on the same NSG, then reasserted outside human_only — the isolation or the block written
    again moved our deny off the old address, a turned rule of ours waiting behind it: the
    new VM opened. The only sequence that catches M1898 (the isolation written over what the
    guard keeps) outside its own."""
    _run(monkeypatch, _PR342_NET, *_PR342_STEPS)



# ── I4B: the nightly run of 30/10 on 897cd21, replayed by every macOS job since (its database) ──

def test_the_nightly_isolation_after_an_address_reused_under_a_turned_rule(monkeypatch):
    """The nightly run of 30/10 (897cd21), saved in Hypothesis's cached database and replayed
    by the macOS job of every PR since: « I4: an operation on …/rg-app1/…/web opened flows of
    …/rg-app1/…/batch ». web isolated on the tier NSG (a 429 at its eighth call), blocked, its
    rule turned into an allow there, its IP changed, batch at the old address on that NSG; a
    customer IP change elsewhere; then web isolated again as its interrupted release begins.
    I4B's seventh case: the isolation written again moved our deny off the old address, the
    turned rule behind it — batch opened. On I4B the blob no longer reproduces (the step goes
    on): here the rest of the step's draws — the release cut at its first call, no
    reassertion."""
    tier = "/subscriptions/s/resourcegroups/rg-net/providers/microsoft.network/networksecuritygroups/nsg-tier"
    _run(monkeypatch, {**_net(web_nic={"own": "tier"}, api_nic={"rules": [_rule(
        "deny-lateral-in", 130, dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                                     destination_address_prefix="*", destination_port_range="*"))]},
        data_subnet=[]), "config": {"forensic": ["10.9.9.9"], "rg": "", "quarantine": False, "readable": True}},
         ("isolate", WEB1, WEB1, (8, "before-429")),
         ("address_reused_under_a_turned_rule", WEB1, WEB1, None, 22,
          (tier, "glorfindel-block-192-31-196-7-web-web-nic-8b70f2"), _nic("rg-app1", "web-nic"), 0, 4,
          "rg-app1", "batch", "/subscriptions/s/resourceGroups/rg-net/providers/Microsoft.Network/"
          "networkSecurityGroups/nsg-tier", "Linux"),
         ("customer_changes_ip", _nic("rg-app2", "web-nic"), 0, 4),
         ("interrupted_release", WEB1, WEB1, None, 1, "before-crash", False))
