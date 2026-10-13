"""Sequences the invariant machine found failing (L26), replayed as fixed examples on
every push: each one broke a property before its fix. A rule's draws are given in the
order it makes them — `_draw` takes the VM, the id it is reached with, the fault.
"""
from __future__ import annotations

from .fake_azure import key
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
