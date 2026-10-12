"""Sequences the invariant machine found failing (L26), replayed as fixed examples on
every push: each one broke a property before its fix. A rule's draws are given in the
order it makes them — `_draw` takes the VM, the id it is reached with, the fault.
"""
from __future__ import annotations

from .fake_azure import key
from .test_invariants import IsolationMachine, invariant_env

WEB1 = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/web"
WEB2 = "/subscriptions/s/resourceGroups/rg-app2/providers/Microsoft.Compute/virtualMachines/web"
DB = "/subscriptions/s/resourceGroups/rg-app1/providers/Microsoft.Compute/virtualMachines/Db--01"


def _nic(rg: str, name: str) -> str:
    return key(f"/subscriptions/s/resourceGroups/{rg}/providers/Microsoft.Network/networkInterfaces/{name}")


class Script:
    """Feeds the rules their draws, in order."""

    def __init__(self, *values):
        self.values = list(values)

    def draw(self, strategy, label=None):
        return self.values.pop(0)


def _net(quarantine=False, subnet_nsg=None, quarantine_rg="", **nics):
    plain = {"own": None, "rules": [], "policy": False}
    return {"subnet_nsg": subnet_nsg, "edge_nsg": None, "tier_rules": [],
            "nics": {n: {**plain, **nics.get(n.replace("-", "_"), {})}
                     for n in ("web-nic", "db-nic-0", "db-nic-1", "api-nic")},
            "windows": None,
            "config": {"quarantine": quarantine, "rg": quarantine_rg, "forensic": [], "readable": True}}


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
         ("customer_changes_ip", _nic("rg-app1", "web-nic"), 0),
         ("lose_state", WEB1),
         ("release", WEB1, WEB1, None))


def test_a_block_is_checked_against_the_nic_as_it_is_now(monkeypatch):
    """A block, then the customer changes an IP of the VM: the verification compared the
    rules with the IPs recorded at block time and said blocked — the new address open."""
    _run(monkeypatch, _net(subnet_nsg=[]),
         ("block", DB, DB, None, 22),
         ("customer_changes_ip", _nic("rg-app1", "db-nic-0"), 0),
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
    _run(monkeypatch, _net(quarantine=True, subnet_nsg=[]),
         ("block", WEB1, WEB1, None, 22),
         ("isolate", WEB1, WEB1, None),
         ("tags_lost", "/subscriptions/s/resourcegroups/rg-app1/providers/microsoft.network/"
                       "networksecuritygroups/nsg-glorfindel-quarantine-westeurope"),
         ("reset_from_azure", WEB1, WEB1, None))


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
        m.customer_changes_ip(Script(_nic("rg-app1", "web-nic"), 0))
        m.block(Script(WEB1, WEB1, None, 22))
        m.delete_vm(Script(WEB1))
        m.customer_changes_ip(Script(_nic("rg-app2", "web-nic"), 0))
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
