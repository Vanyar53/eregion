"""Is a VM held by Glorfindel (DG-b review, point 1): the rule an injector reads before it acts —
Orodruin before a wire (eregion_core/exercise_runner.py), Annatar's preflight
(annatar/executors/azure_vm.py) — on the NSGs of the VM's NICs and of their subnets, wherever they
live, with the names Glorfindel really gives its rules (``_placement_rule_bases``).

ARM is a dict in memory: no network, no Azure. Crosses components on purpose (Glorfindel's names,
Annatar's preflight): TOGETHER. The oracles are written here.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from eregion_core import exercise_runner as er
from eregion_core import held
from glorfindel.providers.azure.network import NetworkMixin

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
VM = f"{SUB}/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
NIC = f"{SUB}/resourceGroups/rg-celebrimbor/providers/Microsoft.Network/networkInterfaces/nic-gondolin"
SUBNET = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
NIC_NSG = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-nic"
SUBNET_NSG = f"{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-subnet"
QUARANTINE = f"{SUB}/resourceGroups/rg-glorfindel/providers/Microsoft.Network/networkSecurityGroups/nsg-glorfindel-quarantine-francecentral"


def _names() -> tuple[str, str]:
    """The two bases Glorfindel writes an isolation under, for this VM's NIC — its own code."""
    return NetworkMixin._placement_rule_bases(object.__new__(NetworkMixin), "glorfindel-iso",
                                              "vm-celebrimbor-gondolin", "nic-gondolin", NIC)


def _arm(nic_nsg=NIC_NSG, nic_rules=(), subnet_rules=(), missing=()):
    world = {
        VM: {"properties": {"networkProfile": {"networkInterfaces": [{"id": NIC}]}}},
        NIC: {"properties": {"networkSecurityGroup": {"id": nic_nsg} if nic_nsg else None,
                             "ipConfigurations": [{"properties": {"subnet": {"id": SUBNET}}}]}},
        SUBNET: {"properties": {"networkSecurityGroup": {"id": SUBNET_NSG}}},
        NIC_NSG: {"properties": {"securityRules": [{"name": n} for n in ("allow-ssh", *nic_rules)]}},
        SUBNET_NSG: {"properties": {"securityRules": [{"name": n} for n in ("allow-https", *subnet_rules)]}},
        QUARANTINE: {"properties": {"securityRules": [{"name": "glorfindel-quarantine-deny-in"}]}},
    }
    calls = []

    def get(path, api):
        calls.append(path)
        if path in missing or path not in world:
            raise RuntimeError(f"HTTP 403 reading {path.rsplit('/', 1)[-1]}")
        return world[path]
    get.calls = calls
    return get


@pytest.mark.parametrize("form", ["in", "out", "second", "second-out"])
def test_glorfindels_isolation_as_it_names_it_holds_the_vm(form):
    first, second = _names()
    name = {"in": first, "out": f"{first}-out", "second": second, "second-out": f"{second}-out"}[form]
    assert name.startswith("glorfindel-iso-") and "isolation" not in name   # not the old fixed name
    assert "nsg-nic" in held.holding(VM, _arm(nic_rules=[name]))


def test_an_isolation_on_the_subnets_nsg_in_another_group_holds_the_vm():
    get = _arm(subnet_rules=[f"{_names()[0]}-out"])
    assert "nsg-subnet" in held.holding(VM, get)
    assert SUBNET_NSG in get.calls and NIC_NSG in get.calls     # read where they live: rg-net


def test_the_quarantine_nsg_holds_the_vm():
    assert "glorfindel-quarantine-deny-in" in held.holding(VM, _arm(nic_nsg=QUARANTINE))


def test_the_old_fixed_name_still_holds():
    assert held.holding(VM, _arm(nic_rules=["glorfindel-isolation-deny-all"]))


def test_a_vm_without_any_of_glorfindels_rules_is_free():
    assert held.holding(VM, _arm(nic_rules=["glorfindel-block-203-0-113-9"])) == ""


@pytest.mark.parametrize("missing", [NIC_NSG, SUBNET_NSG, NIC, SUBNET, VM])
def test_what_cannot_be_read_holds_the_vm(missing):
    """A0: an NSG, a NIC, a subnet unreadable — the wire waits, never goes on blind."""
    assert "unreadable" in held.holding(VM, _arm(missing=(missing,)))


def test_a_path_with_a_query_is_never_read():
    forged = {VM: {"properties": {"networkProfile": {"networkInterfaces": [{"id": NIC + "?api-version=1"}]}}}}
    assert "unreadable" in held.holding(VM, lambda p, a: forged[p])


def test_orodruin_reads_it_with_this_rule(monkeypatch):
    monkeypatch.setattr(er, "_arm_get", _arm(nic_rules=[_names()[1]]))
    assert "Glorfindel's" in er.isolated(VM)
    monkeypatch.setattr(er, "_arm_get", _arm())
    assert er.isolated(VM) == ""


def _executor(get):
    from annatar.executors.azure_vm import AzureVMExecutor
    with patch("annatar.executors.azure_vm.DefaultAzureCredential"), \
         patch("annatar.executors.azure_vm.ComputeManagementClient") as compute:
        ex = AzureVMExecutor({"resource_group": "rg-celebrimbor", "vm_name": "vm-celebrimbor-gondolin",
                              "subscription_id": SUB.rsplit("/", 1)[-1]})
    status = SimpleNamespace(code="PowerState/running")
    compute.return_value.virtual_machines.get.return_value = SimpleNamespace(
        instance_view=SimpleNamespace(statuses=[status]))
    ex._compute = compute.return_value
    ex._arm_get = get
    return ex


def test_annatars_preflight_sees_glorfindels_isolation_as_it_names_it():
    """The preflight read only `glorfindel-isolation-*` in the VM's group: an isolation of today,
    on the NIC's NSG in another group, passed."""
    issues = _executor(_arm(nic_rules=[_names()[0]])).check_preflight()
    assert any("held by Glorfindel" in i for i in issues), issues
    assert _executor(_arm()).check_preflight() == []


def test_annatars_preflight_refuses_when_the_hold_cannot_be_read():
    issues = _executor(_arm(missing=(SUBNET,))).check_preflight()
    assert any("unreadable" in i for i in issues), issues


# ── #358: the paths Orodruin reads on Azure, stricter ────────────────────────────────────────

_SUB = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor"


@pytest.mark.parametrize("path", [
    _SUB + "/providers/Microsoft.Network/networkInterfaces/../../../providers/Microsoft.Authorization",
    _SUB + "/providers/Microsoft.Network/networkInterfaces/./nic-1",
    _SUB + "/providers/Microsoft.Network/networkInterfaces/..",
    _SUB + "/providers/Microsoft.Network/networkInterfaces/nic\x00-1",
    _SUB + "/providers/Microsoft.Network/networkInterfaces/nic\u202e1-cin",       # a bidi override
    _SUB + "/providers/Microsoft.Network/networkInterfaces/nic\u200b-1",          # zero-width
    _SUB + "/providers/Microsoft.Network/networkInterfaces/nic\x7f-1",
    _SUB + "/providers/Microsoft.Network/networkInterfaces/..\\x",      # a backslash: %5C on the wire
    _SUB + "/providers/Microsoft.Network/networkInterfaces/nic\\..\\..\\x",
])
def test_a_path_that_walks_its_segments_or_hides_a_character_is_never_read(path):
    with pytest.raises(ValueError):
        held.safe_path(path)


def test_a_resource_path_as_arm_writes_it_is_read():
    for path in (_SUB + "/providers/Microsoft.Network/networkInterfaces/nic-1.a_b(c)",
                 _SUB + "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"):
        assert held.safe_path(path) == path


def test_a_nic_path_from_azure_that_walks_away_holds_the_vm():
    """A VM whose networkProfile names a NIC by a path with « .. »: read nowhere — A0, it holds."""
    vm = _SUB + "/providers/Microsoft.Compute/virtualMachines/vm-1"
    bad = _SUB + "/providers/Microsoft.Network/networkInterfaces/../../rg-other/x"
    reads = []

    def arm(path, api):
        reads.append(path)
        return {"properties": {"networkProfile": {"networkInterfaces": [{"id": bad}]}}}
    assert held.holding(vm, arm)
    assert reads == [vm]
