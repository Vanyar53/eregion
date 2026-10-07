from __future__ import annotations

import json
from dataclasses import asdict
from unittest.mock import MagicMock

import pytest

from annatar.signals.schema import Signal
from glorfindel.actions import (
    AUTONOMOUS_ACTIONS,
    HUMAN_APPROVAL_REQUIRED,
    _parse_vm_resource_id,
)
from glorfindel.signals import load_signals


# ── actions ───────────────────────────────────────────────────────────────────

def test_autonomous_and_destructive_sets_are_disjoint():
    assert AUTONOMOUS_ACTIONS.isdisjoint(HUMAN_APPROVAL_REQUIRED)


def test_isolate_vm_in_autonomous():
    assert "isolate_vm" in AUTONOMOUS_ACTIONS


def test_delete_resource_requires_human():
    assert "delete_resource" in HUMAN_APPROVAL_REQUIRED


def test_parse_vm_resource_id():
    resource_id = (
        "/subscriptions/sub-123/resourceGroups/rg-test"
        "/providers/Microsoft.Compute/virtualMachines/vm-test"
    )
    rg, vm = _parse_vm_resource_id(resource_id)
    assert rg == "rg-test"
    assert vm == "vm-test"


def test_azure_connector_dry_run_isolate(tmp_path):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.isolate_vm("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
    assert result["status"] == "dry_run"
    assert result["action"] == "isolate_vm"


def test_azure_connector_dry_run_release(tmp_path):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.release_isolation("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
    assert result["status"] == "dry_run"


def test_azure_connector_dry_run_verify_snapshot():
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.verify_snapshot("snap-dry-run-000")
    assert result["verified"] is True
    assert result["method"] == "dry_run"


def test_azure_connector_verify_snapshot_no_id():
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    result = connector.verify_snapshot("")
    assert result["verified"] is None


def test_azure_connector_dry_run_verify_block_ip():
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.verify_block_ip("1.2.3.4", "resource_id")
    assert result["verified"] is True


def test_azure_connector_verify_block_ip_dry_run():
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True)
    result = connector.verify_block_ip("1.2.3.4", "any_resource_id")
    assert result["verified"] is True
    assert result["method"] == "dry_run"


# ── read-only credentials ──────────────────────────────────────────────────────

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def test_read_only_default_is_false(monkeypatch):
    from glorfindel.actions import AzureConnector
    monkeypatch.delenv("GLORFINDEL_READ_ONLY", raising=False)
    connector = AzureConnector(dry_run=False)
    assert connector.read_only is False
    assert connector.permission_mode() == "read_write"


def test_read_only_from_env(monkeypatch):
    from glorfindel.actions import AzureConnector
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", "1")
    connector = AzureConnector(dry_run=False)
    assert connector.read_only is True
    assert connector.permission_mode() == "read_only"


def test_read_only_explicit_param_overrides_env(monkeypatch):
    from glorfindel.actions import AzureConnector
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", "1")
    connector = AzureConnector(dry_run=False, read_only=False)
    assert connector.read_only is False


def test_read_only_blocks_write_actions_with_clear_error():
    """Write actions raise a clear PermissionError on read-only creds — no Azure call."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False, read_only=True)
    for call in (
        lambda: connector.isolate_vm(_RID),
        lambda: connector.release_isolation(_RID),
        lambda: connector.block_suspicious_ip("1.2.3.4", _RID),
        lambda: connector.snapshot(_RID),
        lambda: connector.restore_from_backup(_RID),
        lambda: connector.unblock_ip("1.2.3.4", _RID),
    ):
        with pytest.raises(PermissionError, match="lecture seule"):
            call()


def test_read_only_does_not_block_dry_run():
    """dry_run short-circuits before the read-only guard — no PermissionError."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=True, read_only=True)
    assert connector.isolate_vm(_RID)["status"] == "dry_run"


def _backup_connector(monkeypatch, rps, protected_get_raises):
    """AzureConnector with a mocked RSV client for check_backup_points tests."""
    from unittest.mock import MagicMock
    import azure.mgmt.recoveryservicesbackup as _rsv
    from glorfindel.actions import AzureConnector

    client = MagicMock()
    client.recovery_points.list.return_value = rps
    if protected_get_raises:
        client.protected_items.get.side_effect = Exception("ResourceNotFound")
    else:
        client.protected_items.get.return_value = MagicMock()
    monkeypatch.setattr(_rsv, "RecoveryServicesBackupClient", lambda *a, **k: client)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._credential = object()
    connector._subscription_id = "sub"
    return connector


def test_check_backup_points_protected_no_rp(monkeypatch):
    """Empty RP list + item IS a protected item → protected=True (first backup pending)."""
    connector = _backup_connector(monkeypatch, rps=[], protected_get_raises=False)
    res = connector.check_backup_points(_RID, vault="rsv-annatar")
    assert res["ok"] is False
    assert res["protected"] is True
    assert res["no_recovery_point"] is True
    assert "not linked" not in res["error"].lower()


def test_check_nsg_access_lists_all_nics(monkeypatch):
    """check_nsg_access enumerates EVERY NIC's NSG (nsgs[]) + primary for back-compat."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", scope="nic", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", scope="subnet",
                    ips=("10.0.1.7",), nic_id="nic-b"),
    ])
    net = MagicMock()
    net.security_rules.list.return_value = [MagicMock(), MagicMock()]
    connector._network = net

    res = connector.check_nsg_access(_RID)
    assert res["ok"] is True
    assert [n["nsg"] for n in res["nsgs"]] == ["rg1/nsg-a", "rg2/nsg-b"]
    assert res["nsgs"][1]["nsg_scope"] == "subnet"
    assert res["nsg"] == "rg1/nsg-a"      # back-compat: primary NIC
    assert res["scope"] == "nic"


def test_list_nsgs_dry_run_empty():
    from glorfindel.actions import AzureConnector
    assert AzureConnector(dry_run=True).list_nsgs() == []


def test_list_nsgs_enumerates_all_including_subnet_and_restriction(monkeypatch):
    """list_nsgs surfaces NSGs the per-VM audit misses (subnet NSG, AKS subnet) and
    flags those carrying a Glorfindel restriction."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)

    # A subnet-level NSG (e.g. AKS subnet) — invisible to per-VM audit when NICs have
    # their own NSG / the cluster isn't audited as a VM.
    nsg_subnet = MagicMock()
    nsg_subnet.id = ("/subscriptions/s/resourceGroups/rg-aks/providers/Microsoft.Network"
                     "/networkSecurityGroups/aks-subnet-nsg")
    nsg_subnet.subnets = [MagicMock(id="/subnets/aks")]
    nsg_subnet.network_interfaces = []
    nsg_subnet.security_rules = []

    # A NIC-level NSG carrying an active Glorfindel isolation rule.
    nsg_nic = MagicMock()
    nsg_nic.id = ("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network"
                  "/networkSecurityGroups/vm-nsg")
    nsg_nic.subnets = []
    nsg_nic.network_interfaces = [MagicMock(id="/nic/x")]
    rule = MagicMock()
    rule.name = "glorfindel-iso-vm-nic"
    nsg_nic.security_rules = [rule]

    net = MagicMock()
    net.network_security_groups.list_all.return_value = [nsg_subnet, nsg_nic]
    net.network_interfaces.list_all.return_value = []          # no NIC→VM mapping here
    connector._network = net

    by = {n["nsg"]: n for n in connector.list_nsgs()}
    assert "rg-aks/aks-subnet-nsg" in by                       # subnet NSG surfaced
    assert by["rg-aks/aks-subnet-nsg"]["subnets"] == ["/subnets/aks"]
    assert by["rg-aks/aks-subnet-nsg"]["restricted"] is False
    assert by["rg/vm-nsg"]["restricted"] is True               # has a glorfindel- rule
    assert by["rg/vm-nsg"]["glorfindel_rules"] == 1
    assert by["rg/vm-nsg"]["nics"] == ["/nic/x"]


def test_list_nsgs_attributes_vms_nic_and_subnet(monkeypatch):
    """Each NSG carries the VMs it governs — NIC-level (nic→vm) and subnet-level
    (subnet→vms) — for the War Room monitored flag + hover glow."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)

    # NIC of vm-a → has nic-NSG 'nic-nsg' and sits in subnet 'subnet-x' (NSG 'subnet-nsg')
    nic = MagicMock()
    nic.id = "/nic/a"
    nic.virtual_machine = MagicMock(id="/sub/.../virtualMachines/vm-a")
    nic.ip_configurations = [MagicMock(subnet=MagicMock(id="/subnets/subnet-x"))]

    nic_nsg = MagicMock()
    nic_nsg.id = ("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network"
                  "/networkSecurityGroups/nic-nsg")
    nic_nsg.subnets = []
    nic_nsg.network_interfaces = [MagicMock(id="/nic/a")]
    nic_nsg.security_rules = []

    subnet_nsg = MagicMock()
    subnet_nsg.id = ("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network"
                     "/networkSecurityGroups/subnet-nsg")
    subnet_nsg.subnets = [MagicMock(id="/subnets/subnet-x")]
    subnet_nsg.network_interfaces = []
    subnet_nsg.security_rules = []

    net = MagicMock()
    net.network_interfaces.list_all.return_value = [nic]
    net.network_security_groups.list_all.return_value = [nic_nsg, subnet_nsg]
    connector._network = net

    by = {n["nsg"]: n for n in connector.list_nsgs()}
    # NIC-level NSG → attributed to vm-a via the NIC
    assert by["rg/nic-nsg"]["vms"] == ["/sub/.../virtualMachines/vm-a"]
    # subnet-level NSG → attributed to vm-a via the subnet it sits in
    assert by["rg/subnet-nsg"]["vms"] == ["/sub/.../virtualMachines/vm-a"]


@pytest.mark.parametrize("rid", [
    # VMSS instance (direct id)
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute"
    "/virtualMachineScaleSets/aks-pool/virtualMachines/0",
    # AKS managed cluster — what the AMA heartbeat reports for real AKS nodes
    "/subscriptions/s/resourceGroups/rg/providers"
    "/Microsoft.ContainerService/managedClusters/aks-cluster",
])
def test_check_backup_points_non_vm_not_backupable(rid):
    """Non standalone-VM resources short-circuit to not_backupable WITHOUT an Azure call
    — same error as an unprotected VM otherwise, so the resource SHAPE is the only tell.
    Covers both the VMSS-instance id and the AKS managed-cluster id (real-world)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)  # no clients set — must not be reached
    res = connector.check_backup_points(rid, vault="rsv")
    assert res["not_backupable"] is True
    assert res["ok"] is False
    assert res["iam"] is False


def test_check_backup_points_standalone_vm_is_backupable(monkeypatch):
    """A real standalone VM is NOT short-circuited — it goes through the RSV lookup."""
    from glorfindel.actions import _is_backupable_vm
    assert _is_backupable_vm(
        "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute"
        "/virtualMachines/vm-app") is True


def test_check_backup_points_not_protected(monkeypatch):
    """Empty RP list + item is NOT a protected item → protected=False (not linked)."""
    connector = _backup_connector(monkeypatch, rps=[], protected_get_raises=True)
    res = connector.check_backup_points(_RID, vault="rsv-annatar")
    assert res["ok"] is False
    assert res["protected"] is False
    assert "not linked" in res["error"].lower()


def _backup_items_connector(monkeypatch, items):
    """AzureConnector with a mocked RSV client for list_backup_items tests."""
    from unittest.mock import MagicMock
    import azure.mgmt.recoveryservicesbackup as _rsv
    from glorfindel.actions import AzureConnector

    client = MagicMock()
    client.backup_protected_items.list.return_value = items
    monkeypatch.setattr(_rsv, "RecoveryServicesBackupClient", lambda *a, **k: client)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._credential = object()
    connector._subscription_id = "sub"
    return connector, client


def _protected_item(friendly_name, vm_id, state, last_rp):
    from unittest.mock import MagicMock
    p = MagicMock()
    p.friendly_name = friendly_name
    p.virtual_machine_id = vm_id
    p.source_resource_id = vm_id
    p.protection_state = state
    p.last_recovery_point = last_rp
    it = MagicMock()
    it.properties = p
    it.name = f"VM;iaasvmcontainerv2;annatar;{friendly_name}"
    return it


def test_list_backup_items_dry_run_returns_empty():
    from glorfindel.actions import AzureConnector
    assert AzureConnector(dry_run=True).list_backup_items() == []


def test_list_backup_items_parses_inventory(monkeypatch):
    """Vault items parsed from the single protected-items.list call (cheap leg)."""
    from datetime import datetime, timezone, timedelta
    last = datetime.now(timezone.utc) - timedelta(hours=3)
    items = [
        _protected_item("vm-victim", "/sub/.../vm-victim", "Protected", last),
        _protected_item("vm-elrond", "/sub/.../vm-elrond", "Protected", None),
    ]
    connector, client = _backup_items_connector(monkeypatch, items)
    out = connector.list_backup_items(vault="rsv-annatar", resource_group="annatar")

    # The RSV is queried vault-wide (not per discovered VM) and filtered to IaaS VMs.
    client.backup_protected_items.list.assert_called_once()
    args, kwargs = client.backup_protected_items.list.call_args
    assert args[0] == "rsv-annatar"
    assert "AzureIaasVM" in kwargs["filter"]

    assert [i["name"] for i in out] == ["vm-victim", "vm-elrond"]
    assert out[0]["resource_id"] == "/sub/.../vm-victim"
    assert out[0]["protection_state"] == "Protected"
    assert out[0]["latest_age_h"] == 3.0
    assert out[0]["latest_recovery_point"] is not None
    # No recovery point yet (first backup pending) → freshness None, item still listed.
    assert out[1]["latest_recovery_point"] is None
    assert out[1]["latest_age_h"] is None
    # The expensive RP count is deliberately NOT computed here.
    assert "points" not in out[0]
    client.recovery_points.list.assert_not_called()


def test_list_backup_items_empty_vault(monkeypatch):
    """No protected items → empty list (vault readable but nothing backed up)."""
    connector, _ = _backup_items_connector(monkeypatch, items=[])
    assert connector.list_backup_items() == []


def test_check_backup_points_vault_rg_scopes_lookup(monkeypatch):
    """Central vault: lookup scoped to the VAULT's RG, container to the VM's RG.

    The 'backup missing 0/15' bug: the vault was looked up under each VM's RG
    (ResourceNotFound) instead of the vault's own RG.
    """
    from unittest.mock import MagicMock
    import azure.mgmt.recoveryservicesbackup as _rsv
    from glorfindel.actions import AzureConnector

    client = MagicMock()
    client.recovery_points.list.return_value = []
    client.protected_items.get.return_value = MagicMock()  # protected, first backup pending
    monkeypatch.setattr(_rsv, "RecoveryServicesBackupClient", lambda *a, **k: client)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._credential = object()
    connector._subscription_id = "sub"

    rid = ("/subscriptions/s/resourceGroups/app-rg"
           "/providers/Microsoft.Compute/virtualMachines/vm-x")
    connector.check_backup_points(rid, vault="central-vault", vault_rg="backup-rg")

    args = client.recovery_points.list.call_args.args
    # (vault, vault_rg, fabric, container, item)
    assert args[0] == "central-vault"
    assert args[1] == "backup-rg"            # vault's RG — NOT the VM's 'app-rg'
    assert "app-rg" in args[3]               # container is keyed by the VM's RG
    # Canonical CASE — recovery_points.list is case-sensitive on the type prefix.
    # Lowercase made it return empty → false "first backup pending" (Celebrimbor bench).
    assert args[3] == "IaasVMContainer;iaasvmcontainerv2;app-rg;vm-x"
    assert args[4] == "VM;iaasvmcontainerv2;app-rg;vm-x"


def test_check_backup_points_vault_rg_defaults_to_vm_rg(monkeypatch):
    """No vault_rg → fall back to the VM's RG (sandbox: vault co-located with VM)."""
    from unittest.mock import MagicMock
    import azure.mgmt.recoveryservicesbackup as _rsv
    from glorfindel.actions import AzureConnector

    client = MagicMock()
    client.recovery_points.list.return_value = []
    client.protected_items.get.side_effect = Exception("ResourceNotFound")
    monkeypatch.setattr(_rsv, "RecoveryServicesBackupClient", lambda *a, **k: client)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._credential = object()
    connector._subscription_id = "sub"

    rid = ("/subscriptions/s/resourceGroups/annatar"
           "/providers/Microsoft.Compute/virtualMachines/vm-x")
    connector.check_backup_points(rid, vault="rsv-annatar")  # no vault_rg
    assert client.recovery_points.list.call_args.args[1] == "annatar"


def test_warm_up_azure_sdk_idempotent():
    """warm_up_azure_sdk imports without raising and is safe to call repeatedly."""
    from glorfindel.actions import warm_up_azure_sdk
    warm_up_azure_sdk()
    warm_up_azure_sdk()  # second call is a no-op (already warmed)
    # After warm-up, the lazily-imported SDK modules are in sys.modules (cache hits)
    import sys
    assert "azure.core.pipeline" in sys.modules


def test_ensure_clients_thread_safe_single_init(monkeypatch):
    """Concurrent first-calls to the REAL _ensure_clients build the clients once.

    Regression guard for the audit-parallel import race (dd83df3): without the lock,
    N threads crossed the `if self._network is not None` gate together and triggered
    parallel azure SDK imports. Exercises the real method; mocks the SDK classes
    (and a small sleep) to count constructions and widen the race window.
    """
    import threading
    import time
    from glorfindel.actions import AzureConnector

    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-test")
    calls = {"cred": 0, "net": 0, "comp": 0}

    def _cred(*a, **k):
        calls["cred"] += 1
        time.sleep(0.02)  # widen the window a racing thread could slip through
        return object()

    def _net(*a, **k):
        calls["net"] += 1
        return object()

    def _comp(*a, **k):
        calls["comp"] += 1
        return object()

    monkeypatch.setattr("azure.identity.DefaultAzureCredential", _cred)
    monkeypatch.setattr("azure.mgmt.network.NetworkManagementClient", _net)
    monkeypatch.setattr("azure.mgmt.compute.ComputeManagementClient", _comp)

    connector = AzureConnector(dry_run=False)
    barrier = threading.Barrier(8)

    def _worker():
        barrier.wait()
        connector._ensure_clients()

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert calls["net"] == 1   # built once despite 8 concurrent callers
    assert calls["comp"] == 1
    assert connector._network is not None


def _nic_target(nsg_rg="rg", nsg_name="nsg", scope="nic", ips=("10.0.0.5",), nic_id="nic-a"):
    """Build one _get_vm_nic_targets() entry for the multi-NIC isolation tests."""
    return {
        "nic_id": nic_id, "nic_short": nic_id.rstrip("/").split("/")[-1],
        "nsg_rg": nsg_rg, "nsg_name": nsg_name, "scope": scope,
        "private_ips": list(ips),
    }


def _sd(r):
    """(src, dst) of a SecurityRule, taking the singular prefix or the plural list."""
    src = r.source_address_prefix if r.source_address_prefix is not None else r.source_address_prefixes
    dst = r.destination_address_prefix if r.destination_address_prefix is not None else r.destination_address_prefixes
    return src, dst


def test_isolate_vm_no_orphan_state_file_when_azure_fails(tmp_path, monkeypatch):
    """isolate_vm must NOT write the isolation state file if the NSG write fails.

    Pre-fix, the state file was written before the deny-all rules → a 403 left an
    orphan ~/.glorfindel/isolation/<vm>.json (War Room showing ISOLATED) with no rule.
    """
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, _load_isolation_state

    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="nic")])

    net = MagicMock()
    net.security_rules.list.return_value = []          # no conflicting rules to bump
    net.security_rules.begin_create_or_update.side_effect = _azure_403()  # deny-all write fails
    connector._network = net

    with pytest.raises(Exception):
        connector.isolate_vm(_RID)

    # No orphan state file — the VM is not actually isolated
    assert _load_isolation_state("vm") is None


def test_isolate_vm_subnet_nsg_scopes_to_vm_ip(tmp_path, monkeypatch):
    """isolate_vm on a subnet NSG scopes the deny to THIS VM's IP (no blast radius)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.isolate_vm(_RID)
    assert out["status"] == "isolated"
    assert out["nsg_scope"] == "subnet"
    assert "warning" not in out          # no blast radius anymore — scoped to the VM
    assert "note" in out and "scoped" in out["note"].lower()
    assert out["rule"] == "glorfindel-iso-vm-nic-a"   # per-(vm,nic) name
    # the created deny rules reference the VM IP (augmented list), not any/any
    rules = [c.args[3] for c in net.security_rules.begin_create_or_update.call_args_list]
    addrs = [_sd(r) for r in rules]
    assert ("*", ["10.0.0.5"]) in addrs    # inbound: deny TO the VM's IPs
    assert (["10.0.0.5"], "*") in addrs    # outbound: deny FROM the VM's IPs


def test_isolate_vm_multi_nic_covers_every_nic(tmp_path, monkeypatch):
    """The bug: a VM with 2 NICs (each its own NSG) must be denied on BOTH NSGs."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, _load_isolation_state
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", scope="nic", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", scope="subnet",
                    ips=("10.0.1.7",), nic_id="nic-b"),
    ])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.isolate_vm(_RID)
    assert out["nics_covered"] == 2
    # rules landed on BOTH NSGs
    nsgs = {(c.args[0], c.args[1]) for c in net.security_rules.begin_create_or_update.call_args_list}
    assert ("rg1", "nsg-a") in nsgs
    assert ("rg2", "nsg-b") in nsgs
    # state records both placements (release/verify depend on it)
    state = _load_isolation_state("vm")
    assert len(state["placements"]) == 2
    assert {p["nsg_name"] for p in state["placements"]} == {"nsg-a", "nsg-b"}


def test_verify_isolation_false_when_a_nic_uncovered(monkeypatch):
    """verify_isolation = False if any NIC lacks its deny rules (half-isolated VM)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", nic_id="nic-b"),
    ])
    net = MagicMock()

    def _get(rg, name, rule):
        if name == "nsg-b":               # nic-b has NO rules → uncovered
            from azure.core.exceptions import ResourceNotFoundError
            raise ResourceNotFoundError("rule not found")
        return MagicMock()
    net.security_rules.get.side_effect = _get
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is False
    assert "nic-b" in out["uncovered_nics"]


def test_verify_isolation_unreadable_rules_are_not_missing(monkeypatch):
    """A read error (throttling) is an unknown, not a removal: the reassertion used to
    put back an isolation still in place and alert that it had been removed (T10)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", nic_id="nic-a")])
    net = MagicMock()
    net.security_rules.get.side_effect = Exception("429 Too Many Requests")
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is None and out["unreadable_nics"] == ["nic-a"]
    assert "uncovered_nics" not in out


def test_not_found_in_a_message_is_not_a_missing_target():
    """'…was not found' also describes a missing REFERENCED resource (re-attaching a
    deleted customer NSG): only the SDK's 404 counts (T15)."""
    from azure.core.exceptions import ResourceNotFoundError
    from glorfindel.actions import _is_not_found
    assert _is_not_found(ResourceNotFoundError("gone"))
    assert not _is_not_found(Exception("Resource nsg-client was not found"))


def test_release_isolation_multi_nic_deletes_all_placements(tmp_path, monkeypatch):
    """release_isolation removes the deny rules from EVERY placement's NSG."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, _save_isolation_state
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")
    _save_isolation_state("vm", {
        "resource_id": _RID, "placements": [
            {"nsg_rg": "rg1", "nsg_name": "nsg-a", "rule_in": "iso-a", "rule_out": "iso-a-out", "bumped": []},
            {"nsg_rg": "rg2", "nsg_name": "nsg-b", "rule_in": "iso-b", "rule_out": "iso-b-out", "bumped": []},
        ],
    })
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()
    net.security_rules.begin_delete.return_value.result.return_value = None
    connector._network = net

    connector.release_isolation(_RID)
    deleted = {(c.args[0], c.args[1], c.args[2]) for c in net.security_rules.begin_delete.call_args_list}
    assert ("rg1", "nsg-a", "iso-a") in deleted
    assert ("rg2", "nsg-b", "iso-b") in deleted


def test_isolate_vm_subnet_nsg_picks_free_priority(tmp_path, monkeypatch):
    """On a shared subnet NSG, isolation takes a free priority (no bump of others)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.6",))])
    existing = MagicMock(priority=100, name="someone-else")  # 100 already taken
    net = MagicMock()
    net.security_rules.list.return_value = [existing]
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.isolate_vm(_RID)
    prios = {c.args[3].priority for c in net.security_rules.begin_create_or_update.call_args_list}
    assert 100 not in prios               # didn't reuse the taken priority
    assert all(p >= 100 for p in prios)
    assert out["status"] == "isolated"


def test_block_ip_subnet_nsg_scopes_to_vm_ip(monkeypatch):
    """block_suspicious_ip on a subnet NSG scopes to THIS VM's IP (not the whole subnet)."""
    from glorfindel.actions import AzureConnector
    import glorfindel.actions as actions
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID)
    assert out["nsg_scope"] == "subnet"
    assert "warning" not in out
    assert "note" in out and "scoped" in out["note"].lower()
    assert out["rule"] == "glorfindel-block-95-47-246-223-vm-nic-a"  # per-(vm,nic)
    rules = [c.args[3] for c in net.security_rules.begin_create_or_update.call_args_list]
    addrs = [_sd(r) for r in rules]
    # inbound: attacker → THIS VM's IPs ; outbound: THIS VM's IPs → attacker (not any/*)
    assert ("95.47.246.223", ["10.0.0.5"]) in addrs
    assert (["10.0.0.5"], "95.47.246.223") in addrs


def test_block_ip_multi_nic_covers_every_nic(tmp_path, monkeypatch):
    """A VM block lands on EVERY NIC's NSG (a 2nd NIC must not leave the attacker a path)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, _load_block_entries
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", scope="nic", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", scope="subnet", ips=("10.0.1.9",), nic_id="nic-b"),
    ])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID)
    assert out["nics_covered"] == 2
    nsgs = {(c.args[0], c.args[1]) for c in net.security_rules.begin_create_or_update.call_args_list}
    assert ("rg1", "nsg-a") in nsgs and ("rg2", "nsg-b") in nsgs
    entry = next(e for e in _load_block_entries("vm") if e["ip"] == "95.47.246.223")
    assert len(entry["placements"]) == 2


def test_block_state_records_nsg_scope(tmp_path, monkeypatch):
    """Block state must record the NSG + scope so the War Room shows the true scope."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, active_blocks
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="nsgrg", nsg_name="subnetnsg", scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID)
    assert out["scoped"] is True          # live outcome carries the flag too
    blocks = [b for b in active_blocks() if b["ip"] == "95.47.246.223"]
    assert len(blocks) == 1
    assert blocks[0]["nsg_scope"] == "subnet"
    assert blocks[0]["nsg"] == "nsgrg/subnetnsg"
    assert blocks[0]["scoped"] is True     # War Room reads this → neutral chip (safe)


def test_block_ip_promote_replace_create_then_delete(tmp_path, monkeypatch):
    """replace=True promotes VM→subnet: subnet any-rule created, VM rules deleted AFTER
    (create-then-delete = no protection gap), state replaced (one entry, scoped=False)."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector, active_blocks
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(nsg_rg="rg", nsg_name="subnet-nsg",
                                                    scope="subnet", ips=("10.0.0.5",))])
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "subnet-nsg"))
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    net.security_rules.begin_delete.return_value.result.return_value = None
    connector._network = net

    # 1) a VM-scoped block exists (one placement on the subnet NSG)
    connector.block_suspicious_ip("95.47.246.223", _RID)  # scope=vm
    # 2) promote it to subnet-wide
    order = []
    net.security_rules.begin_create_or_update.side_effect = (
        lambda *a, **k: order.append(("create", a[2])) or MagicMock())
    net.security_rules.begin_delete.side_effect = (
        lambda *a, **k: order.append(("delete", a[2])) or MagicMock())

    out = connector.block_suspicious_ip("95.47.246.223", _RID, scope="subnet", replace=True)

    assert out["scoped"] is False
    assert out["rule"] == "glorfindel-block-95-47-246-223"            # subnet-wide (no suffix)
    assert "glorfindel-block-95-47-246-223-vm-nic-a" in out["promoted_from"]  # removed VM rule
    # create-then-delete: the subnet rule is created BEFORE the VM rule is deleted
    first_create = next(i for i, (op, _) in enumerate(order) if op == "create")
    first_delete = next(i for i, (op, _) in enumerate(order) if op == "delete")
    assert first_create < first_delete
    # state replaced: single entry, now subnet-wide
    blocks = [b for b in active_blocks() if b["ip"] == "95.47.246.223"]
    assert len(blocks) == 1
    assert blocks[0]["scoped"] is False
    assert blocks[0]["rule"] == "glorfindel-block-95-47-246-223"


def test_block_ip_scope_subnet_one_any_rule_on_subnet_nsg(monkeypatch):
    """scope='subnet' → one perimeter rule (any) on the SUBNET NSG, scoped=False."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    # subnet-wide must resolve the SUBNET NSG (not the NIC one)
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "subnet-nsg"))
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID, scope="subnet")
    assert out["nsg"] == "rg/subnet-nsg"
    assert out["nsg_scope"] == "subnet"
    assert out["scoped"] is False          # → War Room ⚠ subnet-wide chip
    assert out["rule"] == "glorfindel-block-95-47-246-223"  # shared, no VM suffix
    assert "perimeter" in out["note"].lower() or "all" in out["note"].lower()
    rules = [c.args[3] for c in net.security_rules.begin_create_or_update.call_args_list]
    addrs = [(r.source_address_prefix, r.destination_address_prefix) for r in rules]
    assert ("95.47.246.223", "*") in addrs   # perimeter: attacker → any
    assert ("*", "95.47.246.223") in addrs


def test_block_ip_scope_subnet_requires_subnet_nsg(monkeypatch):
    """scope='subnet' with no subnet NSG → clear error (no silent fallback)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")

    def _no_subnet_nsg(nic):
        raise RuntimeError("Subnet x has no NSG — subnet-wide block not available")
    monkeypatch.setattr(connector, "_get_subnet_nsg", _no_subnet_nsg)
    connector._network = MagicMock()

    with pytest.raises(RuntimeError, match="subnet-wide block not available"):
        connector.block_suspicious_ip("1.2.3.4", _RID, scope="subnet")


def test_block_ip_nic_nsg_stays_any(monkeypatch):
    """NIC NSG → block stays attacker↔any (scoped to the VM by the NIC NSG itself)."""
    from glorfindel.actions import AzureConnector
    import glorfindel.actions as actions
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="nic")])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID)
    assert out["nsg_scope"] == "nic"
    assert "note" not in out and "warning" not in out
    rules = [c.args[3] for c in net.security_rules.begin_create_or_update.call_args_list]
    addrs = [_sd(r) for r in rules]
    assert ("95.47.246.223", "*") in addrs    # nic NSG → attacker ↔ any (NSG scopes to VM)
    assert ("*", "95.47.246.223") in addrs


def test_isolate_vm_nic_nsg_no_blast_radius_warning(tmp_path, monkeypatch):
    """NIC-level NSG → scoped to this VM, no blast-radius warning."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="nic")])
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.return_value.result.return_value = None
    connector._network = net

    out = connector.isolate_vm(_RID)
    assert out["nsg_scope"] == "nic"
    assert "warning" not in out


def _azure_403():
    from azure.core.exceptions import HttpResponseError
    e = HttpResponseError(message="(AuthorizationFailed) no write permission")
    e.status_code = 403
    return e


def test_audit_reports_read_only_credentials():
    """audit.run prepends a warn check explaining the observe-only posture."""
    from glorfindel import audit
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False, read_only=True)

    # Stub the read checks so we don't hit Azure — we only assert the creds check.
    connector.check_nsg_access = lambda rid: {"ok": True, "nsg": "rg/nsg", "rules": 3}
    connector.check_backup_points = lambda rid, vault="rsv-annatar", vault_rg="": {"ok": True, "points": 2, "latest_age_h": 5}
    connector.check_compute_access = lambda rid: {"ok": True, "vm": "vm", "disks": ["osdisk"]}

    result = audit.run(_RID, connector)
    creds = [c for c in result.checks if c.name == "Credentials"]
    assert len(creds) == 1
    assert creds[0].status == "warn"
    assert "read-only" in creds[0].message.lower()
    # warn (not fail) → the observe-only deployment is still "ready" for its purpose
    assert result.ready is True


# ── signals loader ────────────────────────────────────────────────────────────

_SAMPLE_SIGNAL = Signal(
    signal_id="20260101T000000Z_detection",
    timestamp="2026-01-01T00:00:00+00:00",
    provider="azure",
    resource_id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
    resource_type="vm",
    ttp="T1486",
    severity="critical",
    event="detection",
    raw_signal={"detection_time_s": 42},
    context={"run_id": "20260101T000000Z"},
)


def test_load_signals_from_jsonl(tmp_path):
    path = tmp_path / "signals.jsonl"
    path.write_text(json.dumps(asdict(_SAMPLE_SIGNAL)) + "\n")

    signals = load_signals(path)
    assert len(signals) == 1
    assert signals[0].ttp == "T1486"
    assert signals[0].severity == "critical"
    assert signals[0].event == "detection"


def test_load_signals_multiple(tmp_path):
    path = tmp_path / "signals.jsonl"
    lines = [
        json.dumps(asdict(_SAMPLE_SIGNAL)),
        json.dumps({**asdict(_SAMPLE_SIGNAL), "signal_id": "x_recovery", "event": "recovery_complete"}),
    ]
    path.write_text("\n".join(lines) + "\n")

    signals = load_signals(path)
    assert len(signals) == 2
    assert signals[1].event == "recovery_complete"


# ── agent routing logic ───────────────────────────────────────────────────────

def test_route_autonomous_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "isolate_vm",
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.9,
        "reversible": True,
        "explanation": "",
        "escalation_reason": "",
        "suggested_steps": [],
        "outcome": None,
    }
    assert _route_after_decide(state) == "execute_action"


def test_route_escalates_destructive_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "delete_resource",  # destructive — must escalate regardless
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.9,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "",
        "suggested_steps": [],
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_route_escalates_when_llm_requests():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": True,
        "action": "isolate_vm",  # autonomous, but LLM flagged uncertainty
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.4,
        "reversible": True,
        "explanation": "",
        "escalation_reason": "Confidence too low for autonomous action",
        "suggested_steps": [],
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_route_after_verify_false_escalates():
    from glorfindel.agent import _route_after_verify
    state = {"outcome": {"verified": False, "error": "rule not found"}, "escalate": False}
    assert _route_after_verify(state) == "escalate_to_human"


def test_route_after_verify_none_proceeds():
    from glorfindel.agent import _route_after_verify
    state = {"outcome": {"verified": None, "method": "not_implemented"}, "escalate": False}
    assert _route_after_verify(state) == "store_cycle"


def test_route_after_verify_true_proceeds():
    from glorfindel.agent import _route_after_verify
    state = {"outcome": {"verified": True, "method": "nsg_check"}, "escalate": False}
    assert _route_after_verify(state) == "store_cycle"


def test_verify_action_snapshot_calls_verify_snapshot():
    from glorfindel.agent import verify_action
    connector = MagicMock()
    connector.verify_snapshot.return_value = {"verified": True, "method": "dry_run"}
    state = {
        "action": "snapshot",
        "signal": {"resource_id": "res"},
        "outcome": {"snapshot_id": "snap-001", "executed": True},
        "escalate": False,
        "escalation_reason": "",
    }
    result = verify_action(state, connector=connector)
    connector.verify_snapshot.assert_called_once_with("snap-001")
    assert result["outcome"]["verified"] is True


def test_verify_action_unknown_action_returns_none():
    from glorfindel.agent import verify_action
    connector = MagicMock()
    state = {
        "action": "revoke_temp_access",
        "signal": {"resource_id": "res"},
        "outcome": {"executed": True},
        "escalate": False,
        "escalation_reason": "",
    }
    result = verify_action(state, connector=connector)
    assert result["outcome"]["verified"] is None
    assert result["outcome"]["method"] == "not_implemented"
    assert result["escalate"] is False  # None does not escalate


def test_system_prompt_defines_detection_timeout_behavior():
    from glorfindel.agent import _SYSTEM_PROMPT
    assert "detection_timeout" in _SYSTEM_PROMPT
    assert "snapshot" in _SYSTEM_PROMPT
    assert "escalate=true" in _SYSTEM_PROMPT


def test_system_prompt_recovery_complete_mandates_release():
    from glorfindel.agent import _SYSTEM_PROMPT
    # Must be deterministic: release_isolation after restore
    assert "recovery_complete" in _SYSTEM_PROMPT
    assert "release_isolation" in _SYSTEM_PROMPT


def test_store_cycle_includes_run_id(tmp_path):
    from glorfindel.memory import CycleMemory
    mem = CycleMemory(path=tmp_path / "cycles")
    mem.store({
        "signal_id": "20260101T000000Z_detection",
        "run_id": "20260101T000000Z",
        "ttp": "T1486",
        "severity": "critical",
        "resource_type": "vm",
        "event": "detection",
        "reasoning": "test",
        "action": "isolate_vm",
        "outcome": "isolated",
    })
    results = mem.retrieve_similar({"ttp": "T1486", "severity": "critical", "event": "detection"}, n=1)
    assert results[0]["run_id"] == "20260101T000000Z"


def test_route_escalates_unknown_proposed_action():
    from glorfindel.agent import _route_after_decide

    state = {
        "escalate": False,
        "action": "revoke_service_principal_tokens",  # unknown — LLM proposed it
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.85,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "Revoke all tokens for the compromised SP — not in known action set",
        "suggested_steps": [],
        "outcome": None,
    }
    assert _route_after_decide(state) == "escalate_to_human"


def test_escalate_to_human_marks_proposed_action_type():
    from glorfindel.agent import escalate_to_human

    state = {
        "escalate": False,
        "action": "revoke_service_principal_tokens",
        "signal": {},
        "past_cycles": [],
        "reasoning": "",
        "confidence": 0.85,
        "reversible": False,
        "explanation": "",
        "escalation_reason": "Revoke all tokens for the compromised SP",
        "suggested_steps": [],
        "outcome": None,
    }
    result = escalate_to_human(state)
    assert result["outcome"]["escalation_type"] == "proposed_action"
    assert result["outcome"]["action_pending"] == "revoke_service_principal_tokens"


# ── memory ────────────────────────────────────────────────────────────────────

def test_memory_store_and_retrieve(tmp_path):
    from glorfindel.memory import CycleMemory

    mem = CycleMemory(path=tmp_path / "cycles")
    assert mem.count() == 0

    mem.store({
        "signal_id": "test_001",
        "ttp": "T1486",
        "severity": "critical",
        "resource_type": "vm",
        "event": "detection",
        "reasoning": "Ransomware detected — isolated VM",
        "action": "isolate_vm",
        "outcome": "isolated",
    })
    assert mem.count() == 1

    results = mem.retrieve_similar(
        {"ttp": "T1486", "severity": "critical", "resource_type": "vm", "event": "detection"},
        n=3,
    )
    assert len(results) == 1
    assert results[0]["action"] == "isolate_vm"


def test_memory_retrieve_empty_returns_empty_list(tmp_path):
    from glorfindel.memory import CycleMemory

    mem = CycleMemory(path=tmp_path / "cycles")
    results = mem.retrieve_similar({"ttp": "T1486"}, n=3)
    assert results == []


# ── Revue 2026-09 : NSG partagé, échecs partiels, vérification du release ─────

def _shared_target(nic_id="nic-a", ips=("10.0.0.5",)):
    """A NIC-level NSG that ALSO governs other NICs (shared) → must be IP-scoped."""
    t = _nic_target(scope="nic", ips=ips, nic_id=nic_id)
    t.update(shared_nsg=True, ip_scoped=True)
    return t


def test_get_vm_nic_targets_flags_a_shared_nic_nsg(monkeypatch):
    """A NIC-level NSG attached to several NICs is shared: any/any there would cut off
    every VM behind it. _get_vm_nic_targets must say so (ip_scoped=True)."""
    from types import SimpleNamespace
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    nic_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a"
    compute, net = MagicMock(), MagicMock()
    compute.virtual_machines.get.return_value = SimpleNamespace(
        network_profile=SimpleNamespace(network_interfaces=[SimpleNamespace(id=nic_id)]))
    net.network_interfaces.get.return_value = SimpleNamespace(
        network_security_group=SimpleNamespace(
            id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-tier"),
        ip_configurations=[SimpleNamespace(private_ip_address="10.0.0.5")],
    )
    net.network_security_groups.get.return_value = SimpleNamespace(
        network_interfaces=[SimpleNamespace(id="nic-a"), SimpleNamespace(id="nic-of-another-vm")],
        subnets=None,
    )
    connector._compute, connector._network = compute, net

    [t] = connector._get_vm_nic_targets("rg", "vm")
    assert t["scope"] == "nic"
    assert t["shared_nsg"] is True
    assert t["ip_scoped"] is True


def test_get_vm_nic_targets_dedicated_nic_nsg_stays_any(monkeypatch):
    from types import SimpleNamespace
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    compute, net = MagicMock(), MagicMock()
    nic_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a"
    compute.virtual_machines.get.return_value = SimpleNamespace(
        network_profile=SimpleNamespace(network_interfaces=[SimpleNamespace(id=nic_id)]))
    net.network_interfaces.get.return_value = SimpleNamespace(
        network_security_group=SimpleNamespace(
            id="/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-a"),
        ip_configurations=[SimpleNamespace(private_ip_address="10.0.0.5")],
    )
    net.network_security_groups.get.return_value = SimpleNamespace(
        network_interfaces=[SimpleNamespace(id=nic_id)], subnets=[])
    connector._compute, connector._network = compute, net
    [t] = connector._get_vm_nic_targets("rg", "vm")
    assert t["shared_nsg"] is False and t["ip_scoped"] is False


def test_nsg_unreadable_counts_as_shared():
    """Can't read the NSG's associations → IP-scoped placement (the safe choice)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    connector._network = MagicMock()
    connector._network.network_security_groups.get.side_effect = Exception("boom")
    assert connector._nsg_is_shared("rg", "nsg") is True


def test_isolate_vm_shared_nic_nsg_scopes_to_vm_ip_and_bumps_nothing(tmp_path, monkeypatch):
    """On a shared NIC-level NSG: deny addressed to THIS VM's IPs at a free priority,
    and no customer rule moved (other VMs depend on them)."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_shared_target()])
    customer = MagicMock(priority=100)
    customer.name = "allow-https"
    net = MagicMock()
    net.security_rules.list.return_value = [customer]
    connector._network = net

    out = connector.isolate_vm(_RID)

    rules = [c.args[3] for c in net.security_rules.begin_create_or_update.call_args_list]
    assert all(r.name.startswith("glorfindel-") for r in rules)      # customer rule untouched
    assert ("*", ["10.0.0.5"]) in [_sd(r) for r in rules]
    assert (["10.0.0.5"], "*") in [_sd(r) for r in rules]
    assert {r.priority for r in rules} == {101}                      # free slot, not 100
    assert "shared" in out["note"].lower()


def test_isolate_vm_partial_failure_keeps_and_records_rules(monkeypatch):
    """NIC 1 isolated, NIC 2 fails (403): NIC 1's rules stay, are RECORDED (partial),
    and the error is a PartialActionError that still carries the 403."""
    from glorfindel.actions import AzureConnector, PartialActionError, _load_isolation_state
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", nic_id="nic-b"),
    ])
    net = MagicMock()
    net.security_rules.list.return_value = []

    def _put(rg, nsg, name, rule):
        if nsg == "nsg-b":
            raise _azure_403()
        return MagicMock()
    net.security_rules.begin_create_or_update.side_effect = _put
    connector._network = net

    with pytest.raises(PartialActionError) as ei:
        connector.isolate_vm(_RID)
    assert ei.value.status_code == 403            # write_blocked classification preserved
    assert ei.value.failed_nic == "nic-b"
    state = _load_isolation_state("vm")
    assert state["partial"] is True
    assert [p["nsg_name"] for p in state["placements"]] == ["nsg-a"]


def test_isolate_vm_never_moves_a_customer_rule(monkeypatch):
    """A customer rule at 100 used to be moved to 200 for the deny: a `terraform apply`
    puts it back (or fails on our priority). The deny now takes the first free one."""
    from glorfindel.actions import AzureConnector, _load_isolation_state
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "drain_connections", lambda rid: {"status": "drained"})
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target(scope="nic")])
    customer = _nsg_rule("deny-telnet", 100, access="Deny", port="23")
    net = MagicMock()
    net.security_rules.list.return_value = [customer]
    connector._network = net

    connector.isolate_vm(_RID)
    written = [(c.args[2], c.args[3].priority) for c in net.security_rules.begin_create_or_update.call_args_list]
    assert all(name.startswith("glorfindel-") for name, _ in written)
    assert {prio for _, prio in written} == {101}
    assert _load_isolation_state("vm")["placements"][0]["bumped"] == []


def test_isolation_moves_to_the_subnet_nsg_when_the_nic_nsg_lets_traffic_through(monkeypatch):
    """Traffic must pass the NIC's NSG AND its subnet's: when an ALLOW precedes our deny
    on the first, the deny holds on the second — without touching the customer rule."""
    from glorfindel.actions import AzureConnector, _load_isolation_state
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "drain_connections", lambda rid: {"status": "drained"})
    t = {**_nic_target(nsg_name="nsg-nic", scope="nic", ips=("10.0.0.5",)),
         "alt_nsg": {"nsg_rg": "rg", "nsg_name": "nsg-subnet"}}
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [t])
    net = MagicMock()
    net.security_rules.list.side_effect = lambda rg, nsg: (
        [_nsg_rule(**_BENCH_ALLOW_SSH)] if nsg == "nsg-nic" else [])
    connector._network = net

    out = connector.isolate_vm(_RID)
    nsgs = {c.args[1] for c in net.security_rules.begin_create_or_update.call_args_list}
    assert nsgs == {"nsg-subnet"}
    placement = _load_isolation_state("vm")["placements"][0]
    assert placement["nsg_name"] == "nsg-subnet" and placement["moved_from"]["nsg"] == "rg/nsg-nic"
    assert "shadowed_by" not in out


def test_release_isolation_reports_failed_delete_and_keeps_state(monkeypatch):
    """A delete that fails leaves the VM cut off: release must say so (release_partial)
    and keep that placement in state for a retry, instead of 'released'."""
    from glorfindel.actions import AzureConnector, _load_isolation_state, _save_isolation_state
    _save_isolation_state("vm", {"resource_id": _RID, "placements": [
        {"nsg_rg": "rg1", "nsg_name": "nsg-a", "rule_in": "iso-a", "rule_out": "iso-a-out", "bumped": []},
        {"nsg_rg": "rg2", "nsg_name": "nsg-b", "rule_in": "iso-b", "rule_out": "iso-b-out", "bumped": []},
    ]})
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()

    def _delete(rg, nsg, name):
        if name == "iso-b":
            raise _azure_403()
        return MagicMock()
    net.security_rules.begin_delete.side_effect = _delete
    connector._network = net

    out = connector.release_isolation(_RID)
    assert out["status"] == "release_partial"
    assert any("iso-b" in f for f in out["failed"])
    state = _load_isolation_state("vm")
    assert [p["nsg_name"] for p in state["placements"]] == ["nsg-b"]


def test_release_isolation_without_state_sweeps_every_nic(monkeypatch):
    """No state file (lost / corrupt / never written): rule names are deterministic, so
    release recomputes them on EVERY NIC — the legacy path only knew the primary NIC."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", nic_id="nic-b", scope="subnet"),
    ])
    net = MagicMock()
    connector._network = net

    out = connector.release_isolation(_RID)
    deleted = {(c.args[1], c.args[2]) for c in net.security_rules.begin_delete.call_args_list}
    assert ("nsg-a", "glorfindel-iso-vm-nic-a") in deleted
    assert ("nsg-b", "glorfindel-iso-vm-nic-b-out") in deleted
    # fixed legacy names only on the NSG that governs this VM alone
    assert ("nsg-a", "glorfindel-isolation-deny-all") in deleted
    assert ("nsg-b", "glorfindel-isolation-deny-all") not in deleted
    assert out["status"] == "released"


def test_release_deletes_the_deny_before_restoring_the_customer_rule(monkeypatch):
    """Our deny holds priority 100: the customer rule can only go back once it's gone."""
    from glorfindel.actions import AzureConnector, _save_isolation_state
    _save_isolation_state("vm", {"resource_id": _RID, "placements": [
        {"nsg_rg": "rg", "nsg_name": "nsg", "rule_in": "iso", "rule_out": "iso-out",
         "bumped": [{"name": "allow-ssh", "original_priority": 100}]},
    ]})
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    order = []
    net = MagicMock()
    net.security_rules.begin_delete.side_effect = lambda *a: order.append(("delete", a[2])) or MagicMock()
    net.security_rules.get.return_value = MagicMock(name="allow-ssh")
    net.security_rules.begin_create_or_update.side_effect = (
        lambda rg, nsg, name, rule: order.append(("restore", rule.priority)) or MagicMock())
    connector._network = net

    assert connector.release_isolation(_RID)["status"] == "released"
    assert order[-1] == ("restore", 100)
    assert order.index(("restore", 100)) > max(i for i, o in enumerate(order) if o[0] == "delete")


def _rules_on(net, present: dict):
    """security_rules.get that knows which (nsg, rule) exist; others → NotFound."""
    from azure.core.exceptions import ResourceNotFoundError

    def _get(rg, nsg, name):
        if name in present.get(nsg, set()):
            return MagicMock()
        raise ResourceNotFoundError("NotFound")
    net.security_rules.get.side_effect = _get


def test_verify_release_false_when_one_nic_still_isolated(monkeypatch):
    """The inverted-predicate bug: NIC a released, NIC b still denied. The old check
    (`not verify_isolation()`) called this released. verify_release must not."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_name="nsg-b", nic_id="nic-b"),
    ])
    net = MagicMock()
    _rules_on(net, {"nsg-b": {"glorfindel-iso-vm-nic-b"}})
    connector._network = net

    assert connector.verify_isolation(_RID)["verified"] is False   # half-isolated…
    out = connector.verify_release(_RID)                           # …but NOT released
    assert out["verified"] is False
    assert any("nic-b" in s for s in out["still_isolated"])


def test_verify_release_true_when_no_rule_left(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target()])
    net = MagicMock()
    _rules_on(net, {})
    connector._network = net
    assert connector.verify_release(_RID)["verified"] is True


def test_verify_release_unreadable_rule_is_not_a_success(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target()])
    net = MagicMock()
    net.security_rules.get.side_effect = _azure_403()
    connector._network = net
    out = connector.verify_release(_RID)
    assert out["verified"] is False and out["unreadable"]


def test_verify_block_ip_false_when_outbound_rule_missing(monkeypatch):
    """Only the inbound rule used to be checked: a missing `-out` (egress / C2 / exfil
    still open) passed as verified."""
    from glorfindel.actions import AzureConnector, _save_block_state
    rule = "glorfindel-block-1-2-3-4-vm-nic-a"
    _save_block_state("vm", "1.2.3.4", _RID, nsg="rg/nsg", nsg_scope="nic", rule=rule,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "scope": "nic", "rule": rule}])
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()
    _rules_on(net, {"nsg": {rule}})                    # inbound present, -out absent
    connector._network = net

    out = connector.verify_block_ip("1.2.3.4", _RID)
    assert out["verified"] is False
    assert f"{rule}-out" in out["missing_rules"]


def test_unblock_ip_reports_failure_and_keeps_the_entry(monkeypatch):
    from glorfindel.actions import AzureConnector, _load_block_entries, _save_block_state
    rule = "glorfindel-block-1-2-3-4-vm-nic-a"
    _save_block_state("vm", "1.2.3.4", _RID, nsg="rg/nsg", nsg_scope="nic", rule=rule,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "scope": "nic", "rule": rule}])
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()
    net.security_rules.begin_delete.side_effect = (
        lambda rg, nsg, name: (_ for _ in ()).throw(_azure_403()) if name.endswith("-out") else MagicMock())
    connector._network = net

    out = connector.unblock_ip("1.2.3.4", _RID)
    assert out["status"] == "unblock_partial"
    entry = next(e for e in _load_block_entries("vm") if e["ip"] == "1.2.3.4")
    assert entry["unblock_failed"]


def test_block_ip_on_shared_nsg_without_private_ip_raises(monkeypatch):
    """Same guard as isolate_vm: an empty destination list would match nothing."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_shared_target(ips=())])
    net = MagicMock()
    net.security_rules.list.return_value = []
    connector._network = net
    with pytest.raises(RuntimeError, match="no private IP"):
        connector.block_suspicious_ip("1.2.3.4", _RID)
    net.security_rules.begin_create_or_update.assert_not_called()


def test_block_ip_partial_failure_records_placed_rules(monkeypatch):
    from glorfindel.actions import AzureConnector, PartialActionError, _load_block_entries
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [
        _nic_target(nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_name="nsg-b", nic_id="nic-b"),
    ])
    net = MagicMock()
    net.security_rules.list.return_value = []

    def _put(rg, nsg, name, rule):
        if nsg == "nsg-b":
            raise RuntimeError("conflict")
        return MagicMock()
    net.security_rules.begin_create_or_update.side_effect = _put
    connector._network = net

    with pytest.raises(PartialActionError):
        connector.block_suspicious_ip("1.2.3.4", _RID)
    entry = next(e for e in _load_block_entries("vm") if e["ip"] == "1.2.3.4")
    assert entry["partial"] is True
    assert [p["nsg_name"] for p in entry["placements"]] == ["nsg-a"]


def test_save_block_state_merges_on_retry():
    """A retry after a partial block must record the rules of BOTH attempts (the old
    code silently dropped the second save because the IP was already recorded)."""
    from glorfindel.actions import _load_block_entries, _save_block_state
    a = {"nsg_rg": "rg", "nsg_name": "nsg-a", "scope": "nic", "rule": "r-a"}
    b = {"nsg_rg": "rg", "nsg_name": "nsg-b", "scope": "nic", "rule": "r-b"}
    _save_block_state("vm", "1.2.3.4", _RID, rule="r-a", placements=[a], partial=True)
    _save_block_state("vm", "1.2.3.4", _RID, rule="r-a", placements=[a, b])
    [entry] = _load_block_entries("vm")
    assert {p["rule"] for p in entry["placements"]} == {"r-a", "r-b"}
    assert entry["partial"] is False


def test_corrupt_isolation_state_is_tolerated():
    """A torn / corrupt state file is reported, not raised (release then recomputes the
    rule names) — it used to make `release` crash."""
    import glorfindel.actions as actions
    actions._ISOLATION_STATE_DIR.mkdir(parents=True, exist_ok=True)
    (actions._ISOLATION_STATE_DIR / "vm.json").write_text('{"resource_id": "x", "plac')
    assert actions._load_isolation_state("vm") is None


def test_state_writes_are_atomic():
    """os.replace through a temp file: no half-written file, no temp file left behind."""
    import glorfindel.actions as actions
    actions._save_isolation_state("vm", {"resource_id": _RID})
    files = [f.name for f in actions._ISOLATION_STATE_DIR.iterdir()]
    assert files == ["vm.json"]


def test_warm_up_imports_each_module_on_its_own(monkeypatch):
    """One missing module no longer cancels the warm-up of the installed ones."""
    import sys
    import glorfindel.actions as actions
    monkeypatch.setattr(actions, "_warmed_up", False)
    monkeypatch.setattr(actions, "_WARM_UP_MODULES", ("not_a_real_module_xyz", "json.decoder"))
    sys.modules.pop("json.decoder", None)
    actions.warm_up_azure_sdk()
    assert "json.decoder" in sys.modules
    assert actions._warmed_up is True


# ── Sauvegarde : RG du vault, noms stockés, point le plus récent, job de la VM ──

def _backup_env(monkeypatch, *, rps, jobs, stored_id=None):
    """A connector wired to a fake RSV client + fake REST endpoint."""
    import sys
    import types
    from datetime import datetime, timezone
    from glorfindel.actions import AzureConnector

    client = MagicMock()
    client.recovery_points.list.return_value = rps
    client.backup_jobs.list.return_value = jobs
    if stored_id:
        client.protected_items.get.return_value = MagicMock(id=stored_id)
    else:
        client.protected_items.get.side_effect = Exception("not found")
    fake_mod = types.ModuleType("azure.mgmt.recoveryservicesbackup")
    fake_mod.RecoveryServicesBackupClient = lambda *a, **k: client
    monkeypatch.setitem(sys.modules, "azure.mgmt.recoveryservicesbackup", fake_mod)

    posted = []
    fake_requests = types.ModuleType("requests")
    fake_requests.post = lambda url, json=None, headers=None: (
        posted.append(url) or types.SimpleNamespace(status_code=202, text=""))
    monkeypatch.setitem(sys.modules, "requests", fake_requests)
    monkeypatch.setattr("time.sleep", lambda s: None)

    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._credential = MagicMock()
    connector._subscription_id = "s"
    connector._compute = MagicMock()
    connector._compute.virtual_machines.get.return_value = MagicMock(
        id=_RID, location="westeurope", storage_profile=MagicMock(data_disks=[]))
    return connector, client, posted, datetime.now(timezone.utc)


def _rp(name, when, vaulted=True):
    tier = [MagicMock(type="HardenedRP", status="Valid")] if vaulted else []
    return MagicMock(name=name, properties=MagicMock(recovery_point_time=when,
                                                     recovery_point_tier_details=tier))


def _job(name, vm, op, start):
    return MagicMock(name=name, properties=MagicMock(
        operation=op, status="InProgress", entity_friendly_name=vm, start_time=start))


def test_restore_picks_the_newest_point_not_the_list_order(monkeypatch):
    from datetime import timedelta
    connector, client, posted, now = _backup_env(monkeypatch, rps=[], jobs=[])
    old_rp = _rp("rp-old", now - timedelta(days=2))
    new_rp = _rp("rp-new", now - timedelta(hours=3))
    old_rp.name, new_rp.name = "rp-old", "rp-new"
    client.recovery_points.list.return_value = [old_rp, new_rp]      # oldest FIRST
    job = _job("restore-1", "vm", "Restore", now)
    job.name = "restore-1"
    client.backup_jobs.list.return_value = [job]

    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    assert out["recovery_point"] == "rp-new"
    assert "/recoveryPoints/rp-new/restore" in posted[0]


def test_restore_uses_vault_rg_and_the_names_the_vault_stores(monkeypatch):
    """Central vault in its own RG + stored names read back from the protected item:
    recovery_points.list is case-sensitive (lowercase returned nothing on the bench)."""
    stored = ("/subscriptions/s/resourceGroups/rg-backup/providers/Microsoft.RecoveryServices"
              "/vaults/rsv/backupFabrics/Azure/protectionContainers/IaasVMContainer;iaasvmcontainerv2;rg;vm"
              "/protectedItems/VM;iaasvmcontainerv2;rg;vm")
    connector, client, posted, now = _backup_env(monkeypatch, rps=[], jobs=[], stored_id=stored)
    rp = _rp("rp-1", now)
    rp.name = "rp-1"
    client.recovery_points.list.return_value = [rp]
    job = _job("restore-1", "vm", "Restore", now)
    job.name = "restore-1"
    client.backup_jobs.list.return_value = [job]

    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st",
                                        vault_rg="rg-backup")
    args = client.recovery_points.list.call_args.args
    assert args[1] == "rg-backup"
    assert args[3] == "IaasVMContainer;iaasvmcontainerv2;rg;vm"
    assert args[4] == "VM;iaasvmcontainerv2;rg;vm"
    assert "/resourceGroups/rg-backup/" in posted[0]
    assert out["rg"] == "rg-backup"                     # job lookups run in the vault RG


def test_snapshot_tracks_the_job_of_its_own_vm(monkeypatch):
    """Two jobs InProgress in the vault: the snapshot must track the one of ITS VM, not
    the first one listed (cross-wiring between concurrent snapshots)."""
    connector, client, posted, now = _backup_env(monkeypatch, rps=[], jobs=[])
    other = _job("job-other", "vm-other", "Backup", now)
    other.name = "job-other"
    mine = _job("job-mine", "vm", "Backup", now)
    mine.name = "job-mine"
    client.backup_jobs.list.return_value = [other, mine]

    snap_id = connector.snapshot(_RID, vault="rsv", wait=False, vault_rg="rg-backup")
    assert snap_id == "rsv:rsv/rg-backup/job-mine"
    assert "/resourceGroups/rg-backup/" in posted[0]


# ── Règles allow prioritaires (constat banc Celebrimbor 2026-10-05) ───────────

def _nsg_rule(name, priority, direction="Inbound", access="Allow", src="*", dst="*", port="22"):
    """A security rule shaped like the SDK object (single-prefix form)."""
    r = MagicMock()
    r.name = name
    r.priority = priority
    r.direction = direction
    r.access = access
    r.source_address_prefix = src
    r.source_address_prefixes = []
    r.destination_address_prefix = dst
    r.destination_address_prefixes = []
    r.source_application_security_groups = None
    r.destination_application_security_groups = None
    r.destination_port_range = port
    r.destination_port_ranges = []
    return r


_BENCH_ALLOW_SSH = dict(name="allow-ssh", priority=100)   # the real bench rule


def test_prefix_coverage_rules():
    from glorfindel.actions import _prefix_covers
    assert _prefix_covers("*", "10.0.0.5")
    assert _prefix_covers("VirtualNetwork", "10.0.0.5")
    assert not _prefix_covers("Internet", "10.0.0.5")
    assert _prefix_covers("Internet", "95.47.246.223")
    assert _prefix_covers("10.0.0.0/24", "10.0.0.5")
    assert not _prefix_covers("10.0.1.0/24", "10.0.0.5")
    assert not _prefix_covers("Storage", "10.0.0.5")


def test_bench_allow_ssh_shadows_isolation_and_block():
    """allow-ssh (Inbound, * → *, port 22) at 100 precedes an isolation deny at 101 and
    a block deny at 200: both are bypassed for SSH."""
    from glorfindel.actions import _shadowing_rules
    rules = [_nsg_rule(**_BENCH_ALLOW_SSH), _nsg_rule("deny-inbound-default", 4096, access="Deny")]
    iso = _shadowing_rules(rules, 101, inbound_src=None, inbound_dst=["10.0.0.5"],
                           outbound_src=["10.0.0.5"], outbound_dst=None)
    blk = _shadowing_rules(rules, 200, inbound_src=["95.47.246.223"], inbound_dst=["10.0.0.5"],
                           outbound_src=["10.0.0.5"], outbound_dst=["95.47.246.223"])
    assert [s["rule"] for s in iso] == ["allow-ssh"]
    assert [s["rule"] for s in blk] == ["allow-ssh"]
    assert iso[0]["ports"] == "22"


def test_allow_after_our_deny_or_for_other_ips_does_not_shadow():
    from glorfindel.actions import _shadowing_rules
    rules = [
        _nsg_rule("allow-ssh-late", 1000),                              # after the deny
        _nsg_rule("allow-other-subnet", 100, dst="10.0.9.0/24"),        # other VMs only
        _nsg_rule("glorfindel-iso-x", 100, access="Deny"),             # ours / a deny
    ]
    assert _shadowing_rules(rules, 101, inbound_src=None, inbound_dst=["10.0.0.5"],
                            outbound_src=["10.0.0.5"], outbound_dst=None) == []


def test_isolate_vm_reports_the_allow_that_bypasses_it(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.list.return_value = [_nsg_rule(**_BENCH_ALLOW_SSH)]
    connector._network = net

    out = connector.isolate_vm(_RID)
    assert {c.args[3].priority for c in net.security_rules.begin_create_or_update.call_args_list} == {101}
    assert [s["rule"] for s in out["shadowed_by"]] == ["allow-ssh"]
    assert "contournée" in out["bypass"]


def test_verify_isolation_fails_when_an_allow_precedes_the_deny(monkeypatch):
    """Presence alone said verified=True on the bench while SSH stayed open."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    ours_in = _nsg_rule("glorfindel-iso-vm-nic-a", 101, access="Deny", dst="10.0.0.5", port="*")
    net.security_rules.list.return_value = [_nsg_rule(**_BENCH_ALLOW_SSH), ours_in]
    net.security_rules.get.return_value = MagicMock()          # our rules are present
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is False
    assert "allow-ssh" in out["error"]


def test_verify_isolation_checks_precedence_on_a_dedicated_nsg_too(monkeypatch):
    """The deny no longer forces priority 100 on a dedicated NSG (no customer rule is
    moved), so an ALLOW before it there bypasses it as well."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target(scope="nic")])
    net = MagicMock()
    net.security_rules.get.return_value = MagicMock()
    ours = _nsg_rule("glorfindel-iso-vm-nic-a", 101, access="Deny", port="*")
    net.security_rules.list.return_value = [_nsg_rule(**_BENCH_ALLOW_SSH), ours]
    connector._network = net
    out = connector.verify_isolation(_RID)
    assert out["verified"] is False and [s["rule"] for s in out["shadowed_by"]] == ["allow-ssh"]


def test_verify_isolation_finds_the_deny_on_the_subnet_nsg(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    t = {**_nic_target(nsg_name="nsg-nic", scope="nic"), "alt_nsg": {"nsg_rg": "rg", "nsg_name": "nsg-subnet"}}
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [t])
    net = MagicMock()
    net.security_rules.get.side_effect = (
        lambda rg, nsg, name: MagicMock() if nsg == "nsg-subnet" else _raise_not_found())
    ours = _nsg_rule("glorfindel-iso-vm-nic-a", 100, access="Deny", dst="10.0.0.5", port="*")
    net.security_rules.list.return_value = [ours]
    connector._network = net
    assert connector.verify_isolation(_RID)["verified"] is True


def test_verify_block_ip_fails_when_allow_ssh_precedes_it(monkeypatch):
    """A block of an SSH brute forcer at priority 200 does nothing while allow-ssh at
    100 matches first — the T1110 response on the bench."""
    from glorfindel.actions import AzureConnector, _save_block_state
    rule = "glorfindel-block-95-47-246-223-vm-nic-a"
    _save_block_state("vm", "95.47.246.223", _RID, nsg="rg/nsg", nsg_scope="subnet", rule=rule,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "scope": "subnet",
                                   "rule": rule, "ips": ["10.0.0.5"]}])
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()
    net.security_rules.get.return_value = MagicMock()
    ours = _nsg_rule(rule, 200, access="Deny", src="95.47.246.223", dst="10.0.0.5", port="*")
    net.security_rules.list.return_value = [_nsg_rule(**_BENCH_ALLOW_SSH), ours]
    connector._network = net

    out = connector.verify_block_ip("95.47.246.223", _RID)
    assert out["verified"] is False
    assert [s["rule"] for s in out["shadowed_by"]] == ["allow-ssh"]


def test_check_nsg_access_reports_precedence_issues(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.list.return_value = [
        _nsg_rule(**_BENCH_ALLOW_SSH),
        _nsg_rule("allow-admin", 101, src="20.50.0.10/32"),   # specific source: not flagged for blocks
    ]
    connector._network = net

    res = connector.check_nsg_access(_RID)
    by_action = {(i["action"], i["rule"]) for i in res["precedence"]}
    assert ("isolate_vm", "allow-ssh") in by_action
    assert ("block_suspicious_ip", "allow-ssh") in by_action
    assert ("isolate_vm", "allow-admin") in by_action          # isolation deny would land at 102
    assert ("block_suspicious_ip", "allow-admin") not in by_action


def test_audit_fails_on_nsg_precedence():
    from unittest.mock import MagicMock as _MM
    from glorfindel import audit
    connector = _MM()
    connector.dry_run = False
    connector.read_only = False
    connector.check_nsg_access.return_value = {
        "ok": True, "nsg": "rg/nsg", "rules": 2, "nsgs": [],
        "precedence": [{"rule": "allow-ssh", "priority": 100, "direction": "Inbound",
                        "ports": "22", "nsg": "rg/nsg", "nic": "nic-a", "action": "isolate_vm"}],
    }
    connector.check_backup_points.return_value = {"ok": True, "points": 3, "latest_age_h": 1}
    connector.check_compute_access.return_value = {"ok": True, "vm": "vm", "disks": []}
    result = audit.run(_RID, connector, vault="rsv", staging_storage="st")
    check = next(c for c in result.checks if c.name == "NSG precedence")
    assert check.status == "fail"
    assert "allow-ssh" in check.message
    assert "--priority 1000" in check.fix


def test_unblock_deletes_each_rule_once(monkeypatch):
    """A VM-scoped entry mirrors its first placement in nsg/rule: the bench run showed
    every rule deleted (and listed) twice."""
    from glorfindel.actions import AzureConnector, _save_block_state
    rule = "glorfindel-block-1-2-3-4-vm-nic-a"
    _save_block_state("vm", "1.2.3.4", _RID, nsg="rg/nsg", nsg_scope="subnet", rule=rule,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "scope": "subnet", "rule": rule}])
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._network = MagicMock()
    out = connector.unblock_ip("1.2.3.4", _RID)
    assert out["deleted_rules"] == [rule, f"{rule}-out"]
    assert connector._network.security_rules.begin_delete.call_count == 2


# ── reset --from-azure : Azure comme source de vérité ─────────────────────────

def _named(name):
    r = MagicMock()
    r.name = name
    return r


def test_sweep_vm_rules_removes_only_this_vms_rules(monkeypatch):
    """No local state needed. Never touches another VM (`app-web` vs `web`), a perimeter
    block, or a customer rule."""
    import hashlib
    from glorfindel.actions import AzureConnector, _load_isolation_state, _save_isolation_state
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"
    _save_isolation_state("web", {"resource_id": rid})            # stale local state
    nic_id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"
    h = hashlib.sha1(nic_id.encode()).hexdigest()[:8]
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [{
        "nic_id": nic_id, "nic_short": "nic1", "nsg_rg": "rg", "nsg_name": "nsg",
        "scope": "subnet", "shared_nsg": False, "ip_scoped": True, "private_ips": ["10.0.0.5"]}])
    net = MagicMock()
    net.security_rules.list.return_value = [_named(n) for n in [
        "glorfindel-iso-web-nic1", "glorfindel-iso-web-nic1-out",                  # ours
        "glorfindel-block-1-2-3-4-web-nic1", "glorfindel-block-1-2-3-4-web-nic1-out",  # ours
        f"glorfindel-block-95-47-246-223-web-{h}",                                # ours, hashed
        "glorfindel-block-5-6-7-8-app-web-nic1",                                  # another VM
        "glorfindel-iso-app-web-nic9",                                            # another VM
        "glorfindel-block-9-9-9-9",                                               # perimeter
        "allow-ssh",                                                              # customer
    ]]
    connector._network = net

    out = connector.sweep_vm_rules(rid)
    deleted = {c.args[2] for c in net.security_rules.begin_delete.call_args_list}
    assert deleted == {
        "glorfindel-iso-web-nic1", "glorfindel-iso-web-nic1-out",
        "glorfindel-block-1-2-3-4-web-nic1", "glorfindel-block-1-2-3-4-web-nic1-out",
        f"glorfindel-block-95-47-246-223-web-{h}",
    }
    assert out["status"] == "swept"
    assert out["kept_perimeter"] == ["rg/nsg/glorfindel-block-9-9-9-9"]
    assert _load_isolation_state("web") is None                    # local state cleared


def test_sweep_vm_rules_dry_run_deletes_nothing(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False, read_only=True)       # dry run needs no write
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target()])
    net = MagicMock()
    net.security_rules.list.return_value = [_named("glorfindel-iso-vm-nic-a")]
    connector._network = net
    out = connector.sweep_vm_rules(_RID, dry_run=True)
    assert out["deleted"] == ["rg/nsg/glorfindel-iso-vm-nic-a"]
    net.security_rules.begin_delete.assert_not_called()


def test_sweep_vm_rules_keeps_state_when_a_delete_fails(monkeypatch):
    from glorfindel.actions import AzureConnector, _load_isolation_state, _save_isolation_state
    _save_isolation_state("vm", {"resource_id": _RID})
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target()])
    net = MagicMock()
    net.security_rules.list.return_value = [_named("glorfindel-iso-vm-nic-a")]
    net.security_rules.begin_delete.side_effect = _azure_403()
    connector._network = net
    out = connector.sweep_vm_rules(_RID)
    assert out["status"] == "swept_partial" and out["failed"]
    assert _load_isolation_state("vm") is not None


# ── Seconde passe (2026-10-05) : préséance illisible, nom legacy, blocage périmètre ──

def test_verify_isolation_unreadable_precedence_is_not_verified(monkeypatch):
    """Rules present (`get`) but the listing fails (throttling): the precedence check
    used to read [] as "nothing before our deny" → verified=True on an unknown."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    net = MagicMock()
    net.security_rules.get.return_value = MagicMock()
    net.security_rules.list.side_effect = RuntimeError("429 Too Many Requests")
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is None
    assert out["precedence_unknown"] == ["rg/nsg"]
    assert "non vérifiable" in out["error"]


def test_verify_isolation_checks_precedence_of_a_legacy_named_rule(monkeypatch):
    """A VM isolated before the multi-NIC upgrade carries the legacy VM-suffixed name:
    the precedence check looked for the new name only, found nothing to compare and
    passed — even with allow-ssh evaluated first."""
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets",
                        lambda rg, vm, **_k: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
    legacy_in = "glorfindel-isolation-deny-all-vm"
    net = MagicMock()
    net.security_rules.get.side_effect = (
        lambda rg, nsg, name: MagicMock() if name.startswith(legacy_in) else _raise_not_found())
    net.security_rules.list.return_value = [
        _nsg_rule(**_BENCH_ALLOW_SSH),
        _nsg_rule(legacy_in, 101, access="Deny", dst="10.0.0.5", port="*"),
    ]
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is False
    assert [s["rule"] for s in out["shadowed_by"]] == ["allow-ssh"]


def _raise_not_found():
    raise RuntimeError("(ResourceNotFound) rule not found")


def test_verify_block_ip_unreadable_precedence_is_not_verified(monkeypatch):
    from glorfindel.actions import AzureConnector, _save_block_state
    rule = "glorfindel-block-95-47-246-223-vm-nic-a"
    _save_block_state("vm", "95.47.246.223", _RID, nsg="rg/nsg", nsg_scope="subnet", rule=rule,
                      placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "scope": "subnet",
                                   "rule": rule, "ips": ["10.0.0.5"]}])
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    net = MagicMock()
    net.security_rules.get.return_value = MagicMock()
    net.security_rules.list.side_effect = RuntimeError("timeout")
    connector._network = net

    out = connector.verify_block_ip("95.47.246.223", _RID)
    assert out["verified"] is None
    assert out["precedence_unknown"] == ["rg/nsg"]


def test_perimeter_block_reports_the_allow_that_bypasses_it(monkeypatch):
    """The VM-scoped block reported shadowing at placement; the subnet-wide one only
    learned it at verification."""
    import glorfindel.actions as actions
    from glorfindel.actions import AzureConnector
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: None)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_subnet_nsg", lambda nic: ("rg", "subnet-nsg"))
    net = MagicMock()
    net.security_rules.list.return_value = [_nsg_rule(**_BENCH_ALLOW_SSH)]
    connector._network = net

    out = connector.block_suspicious_ip("95.47.246.223", _RID, scope="subnet")
    assert [s["rule"] for s in out["shadowed_by"]] == ["allow-ssh"]
    assert "contourné" in out["bypass"]


def test_sweep_vm_rules_unreadable_nsg_keeps_state(monkeypatch):
    """An unreadable rule list is not an empty NSG: the sweep must not report success
    and clear the local state while rules may still be there."""
    from glorfindel.actions import AzureConnector, _load_isolation_state, _save_isolation_state
    _save_isolation_state("vm", {"resource_id": _RID})
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target()])
    net = MagicMock()
    net.security_rules.list.side_effect = RuntimeError("403 AuthorizationFailed")
    connector._network = net

    out = connector.sweep_vm_rules(_RID)
    assert out["status"] == "swept_partial"
    assert any("illisibles" in f for f in out["failed"])
    assert _load_isolation_state("vm") is not None


def test_audit_precedence_unreadable_is_a_warning_not_a_pass():
    from glorfindel.audit import _check_precedence
    check = _check_precedence([{"nsg": "rg/nsg", "nic": "nic-a", "unreadable": True}])
    assert check is not None and check.status == "warn"
    assert "rg/nsg" in check.message


# ── Run Azure du 2026-10-05 : rejeu Run Command au restore, sessions ouvertes ──────

def _restore_ready(monkeypatch):
    from datetime import timedelta  # noqa: F401
    connector, client, posted, now = _backup_env(monkeypatch, rps=[], jobs=[])
    rp = _rp("rp-1", now)
    rp.name = "rp-1"
    client.recovery_points.list.return_value = [rp]
    job = _job("restore-1", "vm", "Restore", now)
    job.name = "restore-1"
    client.backup_jobs.list.return_value = [job]
    return connector, posted


def test_restore_neutralizes_run_command_before_swapping_the_disks(monkeypatch):
    """The restored disk replayed the last Run Command at boot — the ransomware script,
    which re-encrypted the restored data (real run, 2026-10-05)."""
    connector, posted = _restore_ready(monkeypatch)
    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    calls = [c[0] for c in connector._compute.mock_calls]
    run = calls.index("virtual_machines.begin_run_command")
    dealloc = calls.index("virtual_machines.begin_deallocate")
    assert run < dealloc
    script = connector._compute.virtual_machines.begin_run_command.call_args.args[2].script
    assert all("ransomware" not in line and "rm " not in line for line in script)
    assert out["run_command_neutralized"] is True and posted


def test_restore_still_runs_when_run_command_cannot_be_neutralized(monkeypatch):
    connector, posted = _restore_ready(monkeypatch)
    connector._compute.virtual_machines.begin_run_command.side_effect = RuntimeError(
        "(OperationNotAllowed) VM is not running")
    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    assert out["run_command_neutralized"] is False
    assert "not running" in out["run_command_error"]
    assert posted                                    # recovery first


def _drain_connector(message="glorfindel-drain-remaining=0", os_type="Linux", error=None):
    from glorfindel.actions import AzureConnector
    c = AzureConnector(dry_run=False)
    c._compute = MagicMock()
    c._compute.virtual_machines.get.return_value.storage_profile.os_disk.os_type = os_type
    if error:
        c._compute.virtual_machines.begin_run_command.side_effect = error
    else:
        res = MagicMock()
        res.value = [MagicMock(message=f"Enable succeeded:\n[stdout]\n{message}\n")]
        c._compute.virtual_machines.begin_run_command.return_value.result.return_value = res
    return c


def test_drain_cuts_established_sessions_but_spares_loopback_and_platform():
    """Measured 2026-10-05: an SSH session (17 min), an idle one and a download all
    survived the isolation rules; `ss -K` through Run Command cut them."""
    c = _drain_connector()
    assert c.drain_connections(_RID) == {"status": "drained"}
    script = " ".join(c._compute.virtual_machines.begin_run_command.call_args.args[2].script)
    assert "ss -K state established" in script
    for spared in ("127.0.0.0/8", "[::1]", "168.63.129.16", "169.254.169.254"):
        assert f"not dst {spared}" in script


def test_drain_reports_what_it_could_not_cut():
    assert _drain_connector("glorfindel-drain-remaining=2").drain_connections(_RID)["status"] == "partial"
    assert _drain_connector(error=RuntimeError("(AuthorizationFailed) runCommand/action"))\
        .drain_connections(_RID)["status"] == "failed"
    assert _drain_connector(os_type="Windows").drain_connections(_RID)["status"] == "unsupported"


def test_isolate_vm_drains_after_the_rules_are_in_place(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target(scope="nic")])
    order = []
    net = MagicMock()
    net.security_rules.list.return_value = []
    net.security_rules.begin_create_or_update.side_effect = lambda *a, **k: order.append("rule") or MagicMock()
    connector._network = net
    monkeypatch.setattr(connector, "drain_connections",
                        lambda rid: order.append("drain") or {"status": "drained"})
    out = connector.isolate_vm(_RID)
    assert out["drain"] == {"status": "drained"}
    assert order[-1] == "drain" and "rule" in order[:-1]


def test_isolation_state_keeps_the_drain_result(monkeypatch):
    """`list` and the War Room must show sessions left open, not only the API response."""
    from glorfindel.actions import AzureConnector, _load_isolation_state
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [_nic_target(scope="nic")])
    net = MagicMock()
    net.security_rules.list.return_value = []
    connector._network = net
    monkeypatch.setattr(connector, "drain_connections",
                        lambda rid: {"status": "failed", "error": "403 runCommand"})
    connector.isolate_vm(_RID)
    assert _load_isolation_state("vm")["drain"]["status"] == "failed"


# ── L3 : port de la menace, NSG de repli pour les blocages ──────────────────────────

def test_rule_covers_port():
    from glorfindel.actions import _rule_covers_port
    assert _rule_covers_port(_nsg_rule("a", 100, port="*"), 22)
    assert _rule_covers_port(_nsg_rule("a", 100, port="20-30"), 22)
    assert not _rule_covers_port(_nsg_rule("a", 100, port="443"), 22)
    multi = _nsg_rule("a", 100, port=None)
    multi.destination_port_ranges = ["80", "22"]
    assert _rule_covers_port(multi, 22)


def _block_env(monkeypatch, rules_by_nsg, target=None):
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    t = target or _nic_target(scope="subnet", ips=("10.0.0.5",))
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm, **_k: [t])
    net = MagicMock()
    net.security_rules.list.side_effect = lambda rg, nsg: rules_by_nsg.get(nsg, [])
    net.security_rules.get.return_value = MagicMock()
    connector._network = net
    return connector, net


def test_ssh_block_is_not_bypassed_by_an_https_allow(monkeypatch):
    """A web server's allow-https before the deny used to declare every SSH block
    bypassed — the alert operators learn to ignore, including the day it is allow-ssh."""
    https = _nsg_rule("allow-https", 150, port="443")
    connector, net = _block_env(monkeypatch, {"nsg": [https]})
    out = connector.block_suspicious_ip("203.0.113.9", _RID, threat_port=22)
    assert "bypass" not in out and "allow-https" in out["exposure"]
    ours = _nsg_rule("glorfindel-block-203-0-113-9-vm-nic-a", 200, access="Deny",
                     src="203.0.113.9", dst="10.0.0.5", port="*")
    net.security_rules.list.side_effect = lambda rg, nsg: [https, ours]
    res = connector.verify_block_ip("203.0.113.9", _RID)
    assert res["verified"] is True and [x["rule"] for x in res["exposure"]] == ["allow-https"]


def test_ssh_block_is_bypassed_by_an_ssh_allow(monkeypatch):
    connector, net = _block_env(monkeypatch, {"nsg": [_nsg_rule(**_BENCH_ALLOW_SSH)]})
    out = connector.block_suspicious_ip("203.0.113.9", _RID, threat_port=22)
    assert "allow-ssh" in out["bypass"]


def test_block_moves_to_the_subnet_nsg_when_the_nic_nsg_lets_the_threat_through(monkeypatch):
    from glorfindel.actions import _load_block_entries
    t = {**_nic_target(nsg_name="nsg-nic", scope="nic", ips=("10.0.0.5",)),
         "alt_nsg": {"nsg_rg": "rg", "nsg_name": "nsg-subnet"}}
    connector, net = _block_env(monkeypatch, {"nsg-nic": [_nsg_rule(**_BENCH_ALLOW_SSH)]}, t)
    out = connector.block_suspicious_ip("203.0.113.9", _RID, threat_port=22)
    assert {c.args[1] for c in net.security_rules.begin_create_or_update.call_args_list} == {"nsg-subnet"}
    assert "bypass" not in out
    entry = _load_block_entries("vm")[0]
    assert entry["threat_port"] == 22 and entry["placements"][0]["nsg_name"] == "nsg-subnet"


def test_shadowing_reads_sdk_enums_not_only_strings():
    """azure-mgmt-network 33 (Docker image) returns enums: str() gave
    'SecurityRuleAccess.ALLOW' and every allow was skipped — precedence check, L3
    fallback and port grading did nothing in the deployed product (2026-10-06)."""
    from azure.mgmt.network.models import SecurityRuleAccess, SecurityRuleDirection
    from glorfindel.actions import _shadowing_rules
    rule = _nsg_rule(**_BENCH_ALLOW_SSH)
    rule.access = SecurityRuleAccess.ALLOW
    rule.direction = SecurityRuleDirection.INBOUND
    found = _shadowing_rules([rule], 200, inbound_src=["203.0.113.9"], inbound_dst=["10.0.0.5"],
                             outbound_src=["10.0.0.5"], outbound_dst=["203.0.113.9"], port=22)
    assert [f["rule"] for f in found] == ["allow-ssh"] and found[0]["threat_port_open"] is True


def test_reapplied_isolation_keeps_its_own_priority(monkeypatch):
    """A re-application (L5) saw its own surviving -out rule at 100 as 'used' and moved
    the pair to 101 (validation run, 2026-10-06)."""
    connector, net = _block_env(monkeypatch, {})
    monkeypatch.setattr(connector, "drain_connections", lambda rid: {"status": "drained"})
    survivor = _nsg_rule("glorfindel-iso-vm-nic-a-out", 100, direction="Outbound", access="Deny", port="*")
    net.security_rules.list.side_effect = lambda rg, nsg: [survivor]
    connector.isolate_vm(_RID)
    assert {c.args[3].priority for c in net.security_rules.begin_create_or_update.call_args_list} == {100}


# ── L4 : NSG de quarantaine sur les NIC sans NSG ─────────────────────────────────────

_NIC_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic-a"
_SUBNET_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/default"
_Q_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-glorfindel-quarantine-westeurope"
_SUBNET_NSG_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-subnet"


def _l4_env(monkeypatch, nic_nsg_id=None, subnet_nsg_id=_SUBNET_NSG_ID, quarantine_exists=False):
    """A VM with one NIC, as the SDK returns it; records NIC updates."""
    from types import SimpleNamespace
    from glorfindel.actions import AzureConnector
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "drain_connections", lambda rid: {"status": "drained"})
    monkeypatch.setattr(connector, "_quarantine_settings", lambda: (True, ""))
    compute, net = MagicMock(), MagicMock()
    compute.virtual_machines.get.return_value = SimpleNamespace(
        network_profile=SimpleNamespace(network_interfaces=[SimpleNamespace(id=_NIC_ID)]))
    nic = SimpleNamespace(
        location="westeurope",
        network_security_group=SimpleNamespace(id=nic_nsg_id) if nic_nsg_id else None,
        ip_configurations=[SimpleNamespace(private_ip_address="10.0.0.5",
                                           subnet=SimpleNamespace(id=_SUBNET_ID))])
    net.network_interfaces.get.return_value = nic
    net.subnets.get.return_value = SimpleNamespace(
        network_security_group=SimpleNamespace(id=subnet_nsg_id) if subnet_nsg_id else None)
    q = SimpleNamespace(id=_Q_ID, tags={}, security_rules=[SimpleNamespace(name=n) for n in (
        "glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out",
        "glorfindel-quarantine-deny-dns", "glorfindel-quarantine-deny-imds")])
    net.network_security_groups.update_tags.side_effect = lambda rg, name, t: setattr(q, "tags", dict(t.tags))
    if quarantine_exists:
        net.network_security_groups.get.return_value = q
    else:
        net.network_security_groups.get.side_effect = _not_found_exc()
    net.network_security_groups.begin_create_or_update.return_value.result.return_value = q
    net.security_rules.list.return_value = []
    connector._compute, connector._network = compute, net
    return connector, net, nic


def _not_found_exc():
    from azure.core.exceptions import ResourceNotFoundError
    return ResourceNotFoundError("(ResourceNotFound) not found")


def test_targets_describe_own_nsg_quarantine_and_no_nsg(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch)
    [t] = connector._get_vm_nic_targets("rg", "vm")
    assert t["nic_has_nsg"] is False and t["scope"] == "subnet" and t["quarantine"] is None
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    [t] = connector._get_vm_nic_targets("rg", "vm")
    assert t["quarantine"]["nsg_name"] == "nsg-glorfindel-quarantine-westeurope"
    assert t["nsg_name"] == "nsg-subnet"            # a block must not land in the quarantine NSG
    net.subnets.get.return_value.network_security_group = None
    nic.network_security_group = None
    [t] = connector._get_vm_nic_targets("rg", "vm", allow_no_nsg=True)
    assert t["scope"] == "none"
    with pytest.raises(RuntimeError, match="no NSG"):
        connector._get_vm_nic_targets("rg", "vm")


def test_isolation_attaches_the_quarantine_nsg_to_a_nic_without_one(monkeypatch):
    """L4: no customer rule touched, nothing evaluated before the deny, and a NIC NSG
    Terraform doesn't manage (verified in the azurerm provider)."""
    from glorfindel.actions import _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch)
    out = connector.isolate_vm(_RID)
    created = net.network_security_groups.begin_create_or_update.call_args
    assert created.args[1] == "nsg-glorfindel-quarantine-westeurope"
    assert {r.name for r in created.args[2].security_rules} == {
        "glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out",
        "glorfindel-quarantine-deny-dns", "glorfindel-quarantine-deny-imds"}
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group.id == _Q_ID
    net.security_rules.begin_create_or_update.assert_not_called()     # nothing in the subnet NSG
    assert out["placements"][0]["scope"] == "quarantine" and out["drain"]["status"] == "drained"
    assert _load_isolation_state("vm")["placements"][0]["kind"] == "quarantine"


def test_refused_attachment_falls_back_to_the_subnet_rules(monkeypatch):
    """An Azure Policy forbidding NIC-level NSGs (frequent) must not leave the VM open."""
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    net.network_interfaces.begin_create_or_update.side_effect = RuntimeError(
        "(RequestDisallowedByPolicy) NSG on NIC not allowed")
    out = connector.isolate_vm(_RID)
    assert {c.args[1] for c in net.security_rules.begin_create_or_update.call_args_list} == {"nsg-subnet"}
    assert "RequestDisallowedByPolicy" in out["quarantine_refused"][0]


def test_no_nsg_at_all_and_attachment_refused_raises(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch, subnet_nsg_id=None, quarantine_exists=True)
    net.network_interfaces.begin_create_or_update.side_effect = RuntimeError("403 Forbidden")
    with pytest.raises(RuntimeError, match="403"):
        connector.isolate_vm(_RID)


def test_release_detaches_only_our_quarantine_nsg(monkeypatch):
    """If the customer's NSG replaced ours in the meantime, release must not touch it."""
    from glorfindel.actions import _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": "/subscriptions/s/.../networkSecurityGroups/nsg-customer"})()
    net.network_interfaces.begin_create_or_update.reset_mock()
    assert connector.release_isolation(_RID)["status"] == "released"
    net.network_interfaces.begin_create_or_update.assert_not_called()
    assert _load_isolation_state("vm") is None


def test_release_detaches_the_quarantine_nsg(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    net.network_interfaces.begin_create_or_update.reset_mock()
    connector.release_isolation(_RID)
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group is None
    net.security_rules.begin_delete.assert_not_called()               # the shared NSG keeps its rules


def test_verify_isolation_and_release_see_the_quarantine_nsg(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    net.security_rules.get.return_value = MagicMock()
    ours = _nsg_rule("glorfindel-quarantine-deny-in", 100, access="Deny", port="*")
    net.security_rules.list.return_value = [ours]
    assert connector.verify_isolation(_RID)["verified"] is True
    assert connector.verify_release(_RID)["verified"] is False


def test_reset_from_azure_detaches_the_quarantine_nsg(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    out = connector.sweep_vm_rules(_RID)
    assert any("retirer nsg-glorfindel-quarantine" in d for d in out["deleted"])
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group is None


# ── JIT : échange du NSG d'une carte qui en a un ─────────────────────────────────────

_CLIENT_NSG_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-client"


def test_jit_swaps_the_customer_nsg_and_keeps_the_original_in_azure(monkeypatch):
    """Validated with Jonathan on 2026-10-06 after measuring it on the bench: Terraform
    neither sees nor reverts a swapped NIC NSG. The customer's NSG is left untouched."""
    from glorfindel.actions import AzureConnector, _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch, nic_nsg_id=_CLIENT_NSG_ID, quarantine_exists=True)
    order = []
    net.network_security_groups.update_tags.side_effect = (
        lambda rg, name, t: order.append("tag") or setattr(net.network_security_groups.get.return_value, "tags", dict(t.tags)))
    net.network_interfaces.begin_create_or_update.side_effect = lambda *a: order.append("swap") or MagicMock()
    connector.isolate_vm(_RID)
    assert order == ["tag", "swap"]                     # the original is in Azure before the swap
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group.id == _Q_ID
    tags = net.network_security_groups.get.return_value.tags
    assert tags[AzureConnector._orig_tag(_NIC_ID)] == _CLIENT_NSG_ID
    assert _load_isolation_state("vm")["placements"][0]["original_nsg_id"] == _CLIENT_NSG_ID
    net.security_rules.begin_create_or_update.assert_not_called()     # nothing written in nsg-client


def test_release_puts_the_customer_nsg_back(monkeypatch):
    from glorfindel.actions import AzureConnector
    connector, net, nic = _l4_env(monkeypatch, nic_nsg_id=_CLIENT_NSG_ID, quarantine_exists=True)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    net.network_interfaces.begin_create_or_update.reset_mock()
    assert connector.release_isolation(_RID)["status"] == "released"
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group.id == _CLIENT_NSG_ID
    assert AzureConnector._orig_tag(_NIC_ID) not in net.network_security_groups.get.return_value.tags


def test_release_without_state_reads_the_original_from_azure(monkeypatch):
    """The local state is lost: the tag on our NSG still says which NSG to put back."""
    from glorfindel.actions import AzureConnector
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    net.network_security_groups.get.return_value.tags = {AzureConnector._orig_tag(_NIC_ID): _CLIENT_NSG_ID}
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    connector.release_isolation(_RID)
    assert net.network_interfaces.begin_create_or_update.call_args.args[2].network_security_group.id == _CLIENT_NSG_ID



# ── Troisième passe (T3, T4) : pas de succès sur une inconnue ─────────────────────────

def test_release_keeps_the_quarantine_when_the_original_is_unknown(monkeypatch):
    """No state and an unreadable tag: the NIC used to lose every NSG while
    verify_release said verified. It stays in quarantine; the release says so."""
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    monkeypatch.setattr(connector, "_quarantine_tags", lambda q: (_ for _ in ()).throw(RuntimeError("429")))
    out = connector.release_isolation(_RID)
    assert out["status"] == "release_partial"
    net.network_interfaces.begin_create_or_update.assert_not_called()


def test_release_checks_the_original_came_back(monkeypatch):
    """Released means the customer's NSG is on the NIC again, not only ours gone."""
    from glorfindel.actions import _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch, nic_nsg_id=_CLIENT_NSG_ID, quarantine_exists=True)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    monkeypatch.setattr(connector, "_nic_nsg_id", lambda nic_id: None)    # Azure didn't apply it
    out = connector.release_isolation(_RID)
    assert out["status"] == "release_partial" and "non remis" in out["failed"][0]
    assert _load_isolation_state("vm")["placements"][0]["original_nsg_id"] == _CLIENT_NSG_ID


def test_an_overwritten_original_tag_cancels_the_swap(monkeypatch):
    """Two isolations at once rewrote the shared NSG's tags: read back, and fall back
    to the rules rather than swap with no record of the customer's NSG."""
    connector, net, nic = _l4_env(monkeypatch, nic_nsg_id=_CLIENT_NSG_ID, quarantine_exists=True)
    net.network_security_groups.update_tags.side_effect = lambda *a: None   # the tag never lands
    out = connector.isolate_vm(_RID)
    assert all(c.args[2].network_security_group.id != _Q_ID
               for c in net.network_interfaces.begin_create_or_update.call_args_list)
    assert "not recorded" in out["quarantine_refused"][0]


def test_reisolation_keeps_the_original_recorded_in_state(monkeypatch):
    """Re-applying on a NIC already in quarantine read the original from the tag only,
    and overwrote the state's with None when the tag was gone."""
    from glorfindel.actions import _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch, nic_nsg_id=_CLIENT_NSG_ID, quarantine_exists=True)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    net.network_security_groups.get.return_value.tags = {}                 # tag lost
    connector.isolate_vm(_RID)
    assert _load_isolation_state("vm")["placements"][0]["original_nsg_id"] == _CLIENT_NSG_ID


def test_windows_isolation_is_not_verified_while_sessions_stay_open():
    """`unsupported` left verified=True and a ✓ notification (T4)."""
    from glorfindel.actions import isolation_verdict
    out = isolation_verdict({"verified": True}, {"drain": {"status": "unsupported", "note": "Windows"}})
    assert out["verified"] is False and "non coupées" in out["error"]


def test_a_drain_count_that_failed_is_not_zero():
    """`ss … | wc -l` printed 0 when ss was missing or refused -H."""
    assert _drain_connector("glorfindel-drain-remaining=error").drain_connections(_RID)["status"] == "failed"

# ── L6 : droits de l'isolation, lus sans rien écrire ─────────────────────────────────

def test_check_permissions_lists_what_is_missing(monkeypatch):
    """Reader + a role whose notActions exclude NIC writes: the JIT swap can't run."""
    import sys
    import types
    from glorfindel.actions import AzureConnector
    perms = {"value": [
        {"actions": ["*/read"], "notActions": []},
        {"actions": ["Microsoft.Network/*", "Microsoft.Compute/virtualMachines/*"],
         "notActions": ["Microsoft.Network/networkInterfaces/write"]},
    ]}
    fake = types.ModuleType("requests")
    fake.get = lambda *a, **k: types.SimpleNamespace(ok=True, json=lambda: perms, status_code=200, text="")
    monkeypatch.setitem(sys.modules, "requests", fake)
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    monkeypatch.setattr(connector, "_quarantine_settings", lambda: (True, ""))
    connector._credential = MagicMock()
    connector._subscription_id = "s"
    res = connector.check_permissions(_RID)
    assert [m["action"] for m in res["missing"]] == ["Microsoft.Network/networkInterfaces/write"]


def test_audit_reports_missing_isolation_permissions():
    from glorfindel import audit
    connector = MagicMock()
    connector.dry_run = False
    connector.read_only = False
    connector.check_nsg_access.return_value = {"ok": True, "nsg": "rg/nsg", "rules": 1, "nsgs": [], "precedence": []}
    connector.check_backup_points.return_value = {"ok": True, "points": 3, "latest_age_h": 1}
    connector.check_compute_access.return_value = {"ok": True, "vm": "vm", "disks": []}
    connector.check_permissions.return_value = {"ok": True, "missing": [
        {"scope": "rg", "action": "Microsoft.Compute/virtualMachines/runCommand/action", "used_by": "isolate_vm"}]}
    result = audit.run(_RID, connector, vault="rsv", staging_storage="st")
    check = next(c for c in result.checks if c.name == "Isolation permissions")
    assert check.status == "fail" and "runCommand" in check.message


def test_an_action_in_another_subscription_is_refused(monkeypatch):
    """Ids were reduced to (group, name) in AZURE_SUBSCRIPTION_ID: a VM discovered in
    subscription B was isolated in A, on the homonymous VM (third review, T1)."""
    from glorfindel.actions import AzureConnector, WrongSubscriptionError
    connector = AzureConnector(dry_run=False)
    monkeypatch.setattr(connector, "_ensure_clients", lambda: None)
    connector._subscription_id = "sub-a"
    connector._network = MagicMock()
    other = "/subscriptions/sub-b/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    for call in (lambda: connector.isolate_vm(other),
                 lambda: connector.block_suspicious_ip("203.0.113.9", other),
                 lambda: connector.release_isolation(other)):
        with pytest.raises(WrongSubscriptionError):
            call()
    connector._network.network_interfaces.begin_create_or_update.assert_not_called()


def test_readiness_says_a_vm_of_another_subscription_is_not_ready():
    from glorfindel.readiness import assess
    c = MagicMock(read_only=False, _subscription_id="sub-a")
    a = assess("/subscriptions/sub-b/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm", c)
    assert a["verdict"] == "not_ready" and a["reasons"][0]["code"] == "other_subscription"
    c.check_permissions.assert_not_called()


def test_release_records_its_intent_before_touching_azure(monkeypatch):
    """A release cut off midway (War Room timeout, crash) must read as 'being released',
    not as an isolation removed outside Glorfindel (third review, T2)."""
    from glorfindel.actions import _load_isolation_state
    connector, net, nic = _l4_env(monkeypatch)
    connector.isolate_vm(_RID)
    nic.network_security_group = type("R", (), {"id": _Q_ID})()
    seen = []
    orig = connector._unquarantine
    monkeypatch.setattr(connector, "_unquarantine",
                        lambda *a: seen.append(_load_isolation_state("vm").get("releasing_at")) or orig(*a))
    assert connector.release_isolation(_RID)["status"] == "released"
    assert seen and seen[0]



def test_quarantine_blocks_azure_dns_and_imds_and_lets_forensics_in(monkeypatch):
    """Measured 2026-10-07: an isolated VM still resolved names through Azure DNS and
    fetched IMDS tokens — NSGs don't filter those without their service tags (L17)."""
    connector, net, nic = _l4_env(monkeypatch)
    monkeypatch.setattr(connector, "_forensic_sources", lambda: ["10.9.0.0/26"])
    connector.isolate_vm(_RID)
    rules = {r.name: r for r in net.network_security_groups.begin_create_or_update.call_args.args[2].security_rules}
    assert rules["glorfindel-quarantine-deny-dns"].destination_address_prefix == "AzurePlatformDNS"
    assert rules["glorfindel-quarantine-deny-imds"].destination_address_prefix == "AzurePlatformIMDS"
    fwd = rules["glorfindel-quarantine-forensic-in"]
    assert fwd.access == "Allow" and fwd.priority < 100 and fwd.source_address_prefixes == ["10.9.0.0/26"]


def test_an_older_quarantine_nsg_gets_the_platform_rules(monkeypatch):
    connector, net, nic = _l4_env(monkeypatch, quarantine_exists=True)
    net.network_security_groups.get.return_value.security_rules = [
        type("R", (), {"name": n})() for n in ("glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out")]
    connector._ensure_quarantine_nsg("westeurope", "rg")
    assert {c.args[2] for c in net.security_rules.begin_create_or_update.call_args_list} == {
        "glorfindel-quarantine-deny-dns", "glorfindel-quarantine-deny-imds"}


def test_neutralized_only_when_the_harmless_command_finished(monkeypatch):
    """result(timeout) returns at the deadline without raising (third review, T13)."""
    connector, posted = _restore_ready(monkeypatch)
    connector._compute.virtual_machines.begin_run_command.return_value.done.return_value = False
    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    assert out["run_command_neutralized"] is False and "600" in out["run_command_error"]


def test_other_replayable_scripts_hold_the_release(monkeypatch):
    """A CustomScript extension or a managed Run Command (v2) replays like Run Command
    v1 on a restored disk: Glorfindel can't vouch for them (third review, T13)."""
    from types import SimpleNamespace
    connector, posted = _restore_ready(monkeypatch)
    def ext(name, publisher, typ):      # the shape azure-mgmt-compute 38 returns (measured)
        d = {"name": name, "type": "Microsoft.Compute/virtualMachines/extensions",
             "properties": {"publisher": publisher, "type": typ}}
        return SimpleNamespace(name=name, publisher=publisher, as_dict=lambda: d)
    connector._compute.virtual_machine_extensions.list.return_value = SimpleNamespace(value=[
        ext("AzureMonitorLinuxAgent", "Microsoft.Azure.Monitor", "AzureMonitorLinuxAgent"),
        ext("setup", "Microsoft.Azure.Extensions", "CustomScript")])
    connector._compute.virtual_machine_run_commands.list_by_virtual_machine.return_value = [
        SimpleNamespace(name="nightly")]
    out = connector.restore_from_backup(_RID, vault="rsv", wait=False, staging_storage="st")
    assert out["run_command_neutralized"] is False
    assert out["replay_vectors"] == ["extension setup", "run command managé nightly"]
