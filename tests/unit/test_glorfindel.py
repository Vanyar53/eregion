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
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm: [
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
                        lambda rg, vm: [_nic_target(scope="nic")])

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
                        lambda rg, vm: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
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
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm: [
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
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm: [
        _nic_target(nsg_rg="rg1", nsg_name="nsg-a", nic_id="nic-a"),
        _nic_target(nsg_rg="rg2", nsg_name="nsg-b", nic_id="nic-b"),
    ])
    net = MagicMock()

    def _get(rg, name, rule):
        if name == "nsg-b":               # nic-b has NO rules → uncovered
            raise Exception("NotFound")
        return MagicMock()
    net.security_rules.get.side_effect = _get
    connector._network = net

    out = connector.verify_isolation(_RID)
    assert out["verified"] is False
    assert "nic-b" in out["uncovered_nics"]


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
                        lambda rg, vm: [_nic_target(scope="subnet", ips=("10.0.0.6",))])
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
                        lambda rg, vm: [_nic_target(scope="subnet", ips=("10.0.0.5",))])
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
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm: [
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
    monkeypatch.setattr(connector, "_get_vm_nic_targets", lambda rg, vm: [
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
                        lambda rg, vm: [_nic_target(nsg_rg="rg", nsg_name="subnet-nsg",
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
                        lambda rg, vm: [_nic_target(scope="nic")])
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
                        lambda rg, vm: [_nic_target(scope="nic")])
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
