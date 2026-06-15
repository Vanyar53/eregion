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


def test_check_backup_points_not_protected(monkeypatch):
    """Empty RP list + item is NOT a protected item → protected=False (not linked)."""
    connector = _backup_connector(monkeypatch, rps=[], protected_get_raises=True)
    res = connector.check_backup_points(_RID, vault="rsv-annatar")
    assert res["ok"] is False
    assert res["protected"] is False
    assert "not linked" in res["error"].lower()


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
    monkeypatch.setattr(connector, "_get_primary_nic_id", lambda rg, vm: "nic-id")
    monkeypatch.setattr(connector, "_get_nic_nsg", lambda nic: ("rg", "nsg"))

    net = MagicMock()
    net.security_rules.list.return_value = []          # no conflicting rules to bump
    net.security_rules.begin_create_or_update.side_effect = _azure_403()  # deny-all write fails
    connector._network = net

    with pytest.raises(Exception):
        connector.isolate_vm(_RID)

    # No orphan state file — the VM is not actually isolated
    assert _load_isolation_state("vm") is None


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
    connector.check_backup_points = lambda rid, vault="rsv-annatar": {"ok": True, "points": 2, "latest_age_h": 5}
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
