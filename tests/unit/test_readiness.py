"""Activation readiness (lot L6): verdict + reasons from Azure, nothing written."""
from __future__ import annotations

from unittest.mock import MagicMock

from glorfindel.readiness import activation_refusal, assess

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"


def _conn(missing=(), precedence=(), nsg_ok=True, os_type="linux", read_only=False):
    c = MagicMock()
    c.read_only = read_only
    c.check_permissions.return_value = {"ok": True, "missing": [
        {"scope": "rg", "action": a, "used_by": "isolate_vm"} for a in missing]}
    c.check_nsg_access.return_value = (
        {"ok": True, "precedence": list(precedence)} if nsg_ok
        else {"ok": False, "error": "NIC nic and its subnet have no NSG — cannot isolate VM"})
    c.vm_os.return_value = os_type
    return c


def test_all_rights_and_no_bypass_is_ready():
    a = assess(_RID, _conn())
    assert a["verdict"] == "ready" and a["reserve_codes"] == []
    assert [r["level"] for r in a["reasons"]] == ["info"]          # AVNM / Policy not checked


def test_read_only_credentials_are_not_ready():
    assert assess(_RID, _conn(read_only=True))["verdict"] == "not_ready"


def test_no_right_to_isolate_at_all_is_not_ready():
    a = assess(_RID, _conn(missing=[
        "Microsoft.Network/networkInterfaces/write",
        "Microsoft.Network/networkSecurityGroups/securityRules/write"]))
    assert a["verdict"] == "not_ready"
    assert "cannot_isolate" in {r["code"] for r in a["reasons"]}


def test_missing_run_command_is_a_reserve_open_sessions_survive():
    a = assess(_RID, _conn(missing=["Microsoft.Compute/virtualMachines/runCommand/action"]))
    assert a["verdict"] == "reserve" and a["reserve_codes"] == ["no_drain"]


def test_rules_fallback_exposes_the_isolation_to_customer_allows():
    a = assess(_RID, _conn(
        missing=["Microsoft.Network/networkInterfaces/write"],
        precedence=[{"rule": "allow-ssh", "action": "isolate_vm"},
                    {"rule": "allow-ssh", "action": "block_suspicious_ip"}]))
    assert a["reserve_codes"] == ["block_may_be_bypassed", "isolation_bypassed", "rules_fallback"]


def test_jit_isolation_ignores_isolation_precedence_but_not_blocks():
    a = assess(_RID, _conn(precedence=[{"rule": "allow-ssh", "action": "isolate_vm"},
                                       {"rule": "allow-https", "action": "block_suspicious_ip"}]))
    assert a["reserve_codes"] == ["block_may_be_bypassed"]


def test_no_nsg_anywhere_still_isolates_but_cannot_block():
    a = assess(_RID, _conn(nsg_ok=False))
    assert a["reserve_codes"] == ["no_nsg_for_blocks"]


def test_windows_has_no_session_drain():
    assert "windows_no_drain" in assess(_RID, _conn(os_type="windows"))["reserve_codes"]


def test_activation_needs_every_reserve_acknowledged():
    a = assess(_RID, _conn(missing=["Microsoft.Compute/virtualMachines/runCommand/action"]))
    assert "no_drain" in activation_refusal(a, [])
    assert activation_refusal(a, ["no_drain"]) is None
    assert "pas prête" in activation_refusal(assess(_RID, _conn(read_only=True)), ["read_only"])
