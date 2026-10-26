"""The provider interface: what Glorfindel asks of a cloud (moved from actions.py, A1).

Azure is the only adapter today (`glorfindel/providers/azure/`).
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class CloudConnector(ABC):
    """Provider-agnostic interface. Azure now, AWS/GCP later."""

    @abstractmethod
    def isolate_vm(self, resource_id: str) -> dict:
        """Block all inbound/outbound traffic on the VM's NIC. Fully reversible."""
        ...

    @abstractmethod
    def release_isolation(self, resource_id: str) -> dict:
        """Remove the isolation NSG rule applied by isolate_vm."""
        ...

    @abstractmethod
    def block_suspicious_ip(
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
        threat_port: int | None = None,
    ) -> dict:
        """Add deny rule for this IP. scope="vm" (this VM only) | "subnet" (all VMs).
        replace=True (with scope="subnet"): promote — apply the subnet rule, then drop
        the now-redundant VM-scoped rule (create-then-delete → no protection gap)."""
        ...

    @abstractmethod
    def snapshot(
        self, resource_id: str, vault: str = "", wait: bool = True,
        vault_rg: str = "",
    ) -> str:
        """Take an on-demand RSV backup snapshot.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately. The agent always uses
        it: a blocking snapshot holds the VM's (serialized) signal queue for the whole
        backup — 4h25 on an initial full backup in a real run.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        ...

    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict:
        """Confirm that isolation rules are active on EVERY NIC of the VM."""
        ...

    def verify_release(self, resource_id: str) -> dict:
        """Confirm that NO isolation rule remains on any NIC of the VM.

        Not `not verify_isolation()`: that is False as soon as ONE NIC is uncovered, so
        its negation would call a VM released while another NIC is still cut off.
        Default for connectors that don't implement it: no claim (verified=None).
        """
        return {"verified": None, "method": "not_implemented"}

    @abstractmethod
    def verify_snapshot(self, snap_id: str) -> dict:
        """Confirm that a snapshot was actually created."""
        ...

    @abstractmethod
    def restore_from_backup(
        self,
        resource_id: str,
        vault: str = "",
        before_attack_time: str | None = None,
        wait: bool = True,
        staging_storage: str = "",
        vault_rg: str = "",
    ) -> dict:
        """Trigger an Azure Backup OriginalLocation restore. Human-approved action.

        before_attack_time: ISO8601 timestamp — selects the most recent recovery point
        that predates the attack, avoiding restoration of a post-attack backup.
        wait=False: returns after triggering the restore job, without polling.
          VM stays deallocated; caller must start it and emit recovery_complete manually.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        ...

    @abstractmethod
    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        """Confirm that the deny rule for this IP is active on the NSG."""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove the deny rules created by block_suspicious_ip for this IP."""
        ...

