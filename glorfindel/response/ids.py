"""Resource ids: comparison, parts, subscription (moved from actions.py, A1).

Every id Glorfindel records today is an Azure resource id.
"""
from __future__ import annotations



def _same_id(a: str, b: str) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def _subscription_of(resource_id: str) -> str:
    parts = (resource_id or "").split("/")
    for i, part in enumerate(parts[:-1]):
        if part.lower() == "subscriptions":
            return parts[i + 1]
    return ""


def _is_backupable_vm(resource_id: str) -> bool:
    """True only for a standalone Microsoft.Compute/virtualMachines.

    Azure Backup IaaS-VM protects standalone VMs only. NOT a backup item (and the
    VM-oriented checks — backup/NSG/compute — don't apply): a VMSS instance, an AKS
    managed cluster (Microsoft.ContainerService/managedClusters — what the AMA heartbeat
    actually reports for AKS nodes, NOT the VMSS-instance id), or any other resource.
    Allowlisting standalone VMs is more robust than denylisting each non-VM type."""
    low = resource_id.lower()
    return (
        "/providers/microsoft.compute/virtualmachines/" in low
        and "/virtualmachinescalesets/" not in low
    )


def _parse_vm_resource_id(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
    return parts[rg_idx + 1], parts[-1]


def _parse_nic_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)


def _parse_nsg_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)
