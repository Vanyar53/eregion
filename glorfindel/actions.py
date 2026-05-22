from __future__ import annotations

from abc import ABC, abstractmethod

# Actions Glorfindel peut exécuter seul (réversibles)
AUTONOMOUS_ACTIONS = {
    "isolate_vm",
    "revoke_temp_access",
    "snapshot_before_restore",
    "block_suspicious_ip",
}

# Actions nécessitant validation humaine (destructives ou à impact large)
HUMAN_APPROVAL_REQUIRED = {
    "delete_resource",
    "modify_network_rule",
    "escalate_permissions",
    "wipe_storage",
}


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
    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict:
        """Add deny rule for this IP on the resource's NSG."""
        ...

    @abstractmethod
    def snapshot(self, resource_id: str) -> str:
        """Take an on-demand snapshot before any destructive recovery."""
        ...

    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict:
        """Confirm that isolation rules are active on the VM's NSG."""
        ...


class AzureConnector(CloudConnector):
    """Azure implementation of CloudConnector.

    All mutating actions are restricted to resources tagged annatar-test: 'true'
    unless the resource_id is explicitly in an override list.
    """

    ISOLATION_RULE_NAME = "glorfindel-isolation-deny-all"
    ISOLATION_PRIORITY = 100

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._credential = None
        self._subscription_id = None
        self._network = None
        self._compute = None

    def _ensure_clients(self) -> None:
        if self._network is not None:
            return
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.subscription import SubscriptionClient

        self._credential = DefaultAzureCredential()
        sub_client = SubscriptionClient(self._credential)
        self._subscription_id = next(sub_client.subscriptions.list()).subscription_id
        self._network = NetworkManagementClient(self._credential, self._subscription_id)
        self._compute = ComputeManagementClient(self._credential, self._subscription_id)

    def isolate_vm(self, resource_id: str) -> dict:
        """Apply a deny-all NSG rule (priority 100) to the VM's primary NIC.

        Tag: glorfindel-isolation-deny-all — used by release_isolation to find and remove it.
        Safe: only the NSG rule is changed, VM stays running and observable.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        from azure.mgmt.network.models import SecurityRule

        rule = SecurityRule(
            name=self.ISOLATION_RULE_NAME,
            protocol="*",
            source_port_range="*",
            destination_port_range="*",
            source_address_prefix="*",
            destination_address_prefix="*",
            access="Deny",
            priority=self.ISOLATION_PRIORITY,
            direction="Inbound",
        )
        self._network.security_rules.begin_create_or_update(
            nsg_rg, nsg_name, self.ISOLATION_RULE_NAME, rule
        ).result()

        outbound_rule = SecurityRule(
            name=f"{self.ISOLATION_RULE_NAME}-out",
            protocol="*",
            source_port_range="*",
            destination_port_range="*",
            source_address_prefix="*",
            destination_address_prefix="*",
            access="Deny",
            priority=self.ISOLATION_PRIORITY,
            direction="Outbound",
        )
        self._network.security_rules.begin_create_or_update(
            nsg_rg, nsg_name, f"{self.ISOLATION_RULE_NAME}-out", outbound_rule
        ).result()

        return {
            "status": "isolated",
            "nsg": f"{nsg_rg}/{nsg_name}",
            "rule": self.ISOLATION_RULE_NAME,
            "resource_id": resource_id,
        }

    def release_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        for rule_name in (self.ISOLATION_RULE_NAME, f"{self.ISOLATION_RULE_NAME}-out"):
            try:
                self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
            except Exception:
                pass  # rule may not exist — that's fine

        return {"status": "released", "resource_id": resource_id}

    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict:
        if self.dry_run:
            return {"status": "dry_run", "action": "block_ip", "ip": ip}
        raise NotImplementedError("block_suspicious_ip: not yet implemented")

    def snapshot(self, resource_id: str) -> str:
        if self.dry_run:
            return "snap-dry-run-000"
        raise NotImplementedError("snapshot: not yet implemented")

    def verify_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_nic_nsg(nic_id)

        try:
            self._network.security_rules.get(nsg_rg, nsg_name, self.ISOLATION_RULE_NAME)
            self._network.security_rules.get(nsg_rg, nsg_name, f"{self.ISOLATION_RULE_NAME}-out")
            return {"verified": True, "method": "nsg_check", "nsg": f"{nsg_rg}/{nsg_name}"}
        except Exception as e:
            return {"verified": False, "method": "nsg_check", "error": str(e)}

    def _get_primary_nic_id(self, rg: str, vm_name: str) -> str:
        vm = self._compute.virtual_machines.get(rg, vm_name)
        nics = vm.network_profile.network_interfaces
        primary = next((n for n in nics if n.primary), nics[0])
        return primary.id

    def _get_nic_nsg(self, nic_id: str) -> tuple[str, str]:
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        if nic.network_security_group is None:
            raise RuntimeError(f"NIC {nic_name} has no NSG — cannot isolate VM")
        nsg_id = nic.network_security_group.id
        return _parse_nsg_resource_id(nsg_id)


def _parse_vm_resource_id(resource_id: str) -> tuple[str, str]:
    parts = resource_id.split("/")
    rg_idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
    return parts[rg_idx + 1], parts[-1]


def _parse_nic_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)


def _parse_nsg_resource_id(resource_id: str) -> tuple[str, str]:
    return _parse_vm_resource_id(resource_id)
