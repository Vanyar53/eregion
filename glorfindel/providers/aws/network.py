"""Instances, ENIs, security groups and network ACLs: the reads, and the one write of an
ENI's groups (MC1). Every call goes through the injected EC2 client (client.Ec2Client).
"""
from __future__ import annotations

from glorfindel.providers.aws.client import is_not_found


def same_groups(a, b) -> bool:
    """Two lists of security groups are the same set (AWS keeps no order that matters)."""
    return sorted(a or []) == sorted(b or [])


class NetworkMixin:
    """Reads and the ENI's groups (part of AwsConnector)."""

    @staticmethod
    def _eni_record(n: dict) -> dict:
        return {"eni": n["NetworkInterfaceId"], "vpc": n.get("VpcId", ""), "subnet": n.get("SubnetId", ""),
                "ips": [a["PrivateIpAddress"] for a in n.get("PrivateIpAddresses") or [] if a.get("PrivateIpAddress")],
                "groups": [g["GroupId"] for g in n.get("Groups") or []]}

    def _instance_enis(self, instance_id: str) -> list[dict]:
        """The ENIs of the instance, by device index. A missing instance raises (its
        `.NotFound` error, H8)."""
        reservations = self._ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations") or []
        instances = [i for r in reservations for i in r.get("Instances") or []]
        if not instances:
            raise LookupError(f"instance {instance_id} introuvable")
        nics = sorted(instances[0].get("NetworkInterfaces") or [],
                      key=lambda n: (n.get("Attachment") or {}).get("DeviceIndex", 0))
        return [self._eni_record(n) for n in nics]

    def _instance_platform(self, instance_id: str) -> str:
        reservations = self._ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations") or []
        instances = [i for r in reservations for i in r.get("Instances") or []]
        return str((instances[0] if instances else {}).get("Platform") or "linux").lower()

    def _eni_groups(self, eni_id: str) -> list[str]:
        nics = self._ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id]).get("NetworkInterfaces") or []
        if not nics:
            raise LookupError(f"ENI {eni_id} introuvable")
        return [g["GroupId"] for g in nics[0].get("Groups") or []]

    def _set_groups(self, eni_id: str, groups: list[str], expect: list[str]) -> bool:
        """Give the ENI `groups`, only if it still carries `expect` (read just before):
        a change in between is someone else's, and is not overwritten. False if it was."""
        if not same_groups(self._eni_groups(eni_id), expect):
            return False
        self._ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=list(groups))
        return True

    def _sg(self, sg_id: str) -> dict | None:
        """The security group, or None when it does not exist (any other error raises)."""
        try:
            found = self._ec2.describe_security_groups(GroupIds=[sg_id]).get("SecurityGroups") or []
        except Exception as exc:
            if is_not_found(exc):
                return None
            raise
        return found[0] if found else None

    def _sg_named(self, vpc: str, name: str) -> dict | None:
        found = self._ec2.describe_security_groups(Filters=[
            {"Name": "vpc-id", "Values": [vpc]}, {"Name": "group-name", "Values": [name]}]).get("SecurityGroups") or []
        return found[0] if found else None

    def _default_sg(self, vpc: str) -> str | None:
        sg = self._sg_named(vpc, "default")
        return sg["GroupId"] if sg else None

    def _acl_of(self, subnet: str) -> dict:
        """The network ACL associated with the subnet — exactly one (H5)."""
        acls = self._ec2.describe_network_acls(Filters=[
            {"Name": "association.subnet-id", "Values": [subnet]}]).get("NetworkAcls") or []
        if len(acls) != 1:
            raise LookupError(f"sous-réseau {subnet} : {len(acls)} ACL réseau associées, une attendue")
        return acls[0]

    def _acl(self, acl_id: str) -> dict | None:
        try:
            acls = self._ec2.describe_network_acls(NetworkAclIds=[acl_id]).get("NetworkAcls") or []
        except Exception as exc:
            if is_not_found(exc):
                return None
            raise
        return acls[0] if acls else None
