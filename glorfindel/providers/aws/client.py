"""The EC2 calls the AWS adapter makes, how it reads their errors, and instance ARNs (MC1).

The adapter is written against an INJECTED client: the methods of `Ec2Client`, with
boto3's names, keyword arguments and answers (plain dicts). In MC1 only the fake world
implements it (tests/unit/fake_aws.py); in MC2, boto3's EC2 client will, unchanged. No AWS
SDK is imported here: an error is read by its shape — botocore's ClientError carries
`response["Error"]["Code"]` and `response["ResponseMetadata"]["HTTPStatusCode"]` (H8,
docs/design/monde-aws.md).
"""
from __future__ import annotations

from typing import Protocol


class Ec2Client(Protocol):
    """What the adapter calls, and nothing else (boto3's EC2 client has them all)."""

    def describe_instances(self, *, InstanceIds: list[str]) -> dict: ...
    def describe_network_interfaces(self, *, NetworkInterfaceIds: list[str]) -> dict: ...
    def modify_network_interface_attribute(self, *, NetworkInterfaceId: str, Groups: list[str]) -> dict: ...
    def describe_security_groups(self, **kwargs) -> dict: ...
    def create_security_group(self, *, GroupName: str, Description: str, VpcId: str,
                              TagSpecifications: list) -> dict: ...
    def authorize_security_group_ingress(self, *, GroupId: str, IpPermissions: list) -> dict: ...
    def revoke_security_group_ingress(self, *, GroupId: str, IpPermissions: list) -> dict: ...
    def revoke_security_group_egress(self, *, GroupId: str, IpPermissions: list) -> dict: ...
    def create_tags(self, *, Resources: list[str], Tags: list[dict]) -> dict: ...
    def delete_tags(self, *, Resources: list[str], Tags: list[dict]) -> dict: ...
    def describe_network_acls(self, **kwargs) -> dict: ...
    def create_network_acl_entry(self, *, NetworkAclId: str, RuleNumber: int, Protocol: str,
                                 RuleAction: str, Egress: bool, CidrBlock: str) -> dict: ...
    def delete_network_acl_entry(self, *, NetworkAclId: str, RuleNumber: int, Egress: bool) -> dict: ...


def error_code(exc: BaseException) -> str:
    return str(((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code") or "")


def http_status(exc: BaseException) -> int | None:
    meta = (getattr(exc, "response", None) or {}).get("ResponseMetadata") or {}
    status = meta.get("HTTPStatusCode")
    return int(status) if isinstance(status, int) else None


def is_not_found(exc: BaseException) -> bool:
    """The resource ASKED FOR does not exist (InvalidInstanceID.NotFound,
    InvalidNetworkInterfaceID.NotFound…). Only for a read of the target itself: a group
    REFERENCED by a write that is missing is a failure, not « already gone »."""
    return error_code(exc).endswith(".NotFound")


def tags_of(resource: dict) -> dict:
    return {t.get("Key"): t.get("Value") for t in resource.get("Tags") or []}


def parse_instance_arn(resource_id: str) -> tuple[str, str, str]:
    """(region, account, instance id) of `arn:aws:ec2:<region>:<account>:instance/<id>`
    (H14). Anything else raises ValueError: an Azure id, a bare instance id — the account
    and the region the action would land in can't be told."""
    parts = (resource_id or "").strip().split(":", 5)
    if (len(parts) != 6 or parts[0] != "arn" or not parts[1].startswith("aws") or parts[2] != "ec2"
            or not parts[5].startswith("instance/") or not parts[5][len("instance/"):]):
        raise ValueError(f"{resource_id!r} n'est pas l'ARN d'une instance EC2 "
                         "(arn:aws:ec2:<région>:<compte>:instance/<id>)")
    return parts[3], parts[4], parts[5][len("instance/"):]
