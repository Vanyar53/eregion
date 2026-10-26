"""What the AWS adapter declares it can do (MC1), and the rights each capability needs.

Written against the simulated world (docs/design/monde-aws.md): the rights are IAM
actions as AWS's documentation names them, unchecked until MC2 — no readiness check reads
them on AWS yet (`check_permissions` is Azure's).

What AWS does NOT declare, and why:
- isolate by rules: a security group only allows, and a network ACL entry names one side
  only — it would cut the whole subnet. `network_rules` serves the blocks only;
- `session_drain`: a tracked connection outlives a change of groups (H10), and no session
  cut is written for AWS;
- `restore_point`: no snapshot nor restore in MC1.
"""
from __future__ import annotations

from glorfindel.providers.interface import (
    NETWORK_QUARANTINE,
    NETWORK_RULES,
    Capability,
    ProviderCapabilities,
)

CAPABILITIES = ProviderCapabilities(
    provider="aws",
    capabilities=(
        # The quarantine security group, in place of the ENI's groups for the time of the
        # isolation; the original groups as a tag on it.
        Capability(NETWORK_QUARANTINE, ("isolate_vm", "release_isolation"), frozenset({
            "ec2:ModifyNetworkInterfaceAttribute",
            "ec2:CreateSecurityGroup",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:CreateTags",
            "ec2:DeleteTags",
        }), note="simulated (MC1)"),
        # Deny entries of the subnet's network ACL: a block reaches every subnet associated
        # with that ACL (often the whole VPC, for its default ACL).
        Capability(NETWORK_RULES, ("block_suspicious_ip", "unblock_ip"), frozenset({
            "ec2:CreateNetworkAclEntry",
            "ec2:DeleteNetworkAclEntry",
        }), note="every subnet of the network ACL; simulated (MC1)"),
    ),
)
