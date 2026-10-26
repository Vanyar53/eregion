"""What the Azure adapter declares it can do (MC0), and the rights each capability needs.

Read by the readiness check (glorfindel/readiness.py) and checked against what
`check_permissions` reads (`REQUIRED_ACTIONS`, `_permission_scopes`):
`tests/unit/test_provider_boundary.py` fails if the two drift apart.
"""
from __future__ import annotations

from glorfindel.providers.interface import (
    NETWORK_QUARANTINE,
    NETWORK_RULES,
    RESTORE_POINT,
    SESSION_DRAIN,
    Capability,
    ProviderCapabilities,
)

CAPABILITIES = ProviderCapabilities(
    provider="azure",
    capabilities=(
        # The quarantine NSG put on each NIC for the time of the isolation (L4, JIT).
        Capability(NETWORK_QUARANTINE, ("isolate_vm", "release_isolation"), frozenset({
            "Microsoft.Network/networkInterfaces/write",
            "Microsoft.Network/virtualNetworks/subnets/join/action",
            "Microsoft.Network/networkSecurityGroups/write",
            "Microsoft.Network/networkSecurityGroups/join/action",
        })),
        # Deny rules on the customer's NSGs: the isolation's fallback, and IP blocks.
        Capability(NETWORK_RULES, ("isolate_vm", "block_suspicious_ip", "unblock_ip"), frozenset({
            "Microsoft.Network/networkSecurityGroups/securityRules/write",
            "Microsoft.Network/networkSecurityGroups/securityRules/delete",
        })),
        # `ss -K` through Run Command (Linux only).
        Capability(SESSION_DRAIN, ("isolate_vm",), frozenset({
            "Microsoft.Compute/virtualMachines/runCommand/action",
        }), note="Linux"),
        # Azure Backup (Recovery Services vault): checked by the audit, not by the readiness.
        Capability(RESTORE_POINT, ("snapshot", "restore_from_backup")),
    ),
)
