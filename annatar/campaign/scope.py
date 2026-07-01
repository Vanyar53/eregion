"""Scope + budget — the load-bearing guardrail of a generative campaign.

Decision Jonathan #1: autonomy = autonomous *within a budget*; the budget/scope
contract IS the only guardrail. Enforced at synthesis (a scenario outside scope is
never materialized) AND re-checked at execution (a hand-edited manifest cannot bypass).
Scope is a HARD allowlist: Celebrimbor sandbox only.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

# A target id must look like a Celebrimbor sandbox resource. Belt-and-suspenders
# next to the explicit allowlist: even an empty allowlist won't admit prod.
SANDBOX_RG_PATTERNS: tuple[str, ...] = ("rg-celebrimbor", "rg-celebrimbor-*")


@dataclass
class GuardResult:
    allowed: bool
    reason: str = ""


@dataclass
class Scope:
    """Hard allowlist of what a campaign may touch."""

    sandbox: str = "celebrimbor"
    subscription_id: str = ""
    allowed_resource_groups: list[str] = field(default_factory=list)
    allowed_resource_ids: list[str] = field(default_factory=list)

    def check(self, resource_id: str, resource_group: str = "") -> GuardResult:
        """Refuse any target not provably inside the sandbox allowlist."""
        if self.sandbox != "celebrimbor":
            return GuardResult(False, f"unknown sandbox '{self.sandbox}' — Celebrimbor only")
        if not resource_id:
            return GuardResult(False, "empty resource_id")

        rid = resource_id.lower()

        # 1. Explicit resource-id allowlist (most specific).
        if self.allowed_resource_ids:
            if not any(rid == a.lower() for a in self.allowed_resource_ids):
                return GuardResult(
                    False,
                    f"resource_id not in allowed_resource_ids: {resource_id}",
                )

        # 2. Resource-group allowlist (and/or derived from the id).
        rg = (resource_group or _rg_from_id(resource_id)).lower()
        if not rg:
            return GuardResult(False, f"cannot determine resource group of {resource_id}")
        rg_ok = any(fnmatch.fnmatch(rg, p.lower()) for p in self.allowed_resource_groups) if \
            self.allowed_resource_groups else False
        sandbox_ok = any(fnmatch.fnmatch(rg, p) for p in SANDBOX_RG_PATTERNS)
        if not (rg_ok or sandbox_ok):
            return GuardResult(
                False,
                f"resource group '{rg}' outside Celebrimbor sandbox allowlist",
            )
        return GuardResult(True)


@dataclass
class Budget:
    """Ceilings + destructive policy for a campaign."""

    max_scenarios: int = 10
    max_cost_usd: float = 5.0
    allow_destructive: bool = False
    detection_window_s: int = 600
    reset_nsg_between: bool = True


def _rg_from_id(resource_id: str) -> str:
    """Extract the resourceGroups/<rg> segment from an Azure resource id."""
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""
