"""Budget of a generative campaign — its ceilings and destructive policy.

Decision Jonathan #1: autonomy = autonomous *within a budget*. The perimeter a
campaign may touch (``Scope``) is the shared inscription of every injector since O0:
``eregion_core/inscription.py``, re-exported here for the campaign modules.
"""

from __future__ import annotations

from dataclasses import dataclass

from eregion_core.inscription import (  # noqa: F401 — the campaign's view of the shared guard
    SANDBOX_RG_PATTERNS,
    GuardResult,
    Scope,
    rg_from_id,
)


@dataclass
class Budget:
    """Ceilings + destructive policy for a campaign."""

    max_scenarios: int = 10
    max_cost_usd: float = 5.0
    allow_destructive: bool = False
    detection_window_s: int = 600
    reset_nsg_between: bool = True
