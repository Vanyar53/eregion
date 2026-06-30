"""Planner — compose a coherent ATT&CK kill-chain from the technique catalog.

The planner is where the *generative* freedom lives (Q5: chaining is the planner's
job, not the catalog's): an LLM picks and orders a subset of techniques into a
coherent campaign. Deterministic post-processing then makes it SAFE and STABLE:

  - only ``status: implemented`` techniques survive (v1 execution filter);
  - every picked TTP must exist in the catalog (LLM hallucination → dropped);
  - ordered by canonical kill-chain tactic order (stable, reproducible);
  - truncated to ``budget.max_scenarios``.

A deterministic fallback (``use_llm=False``) orders ALL implemented techniques by
tactic — no LLM needed, fully unit-testable, and the default in tests/dry runs.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from annatar.campaign.catalog import (
    implemented_techniques,
    load_catalog,
    tactic_rank,
)

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "anthropic/claude-sonnet-4-6"


@dataclass
class PlannedTechnique:
    ttp: str
    tactic: str
    name: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignPlan:
    objective: str
    techniques: list[PlannedTechnique] = field(default_factory=list)


_PLAN_TOOL = {
    "type": "function",
    "function": {
        "name": "campaign_plan",
        "description": (
            "Propose a coherent ATT&CK kill-chain as an ordered list of techniques "
            "chosen ONLY from the provided catalog. Order them along the kill chain "
            "(access → execution → persistence → escalation → ... → impact)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "objective": {
                    "type": "string",
                    "description": "One-line intent of the campaign.",
                },
                "techniques": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ttp": {"type": "string"},
                            "rationale": {"type": "string"},
                        },
                        "required": ["ttp"],
                    },
                },
            },
            "required": ["techniques"],
        },
    },
}


def plan_campaign(
    *,
    objective: str = "",
    max_scenarios: int = 10,
    catalog_path: str | None = None,
    use_llm: bool = False,
    model: str | None = None,
) -> CampaignPlan:
    """Return a validated, kill-chain-ordered plan of implemented techniques."""
    catalog = load_catalog(catalog_path)
    impl = implemented_techniques(catalog)
    impl_by_ttp = {e["ttp"]: e for e in impl}

    if use_llm and impl:
        picked = _llm_pick(objective, impl, model)
        # keep only catalog-known + implemented TTPs (drop hallucinations)
        chosen = [impl_by_ttp[t] for t in picked if t in impl_by_ttp]
        if not chosen:  # LLM produced nothing usable → fall back
            logger.warning("planner LLM returned no valid TTP — deterministic fallback")
            chosen = impl
    else:
        chosen = impl

    # canonical kill-chain order (stable), then truncate to budget
    chosen = sorted(chosen, key=lambda e: (tactic_rank(e.get("tactic", "")), e["ttp"]))
    chosen = chosen[: max(0, max_scenarios)]

    return CampaignPlan(
        objective=objective or "generated kill-chain",
        techniques=[
            PlannedTechnique(
                ttp=e["ttp"],
                tactic=e.get("tactic", ""),
                name=e.get("name", e["ttp"]),
            )
            for e in chosen
        ],
    )


def _llm_pick(
    objective: str,
    impl: list[dict[str, Any]],
    model: str | None,
) -> list[str]:
    """Ask the LLM to pick+order TTPs. Returns a list of TTP strings (best-effort).

    Defensive throughout (mirrors agent.decide): a malformed/no tool-call response
    yields ``[]`` → the caller falls back to the deterministic plan. The LLM never
    gets to inject a TTP that isn't in the catalog (filtered by the caller).
    """
    import litellm

    menu = "\n".join(
        f"- {e['ttp']} ({e.get('tactic','?')}): {e.get('name','')}" for e in impl
    )
    sys_prompt = (
        "You are a red-team campaign planner. Compose a coherent ATT&CK kill-chain "
        "using ONLY techniques from the catalog below. Pick a meaningful subset and "
        "order it along the kill chain. Do not invent TTPs.\n\nCATALOG:\n" + menu
    )
    kwargs: dict = {}
    base_url = os.environ.get("ANNATAR_LLM_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url
    mdl = model or os.environ.get("ANNATAR_LLM_MODEL") or DEFAULT_MODEL

    try:
        response = litellm.completion(
            model=mdl,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": objective or "Plan a coherent campaign."},
            ],
            tools=[_PLAN_TOOL],
            tool_choice={"type": "function", "function": {"name": "campaign_plan"}},
            **kwargs,
        )
        tool_calls = getattr(response.choices[0].message, "tool_calls", None) or []
        d = json.loads(tool_calls[0].function.arguments) if tool_calls else {}
    except Exception as e:  # any LLM/parse failure → deterministic fallback
        logger.warning("planner LLM call failed (%s) — deterministic fallback", e)
        return []

    if not isinstance(d, dict):
        return []
    techs = d.get("techniques") or []
    out: list[str] = []
    for t in techs:
        if isinstance(t, dict) and isinstance(t.get("ttp"), str):
            out.append(t["ttp"].strip())
    return out
