"""Planner — deterministic kill-chain composition. No LLM call in tests."""

from annatar.campaign.catalog import load_catalog, tactic_rank
from annatar.campaign.planner import plan_campaign


def test_deterministic_plan_orders_by_killchain():
    plan = plan_campaign(use_llm=False, max_scenarios=10)
    ttps = [t.ttp for t in plan.techniques]
    # only implemented techniques (5 in the catalog today)
    cat = load_catalog()
    impl = {k for k, v in cat.items() if v.get("status") == "implemented"}
    assert set(ttps) <= impl
    # ordered by canonical tactic rank (non-decreasing)
    ranks = [tactic_rank(t.tactic) for t in plan.techniques]
    assert ranks == sorted(ranks)


def test_plan_respects_max_scenarios():
    plan = plan_campaign(use_llm=False, max_scenarios=2)
    assert len(plan.techniques) == 2


def test_plan_zero_budget_empty():
    plan = plan_campaign(use_llm=False, max_scenarios=0)
    assert plan.techniques == []


def test_impact_comes_after_credential_access():
    # T1486 (impact) must sort after T1110.001 (credential-access) in a full plan
    plan = plan_campaign(use_llm=False, max_scenarios=10)
    ttps = [t.ttp for t in plan.techniques]
    if "T1486" in ttps and "T1110.001" in ttps:
        assert ttps.index("T1110.001") < ttps.index("T1486")
