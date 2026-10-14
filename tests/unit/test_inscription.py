"""Inscription and scope (O0): one target guardrail for every injector. No Azure, no LLM.

Merges the former tests of annatar/safety/guard.py and annatar/campaign/scope.py, and
covers each bug the O0 specification names (scripts/mutation_check.py, M42 to M47).
"""

import pytest

from annatar.campaign.scope import Budget
from eregion_core.inscription import (
    Scope,
    check_target,
    check_zone,
    enrollment,
    rg_from_id,
    subscription_from_id,
)

SANDBOX_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
    "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
PROD_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-prod-payments/providers/"
    "Microsoft.Compute/virtualMachines/vm-prod-db"
)

BENCH = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}
LEGACY = {"annatar-test": "true"}


def tags(zone=None, bench="celebrimbor", **extra):
    t = {"eregion-target": bench, **extra}
    if zone is not None:
        t["eregion-zone"] = zone
    return t


# ── Scope: the bench's perimeter (formerly annatar/campaign/scope.py) ─────────────

def test_ids_are_parsed():
    assert rg_from_id(SANDBOX_VM) == "rg-celebrimbor"
    assert rg_from_id(PROD_VM) == "rg-prod-payments"
    assert rg_from_id("garbage") == ""
    assert subscription_from_id(SANDBOX_VM) == "sub-1"
    assert subscription_from_id("garbage") == ""


def test_sandbox_vm_allowed_by_default_pattern():
    # No explicit allowlist → the celebrimbor RG pattern admits it.
    assert Scope().check(SANDBOX_VM).allowed


def test_prod_vm_refused_even_without_allowlist():
    res = Scope().check(PROD_VM)
    assert not res.allowed
    assert "outside Celebrimbor" in res.reason


def test_instance_suffixed_rg_allowed():
    rid = SANDBOX_VM.replace("rg-celebrimbor", "rg-celebrimbor-ci-1234")
    assert Scope().check(rid).allowed


def test_explicit_resource_id_allowlist_is_restrictive():
    s = Scope(allowed_resource_ids=[SANDBOX_VM])
    assert s.check(SANDBOX_VM).allowed
    other = SANDBOX_VM.replace("gondolin", "nargothrond")
    assert not s.check(other).allowed  # not in explicit list


def test_empty_resource_id_refused():
    assert not Scope().check("").allowed


def test_unknown_sandbox_refused():
    assert not Scope(sandbox="not-celebrimbor").check(SANDBOX_VM).allowed
    assert not Scope(sandbox="").check(SANDBOX_VM).allowed


def test_named_celebrimbor_instance_is_a_bench():
    assert Scope(sandbox="celebrimbor-ci").check(SANDBOX_VM).allowed


def test_the_scope_subscription_is_enforced():
    """The scope named a subscription, and nothing checked it."""
    assert Scope(subscription_id="sub-1").check(SANDBOX_VM).allowed
    assert Scope(subscription_id="SUB-1").check(SANDBOX_VM).allowed
    res = Scope(subscription_id="sub-2").check(SANDBOX_VM)
    assert not res.allowed and "subscription" in res.reason


def test_budget_defaults_no_destructive():
    b = Budget()
    assert b.allow_destructive is False
    assert b.max_scenarios == 10


# ── Enrollment: the tags Celebrimbor sets (formerly annatar/safety/guard.py) ─────

def test_enrolled_target_and_group():
    res = enrollment(BENCH, BENCH, bench="celebrimbor")
    assert res.allowed and res.zone == "bench" and not res.legacy


def test_the_zone_is_the_target_s():
    res = enrollment(tags(), tags("production"), bench="celebrimbor")
    assert res.allowed and res.zone == "production"


def test_untagged_group_refused():
    res = enrollment({"env": "production"}, BENCH, bench="celebrimbor")
    assert not res.allowed and "resource group missing tag" in res.reason


def test_untagged_vm_in_an_enrolled_group_refused():
    """The RG tag alone used to authorize every VM of the group."""
    res = enrollment(BENCH, {"env": "prod"}, bench="celebrimbor")
    assert not res.allowed and "VM missing tag" in res.reason
    assert not enrollment(BENCH, {}, bench="celebrimbor").allowed
    assert not enrollment({}, {}, bench="celebrimbor").allowed


def test_empty_bench_id_enrolls_nothing():
    """M43: an empty bench id would match an empty tag value."""
    empty = {"eregion-target": "", "eregion-zone": "bench"}
    res = enrollment(empty, empty, bench="")
    assert not res.allowed and "empty bench id" in res.reason
    assert not enrollment(empty, empty, bench="  ").allowed
    # The old tag names no bench: only the bench-id check stands between it and an empty id.
    assert not enrollment(LEGACY, LEGACY, bench="").allowed


def test_empty_tag_value_refused():
    empty = {"eregion-target": " ", "eregion-zone": "bench"}
    res = enrollment(empty, empty, bench="celebrimbor")
    assert not res.allowed and "empty" in res.reason


def test_another_bench_refused():
    other = tags("bench", bench="twin-acme")
    res = enrollment(other, other, bench="celebrimbor")
    assert not res.allowed and "'twin-acme'" in res.reason


def test_tag_value_is_compared_exactly():
    """M45: Azure keeps tag values as written — a value in another case is another bench."""
    upper = tags("bench", bench="Celebrimbor")
    res = enrollment(upper, upper, bench="celebrimbor")
    assert not res.allowed and "'Celebrimbor'" in res.reason


def test_tag_names_match_in_any_case():
    """Azure matches tag NAMES case-insensitively."""
    t = {"Eregion-Target": "celebrimbor", "EREGION-ZONE": "bench"}
    assert enrollment(t, t, bench="celebrimbor").allowed


def test_a_target_without_a_zone_is_refused():
    """M47: a zone left out is not the bench."""
    res = enrollment(tags(), tags(), bench="celebrimbor")
    assert not res.allowed and "without a zone" in res.reason


def test_a_zone_is_one_of_three_written_as_such():
    for zone in ("staging", "Production", "BENCH", ""):
        res = check_target(SANDBOX_VM, tags(), tags(zone), kind="technique", destructive=False)
        assert not res.allowed, zone


def test_group_and_target_must_agree_on_the_zone():
    res = enrollment(tags("production"), tags("bench"), bench="celebrimbor")
    assert not res.allowed and "zones disagree" in res.reason


# ── Migration: the old chaos tag ─────────────────────────────────────────────

def test_legacy_tag_enrolls_on_the_bench():
    res = enrollment(LEGACY, LEGACY, bench="celebrimbor")
    assert res.allowed and res.zone == "bench" and res.legacy


def test_legacy_tag_value():
    assert enrollment({"annatar-test": "True"}, LEGACY, bench="celebrimbor").allowed
    assert not enrollment({"annatar-test": "false"}, LEGACY, bench="celebrimbor").allowed


def test_new_tag_wins_over_the_legacy_one():
    t = {**LEGACY, "eregion-target": "twin-acme", "eregion-zone": "twin"}
    assert not enrollment(t, t, bench="celebrimbor").allowed


def test_mixed_tags_during_the_migration():
    assert enrollment(LEGACY, BENCH, bench="celebrimbor").allowed
    res = enrollment(BENCH, LEGACY, bench="celebrimbor")
    assert res.allowed and res.zone == "bench" and res.legacy


def test_legacy_target_keeps_an_explicit_zone():
    res = enrollment(LEGACY, {**LEGACY, "eregion-zone": "production"}, bench="celebrimbor")
    assert res.allowed and res.zone == "production"


def test_legacy_target_against_a_production_group():
    res = enrollment(tags("production"), LEGACY, bench="celebrimbor")
    assert not res.allowed and "zones disagree" in res.reason


# ── Zone: what may run where ─────────────────────────────────────────────────

@pytest.mark.parametrize("zone", ["bench", "twin"])
def test_bench_and_twin_take_everything(zone):
    assert check_zone(zone, kind="technique", destructive=True).allowed
    assert check_zone(zone, kind="technique", destructive=None).allowed
    assert check_zone(zone, kind="fault", destructive=True).allowed


def test_production_takes_a_non_destructive_technique_only():
    """M46: the production rule."""
    assert check_zone("production", kind="technique", destructive=False).allowed
    destructive = check_zone("production", kind="technique", destructive=True)
    assert not destructive.allowed and "destructive" in destructive.reason
    unknown = check_zone("production", kind="technique", destructive=None)
    assert not unknown.allowed and "nobody declared" in unknown.reason
    fault = check_zone("production", kind="fault", destructive=False)
    assert not fault.allowed and "fault never runs in production" in fault.reason


def test_unknown_kind_refused():
    assert not check_zone("bench", kind="chaos", destructive=False).allowed


# ── Everything at execution ──────────────────────────────────────────────────

def test_check_target_on_the_bench():
    res = check_target(SANDBOX_VM, BENCH, BENCH, kind="technique", destructive=True)
    assert res.allowed and res.zone == "bench"


def test_enrolled_resource_outside_the_bench_groups_refused():
    """M44: tags can be copied; the perimeter is checked too."""
    res = check_target(PROD_VM, BENCH, BENCH, kind="technique", destructive=False)
    assert not res.allowed and "outside Celebrimbor" in res.reason


def test_destructive_technique_on_an_enrolled_production_vm_refused():
    prod = tags("production")
    assert check_target(SANDBOX_VM, prod, prod, kind="technique", destructive=False).allowed
    assert not check_target(SANDBOX_VM, prod, prod, kind="technique", destructive=True).allowed
    assert not check_target(SANDBOX_VM, prod, prod, kind="fault", destructive=False).allowed


def test_the_bench_comes_from_the_environment(monkeypatch):
    ci = tags("bench", bench="celebrimbor-ci")
    monkeypatch.setenv("EREGION_BENCH", "celebrimbor-ci")
    assert check_target(SANDBOX_VM, ci, ci, kind="technique", destructive=False).allowed
    assert not check_target(SANDBOX_VM, BENCH, BENCH, kind="technique", destructive=False).allowed
    monkeypatch.setenv("EREGION_BENCH", "")
    assert not check_target(SANDBOX_VM, BENCH, BENCH, kind="technique", destructive=False).allowed


def test_legacy_flag_reaches_the_caller():
    res = check_target(SANDBOX_VM, LEGACY, LEGACY, kind="technique", destructive=True)
    assert res.allowed and res.legacy
