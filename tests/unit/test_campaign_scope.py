"""Scope/budget guard — the load-bearing allowlist. No Azure, no LLM."""

from annatar.campaign.scope import Budget, Scope, _rg_from_id

SANDBOX_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
    "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
PROD_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-prod-payments/providers/"
    "Microsoft.Compute/virtualMachines/vm-prod-db"
)


def test_rg_from_id():
    assert _rg_from_id(SANDBOX_VM) == "rg-celebrimbor"
    assert _rg_from_id(PROD_VM) == "rg-prod-payments"
    assert _rg_from_id("garbage") == ""


def test_sandbox_vm_allowed_by_default_pattern():
    # No explicit allowlist → the celebrimbor RG pattern admits it.
    s = Scope()
    assert s.check(SANDBOX_VM).allowed


def test_prod_vm_refused_even_without_allowlist():
    s = Scope()
    res = s.check(PROD_VM)
    assert not res.allowed
    assert "outside Celebrimbor" in res.reason


def test_instance_suffixed_rg_allowed():
    s = Scope()
    rid = SANDBOX_VM.replace("rg-celebrimbor", "rg-celebrimbor-ci-1234")
    assert s.check(rid).allowed


def test_explicit_resource_id_allowlist_is_restrictive():
    s = Scope(allowed_resource_ids=[SANDBOX_VM])
    assert s.check(SANDBOX_VM).allowed
    other = SANDBOX_VM.replace("gondolin", "nargothrond")
    assert not s.check(other).allowed  # not in explicit list


def test_empty_resource_id_refused():
    assert not Scope().check("").allowed


def test_unknown_sandbox_refused():
    s = Scope(sandbox="not-celebrimbor")
    assert not s.check(SANDBOX_VM).allowed


def test_budget_defaults_no_destructive():
    b = Budget()
    assert b.allow_destructive is False
    assert b.max_scenarios == 10
