"""Synthesizer — materializes schema-valid scenarios + enforces every guard.

Uses the real technique_catalog.yaml and the real scripts/vm/ scripts (both in
the repo). No Azure, no LLM. Output goes to tmp_path.
"""

import pytest
import yaml

from annatar.campaign.catalog import load_catalog
from annatar.campaign.scope import Scope
from annatar.campaign.synthesizer import synthesize
from annatar.runner.parser import ScenarioParser

SANDBOX_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-celebrimbor/providers/"
    "Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
)
PROD_VM = (
    "/subscriptions/sub-1/resourceGroups/rg-prod/providers/"
    "Microsoft.Compute/virtualMachines/vm-prod"
)


@pytest.fixture
def catalog():
    cat = load_catalog()
    assert cat, "technique_catalog.yaml must load"
    return cat


def test_synthesize_implemented_nondestructive(tmp_path, catalog):
    entry = catalog["T1110.001"]
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert res.ok, res.reason
    assert res.path.exists()
    # The produced YAML validates against the scenario schema
    assert ScenarioParser().validate(str(res.path)).valid
    data = yaml.safe_load(res.path.read_text())
    assert data["mitre"] == "T1110.001"
    assert data["target"]["vm_name"] == "vm-celebrimbor-gondolin"
    assert data["target"]["resource_group"] == "rg-celebrimbor"
    # references an existing script, never inline shell
    assert data["steps"][0]["script"] == "scripts/vm/lateral_movement_sim.sh"


def test_planned_technique_refused(tmp_path, catalog):
    entry = catalog["T1070.002"]  # status: planned
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "implemented" in res.reason


def test_out_of_scope_refused(tmp_path, catalog):
    entry = catalog["T1110.001"]
    res = synthesize(
        entry=entry, target_resource_id=PROD_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "out of scope" in res.reason
    assert not list(tmp_path.glob("*.yaml"))  # nothing materialized out of scope


def test_destructive_refused_without_budget(tmp_path, catalog):
    entry = catalog["T1486"]  # destructive + requires_testdata
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, allow_destructive=False,
    )
    assert not res.ok
    assert "destructive" in res.reason


def test_destructive_allowed_with_budget_has_setup(tmp_path, catalog):
    entry = catalog["T1486"]
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, allow_destructive=True,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    # setup_scripts provisioning the testdata must be present before the attack
    assert data["setup"][0]["script"] == "scripts/vm/setup_testdata.sh"


def test_destructive_without_safe_target_refused(tmp_path, catalog):
    # Mutate a copy of an implemented entry: destructive, no safe_target.
    entry = dict(catalog["T1110.001"])
    entry["destructive"] = True
    entry["safe_target"] = ""
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, allow_destructive=True,
    )
    assert not res.ok
    assert "safe_target" in res.reason


def test_missing_reference_script_refused(tmp_path, catalog):
    entry = dict(catalog["T1110.001"])
    entry["reference_script"] = "scripts/vm/does_not_exist.sh"
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "not found" in res.reason
