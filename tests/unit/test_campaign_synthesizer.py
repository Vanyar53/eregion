"""Synthesizer — materializes schema-valid scenarios + enforces every guard.

Uses the real technique_catalog.yaml and the real scripts/vm/ scripts (both in
the repo). No Azure, no LLM. Output goes to tmp_path.
"""

import sys

import pytest
import yaml

from annatar.campaign.catalog import load_catalog
from annatar.campaign.scope import Scope
from annatar.campaign.synthesizer import synthesize
from annatar.runner.parser import ScenarioParser
from eregion_core.experiment import validate_experiment_file

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


def test_syslog_window_floor_covers_p99(tmp_path, catalog):
    # A Syslog entry with an OPTIMISTIC latency (120s → 240s window) must still be
    # clamped to the P99 floor (480s) — never open a window shorter than the
    # source's real ingestion latency. The catalog's own Syslog entries were since
    # aligned on 480 (Glorfindel, 2026-07-30), so the floor is exercised here on a
    # deliberately optimistic copy: it stays the backstop for any future entry.
    entry = {**catalog["T1110.001"], "expected_latency_s": 120}
    assert entry["log_source"] == "Syslog"
    assert int(entry["expected_latency_s"]) + 120 < 480  # would underrun without floor
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    assert data["detection"]["timeout"] == "480s"


def test_syslog_catalog_latency_drives_window_above_floor(tmp_path, catalog):
    # With the catalog aligned on the measured P99 (480s), the window is
    # latency + margin (600s) — above the floor, which no longer binds.
    entry = catalog["T1110.001"]
    assert int(entry["expected_latency_s"]) == 480
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    assert data["detection"]["timeout"] == "600s"


def test_non_syslog_window_uses_latency_plus_margin(tmp_path, catalog):
    # StorageBlobLogs has no floor — window stays latency + margin (120 + 120).
    entry = catalog["T1041"]
    assert entry["log_source"] == "StorageBlobLogs"
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    expected = int(entry["expected_latency_s"]) + 120
    assert data["detection"]["timeout"] == f"{expected}s"


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


# ── engine: atomic (R1) ──────────────────────────────────────────────────────

ATOMIC_TTP = "T1136.001"


def test_atomic_entry_is_atomic_in_catalog(catalog):
    # Guard: T1136.001 is the atomic entry these tests rely on.
    entry = catalog[ATOMIC_TTP]
    assert entry.get("engine") == "atomic"
    assert entry.get("engine_ref")
    assert (entry.get("steady_state") or {}).get("probes")


def test_synthesize_atomic_is_an_e1_experiment_no_steps(tmp_path, catalog):
    # The atomic entry synthesizes an E1 experiment: no steps, the engine_ref, the probes —
    # and it passes the E1 schema (the campaign runner then plays it through the atomic engine).
    res = synthesize(
        entry=catalog[ATOMIC_TTP], target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert res.ok, res.reason
    assert validate_experiment_file(res.path) == []  # passes the E1 schema (M119 backstop)
    data = yaml.safe_load(res.path.read_text())
    assert data["engine"] == "atomic"
    assert data["engine_ref"] == catalog[ATOMIC_TTP]["engine_ref"]
    assert data["kind"] == "technique"
    assert data["schema_version"] == "1"
    assert "steps" not in data  # the engine of the entry decides; never a run_script step (M116)
    assert data["steady_state"]["probes"][0]["expect"] == "USER_ABSENT"  # probes carried (M117)
    # The ScenarioParser can still load it (what the campaign runner uses to run it).
    assert ScenarioParser().validate(str(res.path)).valid


def test_atomic_never_falls_back_to_a_script(tmp_path, catalog):
    # Even with a reference_script lingering on the entry, an atomic is NEVER materialized as a
    # run_script_on_vm scenario — the engine of the entry is authoritative (M116).
    entry = dict(catalog[ATOMIC_TTP])
    entry["reference_script"] = "scripts/vm/account_creation_sim.sh"  # exists on disk
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    assert data["engine"] == "atomic"
    assert "steps" not in data
    assert "run_script_on_vm" not in res.path.read_text()


def test_atomic_without_engine_ref_refused(tmp_path, catalog):
    entry = dict(catalog[ATOMIC_TTP])
    entry.pop("engine_ref", None)
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "engine_ref" in res.reason
    assert not list(tmp_path.glob("*.yaml"))  # nothing materialized


def test_atomic_with_unknown_engine_ref_refused(tmp_path, catalog):
    # A ref the adapter cannot resolve (unknown guid) is refused at plan time — never
    # synthesized, so it never reaches a run (M118).
    entry = dict(catalog[ATOMIC_TTP])
    entry["engine_ref"] = "T1136.001/00000000-0000-0000-0000-000000000000"
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "unresolved" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_atomic_without_probes_refused(tmp_path, catalog):
    entry = dict(catalog[ATOMIC_TTP])
    entry["steady_state"] = {"probes": []}
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "steady_state probe" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_atomic_out_of_scope_refused(tmp_path, catalog):
    res = synthesize(
        entry=catalog[ATOMIC_TTP], target_resource_id=PROD_VM, scope=Scope(),
        out_dir=tmp_path,
    )
    assert not res.ok
    assert "out of scope" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_atomic_synthesizes_without_jsonschema(tmp_path, catalog, monkeypatch):
    # The synthesizer runs in the Orodruin image, which ships neither jsonschema (extra `dev`
    # only) nor schemas/: the plan must not depend on either (review #165 point 1, M120).
    # The E1 schema is checked by the tests above — never at plan time.
    import eregion_core.experiment as experiment_mod

    monkeypatch.setitem(sys.modules, "jsonschema", None)  # `import jsonschema` → ImportError
    monkeypatch.setattr(experiment_mod, "EXPERIMENT_SCHEMA", tmp_path / "absent.schema.json")
    res = synthesize(
        entry=catalog[ATOMIC_TTP], target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path / "scenarios", seq=1,
    )
    assert res.ok, res.reason
    data = yaml.safe_load(res.path.read_text())
    assert data["engine"] == "atomic"
    assert data["steady_state"]["probes"]


def test_atomic_raising_validation_leaves_no_file(tmp_path, catalog, monkeypatch):
    # A validation that RAISES (not just fails) must not leave a half-planned experiment
    # behind, without its manifest (review #165 point 1, M121).
    import annatar.campaign.synthesizer as syn

    def _boom(_path):
        raise ModuleNotFoundError("No module named 'something'")

    monkeypatch.setattr(syn, "_runtime_atomic_errors", _boom)
    res = synthesize(
        entry=catalog[ATOMIC_TTP], target_resource_id=SANDBOX_VM, scope=Scope(),
        out_dir=tmp_path, seq=1,
    )
    assert not res.ok
    assert "could not be validated" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_atomic_probe_without_expect_refused(tmp_path, catalog):
    # The atomic engine's own probe check applies at plan time: a probe with a blank expect
    # is refused, as the run would refuse it.
    entry = dict(catalog[ATOMIC_TTP])
    entry["steady_state"] = {"probes": [{"name": "p", "verify": "true", "expect": "   "}]}
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "verify and expect" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_destructive_atomic_refused_without_allow_destructive(tmp_path, catalog):
    # The destructive guard is shared by every engine (review #165 point 3, M122): an atomic
    # marked destructive is refused without budget.allow_destructive, even with a safe_target.
    entry = {**catalog[ATOMIC_TTP], "destructive": True, "safe_target": "sandbox_disposable"}
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
    )
    assert not res.ok
    assert "allow_destructive" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_destructive_atomic_refused_without_safe_target(tmp_path, catalog):
    entry = {**catalog[ATOMIC_TTP], "destructive": True, "safe_target": ""}
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
        allow_destructive=True,
    )
    assert not res.ok
    assert "safe_target" in res.reason
    assert not list(tmp_path.glob("*.yaml"))


def test_destructive_atomic_allowed_with_budget_and_safe_target(tmp_path, catalog):
    # Both conditions met → synthesized, and the experiment says it is destructive.
    entry = {**catalog[ATOMIC_TTP], "destructive": True, "safe_target": "sandbox_disposable"}
    res = synthesize(
        entry=entry, target_resource_id=SANDBOX_VM, scope=Scope(), out_dir=tmp_path,
        allow_destructive=True,
    )
    assert res.ok, res.reason
    assert yaml.safe_load(res.path.read_text())["destructive"] is True
