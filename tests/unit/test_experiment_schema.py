"""E1: the experiment schema (technique or fault) and the catalog validate. No Azure, no LLM.

"The CI validates the catalog" — this runs in CI (pytest). "The schema is versioned" —
asserted below. "All existing scenarios validate" — asserted below.
"""

import glob
import json
from pathlib import Path

import pytest

from eregion_core.experiment import (
    CATALOG_SCHEMA,
    EXPERIMENT_SCHEMA,
    validate_catalog,
    validate_experiment,
    validate_experiment_file,
)

SCENARIOS = sorted(glob.glob("annatar/scenarios/azure/*.yaml"))


def test_there_are_scenarios_to_check():
    assert len(SCENARIOS) >= 5


@pytest.mark.parametrize("path", SCENARIOS, ids=lambda p: Path(p).name)
def test_every_existing_scenario_validates(path):
    """Existing scenarios are experiments of kind technique / engine local-script by
    default — they validate unchanged (no behaviour change)."""
    assert validate_experiment_file(path) == []


def test_catalog_validates():
    assert validate_catalog() == []


def test_schemas_are_versioned():
    for schema_path in (EXPERIMENT_SCHEMA, CATALOG_SCHEMA):
        schema = json.loads(schema_path.read_text())
        assert schema["$id"].endswith(".v1.json")
        assert "v1" in schema["title"].lower() or schema["title"].endswith("v1")
    exp = json.loads(EXPERIMENT_SCHEMA.read_text())
    assert exp["properties"]["schema_version"]["const"] == "1"
    assert exp["properties"]["kind"]["default"] == "technique"
    assert exp["properties"]["engine"]["default"] == "local-script"


# ── A technique (the default kind) ──────────────────────────────────────────

def _technique():
    return {
        "name": "t", "description": "d", "mitre": "T1486",
        "steps": [{"name": "s", "action": "run_script_on_vm"}],
        "target": {"type": "azure_vm", "resource_group": "rg-celebrimbor"},
    }


def test_a_minimal_technique_validates():
    assert validate_experiment(_technique()) == []


def test_a_technique_without_mitre_is_refused():
    doc = _technique()
    del doc["mitre"]
    assert any("mitre" in e for e in validate_experiment(doc))


def test_a_technique_without_steps_is_refused():
    doc = _technique()
    del doc["steps"]
    assert any("steps" in e for e in validate_experiment(doc))


def test_a_bad_mitre_id_is_refused():
    doc = _technique()
    doc["mitre"] = "1486"
    assert validate_experiment(doc)


# ── A fault ─────────────────────────────────────────────────────────────────

def _fault():
    return {
        "name": "stop-vm", "description": "d", "kind": "fault",
        "engine": "chaos-studio", "engine_ref": "urn:csci:microsoft:...:shutdown/2.0",
        "steady_state": {"probes": [{"name": "heartbeat", "verify": "Heartbeat | ...", "expect": ">0"}]},
        "revert": [{"name": "start", "action": "start_vm"}],
        "targets": {"resource_type": "azure_vm", "zone": "bench"},
    }


def test_a_fault_validates():
    assert validate_experiment(_fault()) == []


def test_a_fault_needs_an_engine_and_reference():
    doc = _fault()
    del doc["engine_ref"]
    assert any("engine_ref" in e for e in validate_experiment(doc))


def test_a_fault_needs_its_steady_state():
    doc = _fault()
    del doc["steady_state"]
    assert any("steady_state" in e for e in validate_experiment(doc))


def test_a_fault_is_not_a_local_script():
    doc = _fault()
    doc["engine"] = "local-script"
    assert validate_experiment(doc)


def test_an_unknown_kind_is_refused():
    doc = _technique()
    doc["kind"] = "chaos"
    assert validate_experiment(doc)


def test_an_unknown_top_level_field_is_refused():
    doc = _technique()
    doc["destructif"] = True  # typo for destructive
    assert validate_experiment(doc)


# ── The catalog holds faults, and keeps its guardrails ──────────────────────

def _catalog(entry):
    return {"version": "1.0", "resource_types": {"azure_vm": {"techniques": [entry]}}}


def _from_catalog(path, ttp):
    import yaml

    doc = yaml.safe_load(Path(path).read_text())
    for rt in doc["resource_types"].values():
        for e in rt["techniques"]:
            if e["ttp"] == ttp:
                return e
    raise AssertionError(ttp)


def test_the_catalog_accepts_a_fault_entry():
    from eregion_core.experiment import _errors

    fault = {
        "ttp": "T9999", "name": "stop a VM", "tactic": "impact", "kind": "fault",
        "status": "planned", "engine": "chaos-studio", "engine_ref": "shutdown/2.0",
        "log_source": "Heartbeat",
    }
    assert _errors(_catalog(fault), CATALOG_SCHEMA) == []


def test_a_catalog_fault_without_an_engine_is_refused():
    from eregion_core.experiment import _errors

    fault = {"ttp": "T9999", "tactic": "impact", "kind": "fault", "status": "planned"}
    assert _errors(_catalog(fault), CATALOG_SCHEMA)


def test_an_implemented_technique_needs_a_reference_script():
    from eregion_core.experiment import _errors

    entry = dict(_from_catalog("technique_catalog.yaml", "T1486"))
    entry["reference_script"] = None
    assert _errors(_catalog(entry), CATALOG_SCHEMA)


def test_a_destructive_technique_needs_a_safe_target():
    from eregion_core.experiment import _errors

    entry = dict(_from_catalog("technique_catalog.yaml", "T1486"))
    entry["safe_target"] = ""
    assert _errors(_catalog(entry), CATALOG_SCHEMA)
