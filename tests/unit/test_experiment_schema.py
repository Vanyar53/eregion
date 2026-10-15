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

REPO = Path(__file__).resolve().parents[2]
CATALOG_FILE = REPO / "technique_catalog.yaml"
SCENARIOS = sorted(glob.glob(str(REPO / "annatar" / "scenarios" / "azure" / "*.yaml")))


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
        assert schema["title"].endswith("v1")
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


def test_a_local_script_technique_without_steps_is_refused():
    doc = _technique()
    del doc["steps"]
    assert any("steps" in e for e in validate_experiment(doc))


def test_an_engine_technique_needs_no_steps_but_its_reference():
    """R1: a Stratus technique is run by the engine, by its id — no steps (Opus 5.5 review of E1)."""
    doc = {"name": "t", "description": "d", "mitre": "T1651", "engine": "stratus",
           "engine_ref": "azure.execution.vm-run-command", "targets": {"resource_type": "azure_vm", "zone": "bench"}}
    assert validate_experiment(doc) == []
    del doc["engine_ref"]
    assert any("engine_ref" in e for e in validate_experiment(doc))


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


def _fault_entry(**over):
    return {"id": "vm-shutdown", "name": "stop a VM", "status": "planned",
            "engine": "chaos-studio", "engine_ref": "shutdown/2.0", "destructive": False,
            "log_source": "Heartbeat", **over}


def test_the_catalog_holds_faults_in_their_own_list():
    """A fault has no ATT&CK id: it gets its own list and its own id (Opus 5.5 review of E1)."""
    from eregion_core.experiment import _errors

    doc = _catalog(dict(_from_catalog(CATALOG_FILE, "T1041")))
    doc["resource_types"]["azure_vm"]["faults"] = [_fault_entry()]
    assert _errors(doc, CATALOG_SCHEMA) == []


def test_a_fault_cannot_hide_among_the_techniques():
    from eregion_core.experiment import _errors

    entry = {"ttp": "T9999", "tactic": "impact", "kind": "fault", "status": "planned"}
    assert _errors(_catalog(entry), CATALOG_SCHEMA)


@pytest.mark.parametrize("over", [{"engine_ref": None}, {"engine": "local-script"}, {"id": "Bad Id"}])
def test_a_bad_catalog_fault_is_refused(over):
    from eregion_core.experiment import _errors

    fault = {k: v for k, v in _fault_entry(**over).items() if v is not None}
    doc = {"version": "1.0", "resource_types": {"azure_vm": {"faults": [fault]}}}
    assert _errors(doc, CATALOG_SCHEMA)


def test_faults_are_invisible_to_both_technique_loaders(tmp_path):
    """Annatar's planner and Glorfindel's rule authoring read `techniques` only: a fault never
    becomes a planned attack nor a detection rule to author."""
    import yaml

    from annatar.campaign.catalog import load_catalog as red
    from glorfindel.detection_authoring import load_catalog as blue

    doc = _catalog(dict(_from_catalog(CATALOG_FILE, "T1041")))
    doc["resource_types"]["azure_vm"]["faults"] = [_fault_entry()]
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(doc))
    assert set(red(path)) == {"T1041"}
    assert set(blue(path)) == {"T1041"}


def test_an_implemented_engine_technique_needs_its_reference_not_a_script():
    from eregion_core.experiment import _errors

    entry = {"ttp": "T1651", "tactic": "execution", "status": "implemented", "engine": "stratus",
             "engine_ref": "azure.execution.vm-run-command", "destructive": False}
    assert _errors(_catalog(entry), CATALOG_SCHEMA) == []
    del entry["engine_ref"]
    assert _errors(_catalog(entry), CATALOG_SCHEMA)


def test_an_implemented_technique_needs_a_reference_script():
    from eregion_core.experiment import _errors

    entry = dict(_from_catalog(CATALOG_FILE, "T1486"))
    entry["reference_script"] = None
    assert _errors(_catalog(entry), CATALOG_SCHEMA)


def test_a_destructive_technique_needs_a_safe_target():
    from eregion_core.experiment import _errors

    entry = dict(_from_catalog(CATALOG_FILE, "T1486"))
    entry["safe_target"] = ""
    assert _errors(_catalog(entry), CATALOG_SCHEMA)
