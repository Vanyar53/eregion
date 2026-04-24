from pathlib import Path
import pytest
from annatar.runner.parser import ScenarioParser

SCENARIOS_DIR = Path(__file__).parent.parent.parent / "scenarios"


def test_validate_ransomware_scenario():
    parser = ScenarioParser()
    result = parser.validate(str(SCENARIOS_DIR / "azure" / "ransomware-vm.yaml"))
    assert result.valid, f"Errors: {result.errors}"


def test_validate_exfil_scenario():
    parser = ScenarioParser()
    result = parser.validate(str(SCENARIOS_DIR / "azure" / "data-exfiltration.yaml"))
    assert result.valid, f"Errors: {result.errors}"


def test_load_ransomware_scenario():
    parser = ScenarioParser()
    s = parser.load(str(SCENARIOS_DIR / "azure" / "ransomware-vm.yaml"))
    assert s.name == "azure-ransomware-vm"
    assert s.mitre == "T1486"
    assert s.target["type"] == "azure_vm"
    assert len(s.steps) >= 1
    assert s.thresholds["detection_time_max"] == "120s"
    assert s.thresholds["recovery_time_max"] == "1800s"


def test_load_exfil_scenario():
    parser = ScenarioParser()
    s = parser.load(str(SCENARIOS_DIR / "azure" / "data-exfiltration.yaml"))
    assert s.name == "azure-data-exfiltration"
    assert s.mitre == "T1041"
    assert s.recovery is None


def test_validate_missing_required_field(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("name: test\ndescription: test\n")
    parser = ScenarioParser()
    result = parser.validate(str(bad_yaml))
    assert not result.valid
    assert any("target" in e for e in result.errors)


def test_validate_invalid_yaml(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("name: [unclosed")
    parser = ScenarioParser()
    result = parser.validate(str(bad_yaml))
    assert not result.valid
    assert any("YAML" in e for e in result.errors)
