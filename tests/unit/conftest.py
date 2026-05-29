import pytest


@pytest.fixture(autouse=True)
def fake_anthropic_key(monkeypatch):
    """Ensure ANTHROPIC_API_KEY is set in all unit tests — actual calls are mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")


@pytest.fixture(autouse=True)
def isolated_escalations_store(tmp_path, monkeypatch):
    """Redirect escalations._STORE to a temp file.

    Prevents test runs from writing pending escalations to ~/.glorfindel/,
    which the Discord bot would then pick up as real incidents.
    """
    import glorfindel.escalations as esc_module
    monkeypatch.setattr(esc_module, "_STORE", tmp_path / "escalations.jsonl")


@pytest.fixture(autouse=True)
def isolated_rule_status(tmp_path, monkeypatch):
    """Redirect rule_status.json to a temp file — avoids root-owned Docker file."""
    import glorfindel.detection_rules as dr_module
    monkeypatch.setattr(dr_module, "_STATUS_FILE", tmp_path / "rule_status.json")
