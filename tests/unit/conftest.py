import pytest


@pytest.fixture(autouse=True)
def fake_anthropic_key(monkeypatch):
    """Ensure ANTHROPIC_API_KEY is set in all unit tests — actual calls are mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")
