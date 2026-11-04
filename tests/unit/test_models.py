"""One model definition (Jonathan, 19/10): the default model was written in eight places —
switching to claude-sonnet-5-5 would have meant hunting them. Only eregion_core/models.py
may name a model; every other place reads it."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LITERAL = re.compile(r"""["']anthropic/claude-[a-z0-9.\-]+["']|:-anthropic/claude-""")


def test_no_model_name_outside_its_definition():
    found = []
    for base in ("glorfindel", "annatar", "eregion_core"):
        for f in (ROOT / base).rglob("*.py"):
            if f.relative_to(ROOT).as_posix() == "eregion_core/models.py":
                continue
            found += [f"{f.relative_to(ROOT)}:{i}" for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1)
                      if LITERAL.search(line)]
    for f in ("docker-compose.yml", "Makefile"):
        found += [f"{f}:{i}" for i, line in enumerate((ROOT / f).read_text(encoding="utf-8").splitlines(), 1)
                  if LITERAL.search(line)]
    assert found == []


def test_an_empty_variable_means_the_default(monkeypatch):
    from eregion_core import models
    monkeypatch.setenv("GLORFINDEL_LLM_MODEL", "")
    monkeypatch.setenv("ANNATAR_LLM_MODEL", "")
    assert models.glorfindel_model() == models.DEFAULT_LLM_MODEL
    assert models.annatar_model() == models.DEFAULT_ANNATAR_MODEL   # its own (19/10)
    monkeypatch.setenv("GLORFINDEL_LLM_MODEL", "anthropic/claude-sonnet-5-5")
    assert models.glorfindel_model() == "anthropic/claude-sonnet-5-5"


def test_the_variables_a_model_needs_follow_its_provider():
    """OL1 (#525): the rule H0's host.env applies (infra/glorfindel-host/host_env.py), defined
    once in the core for whoever checks a deployment — tests/unit/test_glorfindel_host.py holds
    the oracle for each provider."""
    import pytest

    from eregion_core import models
    assert models.model_provider("") == models.model_provider(models.DEFAULT_LLM_MODEL) == "anthropic"
    assert models.required_env("mistral/mistral-large-latest") == ("MISTRAL_API_KEY",)
    assert models.required_env("ollama/llama3.1") == ("GLORFINDEL_LLM_BASE_URL",)
    assert models.required_env("ollama/llama3.1", base_url="http://ollama:11434") == ()
    assert models.missing_env("azure/gpt-4o", {"AZURE_API_KEY": "fake-key"}) == ["AZURE_API_BASE"]
    with pytest.raises(models.UnknownProvider):
        models.required_env("gemini/gemini-pro")
