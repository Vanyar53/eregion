"""IA1: the analysis AI has its own memory and its own model — never Glorfindel's — and it
writes no rule and acts on nothing, by construction (what its package imports). No call to
a real model here."""
import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from analysis import campaign_report as cr
from analysis import separation
from eregion_core import models

ANALYSIS = Path(__file__).resolve().parents[2] / "analysis"


# ── The model ───────────────────────────────────────────────────────────────────────────

def test_the_default_analysis_model_is_not_glorfindel_s(monkeypatch):
    monkeypatch.delenv("GLORFINDEL_LLM_MODEL", raising=False)
    monkeypatch.delenv("EREGION_ANALYSIS_MODEL", raising=False)
    assert separation.check_model(models.analysis_model()) == models.DEFAULT_ANALYSIS_MODEL


@pytest.mark.parametrize("glorfindel, analysis", [
    ("", models.DEFAULT_LLM_MODEL),                                   # the default, as is
    ("", "claude-sonnet-5-5"),                                       # without the provider
    ("", "Anthropic/Claude-Sonnet-5-5 "),                            # case, spaces
    ("azure/gpt-4o", "openai/gpt-4o"),                               # one model, two providers
    ("ollama/mistral-small", "ollama/mistral-small"),
])
def test_glorfindel_s_decision_model_is_refused(monkeypatch, glorfindel, analysis):
    if glorfindel:
        monkeypatch.setenv("GLORFINDEL_LLM_MODEL", glorfindel)
    else:
        monkeypatch.delenv("GLORFINDEL_LLM_MODEL", raising=False)
    with pytest.raises(separation.SharedWithGlorfindel, match="EREGION_ANALYSIS_MODEL"):
        separation.check_model(analysis)


def test_the_report_refuses_glorfindel_s_model_before_any_call(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_LLM_MODEL", "anthropic/claude-sonnet-5-5")
    monkeypatch.setenv("EREGION_ANALYSIS_MODEL", "anthropic/claude-sonnet-5-5")
    calls = []
    llm = SimpleNamespace(completion=lambda **kw: calls.append(kw))
    with pytest.raises(separation.SharedWithGlorfindel):
        cr.write_claims([], [], llm=llm)
    with pytest.raises(separation.SharedWithGlorfindel):
        cr.write_claims([], [], model="claude-sonnet-5-5", llm=llm)
    assert calls == []


# ── The memory ──────────────────────────────────────────────────────────────────────────

@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.mark.parametrize("where", [
    ".glorfindel", ".glorfindel/cycles", ".glorfindel/analysis/chroma",
    ".eregion/../.glorfindel/cycles",                     # read once resolved
])
def test_an_index_in_glorfindel_s_state_is_refused(home, where):
    with pytest.raises(separation.SharedWithGlorfindel, match="EREGION_ANALYSIS_INDEX"):
        separation.check_index(home / where)


def test_an_index_reaching_glorfindel_s_state_through_a_link_is_refused(home):
    (home / ".glorfindel" / "cycles").mkdir(parents=True)
    (home / "elsewhere").symlink_to(home / ".glorfindel" / "cycles")
    with pytest.raises(separation.SharedWithGlorfindel):
        separation.check_index(home / "elsewhere")


def test_the_analysis_index_beside_it_is_its_own(home):
    for where in (".eregion/analysis/chroma", ".glorfindel-analysis", "glorfindel"):
        assert separation.check_index(home / where) == home / where


def test_the_report_never_opens_an_index_in_glorfindel_s_memory(home, monkeypatch):
    pytest.importorskip("chromadb")
    monkeypatch.setenv("EREGION_ANALYSIS_INDEX", str(home / ".glorfindel" / "cycles"))
    with pytest.raises(separation.SharedWithGlorfindel):
        cr.index_facts([cr.RunFact("R1", "C1", 1, "T1486", "R", "executed", "detected")])
    with pytest.raises(separation.SharedWithGlorfindel):
        cr.prior_runs([cr.RunFact("R1", "C1", 1, "T1486", "R", "executed", "detected")], home / ".glorfindel")
    assert not (home / ".glorfindel").exists()        # not even created


def test_the_collection_is_never_glorfindel_s():
    from glorfindel import memory
    assert cr.COLLECTION != separation.GLORFINDEL_COLLECTION
    assert f'name="{separation.GLORFINDEL_COLLECTION}"' in Path(memory.__file__).read_text()
    for name in ("cycles", "Cycles "):
        with pytest.raises(separation.SharedWithGlorfindel):
            separation.check_collection(name)


# ── Writes no rule, acts on nothing: what the package imports ───────────────────────────

# Glorfindel's modules that act (response, providers, actions), write rules (proposed_rules,
# rule_layers, detection_authoring), remember (memory) or decide (agent) — and the ways to
# run a command. The analysis reads Glorfindel's files (its decision files, its rules) as data.
_FORBIDDEN = ("glorfindel", "subprocess", "shutil")   # none of Glorfindel: the analysis also
# runs where Glorfindel's package is not (the image of Annatar, at the end of `campaign run`).


def _imports(path: Path) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
        elif isinstance(node, ast.Call) and getattr(node.func, "attr", "") in ("system", "popen", "execv", "execvp"):
            out.append(f"os.{node.func.attr}")
    return out


@pytest.mark.parametrize("path", sorted(ANALYSIS.glob("*.py")), ids=lambda p: p.name)
def test_the_analysis_imports_nothing_that_acts_writes_a_rule_or_remembers(path):
    bad = [m for m in _imports(path)
           if m.startswith("os.") or any(m == f or m.startswith(f + ".") for f in _FORBIDDEN)]
    assert bad == [], f"{path.name} imports {bad}"


def _names_glorfindel_s_state(path: Path) -> bool:
    """A string of the code (its docstrings aside) that names ``.glorfindel``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = {id(n.body[0].value) for n in ast.walk(tree)
            if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef)) and ast.get_docstring(n)}
    return any(isinstance(n, ast.Constant) and isinstance(n.value, str) and ".glorfindel" in n.value
               and id(n) not in docs for n in ast.walk(tree))


def test_only_the_separation_names_glorfindel_s_state():
    assert [p.name for p in sorted(ANALYSIS.glob("*.py")) if _names_glorfindel_s_state(p)] == ["separation.py"]
