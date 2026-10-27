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


def test_the_refusal_says_what_to_set_before_anything_else(monkeypatch):
    """annatar/cli.py cuts the message at 120 characters (the end of `campaign run`): the
    instruction comes first, so that long model names never cut it off."""
    long = "bedrock/anthropic.claude-sonnet-5-5-20261001-v1:0-with-a-long-suffix"
    monkeypatch.setenv("GLORFINDEL_LLM_MODEL", long)
    with pytest.raises(separation.SharedWithGlorfindel) as e:
        separation.check_model(long)
    assert "set EREGION_ANALYSIS_MODEL" in f"{type(e.value).__name__}: {str(e.value)[:120]}"


def test_the_end_of_a_campaign_run_says_what_to_set(monkeypatch, tmp_path):
    from annatar import cli

    said = []
    monkeypatch.setattr(cli.console, "print", lambda *a, **k: said.append(" ".join(map(str, a))))
    long = "openai/a-deployment-name-long-enough-to-push-the-instruction-out-of-the-line"
    monkeypatch.setenv("GLORFINDEL_LLM_MODEL", long)
    monkeypatch.setattr(cr, "build", lambda cdir: separation.check_model(long))
    cli._write_campaign_report(tmp_path)
    assert "set EREGION_ANALYSIS_MODEL" in said[0] and not (tmp_path / "report.md").exists()


@pytest.mark.parametrize("glorfindel, analysis, code", [
    ("anthropic/claude-haiku-5-5", "", 2),                       # the analysis' default, taken
    ("anthropic/claude-sonnet-5-5", "claude-sonnet-5-5", 2),
    ("anthropic/claude-haiku-5-5", "anthropic/claude-opus-4-7", 0),
    ("", "", 0),                                                 # both defaults: two models
])
def test_the_check_said_after_a_change_of_glorfindel_s_model(monkeypatch, capsys, glorfindel, analysis, code):
    """`make glorfindel-host-model` runs ``python -m analysis.separation`` in H0's watch: a
    model shared with the analysis there would make every campaign report refused."""
    for name, value in (("GLORFINDEL_LLM_MODEL", glorfindel), ("EREGION_ANALYSIS_MODEL", analysis)):
        if value:
            monkeypatch.setenv(name, value)
        else:
            monkeypatch.delenv(name, raising=False)
    assert separation.main() == code and separation.REFUSED == 2   # 1 is Python's: an error
    out = capsys.readouterr().out
    assert ("EREGION_ANALYSIS_MODEL" in out) is bool(code)


_CHECK = "docker exec eregion-watch python -m analysis.separation"


def _check_group() -> str:
    """The recipe's part that runs the check in H0's watch, as the remote shell gets it."""
    make = (ANALYSIS.parent / "Makefile").read_text(encoding="utf-8")
    recipe = make.split("\nglorfindel-host-model:", 1)[1].split("\n\n", 1)[0]
    group = recipe[recipe.index("{ " + _CHECK):]
    group = group[:group.index("true; }") + len("true; }")]
    return group.replace("\\\n", "\n").replace("$$", "$")


@pytest.mark.parametrize("rc, said", [
    (0, ""),                                            # another model: nothing to add
    (2, "pose EREGION_ANALYSIS_MODEL"),                 # refused: what to set
    (1, "contrôle de séparation indisponible"),         # an error (an image before IA1)
])
def test_glorfindel_host_model_advises_on_a_refusal_only_and_never_fails(rc, said):
    """`make glorfindel-host-model` runs the check in H0's watch after the restart: its
    advice on exit 2 (a refusal) only; an error (1) is said apart; the target never fails on
    it. Played with a stand-in for the check, nothing sent to H0."""
    import subprocess
    group = _check_group()
    assert _CHECK in group
    out = subprocess.run(["sh", "-c", group.replace(_CHECK, f"(exit {rc})")],
                         capture_output=True, text=True)
    assert out.returncode == 0
    assert ("pose EREGION_ANALYSIS_MODEL" in out.stdout) is (rc == 2)
    assert (said in out.stdout) if said else out.stdout == ""


def test_the_campaign_run_container_knows_glorfindel_s_model():
    """The end of `campaign run` writes its report in Annatar's container: without
    GLORFINDEL_LLM_MODEL there, the check compares with the default and lets the same model
    through."""
    make = (ANALYSIS.parent / "Makefile").read_text(encoding="utf-8")
    block = make.split("ANNATAR_AZURE_ENV := \\\n", 1)[1].split("\n\n", 1)[0]
    assert "-e GLORFINDEL_LLM_MODEL" in block and "-e EREGION_ANALYSIS_MODEL" in block


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
