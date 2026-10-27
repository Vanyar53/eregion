"""D1 — each component runs alone: Glorfindel, Annatar, Gothmog and the shared core are each
developed and tested apart (scripts/component_check.py; the CI: components.yml).

Here, in the full suite: every module of each component imports with the others absent;
no component reaches another outside the listed crossings; the lists stay true (every test
file has one home, every bridge and crossing still crosses, every dependency called
Glorfindel's is Glorfindel's alone). The oracles are written here, never read from the script.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("component_check", ROOT / "scripts" / "component_check.py")
cc = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("component_check", cc)   # its dataclass looks itself up there
_spec.loader.exec_module(cc)

# Written here: the four components the CI runs alone, and what each must find absent.
EXPECTED_ABSENT = {
    "core": {"glorfindel", "annatar", "gothmog", "eregion_console", "analysis"},
    "glorfindel": {"annatar", "gothmog", "eregion_console", "analysis"},
    "annatar": {"glorfindel", "gothmog", "eregion_console", "analysis"},
    "gothmog": {"glorfindel", "annatar", "eregion_console", "analysis"},
}
# An injector never needs the decision graph, the memory, the bot or the console.
INJECTOR_NEVER = {"langgraph", "chromadb", "discord", "fastapi"}


def test_the_components_and_what_each_finds_absent():
    assert set(cc.COMPONENTS) == set(EXPECTED_ABSENT)
    for name, absent in EXPECTED_ABSENT.items():
        got = set(cc.COMPONENTS[name].absent())
        assert absent <= got, name
        assert not got & set(cc.COMPONENTS[name].own), name
    for name in ("annatar", "gothmog"):
        assert INJECTOR_NEVER <= set(cc.COMPONENTS[name].absent()), name


@pytest.mark.parametrize("component", sorted(EXPECTED_ABSENT))
def test_every_module_of_a_component_imports_alone(component):
    """With the other components (and, for an injector, Glorfindel's dependencies) absent,
    every module of the component imports — and what is called absent does not."""
    res = subprocess.run([sys.executable, str(ROOT / "scripts" / "component_check.py"), component,
                          "--imports"], capture_output=True, text=True, cwd=ROOT, timeout=300)
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"{component}: imports alone" in res.stdout


def test_no_component_reaches_another_outside_the_listed_crossings():
    assert cc.crossings() == []


def test_the_scan_sees_what_it_must_refuse():
    src = ("import os\nfrom annatar.signals.emitter import SignalEmitter\n"
           "def f():\n    import glorfindel.agent\n    from eregion_core import signals\n"
           "class C:\n    import gothmog\n"
           "def g():\n    import importlib\n    importlib.import_module('analysis.campaign_report')\n")
    found = cc.first_party_imports(src)
    assert [(p, top) for _, p, top in found] == [
        ("annatar", True), ("glorfindel", False), ("eregion_core", False), ("gothmog", True),
        ("analysis", False)]
    # A listed crossing holds inside a function only; a bridge anywhere; anything else nowhere.
    assert cc.allowed("glorfindel/cli.py", "eregion_console", at_top=False)
    assert not cc.allowed("glorfindel/cli.py", "eregion_console", at_top=True)
    assert not cc.allowed("glorfindel/cli.py", "annatar", at_top=False)
    assert not cc.allowed("glorfindel/agent.py", "analysis", at_top=False)
    assert cc.allowed("glorfindel/campaign_replay.py", "annatar", at_top=True)


def test_the_signal_contract_lives_in_the_shared_core():
    """Glorfindel read Annatar's signal schema (annatar/signals/schema.py): it could not run
    without Annatar's package. The contract both sides read is the core's now."""
    assert not (ROOT / "annatar" / "signals" / "schema.py").exists()
    for rel in ("glorfindel/signals.py", "annatar/signals/emitter.py"):
        assert "from eregion_core.signals import" in (ROOT / rel).read_text(encoding="utf-8"), rel


def test_every_test_file_has_one_home():
    homes = [f for c in cc.COMPONENTS.values() for f in c.tests] + list(cc.TOGETHER)
    assert len(homes) == len(set(homes)), sorted({f for f in homes if homes.count(f) > 1})
    on_disk = {p.name for p in (ROOT / "tests" / "unit").glob("test_*.py")}
    assert set(homes) == on_disk, {"without a home": on_disk - set(homes),
                                   "gone": set(homes) - on_disk}


def test_every_bridge_and_crossing_still_crosses():
    """The lists say the truth: an entry that no longer crosses goes."""
    for module in cc.BRIDGES:
        rel = module.replace(".", "/") + ".py"
        own = cc.SCANNED[rel.split("/")[0]]
        found = cc.first_party_imports((ROOT / rel).read_text(encoding="utf-8"))
        assert any(top and pkg not in own for _, pkg, top in found), f"{module}: remove it from BRIDGES"
    for rel, pkg in cc.CROSSINGS:
        found = cc.first_party_imports((ROOT / rel).read_text(encoding="utf-8"))
        assert any(p == pkg and not top for _, p, top in found), f"{rel} → {pkg}: remove it"


def test_the_finder_makes_a_package_and_its_modules_absent():
    finder = cc.Absent(("annatar", "azure.mgmt.recoveryservicesbackup"))
    for name in ("annatar", "annatar.cli", "azure.mgmt.recoveryservicesbackup.activestamp"):
        with pytest.raises(ModuleNotFoundError) as e:
            finder.find_spec(name)
        assert e.value.name == name
    for name in ("annatarx", "azure.mgmt.compute", "glorfindel"):
        assert finder.find_spec(name) is None


def _deps(specs: list[str]) -> set[str]:
    import re
    return {re.split(r"[<>=\[ ;]", s, maxsplit=1)[0].lower() for s in specs}


# The distribution each absent module comes from — written here.
DISTRIBUTION = {"langgraph": "langgraph", "chromadb": "chromadb", "anthropic": "anthropic",
                "discord": "discord.py", "fastapi": "fastapi", "uvicorn": "uvicorn",
                "azure.mgmt.recoveryservicesbackup": "azure-mgmt-recoveryservicesbackup"}


def test_what_an_injector_finds_absent_is_glorfindels_alone():
    """Each dependency made absent for Annatar and Gothmog is declared by Glorfindel's or the
    console's extra, and by neither the shared dependencies nor Annatar's extra (the image of
    the injectors installs `.[annatar]`): the check takes away only what is not theirs."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    extras = project["optional-dependencies"]
    glorfindel = _deps(extras["glorfindel"]) | _deps(extras["console"])
    injector = _deps(project["dependencies"]) | _deps(extras["annatar"])
    assert set(cc.GLORFINDEL_ONLY_DEPS) == set(DISTRIBUTION)
    for module, dist in DISTRIBUTION.items():
        assert dist in glorfindel and dist not in injector, module
