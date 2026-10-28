"""D1 — each component runs alone: a technical separation, proved in CI.

Glorfindel is the product and always present (docs/design/console.md, §2); the profiles are
combinations of it with Annatar and Gothmog (docs/profils/). That a profile combines them does
not mean their code is tangled: Glorfindel, Annatar and Gothmog are each developed and tested
apart, over the shared core (eregion_core/) alone. This script proves it — the other
components are made ABSENT from the interpreter (an import of them fails as for a package
that is not installed), and so are the dependencies the component's extra does not bring:

    python scripts/component_check.py annatar              # its tests, the others absent
    python scripts/component_check.py annatar --imports    # every module of it imports alone
    python scripts/component_check.py --list               # which test file belongs where

The CI runs both for each component (.github/workflows/components.yml);
tests/unit/test_components.py runs the imports check and keeps the lists below true: every
test file has one home, every bridge still crosses.

Locally, in a worktree too: the repository this file lives in is put first on sys.path, so
the editable install (which may point at another checkout) is never what gets tested.

Known limits:
- the mutation harness's guard (scripts/mutation_check.py, unmeasurable) may raise wrongly on a
  `FAILED … - ModuleNotFoundError…` line cut at 80 columns outside CI (node id ≤ 31 chars; none today);
- allowed() accepts any package a module of BRIDGES imports, not only the one its bridge is for.
"""
from __future__ import annotations

import argparse
import ast
import importlib
import importlib.abc
import pkgutil
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

FIRST_PARTY = ("eregion_core", "glorfindel", "annatar", "gothmog", "eregion_console", "analysis")

# The dependencies of Glorfindel's and the console's extras (pyproject.toml) that an injector's
# extra does not bring: absent when Annatar or Gothmog runs alone. requests is not among
# them — azure-core brings it to every component. tests/unit/test_components.py checks each
# one against pyproject.toml.
GLORFINDEL_ONLY_DEPS = ("langgraph", "chromadb", "anthropic", "discord", "fastapi", "uvicorn",
                        "azure.mgmt.recoveryservicesbackup")
CONSOLE_DEPS = ("fastapi", "uvicorn")


@dataclass(frozen=True)
class Component:
    own: tuple[str, ...]            # its packages; every other first-party package is absent
    absent_deps: tuple[str, ...]    # third-party modules its extra does not bring
    tests: tuple[str, ...]          # its test files (tests/unit/), run with the others absent

    def absent(self) -> tuple[str, ...]:
        return tuple(p for p in FIRST_PARTY if p not in self.own) + self.absent_deps


COMPONENTS: dict[str, Component] = {
    # The shared core: inscription, exercise windows, the channels, Orodruin's contract, the
    # signal contract, the gate before an injector acts (V1).
    "core": Component(
        own=("eregion_core",),
        absent_deps=GLORFINDEL_ONLY_DEPS + ("litellm",),
        tests=(
            "test_exercise_channel.py", "test_llm_call.py", "test_models.py",
        ),
    ),
    # Glorfindel — the watch, the graph, the response, its providers. The console
    # (eregion_console/) is its face, tested with it in the full suite.
    "glorfindel": Component(
        own=("glorfindel", "eregion_core"),
        absent_deps=CONSOLE_DEPS,
        tests=(
            "test_actions_split.py", "test_agent_nodes.py", "test_audit.py", "test_aws_adapter.py",
            "test_bot.py", "test_cli.py", "test_config.py", "test_detection_authoring.py",
            "test_detection_rules.py", "test_detectors.py", "test_discovery.py", "test_glorfindel.py",
            "test_invariant_regressions.py", "test_invariants.py", "test_invariants_aws.py",
            "test_jobs.py", "test_llm_smoke.py", "test_locks.py", "test_orphan_sweep.py", "test_posture.py", "test_proposed_rules.py", "test_readiness.py",
            "test_reassert.py", "test_rule_layers.py",
        ),
    ),
    # Annatar — its executors, engines (Atomic Red Team), campaigns, signals.
    "annatar": Component(
        own=("annatar", "eregion_core"),
        absent_deps=GLORFINDEL_ONLY_DEPS,
        tests=(
            "test_annatar_atomic.py", "test_annatar_cli.py", "test_annatar_detection.py",
            "test_annatar_run_exit.py", "test_campaign_channel.py", "test_campaign_manifest.py",
            "test_campaign_planner.py", "test_campaign_runner.py", "test_campaign_synthesizer.py",
            "test_engine.py", "test_inscription.py", "test_orodruin.py", "test_parser.py",
            "test_signals.py",
        ),
    ),
    # Gothmog — declared faults, Chaos Studio first.
    "gothmog": Component(
        own=("gothmog", "eregion_core"),
        absent_deps=GLORFINDEL_ONLY_DEPS + ("litellm",),
        tests=("test_gothmog.py",),
    ),
}

# Tests that cross components on purpose — the console over Glorfindel and the injectors'
# runs, the analysis AI over a campaign and Glorfindel's decisions, the gate seen from both
# sides, the host and the Makefile — and the repository-wide checks. The full suite runs them.
TOGETHER = (
    "test_activity_logs.py", "test_agents_discord.py", "test_analysis_rules_parity.py", "test_entra_detection.py", "test_analysis_separation.py",
    "test_analysis_triage.py", "test_api.py", "test_campaign_changes.py", "test_campaign_replay.py", "test_campaign_report.py",
    "test_components.py", "test_console.py", "test_console_escaping.py", "test_console_exercises.py", "test_profiles.py",
    "test_decision_stability.py", "test_dependency_failures.py", "test_dependency_lock.py",
    "test_docs_budget.py", "test_exercise.py", "test_githooks.py", "test_exercise_guard.py",
    "test_experiment_schema.py", "test_glorfindel_host.py", "test_host_console.py",
    "test_host_deploy.py", "test_hosted_report.py", "test_indicators.py",
    "test_makefile_bench.py", "test_makefile_campaign.py", "test_makefile_secrets.py",
    "test_notify_discord.py", "test_observation.py", "test_orodruin_kill.py", "test_palantir.py",
    "test_provider_boundary.py", "test_roadmap_discord.py",
    "test_repo_hermetic.py",
    "test_run_channel.py", "test_watch_channel.py", "test_watch_gate.py",
)

# Modules of a component that exist to meet another one: each is imported only by a command
# that needs the other component installed, never by the component's own path. The check
# skips them; tests/unit/test_components.py fails when one no longer crosses (the list only
# says the truth) — and a new crossing must be added here, with its reason, to pass.
BRIDGES = {
    "glorfindel.campaign_replay": "replays an Annatar campaign (its manifest) — "
                                  "`glorfindel replay-campaign`, with Annatar",
    # Not a component's module, but the watch loads it (IA0): on load, the report reads a
    # run's detections with Annatar's reader (annatar.runner.detection, the format's one
    # source). The report is about an Annatar campaign: without Annatar's package it is not
    # written, and the watch says so (CROSSINGS, glorfindel/cli.py → analysis).
    "analysis.campaign_report": "the campaign report (IA0) reads a run's detections with "
                                "Annatar's reader — written where Annatar is installed",
}

# The other crossings: an import of another component INSIDE a function, by a command or a
# step that needs it, and that says so when it is missing. (file, package it reaches) → why.
# Any other import of another component, wherever it is, fails tests/unit/test_components.py.
# eregion_console and analysis are not components of their own here: the console is
# Glorfindel's face (with the injectors' pages), the analysis AI writes a campaign's report.
CROSSINGS = {
    ("glorfindel/cli.py", "eregion_console"): "`glorfindel war-room`, the former name of "
                                              "`eregion console`",
    ("glorfindel/cli.py", "analysis"): "the watch writes the report of the campaigns Orodruin "
                                       "publishes (IA0) — never stops the watch. The report "
                                       "needs Annatar's package (the bridge "
                                       "analysis.campaign_report): on a Glorfindel without "
                                       "Annatar, the watch (which imports it before the "
                                       "thread) starts with the reports off, and "
                                       "says so",
    ("annatar/cli.py", "analysis"): "the report written at the end of a campaign (IA0) — says "
                                    "so when the package is missing",
}
# The code these rules hold: (directory, its own packages). The analysis AI is no component the
# CI runs alone, but the watch loads it (IA0): what it reaches of another component is listed
# too. The console is not scanned: it is the face of them all.
SCANNED = {"eregion_core": ("eregion_core",), "glorfindel": ("glorfindel", "eregion_core"),
           "annatar": ("annatar", "eregion_core"), "gothmog": ("gothmog", "eregion_core"),
           "analysis": ("analysis", "eregion_core")}


def first_party_imports(source: str) -> list[tuple[int, str, bool]]:
    """(line, first-party package, at module level?) for each import of the source —
    ``import x``, ``from x import …``, and ``importlib.import_module("x…")`` with a literal."""
    tree = ast.parse(source)
    top = {id(n) for stmt in tree.body for n in ast.walk(stmt)
           if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    top |= {id(n) for stmt in tree.body if isinstance(stmt, ast.ClassDef) for n in stmt.body
            if isinstance(n, (ast.Import, ast.ImportFrom))}
    found = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        elif (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", ""))
              in ("import_module", "__import__") and node.args
              and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            names = [node.args[0].value]
        for name in names:
            pkg = name.split(".")[0]
            if pkg in FIRST_PARTY:
                found.append((node.lineno, pkg, id(node) in top))
    return found


def allowed(rel: str, pkg: str, at_top: bool) -> bool:
    """May the file ``rel`` (a component's code) import the package ``pkg`` of another one?
    Only a bridge, or a listed crossing inside a function."""
    module = rel[:-3].replace("/", ".").removesuffix(".__init__")
    return module in BRIDGES or ((rel, pkg) in CROSSINGS and not at_top)


def crossings() -> list[str]:
    """Every import, in a component's code, of a package that is not its own and that
    neither BRIDGES nor CROSSINGS allows."""
    out = []
    for directory, own in SCANNED.items():
        for path in sorted((REPO / directory).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            for line, pkg, at_top in first_party_imports(path.read_text(encoding="utf-8")):
                if pkg not in own and not allowed(rel, pkg, at_top):
                    out.append(f"{rel}:{line} imports {pkg}" + (" at module level" if at_top else ""))
    return out


class Absent(importlib.abc.MetaPathFinder):
    """First on sys.meta_path: an import of an absent package (or of a module under it)
    fails as if it were not installed."""

    def __init__(self, names: tuple[str, ...]):
        self.names = tuple(names)

    def blocks(self, fullname: str) -> bool:
        return any(fullname == n or fullname.startswith(n + ".") for n in self.names)

    def find_spec(self, fullname, path=None, target=None):
        if self.blocks(fullname):
            raise ModuleNotFoundError(f"No module named {fullname!r} (absent: component check)",
                                      name=fullname)
        return None


def make_absent(names: tuple[str, ...]) -> Absent:
    """Install the finder, the repository first on sys.path, and forget any module of the
    absent packages already imported."""
    repo = str(REPO)
    if repo in sys.path:
        sys.path.remove(repo)
    sys.path.insert(0, repo)
    finder = Absent(names)
    sys.meta_path.insert(0, finder)
    for mod in [m for m in sys.modules if finder.blocks(m)]:
        del sys.modules[mod]
    return finder


def own_modules(component: Component) -> list[str]:
    """Every module of the component's packages, bridges excluded."""
    out = []
    for pkg in component.own:
        out.append(pkg)
        for info in pkgutil.walk_packages([str(REPO / pkg)], prefix=pkg + "."):
            if info.name not in BRIDGES:
                out.append(info.name)
    return sorted(out)


def check_imports(name: str) -> list[str]:
    """Import every module of the component with the others absent; what fails, and why."""
    component = COMPONENTS[name]
    make_absent(component.absent())
    failures = []
    # The check itself: what it calls absent must not import — or it proves nothing.
    for pkg in component.absent():
        try:
            importlib.import_module(pkg)
        except ModuleNotFoundError:
            continue
        except Exception:  # noqa: BLE001 — absent or broken, it did not import
            continue
        failures.append(f"{pkg}: still imports — the check would prove nothing")
    for mod in own_modules(component):
        try:
            importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001 — every failure is the report
            failures.append(f"{mod}: {type(e).__name__}: {e}")
    return failures


def run_tests(name: str, extra: list[str]) -> int:
    component = COMPONENTS[name]
    make_absent(component.absent())
    import pytest

    # In the full suite's order (alphabetical), for a run that reads like the full one. No test
    # depends on it: the quarantine locks' test once read what an earlier file left in the
    # module, and has its own empty locks since HY1 (it passes alone, in order and reversed).
    files = [str(REPO / "tests" / "unit" / f) for f in sorted(component.tests)]
    return int(pytest.main([*files, "-q", "-p", "no:cacheprovider", *extra]))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("component", nargs="?", choices=sorted(COMPONENTS))
    ap.add_argument("--imports", action="store_true", help="import every module, run no test")
    ap.add_argument("--list", action="store_true", help="each test file and its component")
    args, extra = ap.parse_known_args(argv)
    if args.list:
        for c, comp in COMPONENTS.items():
            print(f"{c}: {' '.join(comp.tests)}")
        print(f"together: {' '.join(TOGETHER)}")
        return 0
    if not args.component:
        ap.error("a component, or --list")
    if args.imports:
        failures = check_imports(args.component)
        for f in failures:
            print(f"  ✗ {f}")
        absent = ", ".join(COMPONENTS[args.component].absent())
        print(f"{args.component}: {'imports alone' if not failures else f'{len(failures)} module(s) need another component'}"
              f" (absent: {absent})")
        return 1 if failures else 0
    return run_tests(args.component, extra)


if __name__ == "__main__":
    sys.exit(main())
