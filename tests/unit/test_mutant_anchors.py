"""MCG (#448) — every mutant of scripts/mutation_check.py is measured.

The harness run as a script (the Monday measure, `--only`) stops at its
`if __name__ == "__main__"` guard: a block that a merge left after the guard is loaded by
an import (scripts/mutant_anchors.py, the tests) and never measured. Fifty-four mutants
(M2880–M2899, M2940–M2959, M3030–M3036, M3075–M3081) were in that state on 02/11.

Here: what the script run defines is what an import defines; the guard is the harness's
last statement; scripts/mutant_anchors.py names a block after the guard as a fault. The
oracles are written here, never read from the scripts.
"""
from __future__ import annotations

import ast
import importlib.util
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "scripts" / "mutation_check.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


anchors = _load(ROOT / "scripts" / "mutant_anchors.py", "mutant_anchors_mcg")


def _is_guard(node: ast.stmt) -> bool:
    # Written here, not read from mutant_anchors: the guard as the harness writes it.
    return isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"


def _ids_as_a_script() -> set[str]:
    """The mutant ids the harness defines when it runs as a script: its statements up to its
    `__main__` guard, executed, the guard and what follows never reached."""
    body = ast.parse(HARNESS.read_text()).body
    stop = next(i for i, node in enumerate(body) if _is_guard(node))
    code = compile(ast.Module(body=body[:stop], type_ignores=[]), str(HARNESS), "exec")
    ns = {"__name__": "mutation_check_as_a_script", "__file__": str(HARNESS)}
    exec(code, ns)
    return {m[0] for m in ns["MUTANTS"] + ns["CONTROL"]}


def test_the_harness_run_as_a_script_measures_every_mutant_an_import_sees():
    """The defect itself: the ids the Monday measure can reach are the ids an import loads."""
    imported = _load(HARNESS, "mutation_check_mcg")
    every = {m[0] for m in imported.MUTANTS + imported.CONTROL}
    assert sorted(every - _ids_as_a_script()) == []


def test_the_main_guard_is_the_last_statement_of_the_harness():
    body = ast.parse(HARNESS.read_text()).body
    guards = [node.lineno for node in body if _is_guard(node)]
    assert len(guards) == 1, f"one `__main__` guard expected, found at lines {guards}"
    assert _is_guard(body[-1]), (
        f"scripts/mutation_check.py:{body[-1].lineno}: a statement after the `__main__` guard "
        f"(line {guards[0]}) is never run by the harness — a new block goes above the guard")


_SOURCE = '''"""A harness."""
MUTANTS = [("M1", "a mutant before the guard", "a.py", "x", "y")]
TESTS = {}


def main():
    return 0


if __name__ == "__main__":
    main()
MUTANTS += [
    ("M7", "a mutant a merge left after the guard", "a.py", "x", "y"),
    ("M8", "another one", "b.py", "x", "y"),
]
TESTS.update({mid: "t.py" for mid in ("M7", "M8", "M9", "M10", "M11")})
'''


def test_a_block_after_the_guard_is_a_fault_naming_its_mutants():
    faults = anchors.after_guard(_SOURCE)
    assert len(faults) == 1
    fault = faults[0]
    assert fault.startswith("scripts/mutation_check.py:12: 2 statement(s) after the `__main__` guard (line 10)")
    # Its mutants named with their line; the ids a TESTS.update lists are no mutant of their own.
    assert fault.endswith("mutants never measured: M7 (line 13), M8 (line 14)")


def test_a_guard_last_is_no_fault_whichever_way_it_is_written():
    head = _SOURCE.split("MUTANTS += [")[0]
    assert anchors.after_guard(head) == []
    assert anchors.after_guard(head.replace('__name__ == "__main__"', "'__main__' == __name__")) == []


def test_a_harness_without_guard_is_a_fault():
    assert anchors.after_guard('MUTANTS = []\nprint("measured on import only")\n') != []
    # A test that only looks like the guard is no guard.
    assert anchors.after_guard('X = 1\nif __name__ != "__main__":\n    pass\n') != []


def test_mutant_anchors_reports_a_block_after_the_guard(tmp_path):
    """The check run before a push (docs/sessions.md) fails on it, its anchors all good."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("x = 2\n")
    (tmp_path / "scripts" / "mutation_check.py").write_text(_SOURCE)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True, capture_output=True)
    faults = anchors.check(tmp_path)
    assert [f.split(":")[0] for f in faults] == ["scripts/mutation_check.py"]
    assert "M7 (line 13), M8 (line 14)" in faults[0]
    # Moved above the guard, the same mutants are no fault.
    body, after = _SOURCE.split('if __name__ == "__main__":\n    main()\n')
    (tmp_path / "scripts" / "mutation_check.py").write_text(
        body + after + '\n\nif __name__ == "__main__":\n    main()\n')
    assert anchors.check(tmp_path) == []
