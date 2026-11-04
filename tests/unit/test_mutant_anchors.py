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


# ── CI5 (#512): each lot's mutants in a file of its own, scripts/mutants/<lot>.py ─────

LOTS_DIR = ROOT / "scripts" / "mutants"


def _lot_file_ids(path: Path) -> tuple[set[str], dict]:
    """What a lot's file defines, read here on its own (never through the harness's loader)."""
    ns = {"RENAME": object(), "__name__": "a_lot_file"}
    exec(compile(path.read_text(), str(path), "exec"), ns)
    return {m[0] for m in ns.get("MUTANTS", []) + ns.get("CONTROL", [])}, ns.get("TESTS", {})


def _lot_paths() -> list[Path]:
    return sorted(p for p in LOTS_DIR.glob("*.py") if not p.name.startswith("_"))


def test_every_lot_s_mutants_are_measured_by_the_harness_run_as_a_script():
    """A lot's file is loaded before the `__main__` guard: the Monday measure, `--only`, sees
    its mutants, and their tests, as an import does."""
    paths = _lot_paths()
    assert paths, "scripts/mutants/ holds at least CI5's file, the example of the form"
    imported = _load(HARNESS, "mutation_check_ci5")
    as_a_script = _ids_as_a_script()
    for path in paths:
        ids, tests = _lot_file_ids(path)
        assert ids, path.name
        assert sorted(ids - as_a_script) == [], path.name
        assert sorted(ids - {m[0] for m in imported.MUTANTS + imported.CONTROL}) == [], path.name
        assert {mid: imported.TESTS[mid] for mid in tests} == tests, path.name
    assert {"M3580", "M3586"} <= _lot_file_ids(LOTS_DIR / "CI5.py")[0]


def _lot(tmp_path: Path, name: str, text: str) -> tuple[str, dict]:
    mc = _load(HARNESS, "mutation_check_ci5_lots")
    path = tmp_path / name
    path.write_text(text)
    return f"scripts/mutants/{name}", mc.load_lot(path)


_LOT_A = '''MUTANTS = [("M9001", "a bug of lot A", "a.py", "x", "y")]
TESTS = {"M9001": "tests/unit/test_a.py"}
'''
_LOT_B = '''MUTANTS = [("M9001", "a bug of lot B, the same id", "b.py", "x", "y"),
           ("M9002", "another bug of lot B", "b.py", "x", "y")]
'''


def test_two_lot_files_taking_one_id_are_a_fault_naming_both(tmp_path):
    lots = dict([_lot(tmp_path, "LA.py", _LOT_A), _lot(tmp_path, "LB.py", _LOT_B)])
    base = [("M01", "the harness's own", "c.py", "x", "y")]
    mutants = base + [m for lot in lots.values() for m in lot["MUTANTS"]]
    assert anchors.lot_faults(mutants, lots) == [
        "M9001: id used 2 times (scripts/mutants/LA.py, scripts/mutants/LB.py)"]
    # One lot alone is no fault; a lot taking an id of the harness's own blocks is one.
    only_b = {"scripts/mutants/LB.py": lots["scripts/mutants/LB.py"]}
    assert anchors.lot_faults(base + only_b["scripts/mutants/LB.py"]["MUTANTS"], only_b) == []
    taken = dict([_lot(tmp_path, "LC.py", 'MUTANTS = [("M01", "a bug, the harness\'s id", "c.py", "x", "z")]\n')])
    assert anchors.lot_faults(base + taken["scripts/mutants/LC.py"]["MUTANTS"], taken) == [
        "M01: id used 2 times (scripts/mutation_check.py, scripts/mutants/LC.py)"]


def test_a_lot_file_without_mutants_or_taking_another_s_tests_is_a_fault(tmp_path):
    lots = dict([_lot(tmp_path, "LA.py", _LOT_A),
                 _lot(tmp_path, "LD.py", 'mutants = [("M9003", "a name mistyped", "d.py", "x", "y")]\n'),
                 _lot(tmp_path, "LE.py", 'MUTANTS = [("M9004", "a bug of E", "e.py", "x", "y")]\n'
                                         'TESTS = {"M9001": "tests/unit/test_e.py"}\n'
                                         'TESTS_ALSO = {"M9001": "tests/unit/test_e.py", "M9999": "t.py"}\n')])
    mutants = [m for lot in lots.values() for m in lot["MUTANTS"]]
    faults = anchors.lot_faults(mutants, lots)
    assert "scripts/mutants/LD.py: no mutant (MUTANTS = [...])" in faults
    assert any(f.startswith("scripts/mutants/LE.py: TESTS names mutants it does not define (M9001)") for f in faults)
    assert "scripts/mutants/LE.py: TESTS_ALSO names mutants nobody defines (M9999)" in faults
    assert len(faults) == 3


def test_the_harness_loads_each_lot_s_file_its_tests_and_never_another_s(tmp_path):
    """The loader itself, on a copy of the harness whose scripts/mutants/ holds two lots."""
    (tmp_path / "scripts" / "mutants").mkdir(parents=True)
    copy = tmp_path / "scripts" / "mutation_check.py"
    copy.write_text(HARNESS.read_text())
    (tmp_path / "scripts" / "mutants" / "LA.py").write_text(_LOT_A)
    (tmp_path / "scripts" / "mutants" / "LF.py").write_text(
        'MUTANTS = [("M9005", "a file renamed", "f.md", RENAME, "g.md")]\n'
        'TESTS = {"M9005": "tests/unit/test_f.py", "M01": "tests/unit/test_f.py"}\n'
        'TESTS_ALSO = {"M9001": "tests/unit/test_more.py", "M01": "tests/unit/test_more.py"}\n')
    (tmp_path / "scripts" / "mutants" / "_helper.py").write_text("raise SystemExit('never loaded')\n")
    mc = _load(copy, "mutation_check_ci5_copy")
    assert list(mc.LOTS) == ["scripts/mutants/LA.py", "scripts/mutants/LF.py"]
    ids = [m[0] for m in mc.MUTANTS]
    assert ids[-2:] == ["M9001", "M9005"] and ids.count("M9001") == 1
    assert mc.MUTANTS[-1][3] is mc.RENAME                      # the harness's own sentinel
    assert mc.TESTS["M9001"] == "tests/unit/test_a.py tests/unit/test_more.py"
    assert mc.TESTS["M9005"] == "tests/unit/test_f.py"
    assert mc.TESTS["M01"] == f"{mc.INVARIANTS} tests/unit/test_more.py"   # its own, then the lot's
