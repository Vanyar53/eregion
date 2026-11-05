"""Check the mutants of scripts/mutation_check.py, and its control set, before a push: every id
unique, every mutant one the harness can apply (else it skips it as STALE), and every mutant
defined before the `__main__` guard of the harness (else the harness never sees it). The two
places a mutant is written are read: the harness's own blocks, and each lot's file,
scripts/mutants/<lot>.py, which the harness loads (CI5, #512). An id two places take is a fault
naming them; so is a lot's file without a mutant, or whose TESTS names another's mutant; so is
a reason (a mutant's sixth field) whose mark the harness does not read (CI6e, #553): its mutant
would be taken for an unknown survivor; so is a TIMING reason that names no race test (test_…); so is an entry of
scripts/mutants/narrowed.json that no longer applies, or names a test its file lost (CI10a).

    python scripts/mutant_anchors.py            # the checkout this script is in
    python scripts/mutant_anchors.py /path/to/a/worktree

Applies a mutant as the harness's measure() does: a file it renames must exist; old and new
pair up; each text it replaces is found exactly once, in the text left by the replacements
before it; and its file is tracked by git, since the harness copies only `git ls-files` (a new
file: `git add -N` first). It loads the harness as a module, which runs every statement; the
harness run as a script stops at its `__main__` guard, so a block a merge left after the guard
is never measured: that guard must be the file's last statement (MCG, #448). Run it after
merging origin/main, last: two branches in flight do not see each other's mutants. The free id ranges are handed out by the Orchestre (docs/sessions.md),
never read from here. Exits 1 on a fault.
"""
from __future__ import annotations

import ast
import collections
import importlib.util
import re
import subprocess
import sys
from pathlib import Path


def _fault(mutant, rename: object, root: Path, tracked: set[str]) -> str | None:
    mid, _title, rel, old, new = mutant[:5]
    path = root / rel
    if old is rename:
        return None if rel in tracked and path.exists() else f"{mid}: the file to rename is gone ({rel})"
    if rel not in tracked or not path.exists():
        return f"{mid}: {rel} is missing, or not tracked by git (the harness copies only tracked files)"
    if isinstance(old, tuple) != isinstance(new, tuple) or (isinstance(old, tuple) and len(old) != len(new)):
        return f"{mid}: old and new replacements do not pair up"
    text = path.read_text()
    for o, n in zip(old, new) if isinstance(old, tuple) else [(old, new)]:
        if (count := text.count(o)) != 1:
            return f"{mid}: a text it replaces is found {count} times in {rel}"
        text = text.replace(o, n)
    return None


def _is_main_guard(node: ast.stmt) -> bool:
    test = node.test if isinstance(node, ast.If) else None
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)):
        return False
    sides = (test.left, test.comparators[0])
    return (any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
            and any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides))


def _ids(nodes: list[ast.stmt]) -> list[str]:
    """The ids (M…, C…) of the mutants these statements define — a tuple (id, title, file, old,
    new, …) —, with their line."""
    out = []
    for node in nodes:
        for t in ast.walk(node):
            first, title = t.elts[:2] if isinstance(t, ast.Tuple) and len(t.elts) >= 5 else (None, None)
            if (isinstance(first, ast.Constant) and isinstance(first.value, str)
                    and isinstance(title, ast.Constant) and " " in str(title.value)
                    and first.value[:1] in ("M", "C") and first.value[1:].isdigit()):
                out.append(f"{first.value} (line {first.lineno})")
    return out


def after_guard(source: str, rel: str = "scripts/mutation_check.py") -> list[str]:
    """The fault of a harness whose `__main__` guard is not its last statement. What follows the
    guard runs on an import (here, in the tests) but never when the harness runs as a script —
    the Monday measure, `--only` —, so the mutants it defines are never measured."""
    body = ast.parse(source).body
    guard = next((i for i, node in enumerate(body) if _is_main_guard(node)), None)
    if guard is None:
        return [f'{rel}: no `if __name__ == "__main__"` guard, the harness cannot run']
    after = body[guard + 1:]
    if not after:
        return []
    ids = _ids(after)
    return [f"{rel}:{after[0].lineno}: {len(after)} statement(s) after the `__main__` guard "
            f"(line {body[guard].lineno}), never run by the harness: move them above it"
            + (f"; mutants never measured: {', '.join(ids)}" if ids else "")]


HARNESS = "scripts/mutation_check.py"
NARROWED = "scripts/mutants/narrowed.json"     # the narrowed targets (CI10a)


def places(mutants: list, lots: dict) -> dict[str, list[str]]:
    """Where each id is defined: the harness's own blocks, and each lot's file (CI5,
    scripts/mutants/<lot>.py), as many times as it is."""
    total = collections.Counter(m[0] for m in mutants)
    out: dict[str, list[str]] = collections.defaultdict(list)
    for rel, lot in lots.items():
        for m in lot["MUTANTS"] + lot["CONTROL"]:
            out[m[0]].append(rel)
            total[m[0]] -= 1
    for mid, n in total.items():
        out[mid] = [HARNESS] * n + out[mid]
    return dict(out)


def lot_faults(mutants: list, lots: dict) -> list[str]:
    """An id taken twice (in two lots' files, in one, or in a lot's and the harness's), each
    place named; a lot's file that defines no mutant (a name mistyped: `mutants = …`); a TESTS of
    a lot that names another's mutant (it would take that mutant's tests: the loader leaves it)."""
    faults = [f"{mid}: id used {len(at)} times ({', '.join(at)})"
              for mid, at in places(mutants, lots).items() if len(at) > 1]
    for rel, lot in lots.items():
        own = {m[0] for m in lot["MUTANTS"] + lot["CONTROL"]}
        if not own:
            faults.append(f"{rel}: no mutant (MUTANTS = [...])")
        foreign = sorted(set(lot["TESTS"]) - own)
        if foreign:
            faults.append(f"{rel}: TESTS names mutants it does not define ({', '.join(foreign)}): "
                          "TESTS_ALSO adds tests to another's")
        unknown = sorted(set(lot["TESTS_ALSO"]) - set(places(mutants, lots)))
        if unknown:
            faults.append(f"{rel}: TESTS_ALSO names mutants nobody defines ({', '.join(unknown)})")
    return faults


def reason_faults(mutants: list, marks: tuple) -> list[str]:
    """A mutant whose reason opens with no mark the harness reads (`MARK: why`, MARK one of
    `marks`, the harness's KNOWN_MARKS): the harness takes it for an unknown survivor (CI6e)."""
    faults = []
    for m in mutants:
        if len(m) <= 5:
            continue
        word, colon, _ = m[5].partition(":") if isinstance(m[5], str) else ("", "", "")
        if not (colon and word in marks):
            faults.append(f"{m[0]}: its reason opens with no mark the harness reads ({', '.join(marks)}, then "
                          f"a colon): {str(m[5])[:60]!r}")
        elif word == "TIMING" and "test_" not in m[5]:
            faults.append(f"{m[0]}: its TIMING reason names no race test (test_…) that catches it at times")
    return faults


def narrowed_faults(mc, root: Path) -> list[str]:
    """CI10a: an entry of scripts/mutants/narrowed.json that no longer applies (its mutant gone, or
    its lot's target no longer the whole file it was measured on: `--narrow` it again), or a node
    of it that its file no longer defines — the harness would run a test that is not there."""
    load = getattr(mc, "load_narrowed", None)
    if load is None:
        return []
    whole, faults = getattr(mc, "WHOLE", {}), []
    for mid, entry in sorted(load(root / NARROWED).items()):
        if mid not in whole:
            faults.append(f"{mid}: its narrowed.json entry no longer applies (its mutant gone, or its target "
                          f"no longer {entry['whole']}): run --narrow {entry['whole']} again")
            continue
        for node in entry["tests"].split():
            path, _, rest = node.partition("::")
            name = rest.split("::")[-1].split("[")[0]
            try:
                text = (root / path).read_text(encoding="utf-8")
            except OSError:
                text = ""
            if not name or not re.search(rf"^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\(", text, re.M):
                faults.append(f"{mid}: its narrowed test {node} is not defined in {path}: run --narrow again")
    return faults


def check(root: Path) -> list[str]:
    spec = importlib.util.spec_from_file_location("mutation_check", root / HARNESS)
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    mutants = mc.MUTANTS + getattr(mc, "CONTROL", [])
    tracked = set(subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True,
                                 check=True).stdout.splitlines())
    lots = getattr(mc, "LOTS", {})
    faults = lot_faults(mutants, lots)
    faults += [f"{rel}: not tracked by git (git add -N): the harness copies only tracked files"
               for rel in lots if rel not in tracked]
    faults += [f for m in mutants if (f := _fault(m, getattr(mc, "RENAME", None), root, tracked))]
    faults += after_guard((root / "scripts/mutation_check.py").read_text())
    faults += reason_faults(mutants, tuple(getattr(mc, "KNOWN_MARKS", ())))
    faults += narrowed_faults(mc, root)
    if (root / NARROWED).exists() and NARROWED not in tracked:
        faults.append(f"{NARROWED}: not tracked by git: the gate would measure the whole files")
    print(f"{len(mc.MUTANTS)} mutants and {len(mutants) - len(mc.MUTANTS)} of the control set "
          f"({len(lots)} lot file(s) in scripts/mutants/), {len(faults)} fault(s)")
    return faults


if __name__ == "__main__":
    here = Path(__file__).resolve().parent.parent
    faults = check(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else here)
    if faults:
        print("\n".join(faults))
    sys.exit(1 if faults else 0)
