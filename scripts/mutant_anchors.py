"""Check the mutants of scripts/mutation_check.py, and its control set, before a push: every id
unique, every mutant one the harness can apply (else it skips it as STALE), and every mutant
defined before the `__main__` guard of the harness (else the harness never sees it).

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


def check(root: Path) -> list[str]:
    spec = importlib.util.spec_from_file_location("mutation_check", root / "scripts/mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    mutants = mc.MUTANTS + getattr(mc, "CONTROL", [])
    tracked = set(subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True,
                                 check=True).stdout.splitlines())
    faults = [f"{mid}: id used {n} times" for mid, n in collections.Counter(m[0] for m in mutants).items()
              if n > 1]
    faults += [f for m in mutants if (f := _fault(m, getattr(mc, "RENAME", None), root, tracked))]
    faults += after_guard((root / "scripts/mutation_check.py").read_text())
    print(f"{len(mc.MUTANTS)} mutants and {len(mutants) - len(mc.MUTANTS)} of the control set, "
          f"{len(faults)} fault(s)")
    return faults


if __name__ == "__main__":
    here = Path(__file__).resolve().parent.parent
    faults = check(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else here)
    if faults:
        print("\n".join(faults))
    sys.exit(1 if faults else 0)
