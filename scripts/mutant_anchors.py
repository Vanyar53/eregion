"""Check the mutants of scripts/mutation_check.py, and its control set, before a push: every id
unique, and every mutant one the harness can apply (else it skips it as STALE).

    python scripts/mutant_anchors.py            # the checkout this script is in
    python scripts/mutant_anchors.py /path/to/a/worktree

Applies a mutant as the harness's measure() does: a file it renames must exist; old and new
pair up; each text it replaces is found exactly once, in the text left by the replacements
before it; and its file is tracked by git, since the harness copies only `git ls-files` (a new
file: `git add -N` first). Run it after merging origin/main, last: two branches in flight do not
see each other's mutants. The free id ranges are handed out by the Orchestre (docs/sessions.md),
never read from here. Exits 1 on a fault.
"""
from __future__ import annotations

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
    print(f"{len(mc.MUTANTS)} mutants and {len(mutants) - len(mc.MUTANTS)} of the control set, "
          f"{len(faults)} fault(s)")
    return faults


if __name__ == "__main__":
    here = Path(__file__).resolve().parent.parent
    faults = check(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else here)
    if faults:
        print("\n".join(faults))
    sys.exit(1 if faults else 0)
