"""Check the mutants of scripts/mutation_check.py before a push: every id unique, and the text
each one replaces present exactly once in its file (else the harness skips it as STALE).

    python scripts/mutant_anchors.py            # this checkout
    python scripts/mutant_anchors.py /path/to/a/worktree

Run it after merging origin/main, last: two branches in flight do not see each other's
mutants, so a duplicate id or a moved line shows only once both are in. The free id ranges
are handed out by the Orchestre (docs/sessions.md), never read from here. Exits 1 on a fault.
"""
from __future__ import annotations

import collections
import importlib.util
import sys
from pathlib import Path


def check(root: Path) -> list[str]:
    sys.path[:0] = [str(root / "scripts"), str(root)]
    spec = importlib.util.spec_from_file_location("mutation_check", root / "scripts/mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    faults = [f"{mid}: id used {n} times" for mid, n in collections.Counter(m[0] for m in mc.MUTANTS).items()
              if n > 1]
    rename = getattr(mc, "RENAME", None)
    for m in mc.MUTANTS:
        mid, path, old, new = m[0], Path(m[2]), m[3], m[4]
        if old is rename or new is rename:
            continue
        path = path if path.is_absolute() else root / path
        if not path.exists():
            faults.append(f"{mid}: {path} does not exist")
            continue
        text = path.read_text()
        for o in old if isinstance(old, tuple) else (old,):
            if (n := text.count(o)) != 1:
                faults.append(f"{mid}: its text is found {n} times in {path.relative_to(root)}")
    print(f"{len(mc.MUTANTS)} mutants, {len(faults)} fault(s)")
    return faults


if __name__ == "__main__":
    faults = check(Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve())
    print("\n".join(faults))
    sys.exit(1 if faults else 0)
