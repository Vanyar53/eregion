"""The repository's tracked files, in a checkout or outside one (MUT1, #503).

The mutation harness (scripts/mutation_check.py) measures each mutant in a copy of the tracked
files, which is no git repository: a test that asks `git ls-files` there, with check=True, fails
on the unmutated copy and stops the whole run (test_init_never_upgrades_the_providers_on_its_own,
from CI4 on 02/11). One list for every test that reads the repository's files: git's, or —
outside a checkout — the tree, the environments, caches and agents' worktrees aside.
"""
from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

# What a walk of the tree leaves out: no file of these is ever tracked.
SKIP = frozenset({".git", ".venv", "venv", "node_modules", "site-packages", "__pycache__", "build", "dist",
                  ".pytest_cache", ".ruff_cache", ".mypy_cache", ".hypothesis"})


def tracked(root: Path, *patterns: str) -> list[str]:
    """The tracked files under `root`, relative and in POSIX form, matching any of `patterns`
    (git's pathspec globs, `*` across directories as git reads them; none: every file)."""
    listed = subprocess.run(["git", "ls-files", "-z", "--", *patterns], cwd=root, capture_output=True, text=True)
    if listed.returncode == 0 and listed.stdout.strip("\0"):
        return [f for f in listed.stdout.split("\0") if f]
    out = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if not p.is_file() or SKIP & set(rel.parts) or rel.parts[:2] == (".claude", "worktrees"):
            continue
        name = rel.as_posix()
        if not patterns or any(fnmatch.fnmatchcase(name, pat) for pat in patterns):
            out.append(name)
    return out
