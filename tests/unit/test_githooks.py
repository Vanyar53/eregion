"""The hooks that refuse a real infrastructure identifier hold in every worktree.

`.githooks/pre-commit` and `.githooks/commit-msg` read their denylist from git's common
directory. They used to read it from `--git-dir`, which in a worktree is
`.git/worktrees/<name>/`, where the list is not: they exited 0 there, silently — and every
lot of elrond commits from a worktree (found by the CI/CD session, 27/10).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TERM = "example-sentinel-term"  # a placeholder, never a real identifier


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check)


@pytest.fixture(params=["relative", "absolute"])
def repo(tmp_path: Path, request) -> tuple[Path, Path]:
    if shutil.which("git") is None or shutil.which("bash") is None:
        pytest.skip("git and bash are needed")
    main = tmp_path / "repo"
    main.mkdir()
    _git(main, "init", "-q", "-b", "main")
    _git(main, "config", "user.email", "test@example.org")
    _git(main, "config", "user.name", "test")
    shutil.copytree(ROOT / ".githooks", main / ".githooks")
    for hook in (main / ".githooks").iterdir():
        hook.chmod(0o755)
    # relative: each checkout runs its own .githooks ; absolute: every worktree runs the main
    # checkout's — the operator's setup, where the hooks ran but found no list in a worktree.
    hooks = ".githooks" if request.param == "relative" else str(main / ".githooks")
    _git(main, "config", "core.hooksPath", hooks)
    (main / "README").write_text("x\n")
    _git(main, "add", ".")
    _git(main, "commit", "-qm", "init")
    (main / ".git" / "infra-denylist.txt").write_text(f"# test\n{TERM}\n")
    worktree = tmp_path / "worktree"
    _git(main, "worktree", "add", "-q", "-b", "side", str(worktree))
    return main, worktree


@pytest.mark.parametrize("where", ["main", "worktree"])
def test_a_staged_identifier_is_refused_in_every_checkout(repo, where):
    cwd = repo[0] if where == "main" else repo[1]
    (cwd / "notes.txt").write_text(f"host {TERM}\n")
    _git(cwd, "add", "notes.txt")
    done = _git(cwd, "commit", "-m", "notes", check=False)
    assert done.returncode != 0 and "COMMIT BLOCKED" in done.stderr


@pytest.mark.parametrize("where", ["main", "worktree"])
def test_an_identifier_in_the_message_is_refused_in_every_checkout(repo, where):
    cwd = repo[0] if where == "main" else repo[1]
    (cwd / "notes.txt").write_text("nothing to hide\n")
    _git(cwd, "add", "notes.txt")
    done = _git(cwd, "commit", "-m", f"about {TERM}", check=False)
    assert done.returncode != 0


def test_a_clean_commit_passes_in_a_worktree(repo):
    worktree = repo[1]
    (worktree / "notes.txt").write_text("nothing to hide\n")
    _git(worktree, "add", "notes.txt")
    assert _git(worktree, "commit", "-m", "notes", check=False).returncode == 0


def test_the_hooks_are_executable_in_the_repository():
    """Stored 100644, git ignores them in every fresh clone and worktree."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout (a mutant's copy)")
    staged = _git(ROOT, "ls-files", "-s", ".githooks").stdout.split("\n")
    modes = {line.split()[3]: line.split()[0] for line in staged if line.strip()}
    assert modes and all(mode == "100755" for mode in modes.values()), modes
