"""REN1: the repository follows its owner's account — the old login never comes back.

The account was renamed on 03/11 (#470). GitHub redirects the repository's web, git and API
addresses; never the Pages, the images, the canary's OIDC subject nor CODEOWNERS. The old login
is held by an empty organisation, which never gets an `eregion` repository. A file that names it
again — a workflow's guard, a script's default, an image's owner, a reviewer — points at what no
longer answers, or trusts a name that is not the maintainer's any more. Only history keeps it:
the changelog, the historical notes, the canary's note on the rename, and the default of H0's
`eregion_repo`, cloned once through custom_data (changing it replaces the VM).
"""
import re
from pathlib import Path

from .tracked_files import tracked

ROOT = Path(__file__).resolve().parents[2]
OLD = re.compile("vanyar" + "53", re.IGNORECASE)   # split: this file never names it
NEW = "grootcyber"
# Where the old login stays, and on how many lines (None: history, any number).
KEPT = {"CHANGELOG.md": None, "docs/historique.md": None,
        "docs/operations.md": 1, "infra/glorfindel-host/variables.tf": 1}


def _files() -> list[str]:
    """Every tracked file: git's list, or — outside a checkout (the mutants' copy) — the tree,
    the environments and caches aside (tests/unit/tracked_files.py, MUT1)."""
    return tracked(ROOT)


def _naming(rel: str) -> list[str]:
    path = ROOT / rel
    if not path.is_file():          # listed by git, removed in the working tree
        return []
    return [line for line in path.read_bytes().decode("utf-8", "ignore").splitlines() if OLD.search(line)]


def test_the_old_login_never_comes_back():
    found = {rel: lines for rel in _files() if rel not in KEPT and (lines := _naming(rel))}
    assert found == {}, f"l'ancien login revient (REN1) : {sorted(found)}"


def test_what_keeps_it_is_history_only():
    for rel, most in KEPT.items():
        if most is not None:
            assert len(_naming(rel)) <= most, rel
    assert all("REN1" in line for line in _naming("docs/operations.md"))
    assert [line.split("=", 1)[0].strip() for line in _naming("infra/glorfindel-host/variables.tf")] == ["default"]


def test_the_owner_is_the_new_login_where_it_is_trusted():
    image = (ROOT / "scripts/published_image.py").read_text(encoding="utf-8")
    assert f'OWNER = "{NEW}"' in image and f'SOURCE = "{NEW}/eregion"' in image
    assert f"github.repository == '{NEW}/eregion'" in (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    cd = (ROOT / "infra/glorfindel-host/cd/eregion_cd.py").read_text(encoding="utf-8")
    assert f'or "{NEW}/eregion"' in cd
    owners = re.findall(r"@[\w.-]+", (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8"))
    assert owners and set(owners) == {f"@{NEW}"}
    for rel in ("docs/sessions.md", ".claude/skills/elrond/SKILL.md"):
        reviewers = re.findall(r"--author (\S+)", (ROOT / rel).read_text(encoding="utf-8"))
        assert f"{NEW}" in reviewers, rel


def test_mut1_the_tracked_files_are_listed_in_a_checkout_and_outside_one(tmp_path):
    """MUT1 (#503): the mutants' copy is no git repository. The list falls back on the tree there,
    without .git, the environments, the caches or the agents' worktrees; in the checkout, it is
    git's own."""
    for rel in ("README.md", "src/m.py", ".claude/skills/s.py", ".git/HEAD", ".venv/lib/x.py",
                "src/__pycache__/m.cpython-312.pyc", ".pytest_cache/v", ".claude/worktrees/a/b.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x")
    assert tracked(tmp_path) == [".claude/skills/s.py", "README.md", "src/m.py"]
    assert tracked(tmp_path, "*.py") == [".claude/skills/s.py", "src/m.py"]
    import subprocess
    git = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True)
    if git.returncode == 0 and git.stdout:
        assert tracked(ROOT) == [f for f in git.stdout.split("\0") if f]
