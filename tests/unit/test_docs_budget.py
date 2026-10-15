"""DX1: CLAUDE.md stays small, and its index into docs/ resolves (mutants M48, M49).

Every session and every subagent loads CLAUDE.md (the role files import it), so its size
is paid on every start. The detail lives in docs/, reached through the "Où trouver quoi"
index.

The budget is the lot's target, 25 KB. Its specification set the test at 30 KB, but
CLAUDE.md came out at 16 KB: at 30 KB the specified mutant (+10 KB) would survive.
"""
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CLAUDE = REPO / "CLAUDE.md"
BUDGET_BYTES = 25 * 1024
ROLE_FILES = sorted(REPO.glob("CLAUDE_*.md"))
SPLIT_OUT = ("docs/azure.md", "docs/glorfindel.md", "docs/fichiers-cles.md",
             "docs/operations.md", "docs/historique.md")
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def _local_links(path: Path) -> list[str]:
    return [t for t in LINK.findall(path.read_text(encoding="utf-8"))
            if "://" not in t and not t.startswith("mailto:")]


def test_claude_md_stays_within_its_budget():
    size = CLAUDE.stat().st_size
    assert size <= BUDGET_BYTES, (
        f"CLAUDE.md is {size / 1024:.1f} KB, over its {BUDGET_BYTES // 1024} KB budget: "
        "move the detail into docs/ and link it from the « Où trouver quoi » index")


def test_every_doc_split_out_of_claude_md_is_indexed():
    index = set(_local_links(CLAUDE))
    assert [d for d in SPLIT_OUT if d not in index] == []


@pytest.mark.parametrize("path", [CLAUDE, *ROLE_FILES], ids=lambda p: p.name)
def test_every_local_link_resolves(path):
    """A role session finds its docs: no link of CLAUDE.md or a role file points nowhere."""
    broken = [t for t in _local_links(path) if not (path.parent / t).exists()]
    assert broken == []


def test_every_role_file_points_to_its_docs():
    for role in ROLE_FILES:
        assert any(t.startswith("docs/") for t in _local_links(role)), role.name
