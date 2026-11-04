"""GS1 (#520): the internal links of the README, the starting guides and the usage profiles lead
somewhere — the file, and the heading its anchor names, as GitHub names it (scripts/doc_anchors.py;
mutants M3628, M3629). Modelled on tests/unit/test_docs_budget.py, which keeps the links of
CLAUDE.md and the role files.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("doc_anchors", REPO / "scripts" / "doc_anchors.py")
doc_anchors = importlib.util.module_from_spec(_spec)
sys.modules["doc_anchors"] = doc_anchors
_spec.loader.exec_module(doc_anchors)

GUIDES = ("docs/demarrer/bleu.md", "docs/demarrer/banc.md", "docs/demarrer/a-rejouer.md")


def test_the_newcomer_docs_are_the_ones_read():
    files = {p.relative_to(REPO).as_posix() for p in doc_anchors.default_files()}
    assert {"README.md", *GUIDES, "docs/profils/README.md", "docs/profils/decouvrir.md"} <= files


@pytest.mark.parametrize("path", doc_anchors.default_files(), ids=lambda p: p.relative_to(REPO).as_posix())
def test_every_internal_link_and_its_anchor_resolve(path):
    assert doc_anchors.broken(path) == []


@pytest.mark.parametrize("heading,anchor", [
    ("Evaluate on your infrastructure — read-only on Azure", "evaluate-on-your-infrastructure--read-only-on-azure"),
    ("`runs/` : un répertoire par écrivain (SEC18, #455)", "runs--un-répertoire-par-écrivain-sec18-455"),
    ("7. Ce qui part de la machine", "7-ce-qui-part-de-la-machine"),
    ("Le cas sans H0 : un trou", "le-cas-sans-h0--un-trou"),
    ("**Bold** and [a link](x.md) and snake_case", "bold-and-a-link-and-snake_case"),
])
def test_a_heading_is_named_as_github_names_it(heading, anchor):
    assert doc_anchors.slug(heading) == anchor


def test_a_second_heading_of_the_same_name_takes_a_suffix_and_code_blocks_are_not_headings():
    text = "# Usage\n\n## Usage\n\n```bash\n# Usage\n# not-a-heading\n```\n<a id=\"kept\"></a>\n"
    assert doc_anchors.anchors(text) == {"usage", "usage-1", "kept"}


def test_a_link_to_a_missing_anchor_or_file_is_said(tmp_path):
    (tmp_path / "other.md").write_text("# Present\n")
    page = tmp_path / "page.md"
    page.write_text("[ok](other.md#present) [gone](other.md#absent) [here](#top) [no](none.md)\n"
                    "`[in code](other.md#absent)` [web](https://example.org/#x)\n\n# Top\n"
                    "```\n[fenced](other.md#absent)\n```\n")
    assert doc_anchors.broken(page, tmp_path) == [
        "page.md: other.md#absent — no heading of that anchor in other.md",
        "page.md: none.md — no such file"]
    assert doc_anchors.main([str(page)]) == 1


def test_the_readme_and_the_discover_profile_lead_to_the_guides():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "docs/demarrer/bleu.md" in readme and "docs/demarrer/banc.md" in readme
    decouvrir = (REPO / "docs" / "profils" / "decouvrir.md").read_text(encoding="utf-8")
    assert "../demarrer/bleu.md" in decouvrir
