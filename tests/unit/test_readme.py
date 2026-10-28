"""SEC6 (#277): what the README claims stays true without anyone remembering it.

It said « v0.2.0 » and « ~870 tests » at 0.4.3, with about three thousand; it told readers to
install the console from a package index by name, not from the repository. Each claim is now
read against its source.
"""
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text(encoding="utf-8")
USER_DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md")), ROOT / "CONTRIBUTING.md",
             *sorted((ROOT / "eregion_console").glob("*.py"))]


def _version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _test_functions() -> int:
    return sum(len(re.findall(r"^\s*(?:async\s+)?def test_", p.read_text(encoding="utf-8"), re.M))
               for p in (ROOT / "tests").rglob("test_*.py"))


def test_the_status_names_the_packages_version():
    """The release that bumps pyproject.toml updates the README's status with it."""
    (status,) = re.findall(r"\*\*Status — v(\d+\.\d+\.\d+)\.\*\*", README)
    assert status == _version()


def test_every_count_of_tests_is_about_right():
    """« ~N tests » within the suite's size: no fewer than its test functions, no more than
    twice as many (parametrized cases add to them: 2,982 collected for 2,094 at 0.4.3)."""
    functions = _test_functions()
    counts = [int(n.replace(",", "")) for n in re.findall(r"~(\d[\d,]*)(?: tests|, \d+ ?\w+\"\])", README)]
    assert counts, "the README states the suite's size somewhere"
    assert [n for n in counts if not functions <= n <= 2 * functions] == []


def test_nothing_is_installed_from_pypi_by_a_name_we_do_not_hold():
    bad = [f"{p.relative_to(ROOT)}: {m}" for p in USER_DOCS
           for m in re.findall(r"pip install (?:-U\s+)?['\"]?eregion\b[^\s'\"]*", p.read_text(encoding="utf-8"))]
    assert bad == []


def test_the_read_only_evaluation_says_what_leaves():
    """Read-only on Azure is not « zero risk »: the logs go to the model's provider."""
    assert "zero risk" not in README.lower()
    section = README.split("## Evaluate on your infrastructure", 1)[1].split("\n## ", 1)[0]
    assert "What leaves your machine" in section and "ollama/" in section and "--model" in section


def test_the_readme_says_how_to_remove_eregion_and_report_a_flaw():
    assert "## Remove Eregion" in README and "~/.glorfindel/" in README and "glorfindel list" in README
    assert "SECURITY.md" in README and (ROOT / "SECURITY.md").exists()
    assert (ROOT / "docs" / "design" / "modele-de-menace.md").exists()


# ── the security process's documents (SEC6) ─────────────────────────────────────────────────

THREAT_MODEL = ROOT / "docs" / "design" / "modele-de-menace.md"
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def test_security_md_says_where_to_report_without_an_address():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "Report a vulnerability" in text and "latest 0.4.x" in text
    assert re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text) == []      # no e-mail address
    assert "human_only" in text                                   # what is not a vulnerability


def test_the_threat_model_has_a_page_per_boundary():
    text = THREAT_MODEL.read_text(encoding="utf-8")
    pages = re.split(r"\n## \d\. ", text)[1:]
    assert len(pages) == 6
    for page in pages:
        page = page.split("\n## ", 1)[0]
        rows = re.findall(r"^\| ([STRIDE]) \|", page, re.M)
        assert sorted(set(rows)) == sorted("STRIDE"), page[:40]   # one line of STRIDE at least each
        assert "**Ouvert**" in page, page[:40]
    assert "I8S" in text and "Décisions assumées" in text


def test_an_open_point_names_its_plan_never_its_use():
    """A public repository: what is open is « planifié : #n » or « planifié », never a recipe."""
    text = THREAT_MODEL.read_text(encoding="utf-8")
    opens = re.findall(r"\*\*Ouvert\*\* :(.*?)(?=\n---|\n## )", text, re.S)
    assert len(opens) == 6
    item = re.compile(r"[^`/()_\[\]]{3,70} — planifié(?: : #\d+)?")   # a title, its plan: no name, no path
    for o in opens:
        points = [p.strip(" -;.\n") for p in re.split(r"\n- | ; ", o.strip()) if p.strip(" -;.\n")]
        assert points, o
        for p in points:
            assert p.startswith("rien de connu") or item.fullmatch(p), p


@pytest.mark.parametrize("path", [THREAT_MODEL, ROOT / "SECURITY.md", ROOT / "README.md"], ids=lambda p: p.name)
def test_every_anchor_resolves_as_github_computes_it(path):
    """GitHub's anchor: the heading in lower case, every character but letters, digits, `-`, `_`
    and spaces dropped (parentheses, colons, backticks, dashes —), each space a `-`."""
    def slugs(p: Path) -> set[str]:
        heads = re.findall(r"^#{1,6} (.+)$", p.read_text(encoding="utf-8"), re.M)
        return {re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-") for h in heads}
    text = path.read_text(encoding="utf-8")
    broken = []
    for target, anchor in re.findall(r"\]\(([^)#\s]*)#([^)\s]+)\)", text):
        if "://" in target:
            continue
        where = (path.parent / target) if target else path
        if where.suffix == ".md" and anchor not in slugs(where):
            broken.append(f"{target}#{anchor}")
    assert broken == []


def test_the_security_documents_links_resolve():
    for path in (ROOT / "SECURITY.md", THREAT_MODEL, ROOT / "README.md"):
        targets = [t for t in LINK.findall(path.read_text(encoding="utf-8"))
                   if "://" not in t and not t.startswith("mailto:")]
        assert [t for t in targets if not (path.parent / t).exists()] == [], path.name


def test_codeowners_covers_the_paths_that_write_and_the_ci():
    lines = [line.split() for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    owned = {parts[0] for parts in lines if len(parts) >= 2 and parts[1].startswith("@")}
    assert {"*", "/glorfindel/response/", "/glorfindel/providers/", "/infra/", "/.github/"} <= owned
