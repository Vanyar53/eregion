"""GS1 (#520): the internal links of the docs a newcomer follows — the README, the starting
guides (docs/demarrer/) and the usage profiles (docs/profils/) — lead somewhere: the file exists,
and the anchor after its `#` is a heading of it, as GitHub names it.

`decouvrir.md` pointed to `README.md#evaluate-on-your-infrastructure--read-only-zero-risk` long
after the heading had become « … — read-only on Azure »: the file existed, the anchor did not, and
nothing said so.

    python scripts/doc_anchors.py                 # those docs; exit 1 on a broken link
    python scripts/doc_anchors.py docs/x.md …     # other files

GitHub's anchor of a heading: its text as rendered (inline code, emphasis and links reduced to
their text), lower-cased, every character that is not a letter, a digit, `_`, `-` or a space
removed, each space made a `-`; a second heading of the same anchor takes `-1`, then `-2`. An
`<a id="…">` or `<a name="…">` is an anchor too. Headings and links inside a fenced code block
are not read.
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_GLOBS = ("README.md", "docs/demarrer/*.md", "docs/profils/*.md")

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_HTML_ANCHOR = re.compile(r"<a\s+(?:id|name)=[\"']([^\"']+)[\"']", re.I)
_LINK = re.compile(r"!?\[(?:[^\]\\]|\\.)*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_CODE_SPAN = re.compile(r"(`+)(.+?)\1")


def _prose(text: str) -> list[str]:
    """The lines outside fenced code blocks."""
    out, fenced = [], None
    for line in text.splitlines():
        m = _FENCE.match(line)
        if m:
            fenced = None if fenced == m.group(1) else (fenced or m.group(1))
            continue
        if fenced is None:
            out.append(line)
    return out


def slug(heading: str) -> str:
    """GitHub's anchor for a heading's text (before the suffix of a duplicate)."""
    text = _CODE_SPAN.sub(lambda m: m.group(2), heading)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)      # a link: its text
    text = re.sub(r"<[^>]+>", "", text)                          # inline HTML
    text = text.replace("*", "")
    text = re.sub(r"(?<!\w)_+|_+(?!\w)", "", text)              # _emphasis_, not snake_case
    text = text.strip().lower()
    text = "".join(ch for ch in text if ch.isalnum() or ch in "_- ")
    return text.replace(" ", "-")


def anchors(text: str) -> set[str]:
    seen: Counter[str] = Counter()
    out: set[str] = set()
    for line in _prose(text):
        out.update(_HTML_ANCHOR.findall(line))
        m = _HEADING.match(line)
        if not m:
            continue
        base = slug(m.group(2))
        out.add(base if not seen[base] else f"{base}-{seen[base]}")
        seen[base] += 1
    return out


def links(text: str) -> list[str]:
    """The link targets of the prose: inline code and fenced blocks left out."""
    found = []
    for line in _prose(text):
        found += _LINK.findall(_CODE_SPAN.sub("", line))
    return found


def broken(path: Path, repo: Path = REPO) -> list[str]:
    """Each internal link of `path` that leads nowhere: its file missing, or its anchor not
    one of that file's."""
    text = path.read_text(encoding="utf-8")
    out = []
    for target in links(text):
        if "://" in target or target.startswith("mailto:"):
            continue
        file_part, _, anchor = target.partition("#")
        dest = path if not file_part else (path.parent / file_part)
        rel = path.relative_to(repo) if path.is_relative_to(repo) else path
        if not dest.exists():
            out.append(f"{rel}: {target} — no such file")
            continue
        if anchor and dest.suffix == ".md" and dest.is_file():
            if anchor not in anchors(dest.read_text(encoding="utf-8")):
                out.append(f"{rel}: {target} — no heading of that anchor in {dest.name}")
    return out


def default_files(repo: Path = REPO) -> list[Path]:
    return sorted({p for g in DEFAULT_GLOBS for p in repo.glob(g)})


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    files = [Path(a).resolve() for a in args] or default_files()
    faults = [f for p in files for f in broken(p)]
    for f in faults:
        print(f)
    return 1 if faults else 0


if __name__ == "__main__":
    raise SystemExit(main())
