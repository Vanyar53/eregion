"""DOC1 (#365): the project's one page on GitHub Pages (``docs/index.html``) and the pages that
show Dagorlad (the README's section, ``docs/dagorlad.md``).

The home page is static: no script, nothing loaded from elsewhere — no CDN, no remote font, no
frame; an image or a stylesheet is a file of ``docs/``. Its links resolve: a relative one to a file
of ``docs/`` (Pages serves that directory), an absolute one to the repository on GitHub. The one
exception planned: the whole tour, a video attached on GitHub (``user-attachments``). None of
these pages carries an identifier outside the allowed ones (``scripts/console_shots.py``).
"""
from __future__ import annotations

import importlib.util
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
HOME = DOCS / "index.html"
_spec = importlib.util.spec_from_file_location("console_shots", ROOT / "scripts" / "console_shots.py")
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

VIDEO_HOST = "https://github.com/user-attachments/assets/"
LINK_HOSTS = ("github.com",)
LOADING = {"img": ("src", "srcset"), "source": ("src", "srcset"), "video": ("src", "poster"),
           "audio": ("src",), "track": ("src",), "link": ("href",), "input": ("src",)}


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict]] = []
        self.styles: list[str] = []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, {k: v or "" for k, v in attrs}))
        self._in_style = tag == "style"

    def handle_endtag(self, tag):
        self._in_style = False if tag == "style" else self._in_style

    def handle_data(self, data):
        if self._in_style:
            self.styles.append(data)


def _page() -> _Page:
    p = _Page()
    p.feed(HOME.read_text(encoding="utf-8"))
    return p


def test_the_home_page_runs_no_script_and_embeds_nothing():
    p = _page()
    tags = [t for t, _ in p.tags]
    assert not {"script", "iframe", "object", "embed", "frame", "base", "form"} & set(tags)
    handlers = [(t, k) for t, a in p.tags for k in a if k.lower().startswith("on")]
    assert handlers == []
    assert not [a for _, a in p.tags if a.get("href", "").strip().lower().startswith("javascript:")]
    assert not [a for t, a in p.tags if t == "meta" and a.get("http-equiv", "").lower() == "refresh"]


def test_the_home_page_loads_nothing_from_elsewhere():
    p = _page()
    loads = [(t, v) for t, a in p.tags for k in LOADING.get(t, ()) if (v := a.get(k))]
    assert loads, "the page shows the captures"
    for tag, value in loads:
        url = value.split()[0]
        if tag == "video" and url.startswith(VIDEO_HOST):
            continue
        assert not urlparse(url).scheme and not url.startswith("//"), f"{tag} loads {url}"
        assert (DOCS / url).is_file(), f"{tag} loads {url}, which is not in docs/"
    css = "\n".join(p.styles) + "".join(a.get("style", "") for _, a in p.tags)
    assert "@import" not in css and "@font-face" not in css
    assert re.findall(r"url\(", css) == []


def test_every_link_of_the_home_page_resolves():
    p = _page()
    hrefs = [a["href"] for t, a in p.tags if t == "a" and a.get("href")]
    assert hrefs
    for href in hrefs:
        u = urlparse(href)
        if u.scheme:
            assert u.scheme == "https" and u.netloc in LINK_HOSTS, href
            if u.path.startswith("/Vanyar53/eregion/blob/main/"):
                assert (ROOT / u.path.removeprefix("/Vanyar53/eregion/blob/main/")).is_file(), href
        elif not href.startswith("#"):
            assert (DOCS / href.split("#")[0]).exists(), href
    ids = {a["id"] for _, a in p.tags if a.get("id")}
    assert [h for h in hrefs if h.startswith("#") and h[1:] not in ids] == []


def test_the_home_page_names_the_project_and_its_documents():
    text = HOME.read_text(encoding="utf-8")
    assert '<html lang="en">' in text and '<meta name="viewport"' in text and "<title>Eregion</title>" in text
    for target in ("#readme", "ROADMAP.md", "SECURITY.md", "docs/dagorlad.md"):
        assert f'{target}"' in text, target
    for image in ("images/console-overview.png", "images/dagorlad/loop.webp", "images/dagorlad/board.png"):
        assert f'src="{image}"' in text, image
    assert all(a.get("alt") for t, a in _page().tags if t == "img")


def test_the_pages_that_show_dagorlad_carry_no_identifier():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Dagorlad, the exercise board", 1)[1].split("\n## ", 1)[0]
    for name, text in (("README.md", section),
                       ("docs/dagorlad.md", (DOCS / "dagorlad.md").read_text(encoding="utf-8")),
                       ("docs/index.html", HOME.read_text(encoding="utf-8"))):
        assert cs.identifiers(text) == [], name


def test_the_readme_shows_dagorlad_and_links_its_guide():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Dagorlad, the exercise board", 1)[1].split("\n## ", 1)[0]
    assert "docs/images/dagorlad/loop.webp" in section and "docs/images/dagorlad/board.png" in section
    assert "(docs/dagorlad.md)" in section
    assert readme.index("docs/images/console-overview.png") < readme.index("## Dagorlad, the exercise board")
