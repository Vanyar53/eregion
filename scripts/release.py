#!/usr/bin/env python3
"""release — a release in two commands: the version's pull request, then the draft (REL1, #269).

  release.py prepare X.Y.Z --title TEXT [--dry-run]   make release VERSION=X.Y.Z TITLE="…" [DRY_RUN=1]
  release.py release-draft X.Y.Z [--notes FILE] [--dry-run]   make release-draft VERSION=X.Y.Z [NOTES=file] [DRY_RUN=1]

`prepare`, on an up-to-date origin/main with a clean tree: [Unreleased] becomes
[X.Y.Z] — <date> — "<title>" (an empty [Unreleased] above it), the fragments of changes/ (CI5,
#512: one lot's entry per file, `changes/<lot>.md`, its sections `### Security`, `### Added`,
`### Changed`, `### Fixed`) assembled into it, in that order of sections, after what was still
under [Unreleased], and removed in the same commit — no line lost, or nothing is written; the version of pyproject.toml
— the package's only one: annatar.__version__ reads it — and the README's « **Status — vX.Y.Z.** »
follow, and ROADMAP.md's line of X.Y.Z in « Les prochaines releases », if there is one, becomes
« brouillon » (RM1: #roadmap shows that table); then the branch chore/release-X.Y.Z, its commit, pushed, and its pull request. Refused:
a tree not clean, a HEAD that is not origin/main, a version not greater than the current one,
an empty [Unreleased] without a fragment, a fragment malformed, a branch or a tag vX.Y.Z that exists.

`draft`, once that pull request is merged: the release vX.Y.Z as a DRAFT, on the full sha of
origin/main (which must hold the version: its pyproject.toml and its CHANGELOG's [X.Y.Z]), with
the notes given or else the CHANGELOG's section. Refused: a tag or a release vX.Y.Z that exists.
The draft is put on #agents' board, pinged (scripts/agents_discord.py), its line and its ping
deleted when the release is published (notify.yml); and its card goes to #releases, with a
button to it and its notes in short, never pinged nor deleted (REL2, notify_discord.release_ready).
Without Discord's configuration, nothing is sent and the command succeeds.

**No path publishes.** Publishing deploys H0 (its CD, H1): Jonathan alone publishes, on GitHub.
Nothing here ever turns a draft into a release (tests/unit/test_release.py reads this file).

--dry-run shows everything — the checks, the changes, the commands — and runs nothing that writes:
no file, no branch, no commit, no push, no pull request, no draft, no Discord.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
UNRELEASED = "## [Unreleased]\n"
STATUS = re.compile(r"\*\*Status — v(\d+\.\d+\.\d+)\.\*\*")
PROJECT_VERSION = re.compile(r'(?m)^version = "([^"]+)"$')
SECTION = re.compile(r"(?m)^## \[")
# CI5 (#512): the fragments of the CHANGELOG, one lot's entry per file. Its sections, in the
# order the version's section lists them; any other heading is refused.
CHANGES = "changes"
KINDS = ("Security", "Added", "Changed", "Fixed")
FRAGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.md")
HEADING = re.compile(r"### (\S.*?)\s*")
MARKER = "<!-- #agents (REL1) : ping={ping} board={board} — effacés à la publication (notify.yml) -->"


class Refused(Exception):
    """A check that does not hold: nothing was written."""


class Halfway(Exception):
    """A step that failed past the point of no return: the release branch exists. Its text says
    what is left and how to go on, or back."""


# ── the tools ───────────────────────────────────────────────────────────────────────

def run(cmd: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess:
    """git or gh, nothing else, never through a shell; every call names its command literally
    (tests/unit/test_release.py reads it)."""
    if not cmd or cmd[0] not in ("git", "gh"):
        raise ValueError("git or gh only")
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise Refused(f"`{' '.join(cmd[:3])} …` a échoué ({p.returncode}) : {(p.stderr or p.stdout).strip()[:300]}")
    return p


def git(root: Path, *args: str, check: bool = True) -> str:
    return run(["git", *args], root, check=check).stdout.strip()


def say(text: str = "") -> None:
    print(text, flush=True)


def show(cmd: list[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def version_of(text: str) -> str:
    """The version of a pyproject.toml's [project]: its first `version = "…"` line."""
    m = PROJECT_VERSION.search(text)
    return m.group(1) if m else ""


def semver(v: str) -> tuple[int, int, int] | None:
    m = SEMVER.fullmatch(v or "")
    return tuple(int(x) for x in m.groups()) if m else None


# ── the CHANGELOG ───────────────────────────────────────────────────────────────────

def unreleased(changelog: str) -> str:
    """What [Unreleased] holds, up to the next version's heading."""
    if UNRELEASED not in changelog:
        return ""
    rest = changelog.split(UNRELEASED, 1)[1]
    m = SECTION.search(rest)
    return rest[: m.start()] if m else rest


def has_content(text: str) -> bool:
    """At least one line that is not blank nor a heading: headings alone hold nothing."""
    return any(line.strip() and not line.lstrip().startswith("#") for line in text.splitlines())


def cut(changelog: str, version: str, day: str, title: str) -> str:
    """[Unreleased] becomes [X.Y.Z] — <date> — "<title>", an empty [Unreleased] kept above it."""
    head, rest = changelog.split(UNRELEASED, 1)
    return head + UNRELEASED + "\n" + f'## [{version}] — {day} — "{title}"\n\n' + rest.lstrip("\n")


# ── changes/: one lot's entry per file (CI5, #512) ──────────────────────────────────

def parse_fragment(text: str) -> list[tuple[str, str]]:
    """(section, its text) of a fragment, in its order: `### <section>` headings, each one of
    KINDS, at most once, each followed by entries. ValueError says what is wrong, and where."""
    out: list[tuple[str, list[str]]] = []
    for i, line in enumerate(text.split("\n"), 1):
        if line.startswith("#"):
            m = HEADING.fullmatch(line)
            if not m:
                raise ValueError(f"ligne {i} : un titre autre que « ### <section> » ({line.strip()[:40]})")
            name = m.group(1)
            if name not in KINDS:
                raise ValueError(f"ligne {i} : la section « {name} » n'est pas {', '.join(KINDS)}")
            if name in (n for n, _ in out):
                raise ValueError(f"ligne {i} : la section « {name} » deux fois")
            out.append((name, []))
        elif out:
            out[-1][1].append(line)
        elif line.strip():
            raise ValueError(f"ligne {i} : du texte avant la première section (« ### Fixed », …)")
    if not out:
        raise ValueError("aucune section (« ### Security », « ### Added », « ### Changed » ou « ### Fixed »)")
    sections = [(name, "\n".join(body).strip("\n")) for name, body in out]
    for name, body in sections:
        if not has_content(body):
            raise ValueError(f"la section « {name} » est vide")
    return sections


def fragments(root: Path) -> tuple[list[tuple[str, list[tuple[str, str]]]], list[str]]:
    """The fragments of changes/, by name ((path, its sections)), and what is refused there: a
    fragment malformed, or a file that is not one (README.md, which says the form, aside)."""
    where = root / CHANGES
    found, faults = [], []
    if not where.is_dir():
        return found, faults
    for path in sorted(where.iterdir(), key=lambda p: p.name.casefold()):
        rel = f"{CHANGES}/{path.name}"
        if path.name == "README.md":
            continue
        if not path.is_file() or not FRAGMENT.fullmatch(path.name):
            faults.append(f"{rel} : changes/ ne tient que des fragments <lot>.md (et son README)")
            continue
        try:
            found.append((rel, parse_fragment(path.read_text(encoding="utf-8"))))
        except UnicodeDecodeError:
            faults.append(f"{rel} : pas en UTF-8")
        except ValueError as e:
            faults.append(f"{rel} : {e}")
    return found, faults


def split_sections(text: str) -> tuple[str, list[tuple[str, str]]]:
    """(what precedes the first `### `, [(section, its text)]) of [Unreleased]'s text, as it is."""
    head, out = [], []
    for line in text.split("\n"):
        m = HEADING.fullmatch(line)
        if m:
            out.append((m.group(1), []))
        elif out:
            out[-1][1].append(line)
        else:
            head.append(line)
    return "\n".join(head).strip("\n"), [(n, "\n".join(b).strip("\n")) for n, b in out]


def assemble(legacy: str, frags: list[tuple[str, list[tuple[str, str]]]]) -> str:
    """The version's section: by section, Security, Added, Changed, Fixed (then any other the
    transition still holds, in its order), what [Unreleased] held first, then each fragment's,
    by its file's name."""
    head, old = split_sections(legacy)
    names = list(KINDS) + [n for n, _ in old if n not in KINDS]
    bodies: dict[str, list[str]] = {n: [] for n in names}
    for name, body in old:
        bodies[name].append(body)
    for _rel, sections in frags:
        for name, body in sections:
            bodies[name].append(body)
    parts = [head] if head else []
    parts += ["### " + n + "\n" + "\n".join(b for b in bodies[n] if b) for n in dict.fromkeys(names)
              if any(has_content(b) for b in bodies[n])]
    return "\n\n".join(parts)


def _entries(text: str) -> list[str]:
    return sorted(x for x in text.split("\n") if x.strip() and not HEADING.fullmatch(x))


def lost(before: list[str], after: str) -> list[str]:
    """The lines of `before` (texts) the version's section `after` does not hold, as many times
    as they were; and any it holds that came from nowhere. Headings aside: they are regrouped."""
    want = collections.Counter(x for t in before for x in _entries(t))
    have = collections.Counter(_entries(after))
    return sorted((want - have).elements()) + sorted((have - want).elements())


def cut_with(changelog: str, version: str, day: str, title: str,
             frags: list[tuple[str, list[tuple[str, str]]]]) -> str:
    """cut(), the fragments assembled into the version's section; cut() itself without any:
    [Unreleased] then stays as it was written (the transition)."""
    if not frags:
        return cut(changelog, version, day, title)
    head, rest = changelog.split(UNRELEASED, 1)
    m = SECTION.search(rest)
    legacy, after = (rest[: m.start()], rest[m.start():]) if m else (rest, "")
    return (head + UNRELEASED + "\n" + f'## [{version}] — {day} — "{title}"\n\n'
            + assemble(legacy, frags) + "\n" + ("\n" + after if after else ""))


def section(changelog: str, version: str) -> tuple[str, str]:
    """(its heading's title, its text) of the CHANGELOG's [X.Y.Z]; ("", "") when absent."""
    m = re.search(rf"(?m)^## \[{re.escape(version)}\](.*)\n", changelog)
    if not m:
        return "", ""
    title = re.search(r'"([^"]+)"\s*$', m.group(1))
    rest = changelog[m.end():]
    nxt = SECTION.search(rest)
    return (title.group(1) if title else ""), (rest[: nxt.start()] if nxt else rest).strip("\n")


def sections_named(text: str) -> list[str]:
    return re.findall(r"(?m)^### (.+)$", text)


# ── ROADMAP.md: « Les prochaines releases » (RM1) ───────────────────────────────────

def _scripts_dir() -> None:
    """This file's directory on sys.path: its siblings (roadmap_discord, agents_discord,
    notify_discord) import one another by name."""
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)


def roadmap_drafted(roadmap: str, version: str) -> str:
    """ROADMAP.md with its version's line set to « brouillon », in the table of « Les prochaines
    releases » only: the line whose first cell is X.Y.Z or vX.Y.Z, its last cell replaced. The
    table is the one #roadmap reads, by its own reader (roadmap_discord: its heading, its header,
    a section ended by a real heading): a table #roadmap would say « introuvable » is never
    changed. Unchanged without it or without the line: the Orchestre holds the table by hand."""
    _scripts_dir()
    import roadmap_discord as rd
    if rd.releases(roadmap) is None:
        return roadmap
    lines = roadmap.split("\n")
    start = next(i for i, x in enumerate(lines) if x.strip() == rd.RELEASES_HEADING)
    for i in range(start + 1, len(lines)):
        if re.match(r"#{1,6} ", lines[i]):
            break
        cells = lines[i].strip().strip("|").split("|")
        if lines[i].startswith("|") and len(cells) == 4 and cells[0].strip().strip("`").lstrip("v") == version:
            lines[i] = "|" + "|".join(cells[:3] + [" brouillon "]) + "|"
            return "\n".join(lines)
    return roadmap


# ── prepare: the version's pull request ─────────────────────────────────────────────

def _remote_has(root: Path, kind: str, name: str) -> bool:
    return bool(git(root, "ls-remote", f"--{kind}", "origin", name, check=False))


def _local_has(root: Path, ref: str) -> bool:
    return run(["git", "rev-parse", "-q", "--verify", ref], root, check=False).returncode == 0


def prepare(root: Path, version: str, title: str, *, dry_run: bool = False, day: str | None = None) -> int:
    day = day or date.today().isoformat()
    tag, branch = f"v{version}", f"chore/release-{version}"
    refused: list[str] = []
    title = (title or "").strip()
    if not title:
        refused.append('TITLE manque : make release VERSION=X.Y.Z TITLE="…"')
    elif "\n" in title or '"' in title:
        refused.append("TITLE tient sur une ligne, sans guillemet droit (il est écrit entre \"…\" au CHANGELOG)")
    new = semver(version)
    if new is None:
        refused.append(f"VERSION « {version} » n'est pas X.Y.Z")

    if git(root, "status", "--porcelain"):
        refused.append("l'arbre n'est pas propre (git status) : rien n'est coupé d'un arbre modifié")
    git(root, "fetch", "--quiet", "origin")
    head, main = git(root, "rev-parse", "HEAD"), git(root, "rev-parse", "origin/main", check=False)
    if head != main:
        refused.append(f"HEAD ({head[:9]}) n'est pas origin/main à jour ({main[:9] or '—'}) : "
                       "git switch --detach origin/main, ou git pull")

    pyproject_path, changelog_path, readme_path = root / "pyproject.toml", root / "CHANGELOG.md", root / "README.md"
    pyproject = pyproject_path.read_text(encoding="utf-8")
    changelog = changelog_path.read_text(encoding="utf-8")
    readme = readme_path.read_text(encoding="utf-8")
    try:   # RM1: its line in « Les prochaines releases », if there is one
        roadmap = (root / "ROADMAP.md").read_text(encoding="utf-8")
    except OSError:
        roadmap = ""
    current = version_of(pyproject)
    if new is not None and (semver(current) is None or new <= semver(current)):
        refused.append(f"{version} n'est pas plus grande que la version courante ({current or '—'})")
    frags, malformed = fragments(root)   # CI5: changes/<lot>.md
    refused += malformed
    if UNRELEASED not in changelog:
        refused.append("le CHANGELOG n'a pas de section « ## [Unreleased] » : rien où couper")
    elif not has_content(unreleased(changelog)) and not frags:
        refused.append("[Unreleased] est vide au CHANGELOG (ou n'a que des titres), et changes/ n'a aucun "
                       "fragment : rien à publier")
    assembled = ""
    if new is not None and current and UNRELEASED in changelog and (has_content(unreleased(changelog)) or frags):
        assembled = cut_with(changelog, version, day, title, frags)
        # Nothing lost: every line of [Unreleased] and of each fragment, in the version's section.
        missing = lost([unreleased(changelog)] + [b for _rel, parts in frags for _name, b in parts],
                       section(assembled, version)[1])
        if missing:
            refused.append(f"l'assemblage perd ou ajoute {len(missing)} ligne(s), dont « {missing[0][:80]} »")
            assembled = ""
    if new is not None and re.search(rf"(?m)^## \[{re.escape(version)}\]", changelog):
        refused.append(f"le CHANGELOG a déjà une section [{version}]")
    if len(STATUS.findall(readme)) != 1:
        refused.append("le README n'a pas une seule ligne « **Status — vX.Y.Z.** »")
    if new is not None:
        if _local_has(root, f"refs/heads/{branch}") or _remote_has(root, "heads", branch):
            refused.append(f"la branche {branch} existe déjà")
        if _local_has(root, f"refs/tags/{tag}") or _remote_has(root, "tags", tag):
            refused.append(f"le tag {tag} existe déjà")
    if not dry_run and shutil.which("gh") is None:
        refused.append("gh introuvable : la pull request s'ouvre avec gh")

    say(f"Release {tag} — « {title} » ({day}), depuis {current or '—'}")
    for r in refused:
        say(f"  ✗ {r}")
    if refused and not dry_run:
        say("Refusé : rien n'a été écrit.")
        return 1

    edits = {}
    if assembled and title:
        edits = {"pyproject.toml": PROJECT_VERSION.sub(f'version = "{version}"', pyproject, count=1),
                 "CHANGELOG.md": assembled,
                 "README.md": STATUS.sub(f"**Status — v{version}.**", readme, count=1)}
    # Said from ROADMAP.md itself, not from the edits: a dry run refused has none, and its line
    # is there all the same.
    drafted = roadmap_drafted(roadmap, version) if new is not None else roadmap
    if edits and drafted != roadmap:
        edits["ROADMAP.md"] = drafted
    staged = ["pyproject.toml", "CHANGELOG.md", "README.md"] + (["ROADMAP.md"] if "ROADMAP.md" in edits else [])
    roadmap_said = (f"ROADMAP.md : la ligne {version} des prochaines releases passe à « brouillon »"
                    if drafted != roadmap else
                    f"ROADMAP.md : pas de ligne {version} sous « Les prochaines releases » (ou un tableau "
                    "que #roadmap ne lit pas) — l'Orchestre la tient à la main")
    removed = [rel for rel, _ in frags]
    cut_text = (section(assembled, version)[1] if assembled else unreleased(changelog)).strip("\n")
    lines = len([x for x in cut_text.splitlines() if x.strip()])
    subject = f"chore(release): {version} — CHANGELOG [{version}] « {title} », version du paquet"
    body = (f"La section [Unreleased] devient [{version}] ({', '.join(sections_named(cut_text)) or '—'} ; "
            f"{lines} lignes, aucune perdue) ; la version du paquet "
            f"(pyproject.toml, lue par annatar.__version__) et la ligne « Status » du README suivent"
            + (f" ; {len(removed)} fragment(s) de changes/ y sont assemblés, puis retirés" if removed else "")
            + (" ; dans ROADMAP.md, la ligne de la version passe à « brouillon » (« Les prochaines releases »)"
               if "ROADMAP.md" in edits else "") + ".\n\n"
            f"Après la fusion : make release-draft VERSION={version} — un brouillon, que Jonathan publie.")
    shown = [["git", "switch", "-c", branch],          # what runs below, call by call
             ["git", "add", *staged],
             *([["git", "rm", "-q", "--", *removed]] if removed else []),
             ["git", "commit", "-m", subject, "-m", body],
             ["git", "push", "-u", "origin", branch],
             ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", subject, "--body", body]]

    if dry_run:
        say("")
        for name, text in edits.items():
            old = {"pyproject.toml": pyproject, "CHANGELOG.md": changelog, "README.md": readme,
                   "ROADMAP.md": roadmap}[name]
            say("".join(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                             f"a/{name}", f"b/{name}", n=2)).rstrip("\n"))
        say(f"\n[{version}] reçoit {lines} lignes : {', '.join(sections_named(cut_text)) or '—'}")
        say(f"changes/ : {len(removed)} fragment(s) assemblé(s) puis retiré(s) — {', '.join(removed)}"
            if removed else "changes/ : aucun fragment")
        say(roadmap_said)
        say("\nÀ blanc (DRY_RUN=1) — rien n'est écrit ni poussé. Lancerait :")
        for c in shown:
            say(f"  {show(c)}")
        if refused:
            say("Refusé tel quel : les points ✗ d'abord.")
        return 1 if refused else 0

    run(["git", "switch", "-c", branch], root)   # the branch first: main's tree is never touched
    step = "write"
    try:
        for name, text in edits.items():
            (root / name).write_text(text, encoding="utf-8")
        step = "add"
        run(["git", "add", *staged], root)
        if removed:   # in the version's commit: a fragment is never assembled twice
            run(["git", "rm", "-q", "--", *removed], root)
        step = "commit"
        run(["git", "commit", "-m", subject, "-m", body], root)
        step = "push"
        run(["git", "push", "-u", "origin", branch], root)
        step = "pr"
        out = run(["gh", "pr", "create", "--base", "main", "--head", branch, "--title", subject, "--body", body], root)
        say(out.stdout.strip())
    except (Refused, OSError) as e:
        raise Halfway(_halfway(step, branch, str(e))) from None
    say(roadmap_said)
    say(f"\nPR ouverte. Après sa fusion : make release-draft VERSION={version}")
    return 0


def _halfway(step: str, branch: str, why: str) -> str:
    """What is left after a failure past `git switch -c`, and how to go on or back. Back: the
    branch's changes dropped, staged ones too (reset --hard), then where make release started —
    `checkout -` takes a detached HEAD back, as `switch -` does not —, the branch deleted."""
    back = f"git reset -q --hard && git checkout -q - && git branch -D {branch}"
    left, on = {
        "write": ("la branche, des fichiers peut-être à moitié écrits",
                  "revenir en arrière (ci-dessous), corriger, puis relancer make release"),
        "add": ("la branche, les fichiers changés, rien de commité", "git add … && git commit, puis push et PR"),
        "commit": ("la branche, les fichiers changés, rien de commité", "git commit, puis push et PR"),
        "push": ("la branche et son commit, en local seulement",
                 f"git push -u origin {branch} && gh pr create --base main --head {branch}"),
        "pr": ("la branche, son commit, poussée ; pas de PR", f"gh pr create --base main --head {branch}"),
    }[step]
    if step == "pr":   # pushed: the remote branch goes too
        back += f" && git push origin --delete {branch}"
    return (f"échec à l'étape « {step} », après la création de {branch} : {why}\n"
            f"  Reste : {left}.\n  Reprendre : {on}.\n  Ou revenir en arrière : {back}.")


# ── draft: the release, a draft, never published ────────────────────────────────────

def _releases(root: Path) -> list[str]:
    """The tags of the repository's releases, drafts included (gh shows them to its members)."""
    out = run(["gh", "release", "list", "--limit", "1000", "--json", "tagName"], root).stdout
    try:
        return [str(r.get("tagName")) for r in json.loads(out or "[]")]
    except (ValueError, AttributeError):
        raise Refused("gh release list : réponse illisible") from None


def releases_page(url: str) -> str:
    """The repository's list of releases, from the draft's URL gh printed: the link Discord gets.
    A draft's own URL (…/releases/tag/untagged-<hash>) changes at each edit — measured on the
    0.4.4, 29/10: the `gh release edit` below, which writes #agents' ids in the notes, moved it,
    and any edit Jonathan makes on GitHub before publishing would too. The list stays, and
    shows the draft first to the repository's members."""
    m = re.match(r"(https://[^/\s]+/[^/\s]+/[^/\s]+/releases)/", url or "")
    return m.group(1) if m else ""


def _discord(tag: str, url: str, heading: str = "", text: str = "") -> dict:
    """The draft on #agents' board, pinged; {} without configuration or when Discord fails. Then
    its card on #releases (REL2), apart: one failing never keeps the other from being sent."""
    _scripts_dir()
    ids: dict = {}
    try:
        import agents_discord
        ids = agents_discord.release_draft(tag, url)
    except Exception as x:   # Discord never fails the command: the draft exists
        print(f"atelier: not sent — #agents: {type(x).__name__}", file=sys.stderr)
    try:
        import notify_discord
        if notify_discord.release_ready(tag, heading, url, text):
            say("Sur #releases : sa carte, avec un bouton vers le brouillon.")
    except Exception as x:
        print(f"atelier: not sent — #releases: {type(x).__name__}", file=sys.stderr)
    return ids


def draft(root: Path, version: str, notes_file: str = "", *, dry_run: bool = False) -> int:
    tag = f"v{version}"
    refused: list[str] = []
    if semver(version) is None:
        say(f"  ✗ VERSION « {version} » n'est pas X.Y.Z")
        return 1
    git(root, "fetch", "--quiet", "--tags", "origin")
    sha = git(root, "rev-parse", "origin/main^{commit}")
    there = run(["git", "show", f"{sha}:pyproject.toml"], root, check=False).stdout
    changelog = run(["git", "show", f"{sha}:CHANGELOG.md"], root, check=False).stdout
    if version_of(there) != version:
        refused.append(f"origin/main ({sha[:9]}) est en {version_of(there) or '—'}, pas {version} : "
                       f"la PR chore/release-{version} d'abord (make release)")
    heading, text = section(changelog, version)
    if not text:
        refused.append(f"le CHANGELOG d'origin/main n'a pas de section [{version}]")
    if _local_has(root, f"refs/tags/{tag}") or _remote_has(root, "tags", tag):
        refused.append(f"le tag {tag} existe déjà")
    if shutil.which("gh") is None:
        refused.append("gh introuvable")
    elif tag in _releases(root):
        refused.append(f"une release {tag} existe déjà (brouillon compris)")
    if notes_file:
        try:
            text = Path(notes_file).expanduser().read_text(encoding="utf-8").strip("\n")
        except OSError as e:
            refused.append(f"NOTES illisible : {type(e).__name__}")
    if not has_content(text):
        refused.append("des notes vides (ou rien que des titres)")
    title = f"{tag} — {heading}" if heading else tag

    say(f"Brouillon {tag} « {title} » sur origin/main {sha}")
    for r in refused:
        say(f"  ✗ {r}")
    if refused:
        say("Refusé : rien n'a été créé.")
        return 1

    if dry_run:
        say(f"\nNotes ({len(text.splitlines())} lignes{', ' + notes_file if notes_file else ', le CHANGELOG'}) :")
        say("\n".join(text.splitlines()[:12]) + ("\n…" if len(text.splitlines()) > 12 else ""))
        say("\nÀ blanc (DRY_RUN=1) — rien n'est créé, rien n'est envoyé. Lancerait :")
        say(f"  {show(['gh', 'release', 'create', tag, '--draft', '--target', sha, '--title', title, '--notes-file', '<notes>'])}")
        say("  puis la ligne du brouillon sur #agents, et son ping, et sa carte sur #releases "
            "(si Discord est configuré)")
        return 0

    with tempfile.TemporaryDirectory(prefix="eregion-release-") as tmp:
        notes = Path(tmp) / "notes.md"
        notes.write_text(text + "\n", encoding="utf-8")
        url = run(["gh", "release", "create", tag, "--draft", "--target", sha, "--title", title,
                   "--notes-file", str(notes)], root).stdout.strip().splitlines()[-1:] or [""]
        url = releases_page(url[0])
        say(f"Brouillon créé, en tête de {url or '(lien non lu)'} — Jonathan le publie (publier déploie H0).")
        ids = _discord(tag, url, heading, text)
        if ids.get("ping") or ids.get("board"):
            # Where notify.yml finds #agents' messages when the release is published: it has no
            # local state (docs/atelier-discord.md). An HTML comment: unseen in the release's page.
            notes.write_text(text + "\n\n" + MARKER.format(ping=ids.get("ping", ""), board=ids.get("board", ""))
                             + "\n", encoding="utf-8")
            edit = run(["gh", "release", "edit", tag, "--notes-file", str(notes)], root, check=False)
            if edit.returncode != 0:
                print("atelier: not sent — les notes du brouillon : sa ligne de #agents part au "
                      "rafraîchissement suivant", file=sys.stderr)
            say("Sur #agents : la ligne du brouillon et son ping, effacés à la publication.")
    return 0


# ── the command line ────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("version", nargs="?", default=os.environ.get("EREGION_RELEASE_VERSION", ""))
    p.add_argument("--title", default=os.environ.get("EREGION_RELEASE_TITLE", ""))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--date", default=None, help=argparse.SUPPRESS)
    d = sub.add_parser("release-draft")
    d.add_argument("version", nargs="?", default=os.environ.get("EREGION_RELEASE_VERSION", ""))
    d.add_argument("--notes", default=os.environ.get("EREGION_RELEASE_NOTES", ""))
    d.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    try:
        root = Path(git(Path.cwd(), "rev-parse", "--show-toplevel"))
        if a.mode == "prepare":
            return prepare(root, a.version.strip(), a.title, dry_run=a.dry_run, day=a.date)
        return draft(root, a.version.strip(), a.notes.strip(), dry_run=a.dry_run)
    except Refused as r:
        say(f"Refusé : {r}")
        return 1
    except Halfway as h:
        say(f"Arrêté en route — {h}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
