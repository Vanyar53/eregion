#!/usr/bin/env python3
"""release — a release in two commands: the version's pull request, then the draft (REL1, #269).

  release.py prepare X.Y.Z --title TEXT [--dry-run]   make release VERSION=X.Y.Z TITLE="…" [DRY_RUN=1]
  release.py release-draft X.Y.Z [--notes FILE] [--dry-run]   make release-draft VERSION=X.Y.Z [NOTES=file] [DRY_RUN=1]

`prepare`, on an up-to-date origin/main with a clean tree: [Unreleased] becomes
[X.Y.Z] — <date> — "<title>" (an empty [Unreleased] above it), the version of pyproject.toml
— the package's only one: annatar.__version__ reads it — and the README's « **Status — vX.Y.Z.** »
follow; then the branch chore/release-X.Y.Z, its commit, pushed, and its pull request. Refused:
a tree not clean, a HEAD that is not origin/main, a version not greater than the current one,
an empty [Unreleased], a branch or a tag vX.Y.Z that exists.

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
    current = version_of(pyproject)
    if new is not None and (semver(current) is None or new <= semver(current)):
        refused.append(f"{version} n'est pas plus grande que la version courante ({current or '—'})")
    if not has_content(unreleased(changelog)):
        refused.append("[Unreleased] est vide au CHANGELOG (ou n'a que des titres) : rien à publier")
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
    if new is not None and has_content(unreleased(changelog)) and title and current:
        edits = {"pyproject.toml": PROJECT_VERSION.sub(f'version = "{version}"', pyproject, count=1),
                 "CHANGELOG.md": cut(changelog, version, day, title),
                 "README.md": STATUS.sub(f"**Status — v{version}.**", readme, count=1)}
    cut_text = unreleased(changelog).strip("\n")
    lines = len([x for x in cut_text.splitlines() if x.strip()])
    subject = f"chore(release): {version} — CHANGELOG [{version}] « {title} », version du paquet"
    body = (f"La section [Unreleased] devient [{version}] ({', '.join(sections_named(cut_text)) or '—'} ; "
            f"{lines} lignes, aucune perdue) ; la version du paquet "
            f"(pyproject.toml, lue par annatar.__version__) et la ligne « Status » du README suivent.\n\n"
            f"Après la fusion : make release-draft VERSION={version} — un brouillon, que Jonathan publie.")
    shown = [["git", "switch", "-c", branch],          # what runs below, call by call
             ["git", "add", "pyproject.toml", "CHANGELOG.md", "README.md"],
             ["git", "commit", "-m", subject, "-m", body],
             ["git", "push", "-u", "origin", branch],
             ["gh", "pr", "create", "--base", "main", "--head", branch, "--title", subject, "--body", body]]

    if dry_run:
        say("")
        for name, text in edits.items():
            old = {"pyproject.toml": pyproject, "CHANGELOG.md": changelog, "README.md": readme}[name]
            say("".join(difflib.unified_diff(old.splitlines(True), text.splitlines(True),
                                             f"a/{name}", f"b/{name}", n=2)).rstrip("\n"))
        say(f"\n[{version}] reçoit {lines} lignes : {', '.join(sections_named(cut_text)) or '—'}")
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
        run(["git", "add", "pyproject.toml", "CHANGELOG.md", "README.md"], root)
        step = "commit"
        run(["git", "commit", "-m", subject, "-m", body], root)
        step = "push"
        run(["git", "push", "-u", "origin", branch], root)
        step = "pr"
        out = run(["gh", "pr", "create", "--base", "main", "--head", branch, "--title", subject, "--body", body], root)
        say(out.stdout.strip())
    except (Refused, OSError) as e:
        raise Halfway(_halfway(step, branch, str(e))) from None
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
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
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
