"""REL1 (#269): a release in two commands — the version's pull request, then the draft.

On a throwaway git repository (tmp_path: a bare `origin`, a clone), with a fake `gh` first on the
PATH that records every call and answers as GitHub's CLI does, and the fake Discord
(tests/unit/fake_discord.py) for #agents. Nothing reaches GitHub nor Discord: no tag, no release,
no remote branch but the throwaway origin's.
"""
import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from .fake_discord import FakeDiscord

ROOT = Path(__file__).resolve().parents[2]
AGENTS_TOKEN = "AGENTS-SECRET-rel"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is needed")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # agents_discord imports notify_discord; dataclasses look up their module
    spec.loader.exec_module(mod)
    return mod


nd = _load("notify_discord")
ad = _load("agents_discord")
rel = _load("release")

CHANGELOG = """# Changelog

Notable changes to Eregion.

## [Unreleased]

### Added
- **A release in two commands** (REL1).

### Fixed
- Something that was wrong.

## [0.4.3] — 2026-10-28 — "held at the edges"

### Fixed
- An older line.
"""
README = "# Eregion\n\n**Status — v0.4.3.** Glorfindel runs on Azure.\n"
PYPROJECT = '[project]\nname = "eregion"\nversion = "0.4.3"\n\n[tool.ruff]\ntarget-version = "py311"\n'

FAKE_GH = r'''#!/usr/bin/env python3
"""A fake gh: records each call, answers as GitHub's CLI does (drafts listed for members)."""
import json, os, sys
from pathlib import Path
state = Path(os.environ["FAKE_GH_STATE"])
data = json.loads(state.read_text()) if state.exists() else {"releases": [], "calls": []}
args = sys.argv[1:]
call = {"args": args}
if " ".join(args[:2]) == os.environ.get("FAKE_GH_FAIL"):
    print("HTTP 502: Bad Gateway", file=sys.stderr)
    sys.exit(1)
if "--notes-file" in args:
    call["notes"] = Path(args[args.index("--notes-file") + 1]).read_text()
data["calls"].append(call)
out, code = "", 0
if args[:2] == ["release", "list"]:
    out = json.dumps([{"tagName": r["tag"]} for r in data["releases"]])
elif args[:2] == ["release", "create"]:
    n = len(data["releases"]) + 1
    data["releases"].append({"tag": args[2], "draft": "--draft" in args, "notes": call.get("notes", "")})
    out = f"https://github.com/o/r/releases/tag/untagged-{n:04x}"
elif args[:2] == ["release", "edit"]:
    r = next(r for r in data["releases"] if r["tag"] == args[2])
    r["notes"] = call.get("notes", r["notes"])
    out = f"https://github.com/o/r/releases/tag/untagged-{data['releases'].index(r) + 1:04x}"
elif args[:2] == ["pr", "create"]:
    out = "https://github.com/o/r/pull/300"
else:
    code = 1
state.write_text(json.dumps(data))
print(out)
sys.exit(code)
'''


def git(cwd, *args, check=True):
    p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and p.returncode:
        raise AssertionError(p.stderr)
    return p.stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A clone of a bare origin, on main at 0.4.3, [Unreleased] filled; the fake gh first on the PATH."""
    for k in list(os.environ):
        if k.startswith(("EREGION_DISCORD_", "GITHUB_", "GIT_", "EREGION_RELEASE_")):
            monkeypatch.delenv(k)
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(FAKE_GH.replace("#!/usr/bin/env python3", f"#!{sys.executable}", 1))
    (bin_dir / "gh").chmod(0o755)
    env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "test", "GIT_AUTHOR_EMAIL": "test@example.org",
           "GIT_COMMITTER_NAME": "test", "GIT_COMMITTER_EMAIL": "test@example.org",
           "FAKE_GH_STATE": str(tmp_path / "gh.json"), "XDG_STATE_HOME": str(tmp_path / "state"),
           "EREGION_DISCORD_ENV": str(tmp_path / "absent.env"),   # never the operator's file
           "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    origin, work = tmp_path / "origin.git", tmp_path / "work"
    git(tmp_path, "init", "-q", "--bare", "-b", "main", str(origin))
    git(tmp_path, "init", "-q", "-b", "main", str(work))
    (work / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    (work / "README.md").write_text(README, encoding="utf-8")
    (work / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    git(work, "add", ".")
    git(work, "commit", "-qm", "init")
    git(work, "remote", "add", "origin", str(origin))
    git(work, "push", "-q", "-u", "origin", "main")
    monkeypatch.chdir(work)
    return work


def refused(out: str, said: str) -> bool:
    """One of the « ✗ » lines says it."""
    return any(said in line for line in out.splitlines() if line.startswith("  ✗ "))


def gh_calls(tmp_path):
    path = tmp_path / "gh.json"
    return json.loads(path.read_text())["calls"] if path.exists() else []


def gh_releases(tmp_path):
    path = tmp_path / "gh.json"
    return json.loads(path.read_text())["releases"] if path.exists() else []


def files(work):
    return {n: (work / n).read_text(encoding="utf-8") for n in ("CHANGELOG.md", "README.md", "pyproject.toml")}


def merge_release(work, version="0.4.4"):
    """The release pull request merged: origin/main fast-forwarded to its branch."""
    git(work, "push", "-q", "origin", f"chore/release-{version}:main")
    git(work, "fetch", "-q", "origin")


def prepared(work, capsys, version="0.4.4", title="x"):
    assert rel.main(["prepare", version, "--title", title]) == 0, capsys.readouterr().out
    merge_release(work, version)


# ── make release: the version's pull request ────────────────────────────────────────

def test_release_cuts_the_changelog_bumps_the_version_and_opens_the_pull_request(repo, tmp_path, capsys):
    before = files(repo)
    assert rel.main(["prepare", "0.4.4", "--title", "nothing lost"]) == 0, capsys.readouterr().out
    today = date.today().isoformat()
    after = files(repo)
    assert after["CHANGELOG.md"] == before["CHANGELOG.md"].replace(
        "## [Unreleased]\n\n", f'## [Unreleased]\n\n## [0.4.4] — {today} — "nothing lost"\n\n', 1)
    assert 'version = "0.4.4"' in after["pyproject.toml"] and 'target-version = "py311"' in after["pyproject.toml"]
    assert "**Status — v0.4.4.** Glorfindel runs on Azure." in after["README.md"]
    assert rel.unreleased(after["CHANGELOG.md"]).strip() == ""      # an empty [Unreleased] above
    branch = "chore/release-0.4.4"
    assert git(repo, "branch", "--show-current") == branch
    subject = "chore(release): 0.4.4 — CHANGELOG [0.4.4] « nothing lost », version du paquet"
    assert git(repo, "log", "-1", "--format=%s") == subject
    assert set(git(repo, "show", "--name-only", "--format=", "HEAD").split()) == {
        "CHANGELOG.md", "README.md", "pyproject.toml"}
    assert git(repo, "ls-remote", "--heads", "origin", branch)            # pushed (to the throwaway origin)
    assert git(repo, "rev-parse", "origin/main") == git(repo, "rev-parse", "HEAD~1")   # main untouched
    (pr,) = [c["args"] for c in gh_calls(tmp_path) if c["args"][:2] == ["pr", "create"]]
    assert pr[pr.index("--base") + 1] == "main" and pr[pr.index("--head") + 1] == branch
    assert pr[pr.index("--title") + 1] == subject
    assert "make release-draft VERSION=0.4.4" in pr[pr.index("--body") + 1]
    assert not [c for c in gh_calls(tmp_path) if c["args"][0] == "release"]   # no release yet


def test_the_readme_test_holds_on_what_release_wrote(repo, capsys):
    """tests/unit/test_readme.py reads the README's status against pyproject.toml: they move together."""
    assert rel.main(["prepare", "0.5.0", "--title", "x"]) == 0, capsys.readouterr().out
    text = files(repo)
    (status,) = re.findall(r"\*\*Status — v(\d+\.\d+\.\d+)\.\*\*", text["README.md"])
    assert status == rel.version_of(text["pyproject.toml"]) == "0.5.0"


def test_release_dry_run_shows_the_cut_and_writes_nothing(repo, tmp_path, capsys):
    before, head = files(repo), git(repo, "rev-parse", "HEAD")
    assert rel.main(["prepare", "0.4.4", "--title", "x", "--dry-run", "--date", "2026-10-29"]) == 0
    out = capsys.readouterr().out
    assert '+## [0.4.4] — 2026-10-29 — "x"' in out and " ## [Unreleased]" in out
    assert '-version = "0.4.3"' in out and '+version = "0.4.4"' in out
    assert "+**Status — v0.4.4.** Glorfindel runs on Azure." in out
    assert "[0.4.4] reçoit 4 lignes : Added, Fixed" in out
    assert "git push -u origin chore/release-0.4.4" in out and "gh pr create" in out
    assert files(repo) == before and git(repo, "rev-parse", "HEAD") == head
    assert git(repo, "branch", "--list", "chore/*") == "" and git(repo, "status", "--porcelain") == ""
    assert not git(repo, "ls-remote", "--heads", "origin", "chore/release-0.4.4")
    assert gh_calls(tmp_path) == []


def test_release_dry_run_says_what_it_would_refuse(repo, capsys):
    (repo / "stray.txt").write_text("x")
    assert rel.main(["prepare", "0.4.4", "--title", "x", "--dry-run"]) == 1
    out = capsys.readouterr().out
    assert "✗ l'arbre n'est pas propre" in out and "+## [0.4.4]" in out and "Refusé tel quel" in out


def _dirty(work):
    (work / "README.md").write_text(README + "edited\n", encoding="utf-8")


def _untracked(work):
    (work / "notes.txt").write_text("x\n", encoding="utf-8")


def _ahead(work):
    (work / "other.txt").write_text("x\n", encoding="utf-8")
    git(work, "add", "other.txt")
    git(work, "commit", "-qm", "local, not pushed")


def _behind(work):
    """origin/main moved on since this clone: HEAD is not origin/main once fetched."""
    other = work.parent / "other"
    git(work.parent, "clone", "-q", str(work.parent / "origin.git"), str(other))
    (other / "new.txt").write_text("x\n", encoding="utf-8")
    git(other, "add", "new.txt")
    git(other, "commit", "-qm", "someone else's")
    git(other, "push", "-q", "origin", "main")


def _empty_unreleased(work):
    text = CHANGELOG.split("## [Unreleased]\n")[0] + "## [Unreleased]\n\n## [0.4.3]" + CHANGELOG.split("## [0.4.3]")[1]
    (work / "CHANGELOG.md").write_text(text, encoding="utf-8")
    git(work, "commit", "-qam", "empty")
    git(work, "push", "-q", "origin", "main")


def _headings_only(work):
    text = (CHANGELOG.split("## [Unreleased]\n")[0] + "## [Unreleased]\n\n### Added\n\n### Fixed\n\n## [0.4.3]"
            + CHANGELOG.split("## [0.4.3]")[1])
    (work / "CHANGELOG.md").write_text(text, encoding="utf-8")
    git(work, "commit", "-qam", "headings only")
    git(work, "push", "-q", "origin", "main")


def _remote_branch(work):
    git(work, "push", "-q", "origin", "main:refs/heads/chore/release-0.4.4")


def _local_branch(work):
    git(work, "branch", "chore/release-0.4.4")


def _remote_tag(work):
    git(work, "tag", "v0.4.4")
    git(work, "push", "-q", "origin", "v0.4.4")
    git(work, "tag", "-d", "v0.4.4")


def _local_tag(work):
    git(work, "tag", "v0.4.4")


@pytest.mark.parametrize("setup, version, said", [
    (_dirty, "0.4.4", "l'arbre n'est pas propre"),
    (_untracked, "0.4.4", "l'arbre n'est pas propre"),
    (_ahead, "0.4.4", "n'est pas origin/main à jour"),
    (_behind, "0.4.4", "n'est pas origin/main à jour"),
    (None, "0.4.3", "n'est pas plus grande que la version courante (0.4.3)"),
    (None, "0.4.2", "n'est pas plus grande"),
    (None, "0.3.9", "n'est pas plus grande"),
    (None, "0.4", "n'est pas X.Y.Z"),
    (None, "v0.4.4", "n'est pas X.Y.Z"),
    (None, "0.04.4", "n'est pas X.Y.Z"),
    (_empty_unreleased, "0.4.4", "[Unreleased] est vide"),
    (_headings_only, "0.4.4", "[Unreleased] est vide au CHANGELOG (ou n'a que des titres)"),
    (_remote_branch, "0.4.4", "la branche chore/release-0.4.4 existe déjà"),
    (_local_branch, "0.4.4", "la branche chore/release-0.4.4 existe déjà"),
    (_remote_tag, "0.4.4", "le tag v0.4.4 existe déjà"),
    (_local_tag, "0.4.4", "le tag v0.4.4 existe déjà"),
], ids=lambda x: getattr(x, "__name__", str(x))[:40])
def test_release_refuses_and_writes_nothing(repo, tmp_path, capsys, setup, version, said):
    if setup:
        setup(repo)
    before, head = files(repo), git(repo, "rev-parse", "HEAD")
    branches = git(repo, "branch", "--list")
    assert rel.main(["prepare", version, "--title", "x"]) == 1
    out = capsys.readouterr().out
    assert refused(out, said) and "rien n'a été écrit" in out
    assert files(repo) == before and git(repo, "rev-parse", "HEAD") == head
    assert git(repo, "branch", "--list") == branches
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["pr", "create"]] == []


@pytest.mark.parametrize("title", ["", "   ", 'a "quoted" title', "two\nlines"])
def test_release_refuses_a_title_the_changelog_cannot_hold(repo, capsys, title):
    assert rel.main(["prepare", "0.4.4", "--title", title]) == 1
    assert "✗ TITLE" in capsys.readouterr().out


def test_release_reads_its_arguments_from_make_s_environment(repo, monkeypatch, capsys):
    """The Makefile passes VERSION and TITLE by the environment, never on the command line."""
    monkeypatch.setenv("EREGION_RELEASE_VERSION", "0.4.4")
    monkeypatch.setenv("EREGION_RELEASE_TITLE", "from make")
    assert rel.main(["prepare", "--dry-run", "--date", "2026-10-29"]) == 0
    assert '+## [0.4.4] — 2026-10-29 — "from make"' in capsys.readouterr().out


# ── make release-draft: the draft ───────────────────────────────────────────────────

def test_release_draft_creates_a_draft_on_main_s_full_sha_with_the_changelog_s_section(repo, tmp_path, capsys):
    prepared(repo, capsys, title="two commands")
    capsys.readouterr()
    sha = git(repo, "rev-parse", "origin/main")
    git(repo, "switch", "-q", "--detach", "HEAD~1")                       # wherever HEAD is: main's sha
    assert rel.main(["release-draft", "0.4.4"]) == 0, capsys.readouterr().out
    (create,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "create"]]
    args = create["args"]
    assert args[2] == "v0.4.4" and "--draft" in args
    assert args[args.index("--target") + 1] == sha and len(sha) == 40
    assert args[args.index("--title") + 1] == "v0.4.4 — two commands"
    assert create["notes"] == ("### Added\n- **A release in two commands** (REL1).\n\n"
                               "### Fixed\n- Something that was wrong.\n")
    assert gh_releases(tmp_path) == [{"tag": "v0.4.4", "draft": True, "notes": create["notes"]}]
    assert not git(repo, "ls-remote", "--tags", "origin")                 # no tag: a draft has none
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]] == []   # no Discord


def test_release_draft_takes_the_notes_given(repo, tmp_path, capsys):
    prepared(repo, capsys)
    notes = tmp_path / "notes.md"
    notes.write_text("**0.4.4 — x.** The lead paragraph.\n\n### Added\n- one\n", encoding="utf-8")
    assert rel.main(["release-draft", "0.4.4", "--notes", str(notes)]) == 0
    (create,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "create"]]
    assert create["notes"] == "**0.4.4 — x.** The lead paragraph.\n\n### Added\n- one\n"


def test_release_draft_dry_run_creates_nothing(repo, tmp_path, capsys):
    prepared(repo, capsys)
    capsys.readouterr()
    assert rel.main(["release-draft", "0.4.4", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "gh release create v0.4.4 --draft --target" in out and "### Added" in out
    assert [c for c in gh_calls(tmp_path) if c["args"][0] == "release" and c["args"][1] != "list"] == []


def _no_release_merged(work):
    """The pull request not merged yet: origin/main still at 0.4.3."""
    git(work, "push", "-q", "origin", "--delete", "chore/release-0.4.4")
    git(work, "fetch", "-q", "--prune", "origin")
    git(work, "reset", "-q", "--hard", "origin/main")


def _draft_exists(work):
    state = Path(os.environ["FAKE_GH_STATE"])
    state.write_text(json.dumps({"releases": [{"tag": "v0.4.4", "draft": True, "notes": ""}], "calls": []}))


def _notes_unreadable(work):
    return ["--notes", str(work.parent / "absent.md")]


def _notes_headings_only(work):
    (work.parent / "headings.md").write_text("### Added\n\n### Fixed\n", encoding="utf-8")
    return ["--notes", str(work.parent / "headings.md")]


@pytest.mark.parametrize("setup, said", [
    (_no_release_merged, "est en 0.4.3, pas 0.4.4"),
    (_remote_tag, "le tag v0.4.4 existe déjà"),
    (_local_tag, "le tag v0.4.4 existe déjà"),
    (_draft_exists, "une release v0.4.4 existe déjà (brouillon compris)"),
    (_notes_unreadable, "NOTES illisible"),
    (_notes_headings_only, "des notes vides (ou rien que des titres)"),
], ids=lambda x: getattr(x, "__name__", str(x))[:40])
def test_release_draft_refuses_and_creates_nothing(repo, tmp_path, capsys, setup, said):
    assert rel.main(["prepare", "0.4.4", "--title", "x"]) == 0
    if setup is not _no_release_merged:
        merge_release(repo)
    extra = setup(repo) or []
    capsys.readouterr()
    assert rel.main(["release-draft", "0.4.4", *extra]) == 1
    out = capsys.readouterr().out
    assert refused(out, said) and "rien n'a été créé" in out
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] in (["release", "create"], ["release", "edit"])] == []


def test_release_draft_refuses_a_version_main_s_changelog_does_not_hold(repo, tmp_path, capsys):
    """pyproject.toml bumped by hand, the CHANGELOG not cut: no section, no draft."""
    (repo / "pyproject.toml").write_text(PYPROJECT.replace("0.4.3", "0.4.4"), encoding="utf-8")
    git(repo, "commit", "-qam", "bump by hand")
    git(repo, "push", "-q", "origin", "main")
    assert rel.main(["release-draft", "0.4.4"]) == 1
    assert "✗ le CHANGELOG d'origin/main n'a pas de section [0.4.4]" in capsys.readouterr().out
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "create"]] == []


# ── no path publishes ───────────────────────────────────────────────────────────────
# An allow-list, read in the code's syntax tree (never a pattern of what would publish: gh's
# boolean flags take f, F, FALSE, 0…, and a value can be built, concatenated, formatted).
# - In release.py, every list that starts with "gh" is one of four commands, never `gh api`;
#   `release create` holds the literal "--draft" followed by another flag, and `release edit` is
#   exactly [gh, release, edit, <tag>, --notes-file, <path>]. "gh" appears nowhere else but in
#   shutil.which and run()'s own check ("git", "gh"). A command runs only through run(), with a literal list that starts with "git" or
#   "gh"; run() is the only caller of subprocess, and checks its head itself. No shell, no
#   os.system / popen / exec / spawn, no eval, exec, getattr or __import__; no HTTP of its own.
# - Everywhere (release.py, agents_discord.py, notify_discord.py, the make recipes), no string
#   says `draft` as a word, a flag or a field — strings joined by + or in an f-string read whole,
#   keyword arguments (dict(draft=…)) too — but the literal "--draft" of `create`. The names
#   `release-draft` (the make target, the subcommand) and `release_draft` (a function) are names.
# - In agents_discord.py and notify_discord.py, a URL that holds `releases` is only ever read
#   (GET), by fetch(method, url, …) as by the bot's call(method, path, …), positional or named;
#   and no call, whatever its name (getattr…), takes a method that writes with such a URL.
# What no reading of the text can see: a method AND a URL both computed at run time (a join, a
# lookup) behind a function looked up by a computed name. The dynamic tests cover it: no request
# but GET ever reaches the fake GitHub (test_the_draft_is_on_the_board_…), and every gh call is
# compared argument by argument (test_no_call_publishes).

GH_COMMANDS = {("pr", "create"), ("release", "list"), ("release", "create"), ("release", "edit")}
DRAFT_WORD = re.compile(r"(?i)(?<!release)(?<!release[-_])-*draft")
WRITES = {"POST", "PATCH", "PUT", "DELETE"}
SCRIPTS = ("release.py", "agents_discord.py", "notify_discord.py")
FORBIDDEN_CALLS = {"eval", "exec", "getattr", "__import__", "compile", "globals", "vars"}
FORBIDDEN_OS = re.compile(r"system|popen|exec.*|spawn.*|fork.*|posix_spawn.*")


def _const(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _folded(node) -> str | None:
    """A string the code writes in pieces: "a" + "b", f"a{x}b" (its literal parts), as one."""
    if (c := _const(node)) is not None:
        return c
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _folded(node.left), _folded(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        return "".join(_const(v) or "" for v in node.values)
    return None


def _docstrings(tree) -> set[int]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and _const(first.value) is not None:
                out.add(id(first.value))
    return out


def _gh_lists(tree) -> list:
    return [n for n in ast.walk(tree) if isinstance(n, ast.List) and n.elts and _const(n.elts[0]) == "gh"]


def _parents(tree) -> dict[int, ast.AST]:
    return {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def publishes_gh(source: str) -> list[str]:
    """What, in release.py's code, could run another gh command than the four allowed."""
    tree, bad = ast.parse(source), []
    lists = _gh_lists(tree)
    for n in lists:
        head = tuple(_const(e) for e in n.elts[1:3])
        if head not in GH_COMMANDS:
            bad.append(f"gh {head}")
            continue
        consts = [_const(e) for e in n.elts]
        if head == ("release", "create"):
            at = [i for i, c in enumerate(consts) if c == "--draft"]
            if len(at) != 1 or not (at[0] + 1 < len(consts) and (consts[at[0] + 1] or "").startswith("--")):
                bad.append("create without its --draft, or --draft given a value")
        if head == ("release", "edit"):
            if len(n.elts) != 6 or consts[4] != "--notes-file" or consts[3] is not None or consts[5] is not None:
                bad.append(f"edit is not [gh, release, edit, <tag>, --notes-file, <path>]: {consts}")
    ghs = sum(_const(n) == "gh" for n in ast.walk(tree))
    whiches = sum(isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "which" for n in ast.walk(tree))
    guards = sum(isinstance(n, ast.Tuple) and [_const(e) for e in n.elts] == ["git", "gh"] for n in ast.walk(tree))
    if ghs != len(lists) + whiches + guards:
        bad.append("gh named outside a command list")
    drafts = sum(_const(n) == "--draft" for n in ast.walk(tree))
    if drafts != sum(1 for n in lists if tuple(_const(e) for e in n.elts[1:3]) == ("release", "create")):
        bad.append("a --draft outside release create")
    for n in ast.walk(tree):
        names = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""] if isinstance(
            n, ast.ImportFrom) else []
        bad += [f"import {m}" for m in names if m.split(".")[0] in ("urllib", "http", "requests", "socket")]
    return bad


def publishes_code(source: str) -> list[str]:
    """How release.py may start a process: run() with a literal git or gh list, nothing else."""
    tree, bad = ast.parse(source), []
    parents = _parents(tree)
    defs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for n in ast.walk(tree):
        if isinstance(n, ast.keyword) and n.arg == "shell":
            bad.append("shell=")
        if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] in ("subprocess", "os", "pty"):
            bad.append(f"from {n.module} import")
        if isinstance(n, ast.Import) and any(a.name.split(".")[0] in ("pty", "multiprocessing") for a in n.names):
            bad.append("import pty/multiprocessing")
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            if n.value.id == "os" and FORBIDDEN_OS.fullmatch(n.attr):
                bad.append(f"os.{n.attr}")
            if n.value.id == "subprocess" and n.attr != "CompletedProcess":
                call = parents.get(id(n))
                inside = defs.get("run")
                ok = (n.attr == "run" and isinstance(call, ast.Call) and call.func is n and inside is not None
                      and any(x is call for x in ast.walk(inside))
                      and len(call.args) == 1 and isinstance(call.args[0], ast.Name) and call.args[0].id == "cmd")
                if not ok:
                    bad.append(f"subprocess.{n.attr} outside run(cmd)")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in FORBIDDEN_CALLS:
            bad.append(f"{n.func.id}()")
        if isinstance(n, ast.Name) and n.id == "run" and isinstance(n.ctx, ast.Load):
            call = parents.get(id(n))
            if not (isinstance(call, ast.Call) and call.func is n):
                bad.append("run passed around")
            elif not (call.args and isinstance(call.args[0], ast.List) and call.args[0].elts
                      and _const(call.args[0].elts[0]) in ("git", "gh")):
                bad.append("run() without a literal git or gh list")
    inside = defs.get("run")
    if inside is not None and 'cmd[0] not in ("git", "gh")' not in ast.get_source_segment(source, inside):
        bad.append("run() does not check its command's head")
    return bad


def publishes_words(source: str) -> list[str]:
    """Every string of the code (docstrings aside) that says draft, but "--draft" itself; and
    every keyword argument named so."""
    tree = ast.parse(source)
    skip = _docstrings(tree)
    bad = [n.arg for n in ast.walk(tree) if isinstance(n, ast.keyword) and n.arg and "draft" in n.arg.lower()]
    for n in ast.walk(tree):
        if id(n) in skip:
            continue
        if isinstance(n, (ast.Constant, ast.BinOp, ast.JoinedStr)):
            c = _folded(n)
            if c is not None and c != "--draft" and DRAFT_WORD.search(c):
                bad.append(c)
    return bad


def _arg(call: ast.Call, at: int, *names: str):
    if len(call.args) > at:
        return call.args[at]
    return next((k.value for k in call.keywords if k.arg in names), None)


def publishes_http(source: str) -> list[str]:
    """A URL holding `releases` called with another method than GET."""
    bad = []
    for n in ast.walk(ast.parse(source)):
        if not isinstance(n, ast.Call):
            continue
        args = [*n.args, *(k.value for k in n.keywords)]
        texts = ["".join(c for x in ast.walk(a) if (c := _const(x)) is not None) for a in args]
        texts += [f for a in args if (f := _folded(a))]
        if any(t in WRITES for t in texts) and any("releases" in t for t in texts):
            bad.append(f"a write on releases: {texts}")
            continue
        name = getattr(n.func, "attr", None) or getattr(n.func, "id", None)
        if name in ("fetch", "call"):
            method, url = _arg(n, 0, "method"), _arg(n, 1, "url", "path")
        elif name in ("Request", "urlopen"):
            method, url = next((k.value for k in n.keywords if k.arg == "method"), None), _arg(n, 0, "url")
        else:
            continue
        where = "".join(c for x in ast.walk(url) if (c := _const(x)) is not None) if url is not None else ""
        if "releases" in where and (_folded(method) if method is not None else "GET") != "GET":
            bad.append(f"{_folded(method) if method is not None else None} {where}")
    return bad


def publishes(source: str) -> list[str]:
    return publishes_gh(source) + publishes_code(source) + publishes_words(source) + publishes_http(source)


def _recipes(text: str, *targets: str) -> str:
    out = []
    for t in targets:
        m = re.search(rf"(?m)^{re.escape(t)}:\n((?:\t.*\n)+)", text)
        assert m, t
        out.append(m.group(1))
    return "".join(out)


def test_no_path_publishes_in_the_code():
    """Publishing deploys H0: nothing in the release's code turns a draft into a release."""
    code = {n: (ROOT / "scripts" / n).read_text(encoding="utf-8") for n in SCRIPTS}
    assert publishes_gh(code["release.py"]) == []
    assert publishes_code(code["release.py"]) == []
    heads = sorted(tuple(_const(e) for e in n.elts[1:3]) for n in _gh_lists(ast.parse(code["release.py"])))
    assert heads == sorted([("pr", "create")] * 2 + [("release", "list"), ("release", "create"), ("release", "create"),
                                                      ("release", "edit")])   # each command shown and run
    for name, text in code.items():
        assert publishes_words(text) == [], name
    for name in ("agents_discord.py", "notify_discord.py"):
        assert publishes_http(code[name]) == [], name
    make = _recipes((ROOT / "Makefile").read_text(encoding="utf-8"), "release", "release-draft")
    assert DRAFT_WORD.findall(make) == [] and "gh " not in make and "curl" not in make


@pytest.mark.parametrize("snippet", [
    '["gh", "release", "edit", tag, "--draft=f"]',
    'x = ["gh", "release", "edit", tag, "--notes-file", "--draft=F"]',
    'x = "--draft=FALSE"',
    '["gh", "release", "create", tag, "--draft", "False", "--target", sha]',
    '["gh", "release", "create", tag, "--draft", "--target", sha, "--draft", "0"]',
    'x = "--draft=" + "false"',
    'x = "--dr" + "aft=f"',
    'x = f"--draft={value}"',
    '["gh", "api", "-X", "PATCH", f"repos/o/r/releases/{rid}", "-F", "draft=f"]',
    '["gh", "api", "--method", "PATCH", "repos/o/r/releases/1", "--input", path]',
    '["gh", *args]',
    'cmd = ["gh"] + ["release", "edit", tag, "--draft=false"]',
    'subprocess.run(["gh", "release", "edit", tag, "--notes-file", p, "--prerelease"])',
    'run([shutil.which("gh"), "api", "-X", "PATCH", "repos/o/r/releases/1"], root)',
    'run(cmd, root)',
    'r = run\nr(["gh", "api"], root)',
    'subprocess.run("gh api -X PATCH repos/o/r/releases/1", shell=True)',
    'os.system("gh release edit v1 --notes-file n")',
    'os.popen("gh api repos/o/r/releases")',
    'from subprocess import run as go',
    'json.dumps(dict(draft=False))',
    'import urllib.request',
    'nd.fetch("PATCH", f"{api}/repos/o/r/releases/{rid}", "GitHub API", {"draft": False})',
    'nd.fetch("PATCH", url=f"{api}/repos/o/r/releases/{rid}")',
    'nd.fetch(method="PATCH", url=f"{api}/repos/o/r/releases/{rid}")',
    'getattr(nd, "fe" + "tch")("PATCH", f"{api}/repos/o/r/releases/{rid}")',
    'fetch("POST", api + "/repos/o/r/releases", "x", body)',
    'fetch(method, f"{api}/releases/{rid}", "x")',
    'fetch("PA" + "TCH", f"{api}/releases/{rid}", "x")',
    'x = {"Draft": 0}',
    'x = "publish -F draft=f"',
    'x = "undraft"',
], ids=lambda s: s[:40])
def test_the_allow_list_sees_a_path_that_would_publish(snippet):
    assert publishes(snippet), snippet


@pytest.mark.parametrize("snippet", ['x = "make release-draft VERSION=1"', "def release_draft(): pass",
                                     'run(["gh", "release", "list"], root)', 'run(["git", *args], root)'])
def test_the_allow_list_lets_the_names_through(snippet):
    assert publishes_words(snippet) == [] and [b for b in publishes_code(snippet) if "run()" in b
                                                                                       and "literal" in b] == []


def test_the_makefile_check_sees_a_recipe_that_would_publish():
    for recipe in ("\tgh release edit v1 --draft=false\n", "\tgh api -X PATCH repos/o/r/releases/1 -F draft=f\n"):
        assert DRAFT_WORD.findall(recipe) or "gh " in recipe


def test_no_call_publishes(repo, tmp_path, capsys, monkeypatch):
    """Every gh call of both commands, Discord configured: a draft, never published."""
    f = FakeDiscord()
    try:
        _discord(monkeypatch, f)
        prepared(repo, capsys)
        assert rel.main(["release-draft", "0.4.4"]) == 0
        assert [r for r in f.requests if r["path"].startswith("/gh/") and r["method"] != "GET"] == []
    finally:
        f.close()
    calls = [c["args"] for c in gh_calls(tmp_path)]
    assert [c[:2] for c in calls] == [["pr", "create"], ["release", "list"], ["release", "create"],
                                      ["release", "edit"]]
    create, edit = calls[2], calls[3]
    assert [a for a in create if "draft" in a.lower()] == ["--draft"]
    assert create[create.index("--draft") + 1].startswith("--")
    assert edit[:4] == ["release", "edit", "v0.4.4", "--notes-file"] and len(edit) == 5
    assert Path(edit[4]).name == "notes.md"
    assert all(r["draft"] for r in gh_releases(tmp_path))


# ── the draft seen on #agents ───────────────────────────────────────────────────────

def _discord(monkeypatch, f):
    monkeypatch.setenv("EREGION_DISCORD_API", f.base + "/api")
    monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_AGENTS", f"{f.base}/api/webhooks/2/{AGENTS_TOKEN}")
    monkeypatch.setenv("EREGION_DISCORD_MENTION", "42")
    monkeypatch.setenv("EREGION_DISCORD_SYNC", "1")
    monkeypatch.setenv("GITHUB_API_URL", f.base + "/gh")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")


@pytest.fixture
def fake(monkeypatch, tmp_path):
    """The fake Discord; the local state and the configuration file in tmp_path, never the operator's;
    none of the shell's Discord or GitHub variables (a real #ci webhook exported there)."""
    for k in list(os.environ):
        if k.startswith(("EREGION_DISCORD_", "GITHUB_")):
            monkeypatch.delenv(k)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("EREGION_DISCORD_ENV", str(tmp_path / "absent.env"))
    f = FakeDiscord()
    _discord(monkeypatch, f)
    yield f
    f.close()


PUBLISHED = {"tag_name": "v0.4.4", "draft": False, "published_at": "2026-10-30T09:00:00Z",
             "html_url": "https://github.com/o/r/releases/tag/v0.4.4"}


def _board(f):
    state = json.loads((Path(os.environ["XDG_STATE_HOME"]) / "eregion" / "discord.json").read_text())
    return f.messages[state["board"]]["embeds"][0], state


def _published(tmp_path, monkeypatch, body):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"action": "published", "release": {
        "tag_name": "v0.4.4", "name": "v0.4.4 — x", "body": body, "prerelease": False,
        "html_url": "https://github.com/o/r/releases/tag/v0.4.4"}}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert nd.github() == 0


def test_the_draft_is_on_the_board_and_pinged_then_both_go_when_published(repo, tmp_path, capsys, fake, monkeypatch):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    url = "https://github.com/o/r/releases/tag/untagged-0001"
    line = "🙋 release v0.4.4 en brouillon, à publier"

    # Pinged, with Jonathan's mention and the draft's link; on the board, its link too.
    (ping,) = [b for b in fake.webhook_posts(AGENTS_TOKEN) if b.get("content")]
    assert ping["content"] == "<@42>" and ping["allowed_mentions"] == {"parse": [], "users": ["42"]}
    assert ping["embeds"][0]["title"] == line and ping["embeds"][0]["url"] == url
    board, state = _board(fake)
    assert f"{line} — publier déploie H0" in board["description"] and f"[brouillon]({url})" in board["description"]
    ping_id = state["waiting"][0]["ping"]
    assert ping_id in fake.messages

    # Where notify.yml will find them: the draft's notes, an HTML comment after the CHANGELOG's section.
    (edit,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]]
    notes = edit["notes"]
    assert notes.startswith("### Added\n- **A release in two commands** (REL1).")
    assert f"<!-- #agents (REL1) : ping={ping_id} board={state['board']} " in notes
    assert gh_gh_release_notes(tmp_path) == notes

    # Still a draft: the board's refresh keeps it (GitHub knows no release by that tag yet).
    assert ad.main(["board"]) == 0
    assert line in _board(fake)[0]["description"] and ping_id in fake.messages

    # Published by Jonathan: notify.yml (on GitHub, no local state) deletes the ping and the line.
    _published(tmp_path, monkeypatch, notes)
    assert ping_id not in fake.messages
    board = fake.messages[state["board"]]["embeds"][0]
    assert line not in board["description"] and "**🙋 T'attend**\nRien ne t'attend." in board["description"]
    assert board["color"] == nd.GREY
    assert fake.messages[state["board"]]["allowed_mentions"] == {"parse": []}

    # And the local board, asked of GitHub, settles it for good: never back on the board.
    fake.gh["releases"]["v0.4.4"] = PUBLISHED
    assert ad.main(["board"]) == 0
    board, state = _board(fake)
    assert state["waiting"] == [] and line not in board["description"]
    assert "release v0.4.4 publiée" in board["description"]
    assert [r for r in fake.requests if r["path"].startswith("/gh/") and r["method"] != "GET"] == []


def gh_gh_release_notes(tmp_path):
    (r,) = gh_releases(tmp_path)
    return r["notes"]


def test_published_without_the_ci_the_local_board_settles_it(repo, tmp_path, capsys, fake):
    """notify.yml without #agents' webhook (the secret not set): the board's next refresh does it."""
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    board, state = _board(fake)
    ping_id = state["waiting"][0]["ping"]
    fake.gh["releases"]["v0.4.4"] = PUBLISHED
    assert ad.main(["board"]) == 0
    board, state = _board(fake)
    assert state["waiting"] == [] and ping_id not in fake.messages
    assert "en brouillon" not in board["description"]


def test_a_draft_can_be_cleared_by_hand(repo, capsys, fake):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    assert ad.main(["clear", "v0.4.4"]) == 0
    board, state = _board(fake)
    assert state["waiting"] == [] and "en brouillon" not in board["description"]


def test_a_published_release_without_its_marker_touches_nothing(tmp_path, monkeypatch, fake):
    mid = nd.post_webhook(f"{fake.base}/api/webhooks/2/{AGENTS_TOKEN}", {"embeds": [{"title": "x"}]}, "t")
    for body in ("", "notes", f"<!-- #agents (REL1) : ping=../{mid} board= -->",
                 f"<!-- #agents (REL1) : ping={mid}?x board= -->"):
        _published(tmp_path, monkeypatch, body)
    assert mid in fake.messages
    assert [r for r in fake.requests if r["method"] in ("DELETE", "PATCH")] == []


def test_a_published_release_s_ping_already_gone_is_no_error(tmp_path, monkeypatch, fake, capsys):
    _published(tmp_path, monkeypatch, "x\n\n<!-- #agents (REL1) : ping=999 board=998 — effacés -->")
    assert "not sent" not in capsys.readouterr().err


def test_without_discord_the_draft_succeeds_and_nothing_is_sent(repo, tmp_path, capsys):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    assert gh_releases(tmp_path)[0]["draft"] is True
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]] == []
    assert not (tmp_path / "state").exists()                     # not even the local state


def test_a_discord_that_fails_never_fails_the_draft(repo, tmp_path, capsys, fake):
    fake.fail["/api/webhooks"] = 500
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    assert gh_releases(tmp_path)[0]["draft"] is True
    err = capsys.readouterr().err
    assert "atelier: not sent — webhook #agents: HTTP 500" in err and AGENTS_TOKEN not in err
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]] == []


# ── one source of version ───────────────────────────────────────────────────────────

def test_annatar_s_version_is_the_package_s():
    import tomllib

    import annatar
    version = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert annatar.__version__ == version
    assert re.findall(r'__version__ = "', (ROOT / "annatar" / "__init__.py").read_text(encoding="utf-8")) == []


def _annatar_in(where: Path, pyproject: str | None):
    pkg = where / "annatar"
    pkg.mkdir(parents=True)
    shutil.copy(ROOT / "annatar" / "__init__.py", pkg / "__init__.py")
    if pyproject is not None:
        (where / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("annatar_copy", pkg / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.__version__


def test_annatar_s_version_follows_the_tree_then_the_metadata(tmp_path, monkeypatch):
    """The tree's pyproject.toml first (an editable install's metadata is frozen at install time),
    another project's never; else the installed metadata; else « 0+unknown »."""
    import importlib.metadata
    assert _annatar_in(tmp_path / "a", PYPROJECT.replace("0.4.3", "9.8.7")) == "9.8.7"
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "1.2.3" if name == "eregion" else "0")
    assert _annatar_in(tmp_path / "b", '[project]\nname = "other"\nversion = "5.5.5"\n') == "1.2.3"
    assert _annatar_in(tmp_path / "c", None) == "1.2.3"

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert _annatar_in(tmp_path / "d", None) == "0+unknown"


# ── the Makefile ────────────────────────────────────────────────────────────────────

@pytest.fixture
def make_env(tmp_path):
    if shutil.which("make") is None:
        pytest.skip("make not installed")
    bin_dir = tmp_path / "stubs"
    bin_dir.mkdir()
    for tool in ("docker", "terraform", "az", "curl", "ssh", "scp", "uv", "gh"):
        (bin_dir / tool).write_text("#!/bin/sh\nexit 0\n")
        (bin_dir / tool).chmod(0o755)
    (tmp_path / "home").mkdir(exist_ok=True)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}", "HOME": str(tmp_path / "home"),
            "LC_ALL": "C"}


def _make(env, cwd, *args):
    return subprocess.run(["make", "-s", "-f", str(ROOT / "Makefile"), *args], cwd=cwd, env=env,
                          capture_output=True, text=True)


def test_make_passes_the_title_by_the_environment_never_on_the_command_line(make_env, tmp_path):
    out = _make(make_env, ROOT, "-n", "release", "VERSION=0.4.4", 'TITLE=a $(shell id) `id` "b"', "DRY_RUN=1")
    assert out.returncode == 0, out.stderr
    assert "python3 scripts/release.py prepare --dry-run" in out.stdout
    assert "$(shell id)" not in out.stdout and "`id`" not in out.stdout and "uid=" not in out.stdout
    draft = _make(make_env, ROOT, "-n", "release-draft", "VERSION=0.4.4", "NOTES=notes.md")
    assert "python3 scripts/release.py release-draft\n" in draft.stdout and "notes.md" not in draft.stdout


@pytest.mark.parametrize("target", ["release", "release-draft"])
def test_make_refuses_a_version_from_the_environment(make_env, tmp_path, target):
    """A VERSION exported for something else is never released in silence."""
    out = _make({**make_env, "VERSION": "1.0.0", "TITLE": "x"}, tmp_path, target)
    assert out.returncode != 0 and "vient de l'environnement" in out.stderr
    given = _make(make_env, tmp_path, target, "VERSION=1.0.0", "TITLE=x")
    assert "vient de l'environnement" not in given.stderr and "scripts/release.py" in given.stderr   # past the guard


# ── a failure past the point of no return ───────────────────────────────────────────

def _way_back(out: str) -> str:
    (line,) = [x for x in out.splitlines() if "Ou revenir en arrière : " in x]
    return line.split("Ou revenir en arrière : ", 1)[1].removesuffix(".")


def _went_back(repo, out):
    """The way back said, run as said: a clean tree, HEAD on origin/main, the branch gone here and there."""
    p = subprocess.run(_way_back(out), shell=True, cwd=repo, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert git(repo, "status", "--porcelain") == ""
    assert git(repo, "rev-parse", "HEAD") == git(repo, "rev-parse", "origin/main")
    assert git(repo, "branch", "--list", "chore/*") == ""
    assert not git(repo, "ls-remote", "--heads", "origin", "chore/release-0.4.4")


@pytest.fixture
def detached(repo):
    """The start docs/operations.md gives: git switch --detach origin/main."""
    git(repo, "switch", "-q", "--detach", "origin/main")
    return repo


def test_a_pull_request_that_fails_says_what_is_left_and_how_to_go_on(detached, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_GH_FAIL", "pr create")
    assert rel.main(["prepare", "0.4.4", "--title", "x"]) == 2
    out = capsys.readouterr().out
    assert "rien n'a été écrit" not in out and "Refusé" not in out
    assert "Arrêté en route — échec à l'étape « pr », après la création de chore/release-0.4.4" in out
    assert "HTTP 502" in out and "Reste : la branche, son commit, poussée ; pas de PR" in out
    assert "Reprendre : gh pr create --base main --head chore/release-0.4.4" in out
    assert git(detached, "branch", "--show-current") == "chore/release-0.4.4"      # it is there, as said
    assert git(detached, "ls-remote", "--heads", "origin", "chore/release-0.4.4")
    assert _way_back(out).endswith("&& git push origin --delete chore/release-0.4.4")
    _went_back(detached, out)


def test_a_push_that_fails_says_what_is_left_and_how_to_go_back(detached, tmp_path, capsys):
    hook = tmp_path / "origin.git" / "hooks" / "pre-receive"
    hook.write_text("#!/bin/sh\necho 'refused by the test' >&2\nexit 1\n")
    hook.chmod(0o755)
    assert rel.main(["prepare", "0.4.4", "--title", "x"]) == 2
    out = capsys.readouterr().out
    assert "échec à l'étape « push »" in out and "Reste : la branche et son commit, en local seulement" in out
    assert "git push -u origin chore/release-0.4.4 && gh pr create --base main --head chore/release-0.4.4" in out
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["pr", "create"]] == []
    hook.unlink()
    _went_back(detached, out)


def test_a_commit_that_fails_leaves_staged_files_the_way_back_drops(detached, tmp_path, capsys):
    hook = detached / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'refused by the test' >&2\nexit 1\n")
    hook.chmod(0o755)
    assert rel.main(["prepare", "0.4.4", "--title", "x"]) == 2
    out = capsys.readouterr().out
    assert "échec à l'étape « commit »" in out and "rien de commité" in out
    assert git(detached, "diff", "--cached", "--name-only")                # staged: checkout -- . would not do
    hook.unlink()
    _went_back(detached, out)


# ── notify.yml reads ids from the notes: only this draft's ping, only the board ─────

def test_ids_in_the_notes_never_delete_another_message(repo, tmp_path, capsys, fake, monkeypatch):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    hook = f"{fake.base}/api/webhooks/2/{AGENTS_TOKEN}"
    other = nd.post_webhook(hook, {"embeds": [{"title": "⛔ A3 bloqué"}]}, "t")
    fake_board = nd.post_webhook(hook, {"embeds": [{"title": "⛔ A4 bloqué",
                                                    "description": "🙋 release v0.4.4 en brouillon, à publier"}]}, "t")
    before = {k: json.dumps(v, sort_keys=True) for k, v in fake.messages.items()}
    _published(tmp_path, monkeypatch, f"x\n\n<!-- #agents (REL1) : ping={other} board={fake_board} — effacés -->")
    assert {k: json.dumps(v, sort_keys=True) for k, v in fake.messages.items()} == before
    assert [r for r in fake.requests if r["method"] in ("DELETE", "PATCH") and "/webhooks/" in r["path"]
            and r["path"].rsplit("/", 1)[1] in (other, fake_board)] == []


def test_another_release_s_ping_is_not_this_one_s(repo, tmp_path, capsys, fake, monkeypatch):
    """The ping of v0.4.4 named in the notes of a v0.4.5 published: left alone."""
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    _, state = _board(fake)
    ping = state["waiting"][0]["ping"]
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"action": "published", "release": {
        "tag_name": "v0.4.5", "body": f"<!-- #agents (REL1) : ping={ping} board={state['board']} -->"}}))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "release")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    assert nd.github() == 0
    assert ping in fake.messages and "release v0.4.4 en brouillon" in fake.messages[state["board"]]["embeds"][0][
        "description"]


# ── the local board after notify.yml, and a draft made again ────────────────────────

def test_the_line_notify_yml_took_off_never_comes_back(repo, tmp_path, capsys, fake, monkeypatch):
    """The board refreshed right after the publication (GitHub asked a minute ago): its ping
    gone, GitHub is asked at once, and the line stays off."""
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    assert ad.main(["board"]) == 0                        # GitHub asked now: still a draft
    (edit,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]]
    _published(tmp_path, monkeypatch, edit["notes"])
    fake.gh["releases"]["v0.4.4"] = PUBLISHED
    asked = len([r for r in fake.requests if "/releases/tags/" in r["path"]])
    ad.command({}, nd.load_config())                      # an elrond event within the five minutes
    board, state = _board(fake)
    assert len([r for r in fake.requests if "/releases/tags/" in r["path"]]) == asked + 1
    assert state["waiting"] == [] and "en brouillon" not in board["description"]


def test_a_draft_made_again_replaces_the_stale_link_and_ping(fake, tmp_path):
    cfg = nd.load_config()
    first = ad.release_draft("v0.4.4", "https://github.com/o/r/releases/tag/untagged-old")
    second = ad.release_draft("v0.4.4", "https://github.com/o/r/releases/tag/untagged-new")
    assert first["ping"] != second["ping"] and first["ping"] not in fake.messages
    board, state = _board(fake)
    assert "untagged-new" in board["description"] and "untagged-old" not in board["description"]
    assert [w["url"] for w in state["waiting"]] == ["https://github.com/o/r/releases/tag/untagged-new"]
    assert cfg.agents


def test_the_agents_webhook_is_given_to_release_events_only():
    import yaml
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "notify.yml").read_text(encoding="utf-8"))
    (step,) = [s for s in doc["jobs"]["notify"]["steps"] if s.get("name") == "Discord"]
    assert step["env"]["EREGION_DISCORD_WEBHOOK_AGENTS"] == (
        "${{ github.event_name == 'release' && secrets.EREGION_DISCORD_WEBHOOK_AGENTS || '' }}")



# ── the fixture, the probe, a webhook that fails ────────────────────────────────────

def test_the_shell_s_discord_and_github_never_reach_a_test(monkeypatch, tmp_path, request):
    """A real #ci webhook, a bot and a GitHub token exported in the shell that runs pytest."""
    trap = FakeDiscord()
    try:
        monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_CI", f"{trap.base}/api/webhooks/1/CI-SECRET")
        monkeypatch.setenv("EREGION_DISCORD_BOT_TOKEN", "BOT-SECRET")
        monkeypatch.setenv("EREGION_DISCORD_LOTS_FORUM", "FORUM")
        monkeypatch.setenv("GITHUB_TOKEN", "GH-SECRET")
        f = request.getfixturevalue("fake")
        _published(tmp_path, monkeypatch, "notes")
        ad.release_draft("v0.4.4", "https://github.com/o/r/releases/tag/untagged-1")
        assert ad.main(["board"]) == 0
        assert trap.requests == []
        assert [r for r in f.requests if "/webhooks/1/" in r["path"] or "/channels/" in r["path"]] == []
        assert not any("SECRET" in json.dumps(r["headers"]) for r in f.requests)
    finally:
        trap.close()


def test_the_ping_is_looked_for_once_a_minute_at_most(repo, capsys, fake):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    assert ad.main(["board"]) == 0                        # GitHub asked now: the next refreshes are not due
    _, state = _board(fake)
    ping, cfg = state["waiting"][0]["ping"], nd.load_config()
    for _ in range(4):
        ad.command({}, cfg)
    assert len([r for r in fake.requests if r["method"] == "GET" and r["path"].endswith(f"/messages/{ping}")]) == 1


def test_a_webhook_that_fails_to_read_touches_nothing(repo, tmp_path, capsys, fake, monkeypatch):
    prepared(repo, capsys)
    assert rel.main(["release-draft", "0.4.4"]) == 0
    (edit,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]]
    capsys.readouterr()
    fake.fail["/api/webhooks"] = 500
    n = len(fake.requests)
    _published(tmp_path, monkeypatch, edit["notes"])
    assert [r["method"] for r in fake.requests[n:] if "/webhooks/" in r["path"]] == ["GET", "GET"]
    assert "atelier: not sent — webhook #agents: HTTP 500" in capsys.readouterr().err
