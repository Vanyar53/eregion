"""REL1 (#269): a release in two commands — the version's pull request, then the draft.

On a throwaway git repository (tmp_path: a bare `origin`, a clone), with a fake `gh` first on the
PATH that records every call and answers as GitHub's CLI does, and the fake Discord
(tests/unit/fake_discord.py) for #agents. Nothing reaches GitHub nor Discord: no tag, no release,
no remote branch but the throwaway origin's.
"""
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
    assert rel.main(["draft", "0.4.4"]) == 0, capsys.readouterr().out
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
    assert rel.main(["draft", "0.4.4", "--notes", str(notes)]) == 0
    (create,) = [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "create"]]
    assert create["notes"] == "**0.4.4 — x.** The lead paragraph.\n\n### Added\n- one\n"


def test_release_draft_dry_run_creates_nothing(repo, tmp_path, capsys):
    prepared(repo, capsys)
    capsys.readouterr()
    assert rel.main(["draft", "0.4.4", "--dry-run"]) == 0
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


@pytest.mark.parametrize("setup, said", [
    (_no_release_merged, "est en 0.4.3, pas 0.4.4"),
    (_remote_tag, "le tag v0.4.4 existe déjà"),
    (_local_tag, "le tag v0.4.4 existe déjà"),
    (_draft_exists, "une release v0.4.4 existe déjà (brouillon compris)"),
    (_notes_unreadable, "NOTES illisible"),
], ids=lambda x: getattr(x, "__name__", str(x))[:40])
def test_release_draft_refuses_and_creates_nothing(repo, tmp_path, capsys, setup, said):
    assert rel.main(["prepare", "0.4.4", "--title", "x"]) == 0
    if setup is not _no_release_merged:
        merge_release(repo)
    extra = setup(repo) or []
    capsys.readouterr()
    assert rel.main(["draft", "0.4.4", *extra]) == 1
    out = capsys.readouterr().out
    assert refused(out, said) and "rien n'a été créé" in out
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] in (["release", "create"], ["release", "edit"])] == []


def test_release_draft_refuses_a_version_main_s_changelog_does_not_hold(repo, tmp_path, capsys):
    """pyproject.toml bumped by hand, the CHANGELOG not cut: no section, no draft."""
    (repo / "pyproject.toml").write_text(PYPROJECT.replace("0.4.3", "0.4.4"), encoding="utf-8")
    git(repo, "commit", "-qam", "bump by hand")
    git(repo, "push", "-q", "origin", "main")
    assert rel.main(["draft", "0.4.4"]) == 1
    assert "✗ le CHANGELOG d'origin/main n'a pas de section [0.4.4]" in capsys.readouterr().out
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "create"]] == []


# ── no path publishes ───────────────────────────────────────────────────────────────

PUBLISHES = re.compile(r"""--draft[= ]+(?:false|0)|draft["']?\s*[:=]\s*(?:false|False|0)\b|--publish|"publish"|"""
                       r"""["']--draft["'],\s*["'](?:false|0)["']|releases/\{?[\w}]*\}?["']?,?\s*["']PATCH""")


def _recipes(text: str, *targets: str) -> str:
    out = []
    for t in targets:
        m = re.search(rf"(?m)^{re.escape(t)}:\n((?:\t.*\n)+)", text)
        assert m, t
        out.append(m.group(1))
    return "".join(out)


def test_no_path_publishes_in_the_code():
    """Publishing deploys H0: nothing in the release's code turns a draft into a release."""
    code = (ROOT / "scripts" / "release.py").read_text(encoding="utf-8")
    make = _recipes((ROOT / "Makefile").read_text(encoding="utf-8"), "release", "release-draft")
    for name, text in (("release.py", code), ("Makefile", make),
                       ("agents_discord.py", (ROOT / "scripts" / "agents_discord.py").read_text(encoding="utf-8")),
                       ("notify_discord.py", (ROOT / "scripts" / "notify_discord.py").read_text(encoding="utf-8"))):
        assert PUBLISHES.findall(text) == [], name
    creates = re.findall(r"\[[^\]]*\"release\",\s*\"create\"[^\]]*\]", code)
    assert creates and all('"--draft"' in c for c in creates)
    edits = re.findall(r"\[[^\]]*\"release\",\s*\"edit\"[^\]]*\]", code)
    assert edits and all("--draft" not in e for e in edits)
    assert "gh release" not in make and "api.github.com" not in code


def test_the_pattern_sees_a_path_that_would_publish():
    for bad in ('"gh", "release", "edit", tag, "--draft=false"', "gh release edit v1 --draft false",
                '{"draft": False}', '"--draft", "false"'):
        assert PUBLISHES.search(bad), bad


def test_no_call_publishes(repo, tmp_path, capsys, monkeypatch):
    """Every gh call of both commands, Discord configured: a draft, never published."""
    f = FakeDiscord()
    try:
        _discord(monkeypatch, f)
        prepared(repo, capsys)
        assert rel.main(["draft", "0.4.4"]) == 0
    finally:
        f.close()
    calls = [c["args"] for c in gh_calls(tmp_path)]
    assert [c[:2] for c in calls] == [["pr", "create"], ["release", "list"], ["release", "create"],
                                      ["release", "edit"]]
    for c in calls:
        assert not any(re.fullmatch(r"--draft=?(false|0)?|--publish|false", a) for a in c if a != "--draft"), c
    assert "--draft" in calls[2] and "--draft" not in " ".join(calls[3])
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
def fake(monkeypatch):
    f = FakeDiscord()
    _discord(monkeypatch, f)
    yield f
    f.close()


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
    assert rel.main(["draft", "0.4.4"]) == 0
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
    fake.gh["releases"]["v0.4.4"] = {"tag_name": "v0.4.4", "draft": False,
                                     "html_url": "https://github.com/o/r/releases/tag/v0.4.4"}
    assert ad.main(["board"]) == 0
    board, state = _board(fake)
    assert state["waiting"] == [] and line not in board["description"]
    assert "release v0.4.4 publiée" in board["description"]


def gh_gh_release_notes(tmp_path):
    (r,) = gh_releases(tmp_path)
    return r["notes"]


def test_published_without_the_ci_the_local_board_settles_it(repo, tmp_path, capsys, fake):
    """notify.yml without #agents' webhook (the secret not set): the board's next refresh does it."""
    prepared(repo, capsys)
    assert rel.main(["draft", "0.4.4"]) == 0
    board, state = _board(fake)
    ping_id = state["waiting"][0]["ping"]
    fake.gh["releases"]["v0.4.4"] = {"tag_name": "v0.4.4", "draft": False, "html_url": ""}
    assert ad.main(["board"]) == 0
    board, state = _board(fake)
    assert state["waiting"] == [] and ping_id not in fake.messages
    assert "en brouillon" not in board["description"]


def test_a_draft_can_be_cleared_by_hand(repo, capsys, fake):
    prepared(repo, capsys)
    assert rel.main(["draft", "0.4.4"]) == 0
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
    assert rel.main(["draft", "0.4.4"]) == 0
    assert gh_releases(tmp_path)[0]["draft"] is True
    assert [c for c in gh_calls(tmp_path) if c["args"][:2] == ["release", "edit"]] == []
    assert not (tmp_path / "state").exists()                     # not even the local state


def test_a_discord_that_fails_never_fails_the_draft(repo, tmp_path, capsys, fake):
    fake.fail["/api/webhooks"] = 500
    prepared(repo, capsys)
    assert rel.main(["draft", "0.4.4"]) == 0
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
    assert "python3 scripts/release.py draft\n" in draft.stdout and "notes.md" not in draft.stdout


@pytest.mark.parametrize("target", ["release", "release-draft"])
def test_make_refuses_a_version_from_the_environment(make_env, tmp_path, target):
    """A VERSION exported for something else is never released in silence."""
    out = _make({**make_env, "VERSION": "1.0.0", "TITLE": "x"}, tmp_path, target)
    assert out.returncode != 0 and "vient de l'environnement" in out.stderr
    given = _make(make_env, tmp_path, target, "VERSION=1.0.0", "TITLE=x")
    assert "vient de l'environnement" not in given.stderr and "scripts/release.py" in given.stderr   # past the guard
