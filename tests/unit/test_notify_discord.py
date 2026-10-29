"""notify_discord (N1, #242) — the workshop's news in Discord, against a fake Discord.
elrond's lots and #agents: tests/unit/test_agents_discord.py (N3, #262).

The fake (tests/unit/fake_discord.py) is an HTTP server on the loopback: nothing leaves the
machine, and the requests are read back as Discord would get them.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

from .fake_discord import TAG, TAG_NAMES, FakeDiscord

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("notify_discord", ROOT / "scripts" / "notify_discord.py")
nd = importlib.util.module_from_spec(_SPEC)
sys.modules["notify_discord"] = nd   # its dataclasses look their module up
_SPEC.loader.exec_module(nd)

CI_TOKEN, AGENTS_TOKEN, BOT_TOKEN = "CI-SECRET-abc", "AGENTS-SECRET-def", "BOT-SECRET-ghi"
RELEASES_TOKEN = "RELEASES-SECRET-jkl"
assert TAG_NAMES == nd.STATE_TAGS + nd.MILESTONE_TAGS   # the fake forum has the script's tags


@pytest.fixture
def fake(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("EREGION_DISCORD_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("EREGION_DISCORD_ENV", str(tmp_path / "absent.env"))  # never the operator's file
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("EREGION_DISCORD_SYNC", "1")
    f = FakeDiscord()
    yield f
    f.close()


def configure(monkeypatch, f, *, ci=True, agents=True, bot=True, mention="42", releases=False):
    monkeypatch.setenv("EREGION_DISCORD_API", f.base + "/api")
    if releases:
        monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_RELEASES", f"{f.base}/api/webhooks/3/{RELEASES_TOKEN}")
    if ci:
        monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_CI", f"{f.base}/api/webhooks/1/{CI_TOKEN}")
    if agents:
        monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_AGENTS", f"{f.base}/api/webhooks/2/{AGENTS_TOKEN}")
    if bot:
        monkeypatch.setenv("EREGION_DISCORD_BOT_TOKEN", BOT_TOKEN)
        monkeypatch.setenv("EREGION_DISCORD_LOTS_FORUM", "FORUM")
    if mention:
        monkeypatch.setenv("EREGION_DISCORD_MENTION", mention)


def run_github(monkeypatch, tmp_path, name, event, f=None):
    path = tmp_path / "event.json"
    path.write_text(json.dumps(event), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", name)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    if f:
        monkeypatch.setenv("GITHUB_API_URL", f.base + "/gh")
    return nd.main(["github"])


def wr(conclusion, event="pull_request", branch="lot/a3-regles-orphelines", number=7, run_number=11,
       head_repo="o/r"):
    run = {"name": "CI", "conclusion": conclusion, "event": event, "head_branch": branch,
           "display_title": "feat(isolation): règles orphelines (A3, #73)", "html_url": "https://x/run",
           "workflow_id": 9, "run_number": run_number,
           "repository": {"full_name": "o/r"}, "head_repository": {"full_name": head_repo},
           "pull_requests": [{"number": number, "head": {"ref": branch}}] if event == "pull_request" else []}
    return {"workflow_run": run, "repository": {"default_branch": "main"}}


def closed_issue(number, title, association="OWNER", **more):
    return {"action": "closed", "issue": {"number": number, "title": title,
                                          "author_association": association, **more}}


def pr_event(action="closed", merged=True, title="@everyone feat(x): y (A3, #73)", branch="lot/a3-x"):
    return {"action": action, "pull_request": {"number": 236, "title": title, "merged": merged,
                                               "head": {"ref": branch}, "body": "Closes #73",
                                               "html_url": "https://x/pr", "milestone": {"title": "v0.x"}}}


# ── nothing configured, nothing broken ─────────────────────────────────────────────

def test_nothing_configured_sends_nothing_and_exits_zero(fake, monkeypatch, tmp_path, capsys):
    assert run_github(monkeypatch, tmp_path, "workflow_run", wr("failure")) == 0
    assert fake.requests == []
    assert capsys.readouterr().err == ""


def test_the_file_fills_what_the_environment_leaves_out(fake, monkeypatch, tmp_path):
    env = tmp_path / "discord.env"
    env.write_text("export EREGION_DISCORD_WEBHOOK_AGENTS='from-file'\nEREGION_DISCORD_MENTION=7\nOTHER=x\n", encoding="utf-8")
    monkeypatch.setenv("EREGION_DISCORD_ENV", str(env))
    monkeypatch.setenv("EREGION_DISCORD_MENTION", "42")
    cfg = nd.load_config()
    assert (cfg.agents, cfg.mention, cfg.ci) == ("from-file", "42", "")
    monkeypatch.setenv("EREGION_DISCORD_MENTION", "not-an-id")
    assert nd.load_config().mention == ""


# ── never a ping from a title, never a secret in a log, never a failure ────────────

def test_no_message_mentions_anyone_but_the_configured_user(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event())
    bodies = [r["body"] for r in fake.requests if r["method"] in ("POST", "PATCH") and r["body"]]
    payloads = [b.get("message", b) for b in bodies if "embeds" in b or "message" in b]
    assert payloads and all(p["allowed_mentions"]["parse"] == [] for p in payloads)
    assert all(p["allowed_mentions"].get("users", ["42"]) == ["42"] for p in payloads)
    assert "@everyone" in json.dumps(payloads)   # the text is there, inert


def test_a_discord_failure_never_fails_the_caller_nor_prints_a_secret(fake, monkeypatch, tmp_path, capsys):
    configure(monkeypatch, fake)
    fake.fail.update({"/api/webhooks": 500, "/api/channels": 503})
    assert run_github(monkeypatch, tmp_path, "release",
                      {"action": "published", "release": {"tag_name": "v0.4.0"}}) == 0
    err = capsys.readouterr().err
    assert "HTTP 500" in err
    for secret in (CI_TOKEN, AGENTS_TOKEN, BOT_TOKEN, fake.base):
        assert secret not in err


def test_a_rate_limit_is_waited_once(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    fake.fail["/api/webhooks/1"] = 429
    fake.once.add("/api/webhooks/1")
    run_github(monkeypatch, tmp_path, "release", {"action": "published", "release": {"tag_name": "v0.4.0"}})
    assert len(fake.webhook_posts(CI_TOKEN)) == 2 and len(fake.messages) == 1


def test_the_bot_and_the_webhooks_get_their_headers(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event())
    bot = [r for r in fake.requests if r["path"].startswith("/api/channels") or r["path"].startswith("/api/guilds")]
    hooks = [r for r in fake.requests if r["path"].startswith("/api/webhooks")]
    assert bot and all(r["headers"]["Authorization"] == f"Bot {BOT_TOKEN}" for r in bot)
    assert hooks and all("Authorization" not in r["headers"] for r in hooks)
    assert all(r["headers"]["User-Agent"].startswith("DiscordBot (") for r in fake.requests)


# ── #ci: what is worth saying ──────────────────────────────────────────────────────

@pytest.mark.parametrize("conclusion, said", [("failure", True), ("timed_out", True), ("success", False),
                                              ("cancelled", False), ("skipped", False)])
def test_a_pull_request_run_is_said_only_when_red(fake, monkeypatch, tmp_path, conclusion, said):
    configure(monkeypatch, fake, bot=False)
    run_github(monkeypatch, tmp_path, "workflow_run", wr(conclusion))
    posts = fake.webhook_posts(CI_TOKEN)
    assert len(posts) == (1 if said else 0)
    if said:
        assert "flags" not in posts[0] and posts[0]["embeds"][0]["color"] == nd.RED   # red notifies


@pytest.mark.parametrize("before, said", [("failure", True), ("success", False), ("", False)])
def test_main_green_is_said_only_after_red(fake, monkeypatch, tmp_path, before, said):
    configure(monkeypatch, fake, bot=False)
    # GitHub lists the newest first: this very run (12) comes back too.
    fake.runs = [{"run_number": 12, "conclusion": "success"}, {"run_number": 11, "conclusion": "cancelled"}]
    if before:
        fake.runs.append({"run_number": 10, "conclusion": before})
    run_github(monkeypatch, tmp_path, "workflow_run", wr("success", "push", "main", run_number=12), fake)
    posts = fake.webhook_posts(CI_TOKEN)
    assert len(posts) == (1 if said else 0)
    if said:
        assert "de nouveau verte" in posts[0]["embeds"][0]["title"] and posts[0]["flags"] == nd.SILENT


def test_nightly_runs_are_said_only_when_red(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    run_github(monkeypatch, tmp_path, "workflow_run", wr("success", "schedule", "main"))
    run_github(monkeypatch, tmp_path, "workflow_run", wr("failure", "schedule", "main"))
    posts = fake.webhook_posts(CI_TOKEN)
    assert len(posts) == 1 and "de nuit" in posts[0]["embeds"][0]["title"]


def test_merged_opened_closed_issue_and_release(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event("opened", merged=False))
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event("closed", merged=False))  # not said
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event())
    run_github(monkeypatch, tmp_path, "issues", closed_issue(73, "A3 — x"))
    run_github(monkeypatch, tmp_path, "release", {"action": "published", "release": {"tag_name": "v0.4.0"}})
    titles = [p["embeds"][0]["title"] for p in fake.webhook_posts(CI_TOKEN)]
    assert [t.split(" · ")[0] for t in titles] == ["📬 PR ouverte", "🔀 PR fusionnée", "✅ #73 fermée", "🏷️ v0.4.0 publiée"]
    silent = [p.get("flags") == nd.SILENT for p in fake.webhook_posts(CI_TOKEN)]
    assert silent == [True, True, True, False]


@pytest.mark.parametrize("kw, expected", [
    ({"branch": "lot/a3-regles-orphelines"}, ("A3", "")),
    ({"branch": "lot/i1f-quarantaine-alteree"}, ("I1F", "")),
    ({"branch": "lot/ui-2-indicateurs"}, ("UI-2", "")),
    ({"branch": "lot/193-rapport-run-h0"}, ("", "193")),
    ({"branch": "lot/console-finitions", "title": "feat(console): finitions — CSP (#222)"}, ("", "222")),
    ({"title": "fix(glorfindel): un NSG modifié (I1F, #226)"}, ("I1F", "226")),
    ({"title": "AL1 — Ingestion des Activity Logs"}, ("AL1", "")),
    ({"title": "Console Eregion (UI-2) : les cinq indicateurs"}, ("UI-2", "")),
    ({"title": "chore: bump", "body": "Fixes #12"}, ("", "12")),
    ({"title": "chore: bump"}, ("", "")),
])
def test_a_lot_is_found_from_its_branch_title_or_body(kw, expected):
    assert nd.lot_of(**kw) == expected


# ── #lots: one thread per lot, its tags true ───────────────────────────────────────

def test_a_merge_moves_the_state_and_keeps_the_other_tags(fake, monkeypatch, tmp_path):
    """A pull request without a milestone: the thread keeps its own."""
    configure(monkeypatch, fake, ci=False)
    t = fake.thread("A3 · règles orphelines", [TAG["en relecture"], TAG["v0.x"]])
    event = pr_event()
    event["pull_request"]["milestone"] = None
    run_github(monkeypatch, tmp_path, "pull_request_target", event)
    assert sorted(t["applied_tags"]) == sorted([TAG["fait"], TAG["v0.x"]])
    assert t["posts"][-1]["flags"] == nd.SILENT and len(fake.threads) == 1


def test_an_archived_thread_is_found_reopened_never_duplicated(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, ci=False)
    t = fake.thread("A3 · règles orphelines", [TAG["fait"]], archived=True)
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event("opened", merged=False))
    assert len(fake.threads) == 1 and t["posts"] and not t["thread_metadata"]["archived"]


def test_a_closed_issue_tags_its_thread_done_and_archives_it(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, ci=False)
    run_github(monkeypatch, tmp_path, "issues", closed_issue(225, "AL1 — Activity Logs",
                                                             milestone={"title": "v0.x"}))
    (t,) = fake.threads
    assert t["name"].startswith("AL1 · ") and t["thread_metadata"]["archived"]
    assert sorted(t["applied_tags"]) == sorted([TAG["fait"], TAG["v0.x"]])


def test_a_red_run_never_creates_a_thread(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, ci=False)
    run_github(monkeypatch, tmp_path, "workflow_run", wr("failure"))
    assert fake.threads == []
    t = fake.thread("A3 · règles orphelines")
    run_github(monkeypatch, tmp_path, "workflow_run", wr("failure"))
    assert len(t["posts"]) == 1 and len(fake.threads) == 1


@pytest.mark.parametrize("path", ["docker-compose.yml", "infra/glorfindel-host/host_env.py",
                                  "infra/glorfindel-host/host.env.example"])
def test_the_workshop_variables_never_reach_the_containers_nor_h0(path):
    """EREGION_DISCORD_* is the workshop's (the CI, elrond), not the product's: the Eregion bot's
    token never goes into a container nor onto H0 — only Glorfindel's DISCORD_* do. #deploy's
    webhook reaches H0 only in the CD's own file (~/.eregion-cd/discord.env, H1): never through
    host.env nor a container (tests/unit/test_host_cd.py, the installation's export)."""
    assert "EREGION_DISCORD_" not in (ROOT / path).read_text(encoding="utf-8")


# ── after the review of 27/10 (F5, F6) ──────────────────────────────────────────

def test_a_forks_pull_request_is_announced_never_threaded(fake, monkeypatch, tmp_path):
    """F5: its title can name any lot; it reaches #ci, never a lot's thread."""
    configure(monkeypatch, fake)
    t = fake.thread("A3 · règles orphelines", [TAG["en relecture"]])
    event = pr_event("opened", merged=False)
    event["pull_request"]["head"]["repo"] = {"full_name": "someone/eregion"}
    event["pull_request"]["base"] = {"repo": {"full_name": "o/r"}}
    run_github(monkeypatch, tmp_path, "pull_request_target", event)
    assert len(fake.webhook_posts(CI_TOKEN)) == 1
    assert t["posts"] == [] and t["applied_tags"] == [TAG["en relecture"]] and len(fake.threads) == 1


def test_an_issue_without_a_lot_gets_no_thread_but_its_own_is_archived(fake, monkeypatch, tmp_path):
    """F5: N1 creates a thread only for a known lot; an existing « #n · … » one (N2's) is closed."""
    configure(monkeypatch, fake, ci=False)
    closed = closed_issue(248, "Console : les cartes", "MEMBER")
    run_github(monkeypatch, tmp_path, "issues", closed)
    assert fake.threads == []
    t = fake.thread("#248 · Console : les cartes", [TAG["en cours"]])
    run_github(monkeypatch, tmp_path, "issues", closed)
    assert t["thread_metadata"]["archived"] and t["applied_tags"] == [TAG["fait"]]


def test_a_forks_red_run_is_announced_never_threaded(fake, monkeypatch, tmp_path):
    """SEC6 (N-11): a fork's pull request runs CI here (workflow_run), on the fork's head — its
    branch `lot/a3-…` and its title are the fork's to choose. #ci gets the red run; the lot's
    thread gets nothing. A run that does not say where its head is from is treated alike."""
    configure(monkeypatch, fake)
    t = fake.thread("A3 · règles orphelines", [TAG["en relecture"]])
    run_github(monkeypatch, tmp_path, "workflow_run", wr("failure", head_repo="someone/eregion"))
    no_head = wr("failure")
    del no_head["workflow_run"]["head_repository"]
    run_github(monkeypatch, tmp_path, "workflow_run", no_head)
    assert len(fake.webhook_posts(CI_TOKEN)) == 2
    assert t["posts"] == [] and len(fake.threads) == 1
    run_github(monkeypatch, tmp_path, "workflow_run", wr("failure"))   # the repository's own: threaded
    assert len(t["posts"]) == 1


@pytest.mark.parametrize("association", ["NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", None])
def test_an_outsiders_closed_issue_never_moves_a_lots_thread(fake, monkeypatch, tmp_path, association):
    """SEC6 (N-11): anyone may open an issue named « A3 — … » and close it. It is said in #ci;
    the lot's thread is neither tagged « fait » nor archived, and no thread is created."""
    configure(monkeypatch, fake)
    t = fake.thread("A3 · règles orphelines", [TAG["en cours"], TAG["v0.x"]])
    own = fake.thread("#300 · A3 — x", [TAG["en cours"]])
    event = closed_issue(300, "A3 — x", association, milestone={"title": "v0.x"})
    if association is None:
        del event["issue"]["author_association"]
    run_github(monkeypatch, tmp_path, "issues", event)
    assert len(fake.webhook_posts(CI_TOKEN)) == 1
    for thread in (t, own):
        assert thread["posts"] == [] and not thread["thread_metadata"]["archived"]
    assert sorted(t["applied_tags"]) == sorted([TAG["en cours"], TAG["v0.x"]]) and len(fake.threads) == 2


@pytest.mark.parametrize("association", sorted(nd.MEMBERS))
def test_a_members_closed_issue_moves_its_lots_thread(fake, monkeypatch, tmp_path, association):
    configure(monkeypatch, fake, ci=False)
    t = fake.thread("A3 · règles orphelines", [TAG["en cours"]])
    run_github(monkeypatch, tmp_path, "issues", closed_issue(73, "A3 — x", association))
    assert t["thread_metadata"]["archived"] and t["applied_tags"] == [TAG["fait"]]


def test_a_malformed_webhook_url_is_said_without_its_token(fake, monkeypatch, tmp_path, capsys):
    """F6: http.client's InvalidURL quotes the URL; a trailing newline is stripped."""
    configure(monkeypatch, fake, bot=False)
    release = {"action": "published", "release": {"tag_name": "v0.4.0"}}
    monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_CI", f"{fake.base}/api/webhooks/1/{CI_TOKEN}\t/x")
    assert run_github(monkeypatch, tmp_path, "release", release) == 0
    err = capsys.readouterr().err
    assert "not sent" in err and CI_TOKEN not in err
    monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_CI", f"{fake.base}/api/webhooks/1/{CI_TOKEN}\n")
    run_github(monkeypatch, tmp_path, "release", release)
    assert len(fake.messages) == 1


# ── #releases (REL2): a release's story, one card per step ─────────────────────────

ZWSP = "​"
PUBLISHED = {"action": "published", "release": {
    "tag_name": "v0.4.5", "name": "v0.4.5 — @everyone [Support](https://evil.example) <@&1>",
    "prerelease": False, "body": "### Added\n- x", "html_url": "https://github.com/o/r/releases/tag/v0.4.5"}}


def version_pr(action="opened", merged=False, branch="chore/release-0.4.5", head_repo="o/r", title=None):
    return {"action": action, "pull_request": {
        "number": 310, "merged": merged, "html_url": "https://github.com/o/r/pull/310",
        "title": title or "chore(release): 0.4.5 — CHANGELOG [0.4.5] « x », version du paquet",
        "head": {"ref": branch, "repo": {"full_name": head_repo}}, "base": {"ref": "main", "repo": {"full_name": "o/r"}},
        "body": ""}}


def releases_posts(f):
    return [r for r in f.requests if r["method"] == "POST" and RELEASES_TOKEN in r["path"]]


def test_the_publication_goes_to_releases_and_leaves_ci(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, releases=True)
    assert run_github(monkeypatch, tmp_path, "release", PUBLISHED) == 0
    assert fake.webhook_posts(CI_TOKEN) == []                       # no longer in #ci
    (post,) = releases_posts(fake)
    body = post["body"]
    card = body["embeds"][0]
    assert card["title"] == "🏷️ v0.4.5 publiée" and card["url"] == "https://github.com/o/r/releases/tag/v0.4.5"
    assert card["description"].endswith("\nle CD de H0 la déploie : voir #deploy")
    (button,) = body["components"][0]["components"]
    assert button == {"type": 2, "style": 5, "label": "Voir la release",
                      "url": "https://github.com/o/r/releases/tag/v0.4.5"}
    # Silent, no mention: neither the configured user nor anything the name says.
    assert body["flags"] == nd.SILENT and "content" not in body and body["allowed_mentions"] == {"parse": []}
    assert "with_components=true" in post["path"] and "wait=true" in post["path"]
    assert fake.threads == []                                       # never a lot's thread


def test_a_release_s_name_is_inert(fake, monkeypatch, tmp_path):
    """SEC6: a member may write anything in a release's name; it shows, it never applies."""
    configure(monkeypatch, fake, releases=True)
    run_github(monkeypatch, tmp_path, "release", PUBLISHED)
    said = releases_posts(fake)[0]["body"]["embeds"][0]["description"]
    assert f"@{ZWSP}everyone" in said and "@everyone" not in said
    assert "[Support](" not in said and r"\[Support\]\(" in said and r"\<@&1\>" in said


def test_without_releases_the_publication_stays_in_ci(fake, monkeypatch, tmp_path):
    """Before #releases is set up, nothing changes: the card in #ci, notifying, as before."""
    configure(monkeypatch, fake)
    run_github(monkeypatch, tmp_path, "release", PUBLISHED)
    (post,) = fake.webhook_posts(CI_TOKEN)
    assert post["embeds"][0]["title"] == "🏷️ v0.4.5 publiée" and "flags" not in post
    assert releases_posts(fake) == []


def test_the_version_s_pull_request_goes_to_releases(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, releases=True)
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr())
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr("closed", merged=False))   # not said
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr("closed", merged=True))
    assert fake.webhook_posts(CI_TOKEN) == [] and fake.threads == []
    cards = [p["body"]["embeds"][0] for p in releases_posts(fake)]
    assert [c["title"].split(" · ")[0] for c in cards] == ["📬 PR de version ouverte", "🔀 PR de version fusionnée"]
    assert all(c["url"] == "https://github.com/o/r/pull/310" for c in cards)
    assert "make release-draft" in cards[1]["description"]
    assert all(p["body"]["components"][0]["components"][0]["url"] == "https://github.com/o/r/pull/310"
               for p in releases_posts(fake))


def test_a_fork_s_version_branch_stays_in_ci(fake, monkeypatch, tmp_path):
    """SEC6: a fork names its branch as it likes; chore/release-0.4.5 from a fork is just a PR."""
    configure(monkeypatch, fake, releases=True)
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr(head_repo="someone/eregion"))
    assert releases_posts(fake) == []
    (post,) = fake.webhook_posts(CI_TOKEN)
    assert post["embeds"][0]["title"].startswith("📬 PR ouverte · #310")


@pytest.mark.parametrize("branch", ["chore/release-notes", "chore/release-0.4", "chore/release-0.4.5-bis",
                                    "lot/chore/release-0.4.5", "chore/release-04.5.0"])
def test_only_a_version_branch_is_the_version_s_pull_request(fake, monkeypatch, tmp_path, branch):
    configure(monkeypatch, fake, releases=True)
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr(branch=branch))
    assert releases_posts(fake) == [] and len(fake.webhook_posts(CI_TOKEN)) == 1


def test_without_releases_the_version_s_pull_request_stays_in_ci(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    run_github(monkeypatch, tmp_path, "pull_request_target", version_pr())
    (post,) = fake.webhook_posts(CI_TOKEN)
    assert post["embeds"][0]["title"].startswith("📬 PR de version ouverte · #310")


def test_a_failing_releases_webhook_never_fails_the_job_nor_says_its_token(fake, monkeypatch, tmp_path, capsys):
    configure(monkeypatch, fake, releases=True)
    fake.fail["/api/webhooks/3"] = 500
    assert run_github(monkeypatch, tmp_path, "release", PUBLISHED) == 0
    err = capsys.readouterr().err
    assert "atelier: not sent — webhook #releases: HTTP 500" in err
    assert RELEASES_TOKEN not in err and fake.base not in err
    assert fake.webhook_posts(CI_TOKEN) == []           # never sent to #ci instead: #releases is its place


def test_a_button_refused_is_sent_again_without_it(fake, monkeypatch, tmp_path, capsys):
    """A webhook that would not take a component (400): the card goes, its title links."""
    configure(monkeypatch, fake, releases=True)
    prefix = f"/api/webhooks/3/{RELEASES_TOKEN}?wait=true&with_components=true"
    fake.fail[prefix] = 400
    fake.once.add(prefix)
    run_github(monkeypatch, tmp_path, "release", PUBLISHED)
    first, second = releases_posts(fake)
    assert "components" in first["body"] and "components" not in second["body"]
    assert second["path"].endswith("?wait=true")
    (msg,) = fake.messages.values()
    assert msg["embeds"][0]["url"] == "https://github.com/o/r/releases/tag/v0.4.5"
    assert "not sent" not in capsys.readouterr().err


def test_a_link_that_is_not_https_makes_no_button_nor_card_link(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, releases=True)
    event = json.loads(json.dumps(PUBLISHED))
    event["release"]["html_url"] = "javascript:alert(1)"
    run_github(monkeypatch, tmp_path, "release", event)
    (post,) = releases_posts(fake)
    assert "components" not in post["body"] and "url" not in post["body"]["embeds"][0]


def test_check_names_the_releases_webhook(fake, monkeypatch, capsys):
    configure(monkeypatch, fake, bot=False, releases=True)
    assert nd.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "✓ EREGION_DISCORD_WEBHOOK_RELEASES" in out and RELEASES_TOKEN not in out


def test_the_releases_webhook_is_given_to_a_release_s_events_only():
    """The release, and the version's pull request: pull_request_target whose head is this
    repository's chore/release-… branch — never a fork's pull request, never a run (a red run on
    chore/release-* stays in #ci, with its ping), never an issue. version_pull checks it again.
    And chat_text comes with the sparse checkout: the notes are made inert (SEC6)."""
    import yaml
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "notify.yml").read_text(encoding="utf-8"))
    steps = doc["jobs"]["notify"]["steps"]
    (step,) = [s for s in steps if s.get("name") == "Discord"]
    given = step["env"]["EREGION_DISCORD_WEBHOOK_RELEASES"]
    assert given == (
        "${{ (github.event_name == 'release' || (github.event_name == 'pull_request_target' "
        "&& github.event.pull_request.head.repo.full_name == github.repository "
        "&& startsWith(github.event.pull_request.head.ref, 'chore/release-'))) "
        "&& secrets.EREGION_DISCORD_WEBHOOK_RELEASES || '' }}")
    assert "workflow_run" not in given and "issues" not in given
    (checkout,) = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert "glorfindel/chat_text.py" in checkout["with"]["sparse-checkout"].split()


def test_the_notes_are_made_inert_by_chat_text_itself():
    """The very escaping Glorfindel's bot uses, read from its file (the sparse checkout's)."""
    spec = importlib.util.spec_from_file_location("chat_text_ref", ROOT / "glorfindel" / "chat_text.py")
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    text = "@here [a](https://b) **c** <@1> # d"
    assert nd.inert(text) == ref.discord_text(text) != text


def test_without_chat_text_the_strict_filter_keeps_nothing_that_formats(monkeypatch, tmp_path):
    """chat_text missing (a copy without glorfindel/, an unreadable file): the fallback shows
    every mark Discord reads as « · » — `_` and `*` too (__underline__ _italic_)."""
    monkeypatch.setattr(nd, "ROOT", tmp_path)        # no glorfindel/ there, none beside the script
    monkeypatch.setattr(nd, "_INERT", [])
    text = "@everyone [x](https://evil.example) <@&1> __souligné__ _it_ **gras** ~~b~~ `c` # t"
    out = nd.inert(text)
    assert nd._INERT == [nd._strict]
    for mark in ("@", "[", "]", "(", ")", "<", ">", "_", "*", "~", "`", "#"):
        assert mark not in out, mark
    assert "everyone" in out and "souligné" in out and "https:/" in out   # the words still read


def test_the_version_s_pull_request_title_is_inert(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, releases=True)
    run_github(monkeypatch, tmp_path, "pull_request_target",
               version_pr(title="chore(release): 0.4.5 @here [x](https://evil.example) <@&1>"))
    title = releases_posts(fake)[0]["body"]["embeds"][0]["title"]
    assert f"@{ZWSP}here" in title and "@here" not in title
    assert "[x](" not in title and r"\[x\]\(" in title and r"\<@&1\>" in title


def test_the_notes_in_short():
    notes = ("### Added\n- **A release in two commands** (REL1).\n  - a sub-item\n- Second.\n"
             "### Fixed\n- Third.\n- Fourth.\n\n<!-- #agents (REL1) : ping=1 board=2 -->")
    assert nd.notes_summary(notes) == ("Added · Fixed\n• A release in two commands \\(REL1\\).\n• Second.\n"
                                       "• Third.\n… et 1 de plus")
    assert nd.notes_summary("Une ligne.\nUne autre.") == "• Une ligne.\n• Une autre."
    assert len(nd.notes_summary("- " + "x" * 5000)) < 200
