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


def configure(monkeypatch, f, *, ci=True, agents=True, bot=True, mention="42"):
    monkeypatch.setenv("EREGION_DISCORD_API", f.base + "/api")
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


def wr(conclusion, event="pull_request", branch="lot/a3-regles-orphelines", number=7, run_number=11):
    run = {"name": "CI", "conclusion": conclusion, "event": event, "head_branch": branch,
           "display_title": "feat(isolation): règles orphelines (A3, #73)", "html_url": "https://x/run",
           "workflow_id": 9, "run_number": run_number,
           "pull_requests": [{"number": number, "head": {"ref": branch}}] if event == "pull_request" else []}
    return {"workflow_run": run, "repository": {"default_branch": "main"}}


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
    run_github(monkeypatch, tmp_path, "issues", {"action": "closed", "issue": {"number": 73, "title": "A3 — x"}})
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
    run_github(monkeypatch, tmp_path, "issues", {"action": "closed", "issue": {
        "number": 225, "title": "AL1 — Activity Logs", "milestone": {"title": "v0.x"}}})
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
    token never goes into a container nor onto H0 — only Glorfindel's DISCORD_* do."""
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
    closed = {"action": "closed", "issue": {"number": 248, "title": "Console : les cartes"}}
    run_github(monkeypatch, tmp_path, "issues", closed)
    assert fake.threads == []
    t = fake.thread("#248 · Console : les cartes", [TAG["en cours"]])
    run_github(monkeypatch, tmp_path, "issues", closed)
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
