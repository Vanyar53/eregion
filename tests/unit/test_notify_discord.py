"""notify_discord (N1, #242) — the workshop's news in Discord, against a fake Discord.

The fake (tests/unit/fake_discord.py) is an HTTP server on the loopback: nothing leaves the
machine, and the requests are read back as Discord would get them.
"""
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from .fake_discord import TAG, TAG_NAMES, FakeDiscord

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("notify_discord", ROOT / "scripts" / "notify_discord.py")
nd = importlib.util.module_from_spec(_SPEC)
sys.modules["notify_discord"] = nd   # its dataclasses look their module up
_SPEC.loader.exec_module(nd)

PINNED, FALLBACK = "claude-opus-5-5", "claude-opus-4-8"
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


# ── transcripts of elrond's agents, as palantir reads them ─────────────────────────

def _turn(mid, model, ts, tool="Read"):
    return {"type": "assistant", "timestamp": ts,
            "message": {"id": mid, "model": model, "stop_reason": "tool_use",
                        "content": [{"type": "tool_use", "name": tool, "input": {"file_path": "x.py"}}]}}


def agent(tmp_path, desc, agent_type="elrond-worker", fallback=False, tool_use="toolu_1", report=""):
    """An elrond agent's transcript. Its report, as the real ones end (measured on 27/10): a call
    to the SubagentHandback tool holding it — not a text, so last_assistant_message is empty."""
    path = tmp_path / "proj" / "sess" / "subagents" / f"agent-{tool_use}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    turns = [_turn("m1", PINNED, "2026-10-27T14:00:00Z")]
    if fallback:
        turns += [_turn("m2", FALLBACK, "2026-10-27T14:02:00Z", "Write"), _turn("m3", PINNED, "2026-10-27T14:09:00Z")]
    if report:
        turns.append({"type": "assistant", "timestamp": "2026-10-27T14:10:00Z", "message": {
            "id": "m9", "model": PINNED, "stop_reason": "tool_use",
            "content": [{"type": "tool_use", "name": "SubagentHandback", "input": {"message": report}}]}})
    path.write_text("\n".join(json.dumps(t) for t in turns) + "\n", encoding="utf-8")
    path.with_name(path.stem + ".meta.json").write_text(
        json.dumps({"agentType": agent_type, "description": desc, "toolUseId": tool_use}), encoding="utf-8")
    return path


def launch(desc, agent_type="elrond-worker", tool_use="toolu_1"):
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_use_id": tool_use,
                       "tool_input": {"description": desc, "subagent_type": agent_type, "prompt": "…"}})


def stop(path, agent_type="elrond-worker", last=""):
    return json.dumps({"hook_event_name": "SubagentStop", "agent_type": agent_type,
                       "agent_transcript_path": str(path), "last_assistant_message": last})


# ── nothing configured, nothing broken ─────────────────────────────────────────────

def test_nothing_configured_sends_nothing_and_exits_zero(fake, monkeypatch, tmp_path, capsys):
    assert run_github(monkeypatch, tmp_path, "workflow_run", wr("failure")) == 0
    assert nd.hook(launch("elrond A3 · règles orphelines")) == 0
    assert nd.main(["run-end", "2 lots faits"]) == 0
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
    nd.main(["run-end", "@everyone fin"])
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
    assert nd.hook(stop(agent(tmp_path, "elrond A3 · x", fallback=True))) == 0
    assert nd.main(["lot", "A3", "blocked", "--note", "attend Jonathan"]) == 0
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
    configure(monkeypatch, fake, ci=False)
    t = fake.thread("A3 · règles orphelines", [TAG["en relecture"], TAG["v0.x"]])
    run_github(monkeypatch, tmp_path, "pull_request_target", pr_event())
    assert sorted(t["applied_tags"]) == sorted([TAG["fait"], TAG["v0.x"]])
    assert t["posts"][-1]["flags"] == nd.SILENT and len(fake.threads) == 1


def test_an_archived_thread_is_found_reopened_never_duplicated(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, ci=False)
    t = fake.thread("A3 · règles orphelines", [TAG["fait"]], archived=True)
    assert nd.hook(launch("elrond A3 · correction")) == 0
    assert len(fake.threads) == 1 and t["posts"] and not t["thread_metadata"]["archived"]
    assert TAG["en correction"] in t["applied_tags"] and TAG["fait"] not in t["applied_tags"]


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


# ── elrond's agents ────────────────────────────────────────────────────────────────

def test_only_elronds_agents_are_followed(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    for data in (launch("Find API endpoints", "Explore"), launch("elrond plan · x", "elrond-planner"),
                 stop(agent(tmp_path, "something", "general-purpose"), "general-purpose"),
                 json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}})):
        assert nd.hook(data) == 0
    assert fake.requests == []


def test_a_lot_is_followed_from_launch_to_review(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    nd.hook(launch("elrond A3 · règles orphelines"))
    (t,) = fake.threads
    assert t["name"] == "A3 · règles orphelines" and t["applied_tags"] == [TAG["en cours"]]
    nd.hook(stop(agent(tmp_path, "elrond A3 · règles orphelines")))
    nd.hook(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_2"))
    nd.hook(stop(agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", tool_use="toolu_2",
                       report="**Verdict : `ok`**\n\nAucun constat."), "elrond-reviewer"))
    titles = [p["embeds"][0]["title"].split(" · ")[0] for p in t["posts"]]
    assert titles == ["🚀 Lancé", "📦 Rendu", "🔎 Relecture lancée", "✅ Relecture ok"]
    assert all(p["flags"] == nd.SILENT for p in t["posts"]) and t["applied_tags"] == [TAG["fait"]]
    assert all(not p.get("content") for p in fake.webhook_posts(AGENTS_TOKEN))   # no alert: no ping


def test_a_fallback_is_an_alert_that_mentions_jonathan(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    nd.hook(stop(agent(tmp_path, "elrond I8F · constat", fallback=True)))
    alerts = [p for p in fake.webhook_posts(AGENTS_TOKEN) if p.get("content")]
    assert len(alerts) == 1 and alerts[0]["content"] == "<@42>" and "flags" not in alerts[0]
    assert FALLBACK in alerts[0]["embeds"][0]["description"]
    (t,) = fake.threads
    assert "Repli" in t["posts"][-1]["embeds"][0]["title"] and t["applied_tags"] == [TAG["en relecture"]]


@pytest.mark.parametrize("report, fell, title, state", [
    ("Relu.\n\n**Verdict : `changes`**\n\n1. …", False, "🛠️ Relecture : changes", "en correction"),
    ("- **Verdict :** blocking", False, "🛠️ Relecture : blocking", "en correction"),
    ("Je n'ai rien conclu.", False, "❔ Relecture sans verdict lisible", None),
    ("**Verdict :** `ok`", True, "⚠️ Relecture non obtenue", None),   # the reviewer fell back itself
])
def test_a_review_that_needs_jonathan_alerts_him(fake, monkeypatch, tmp_path, report, fell, title, state):
    configure(monkeypatch, fake)
    t = fake.thread("A3 · x", [TAG["en relecture"]])
    nd.hook(stop(agent(tmp_path, "elrond A3 · relecture 2", "elrond-reviewer", fallback=fell, report=report),
                 "elrond-reviewer"))
    alerts = [p for p in fake.webhook_posts(AGENTS_TOKEN) if p.get("content") == "<@42>"]
    assert len(alerts) == 1 and alerts[0]["embeds"][0]["title"].startswith(title)
    assert t["applied_tags"] == [TAG[state or "en relecture"]]


def test_the_running_message_is_rewritten_in_place(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    nd.hook(launch("elrond A3 · règles orphelines", tool_use="toolu_a"))
    nd.hook(launch("elrond I8F · constat", tool_use="toolu_b"))
    nd.hook(stop(agent(tmp_path, "elrond A3 · règles orphelines", tool_use="toolu_a")))
    (mid,) = fake.messages
    text = fake.messages[mid]["embeds"][0]["description"]
    assert "`I8F` worker" in text and "A3" not in text
    assert len(fake.webhook_posts(AGENTS_TOKEN)) == 1   # one POST, then PATCHes
    del fake.messages[mid]                              # deleted in Discord: a new one
    nd.hook(stop(agent(tmp_path, "elrond I8F · constat", tool_use="toolu_b")))
    (new,) = fake.messages
    assert new != mid and fake.messages[new]["embeds"][0]["description"] == "Rien ne tourne."


def test_a_blocked_lot_and_the_end_of_a_run_alert_jonathan(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    t = fake.thread("A3 · x", [TAG["en cours"]])
    nd.main(["lot", "A3", "blocked", "--note", "attend une décision"])
    nd.main(["run-end", "1 lot fait, 1 bloqué"])
    alerts = [p["embeds"][0]["title"] for p in fake.webhook_posts(AGENTS_TOKEN) if p.get("content") == "<@42>"]
    assert alerts == ["⛔ Lot bloqué · A3", "🏁 Fin du run elrond"]
    assert t["applied_tags"] == [TAG["bloqué"]]


def test_the_hook_delivers_in_the_background(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    monkeypatch.delenv("EREGION_DISCORD_SYNC")
    start = time.monotonic()
    assert nd.hook(launch("elrond A3 · x")) == 0
    assert time.monotonic() - start < 2
    for _ in range(100):
        if fake.messages:
            break
        time.sleep(0.05)
    assert fake.messages


# ── the hooks can never stop Claude Code ───────────────────────────────────────────

@pytest.mark.parametrize("stdin", ["", "not json", "[]", json.dumps({"hook_event_name": "SubagentStop",
                                                                     "agent_type": "elrond-worker"})])
def test_the_hook_exits_zero_on_anything(fake, monkeypatch, stdin):
    configure(monkeypatch, fake)
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "notify_discord.py"), "hook"],
                         input=stdin, capture_output=True, text=True, env=os.environ, timeout=30)
    assert out.returncode == 0 and out.stdout == ""


def _hooks(home, mode):
    subprocess.run(["bash", str(ROOT / "scripts" / "elrond-hooks.sh"), mode], check=True, capture_output=True,
                   env={**os.environ, "CLAUDE_HOME": str(home)}, timeout=30)
    return json.loads((home / "settings.json").read_text(encoding="utf-8")).get("hooks", {})


def test_the_user_hooks_never_block_and_leave_the_others_alone(tmp_path):
    """The hooks are the operator's (~/.claude/settings.json), never the repository's. Exit 2
    from a PreToolUse hook blocks the tool, from SubagentStop it keeps the agent going — and
    python3 exits 2 on a missing file: every command of ours ends in `|| true`."""
    home = tmp_path / "claude"
    home.mkdir()
    rtk = {"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}
    (home / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [rtk]}}), encoding="utf-8")
    _hooks(home, "install")
    hooks = _hooks(home, "install")                         # twice: still one of each
    ours = [(event, g["matcher"], h["command"]) for event, groups in hooks.items() for g in groups
            for h in g["hooks"] if "rtk" not in h["command"]]
    assert sorted((e, m, "notify" in c) for e, m, c in ours) == [
        ("PreToolUse", "Agent", True), ("Stop", "", False),
        ("SubagentStop", "", False), ("SubagentStop", "elrond-worker|elrond-reviewer", True)]
    assert all(c.endswith("|| true") for _, _, c in ours)
    assert rtk in hooks["PreToolUse"]
    assert _hooks(home, "uninstall") == {"PreToolUse": [rtk]}


@pytest.mark.parametrize("path", ["docker-compose.yml", "infra/glorfindel-host/host_env.py",
                                  "infra/glorfindel-host/host.env.example"])
def test_the_workshop_variables_never_reach_the_containers_nor_h0(path):
    """EREGION_DISCORD_* is the workshop's (the CI, elrond), not the product's: the Eregion bot's
    token never goes into a container nor onto H0 — only Glorfindel's DISCORD_* do."""
    assert "EREGION_DISCORD_" not in (ROOT / path).read_text(encoding="utf-8")


# ── after the review of 27/10 (F1, F5–F8) ──────────────────────────────────────────

def test_the_verdict_is_read_where_elrond_hands_it_back(fake, monkeypatch, tmp_path):
    """F1: the report is in the transcript's last SubagentHandback; the hook's
    last_assistant_message is only a fallback, for an agent that ends on a text."""
    configure(monkeypatch, fake)
    a = fake.thread("A3 · x", [TAG["en relecture"]])
    nd.hook(stop(agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer",
                       report="Troisième relecture.\n\n**Verdict : `changes`**\n\n1. …"), "elrond-reviewer", ""))
    b = fake.thread("B1 · y", [TAG["en relecture"]])
    nd.hook(stop(agent(tmp_path, "elrond B1 · relecture", "elrond-reviewer", tool_use="toolu_9"),
                 "elrond-reviewer", "- **Verdict :** `ok`"))
    assert a["applied_tags"] == [TAG["en correction"]] and b["applied_tags"] == [TAG["fait"]]


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


def test_a_blocked_lot_without_configuration_writes_nothing(fake, tmp_path):
    """F7: nothing configured, nothing written — not even the local state (SKILL.md)."""
    assert nd.main(["lot", "A3", "blocked", "--note", "x"]) == 0
    assert fake.requests == [] and not (tmp_path / "state").exists()


def test_archived_threads_are_paged_with_an_encoded_timestamp(fake, monkeypatch, tmp_path):
    """F8: the archive timestamp (« +00:00 ») goes into the query encoded."""
    configure(monkeypatch, fake, ci=False)
    fake.thread("B1 · autre", archived=True)
    t = fake.thread("A3 · règles orphelines", [TAG["fait"]], archived=True)
    nd.hook(launch("elrond A3 · correction"))
    assert len(fake.threads) == 2 and t["posts"]
    pages = [r["path"] for r in fake.requests if "archived/public" in r["path"] and "before=" in r["path"]]
    assert pages and "before=2026-10-01T00%3A00%3A00%2B00%3A00" in pages[0]
