"""agents_discord (N3, #262) — elrond's lots in Discord: #agents is what waits for Jonathan.

Against the fake Discord (tests/unit/fake_discord.py), on the loopback. The hook payloads are
those Claude Code documents (PreToolUse on SubagentHandback holds the report in
tool_input.message; SubagentStop's background_tasks), and those measured in the transcripts of
28/10 (SendMessage's `to`, an agent's id; AskUserQuestion's questions).
"""
import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

from .fake_discord import TAG, FakeDiscord

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # agents_discord imports notify_discord; dataclasses look up their module
    spec.loader.exec_module(mod)
    return mod


nd = _load("notify_discord")
ad = _load("agents_discord")

PINNED, FALLBACK = "claude-opus-5-5", "claude-opus-4-8"
AGENTS_TOKEN, BOT_TOKEN = "AGENTS-SECRET-def", "BOT-SECRET-ghi"


@pytest.fixture
def fake(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("EREGION_DISCORD_") or k.startswith("GITHUB_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("EREGION_DISCORD_ENV", str(tmp_path / "absent.env"))  # never the operator's file
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("EREGION_DISCORD_SYNC", "1")
    f = FakeDiscord()
    monkeypatch.setenv("GITHUB_API_URL", f.base + "/gh")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    yield f
    f.close()


def configure(monkeypatch, f, *, agents=True, bot=True, mention="42"):
    monkeypatch.setenv("EREGION_DISCORD_API", f.base + "/api")
    if agents:
        monkeypatch.setenv("EREGION_DISCORD_WEBHOOK_AGENTS", f"{f.base}/api/webhooks/2/{AGENTS_TOKEN}")
    if bot:
        monkeypatch.setenv("EREGION_DISCORD_BOT_TOKEN", BOT_TOKEN)
        monkeypatch.setenv("EREGION_DISCORD_LOTS_FORUM", "FORUM")
    if mention:
        monkeypatch.setenv("EREGION_DISCORD_MENTION", mention)


# ── the session, its agents, the hooks' payloads ───────────────────────────────────

def ts(iso):
    return int(datetime.fromisoformat(iso + "+00:00").timestamp())


def _turn(mid, model, at, tool="Read"):
    return {"type": "assistant", "timestamp": at,
            "message": {"id": mid, "model": model, "stop_reason": "tool_use",
                        "content": [{"type": "tool_use", "name": tool, "input": {"file_path": "x.py"}}]}}


def agent(tmp_path, desc, agent_type="elrond-worker", aid="w1", tool_use="toolu_1", fallback=False):
    """An elrond agent's transcript and meta, under the session's folder. Without its hand-back:
    when the hooks run, the transcript does not hold it yet (measured on 28/10)."""
    path = tmp_path / "proj" / "sess" / "subagents" / f"agent-{aid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    turns = [_turn("m1", PINNED, "2026-10-27T14:00:00Z")]
    if fallback:
        turns += [_turn("m2", FALLBACK, "2026-10-27T14:02:00Z", "Write"), _turn("m3", PINNED, "2026-10-27T14:09:00Z")]
    path.write_text("\n".join(json.dumps(t) for t in turns) + "\n", encoding="utf-8")
    path.with_name(path.stem + ".meta.json").write_text(
        json.dumps({"agentType": agent_type, "description": desc, "toolUseId": tool_use}), encoding="utf-8")
    return path


def main_transcript(tmp_path):
    return tmp_path / "proj" / "sess.jsonl"


def launch(desc, agent_type="elrond-worker", tool_use="toolu_1", session="S1", at=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_use_id": tool_use, "session_id": session,
            "tool_input": {"description": desc, "subagent_type": agent_type, "prompt": "…"}, "at": at}


def handback(path, report, agent_type="elrond-worker", session="S1"):
    """SubagentHandback's PreToolUse, inside the agent: its id and type, the main transcript."""
    return {"hook_event_name": "PreToolUse", "tool_name": "SubagentHandback", "session_id": session,
            "agent_id": path.stem.removeprefix("agent-"), "agent_type": agent_type,
            "transcript_path": str(path.parents[1].with_suffix(".jsonl")), "tool_input": {"message": report}}


def stop(path, agent_type="elrond-worker", last="", bg=()):
    return {"hook_event_name": "SubagentStop", "agent_type": agent_type, "session_id": "S1",
            "agent_id": path.stem.removeprefix("agent-"), "agent_transcript_path": str(path),
            "last_assistant_message": last, "background_tasks": list(bg)}


def resume(aid, session="S1", at=None, transcript=None):
    return {"hook_event_name": "PreToolUse", "tool_name": "SendMessage", "session_id": session,
            "transcript_path": str(transcript) if transcript else None,
            "tool_input": {"to": aid, "summary": "…", "message": "…"}, "at": at}


def ask(session, transcript, question="Je fusionne H1 ?", event="PreToolUse"):
    return {"hook_event_name": event, "tool_name": "AskUserQuestion", "session_id": session,
            "transcript_path": str(transcript), "tool_input": {"questions": [{"question": question}]}}


def notification(session, transcript, text="Claude needs your permission to use Bash"):
    return {"hook_event_name": "Notification", "notification_type": "permission_prompt", "session_id": session,
            "transcript_path": str(transcript), "message": text, "title": "Permission needed"}


def session_stop(session):
    return {"hook_event_name": "Stop", "session_id": session, "transcript_path": "/nowhere.jsonl"}


def send(data):
    return ad.hook(json.dumps({k: v for k, v in data.items() if v is not None}))


# ── what Discord holds ─────────────────────────────────────────────────────────────

def pings(fake):
    """The messages of #agents that mention Jonathan, still there (a settled one is deleted)."""
    return [m for m in fake.messages.values() if m.get("content")]


def board_text(fake):
    (b,) = [m for m in fake.messages.values() if m["embeds"][0]["title"] == "📋 elrond"]
    return b["embeds"][0]["description"]


def titles(thread):
    return [p["embeds"][0]["title"].split(" · ")[0] for p in thread["posts"] if "embeds" in p]


# ── nothing configured, nothing broken, nothing else followed ──────────────────────

def test_nothing_configured_sends_nothing_writes_nothing(fake, tmp_path, capsys):
    assert send(launch("elrond A3 · règles orphelines")) == 0
    assert ad.main(["lot", "A3", "blocked", "--note", "x"]) == 0
    assert ad.main(["run-end", "2 lots faits"]) == 0
    assert fake.requests == [] and not (tmp_path / "state").exists()
    assert capsys.readouterr().err == ""


def test_only_elronds_agents_and_session_are_followed(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    other = agent(tmp_path / "other", "something", "general-purpose", aid="g1")
    elsewhere = tmp_path / "other" / "proj" / "sess.jsonl"
    for data in (launch("Find API endpoints", "Explore"), launch("elrond plan · x", "elrond-planner"),
                 stop(other, "general-purpose"), handback(other, "**Verdict : ok**", "general-purpose"),
                 {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}}, resume("a-stranger"),
                 ask("S9", elsewhere), notification("S9", elsewhere), session_stop("S9")):
        assert send(data) == 0
    assert fake.requests == []


def test_a_discord_failure_never_fails_the_caller_nor_prints_a_secret(fake, monkeypatch, tmp_path, capsys):
    configure(monkeypatch, fake)
    fake.fail.update({"/api/webhooks": 500, "/api/channels": 503})
    w = agent(tmp_path, "elrond A3 · x", tool_use="toolu_w")
    assert send(launch("elrond A3 · x", tool_use="toolu_w")) == 0
    assert send(handback(w, "Fait.")) == 0
    assert ad.main(["lot", "A3", "blocked", "--note", "attend Jonathan"]) == 0
    assert ad.main(["run-end", "fin"]) == 0
    err = capsys.readouterr().err
    assert "HTTP 500" in err and "HTTP 503" in err
    for secret in (AGENTS_TOKEN, BOT_TOKEN, fake.base):
        assert secret not in err


def test_a_forum_that_fails_never_keeps_what_waits_off_the_board(fake, monkeypatch, tmp_path, capsys):
    """#lots down: the lot's thread is lost for this event, the ping to Jonathan is not."""
    configure(monkeypatch, fake)
    fake.fail.update({"/api/channels": 503, "/api/guilds": 503})
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    ad.main(["lot", "B1", "blocked", "--note", "attend une décision"])
    assert sorted(p["embeds"][0]["title"] for p in pings(fake)) == ["⚠️ A3 : relecture non obtenue", "⛔ B1 bloqué"]
    assert "HTTP 503" in capsys.readouterr().err


def test_no_message_mentions_anyone_but_the_configured_user(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "@everyone " + "x" * 2000, "elrond-reviewer"))
    ad.main(["lot", "A3", "blocked", "--note", "@everyone"])
    ad.main(["run-end", "@everyone fin"])
    bodies = [r["body"] for r in fake.requests if r["method"] in ("POST", "PATCH") and r["body"]]
    payloads = [b.get("message") or b.get("payload_json") or b for b in bodies
                if {"embeds", "message", "payload_json"} & set(b)]
    assert len(payloads) > 8 and all(p["allowed_mentions"]["parse"] == [] for p in payloads)
    assert all(p["allowed_mentions"].get("users", ["42"]) == ["42"] for p in payloads)
    assert "@everyone" in json.dumps(payloads)   # the text is there, inert


# ── the bugs of 28/10: a pause, a report read too early, resumes unseen ────────────

def test_a_review_resumed_by_elrond_is_followed_to_the_end(fake, monkeypatch, tmp_path):
    """28/10, I8S: the reviewer paused for its mutants, handed back « blocking »; elrond sent the
    findings to the worker (SendMessage), then asked the reviewer again: « ok ». Each step said
    once and rightly — no « sans verdict », no stale verdict — and no ping: elrond goes on alone."""
    configure(monkeypatch, fake)
    w = agent(tmp_path, "elrond I8S · deux hôtes", aid="w1", tool_use="toolu_w")
    r = agent(tmp_path, "elrond I8S · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    send(launch("elrond I8S · deux hôtes", tool_use="toolu_w"))
    send(handback(w, "Fait : deux hôtes."))
    send(stop(w))
    send(launch("elrond I8S · relecture", "elrond-reviewer", "toolu_r"))
    send(stop(r, "elrond-reviewer", last="J'attends les mutants.", bg=["mutants"]))   # a pause
    assert "`I8S` relecture" in board_text(fake)
    send(handback(r, "**Verdict : blocking**\n\nUn bug.", "elrond-reviewer"))
    send(stop(r, "elrond-reviewer"))
    send(resume("w1"))
    assert "`I8S` correction" in board_text(fake)
    send(handback(w, "Corrigé."))
    send(stop(w))
    send(resume("r1"))
    send(handback(r, "Seconde relecture.\n\n**Verdict : ok**", "elrond-reviewer"))
    send(stop(r, "elrond-reviewer"))
    (t,) = fake.threads
    assert titles(t) == ["🚀 Lancé", "📦 Rendu", "🔎 Relecture lancée", "🛠️ Relecture : blocking",
                         "🔧 Correction lancée", "📦 Rendu", "🔎 Relecture lancée", "✅ Relecture ok"]
    assert t["applied_tags"] == [TAG["fait"]] and all(p["flags"] == nd.SILENT for p in t["posts"])
    assert pings(fake) == [] and not any(p.get("content") for p in fake.webhook_posts(AGENTS_TOKEN))
    text = board_text(fake)
    assert "Rien ne tourne." in text and "Rien ne t'attend." in text
    assert "`I8S` relecture ok" in text and "`I8S` correction rendue" in text and "`I8S` relecture blocking" in text


def test_the_verdict_is_read_from_the_hand_back_not_the_transcript(fake, monkeypatch, tmp_path):
    """28/10: when SubagentStop runs, the transcript does not hold the hand-back yet. The report
    comes with SubagentHandback's PreToolUse (tool_input.message), as Claude Code documents it."""
    configure(monkeypatch, fake)
    t = fake.thread("H1 · le CD de H0", [TAG["en relecture"]])
    r = agent(tmp_path, "elrond H1 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    send(launch("elrond H1 · relecture", "elrond-reviewer", "toolu_r"))
    send(handback(r, "**Verdict : blocking**\n\nUn bug.", "elrond-reviewer"))
    send(stop(r, "elrond-reviewer", last="Rapport envoyé."))
    assert titles(t)[-2:] == ["🔎 Relecture lancée", "🛠️ Relecture : blocking"]
    assert t["applied_tags"] == [TAG["en correction"]]


def test_an_agent_without_hand_back_is_read_from_its_last_message(fake, monkeypatch, tmp_path):
    """Outside auto mode there is no SubagentHandback: the agent's last text is its report."""
    configure(monkeypatch, fake)
    t = fake.thread("B1 · y", [TAG["en relecture"]])
    r = agent(tmp_path, "elrond B1 · relecture", "elrond-reviewer", aid="r9", tool_use="toolu_9")
    send(launch("elrond B1 · relecture", "elrond-reviewer", "toolu_9"))
    send(stop(r, "elrond-reviewer", last="- **Verdict :** `ok`"))
    assert t["applied_tags"] == [TAG["fait"]] and titles(t)[-1] == "✅ Relecture ok"


def test_a_fallback_counts_only_in_the_stretch_it_happened(fake, monkeypatch, tmp_path):
    """A worker that fell back, resumed for a correction later, comes back clean: « Rendu », not
    a second fallback. A worker's fallback never pings: elrond has the work reviewed."""
    configure(monkeypatch, fake)
    w = agent(tmp_path, "elrond A3 · règles", aid="w1", tool_use="toolu_w", fallback=True)   # 14:02–14:09
    send(launch("elrond A3 · règles", tool_use="toolu_w", at=ts("2026-10-27T14:00:00")))
    send(handback(w, "Fait."))
    send(resume("w1", at=ts("2026-10-27T15:00:00")))
    send(handback(w, "Corrigé."))
    (t,) = fake.threads
    assert titles(t) == ["🚀 Lancé", "⚠️ Repli de modèle", "🔧 Correction lancée", "📦 Rendu"]
    assert FALLBACK in t["posts"][1]["embeds"][0]["description"] and pings(fake) == []
    assert "Fait." in t["posts"][1]["embeds"][0]["description"]   # a short report, in the card


# ── what waits for Jonathan: on the board, pinged, the ping deleted once settled ───

def test_a_review_not_obtained_pings_jonathan_until_the_lot_moves(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    t = fake.thread("A3 · règles orphelines · #73", [TAG["en relecture"]])
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    (p,) = pings(fake)
    card, url = p["embeds"][0], f"https://discord.com/channels/GUILD/{t['id']}"
    assert card["title"] == "⚠️ A3 : relecture non obtenue" and FALLBACK in card["description"]
    assert card["url"] == url and f"[fil du lot]({url})" in card["description"]
    assert "[#73](https://github.com/o/r/issues/73)" in card["description"]
    assert p["content"] == "<@42>" and "flags" not in p and p["allowed_mentions"]["users"] == ["42"]
    assert "⚠️ A3 : relecture non obtenue" in board_text(fake)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r2"))
    assert pings(fake) == [] and "Rien ne t'attend." in board_text(fake)


def test_a_blocked_lot_pings_once_until_settled(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    t = fake.thread("A3 · x", [TAG["en cours"]])
    send(launch("elrond A3 · x", tool_use="toolu_a"))
    ad.main(["lot", "A3", "blocked", "--note", "attend une décision"])
    ad.main(["lot", "A3", "blocked", "--note", "attend toujours"])   # said again: still one ping
    (p,) = pings(fake)
    assert p["embeds"][0]["title"] == "⛔ A3 bloqué" and "attend une décision" in p["embeds"][0]["description"]
    text = board_text(fake)
    assert "⛔ A3 bloqué — attend toujours" in text and "Rien ne tourne." in text
    assert t["applied_tags"] == [TAG["bloqué"]] and titles(t)[-1] == "⛔ Lot bloqué"
    ad.main(["clear", "A3"])
    assert pings(fake) == [] and "Rien ne t'attend." in board_text(fake)


def test_a_pull_request_to_merge_pings_until_it_is_merged(fake, monkeypatch, tmp_path):
    """GitHub is asked whether it was merged at most every five minutes, or on `board`."""
    configure(monkeypatch, fake)
    fake.gh["pulls"] = [{"number": 255, "state": "open", "merged_at": None}]
    ad.main(["lot", "H1", "merge", "--pr", "255", "--note", "CI verte, relecture ok"])
    (p,) = pings(fake)
    assert p["embeds"][0]["title"] == "🔀 H1 : PR #255 à fusionner"
    assert "[PR #255](https://github.com/o/r/pull/255)" in p["embeds"][0]["description"]
    ad.main(["board"])
    fake.gh["pulls"][0].update(state="closed", merged_at="2026-10-28T12:00:00Z")
    send(launch("elrond A3 · x"))   # within five minutes: GitHub not asked again
    assert len(pings(fake)) == 1
    assert len([r for r in fake.requests if r["path"].startswith("/gh/")]) == 2
    ad.main(["board"])
    assert pings(fake) == [] and "PR #255 fusionnée" in board_text(fake)


def test_a_question_pings_only_when_left_unanswered(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    agent(tmp_path, "elrond A3 · x")   # the session has elrond's agents: it is elrond's
    session = main_transcript(tmp_path)
    clock = [1_800_000_000]
    monkeypatch.setattr(ad.time, "time", lambda: clock[0])
    send(ask("S1", session, "Je fusionne H1 ?"))
    assert pings(fake) == [] and "❓ elrond te pose une question — Je fusionne H1 ?" in board_text(fake)
    send(ask("S1", session, event="PostToolUse"))   # answered at once: never pinged
    clock[0] += ad.ASK_DELAY_S + 1
    ad.main(["board"])
    assert pings(fake) == [] and "Rien ne t'attend." in board_text(fake)
    send(ask("S1", session, "Et I8S ?"))
    clock[0] += ad.ASK_DELAY_S + 1
    ad.main(["board"])
    (p,) = pings(fake)
    assert p["embeds"][0]["title"] == "❓ elrond te pose une question" and "Et I8S ?" in p["embeds"][0]["description"]
    send(ask("S1", session, event="PostToolUse"))
    assert pings(fake) == []


def test_a_permission_prompt_pings_until_the_session_goes_on(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    w = agent(tmp_path, "elrond A3 · x", tool_use="toolu_w")
    send(launch("elrond A3 · x", tool_use="toolu_w"))
    send(notification("S1", main_transcript(tmp_path)))
    (p,) = pings(fake)
    assert p["embeds"][0]["title"] == "🔐 elrond attend ta permission"
    send(handback(w, "Fait."))   # a subagent's event: the main session still waits
    assert len(pings(fake)) == 1
    send(session_stop("S1"))
    assert pings(fake) == [] and "Rien ne t'attend." in board_text(fake)


def test_the_end_of_a_run_pings_and_the_next_run_clears_it(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    ad.main(["run-end", "2 lots faits"])
    ad.main(["run-end", "3 lots faits\nH1 à fusionner"])
    (p,) = pings(fake)
    assert p["embeds"][0]["title"] == "🏁 Fin du run elrond" and "3 lots" in p["embeds"][0]["description"]
    assert "**🏁 Dernier run**" in board_text(fake) and "3 lots faits\nH1 à fusionner" in board_text(fake)
    send(launch("elrond A3 · x"))
    assert pings(fake) == [] and "3 lots faits" in board_text(fake)


# ── the board and the threads ──────────────────────────────────────────────────────

def test_the_board_is_one_message_rewritten_in_place(fake, monkeypatch, tmp_path):
    """N1's « En cours » message, pinned in #agents, becomes the board; deleted, a new one."""
    configure(monkeypatch, fake, bot=False)
    old = fake._id()
    fake.messages[old] = {"embeds": [{"title": "🔄 En cours"}]}
    state = tmp_path / "state" / "eregion"
    state.mkdir(parents=True)
    (state / "discord.json").write_text(json.dumps({"running": {}, "status_message": old}), encoding="utf-8")
    send(launch("elrond A3 · règles orphelines", tool_use="toolu_a"))
    send(launch("elrond I8F · constat", tool_use="toolu_b"))
    assert list(fake.messages) == [old] and fake.webhook_posts(AGENTS_TOKEN) == []   # PATCHes only
    text = board_text(fake)
    assert "`A3` worker" in text and "`I8F` worker" in text and "Rien ne t'attend." in text
    del fake.messages[old]
    send(launch("elrond B1 · x", tool_use="toolu_c"))
    (new,) = fake.messages
    assert new != old and fake.messages[new]["flags"] == nd.SILENT


def test_the_report_lands_whole_in_the_thread_and_is_linked_from_the_board(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    t = fake.thread("I8S · deux hôtes · #245", [TAG["en relecture"]])
    r = agent(tmp_path, "elrond I8S · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    report = "## Relecture I8S\n\n**Verdict : changes**\n\n" + "\n\n".join(f"{i}. constat " + "x" * 200 for i in range(30))
    send(launch("elrond I8S · relecture", "elrond-reviewer", "toolu_r"))
    send(handback(r, report, "elrond-reviewer"))
    card, attached = t["posts"][-2], t["posts"][-1]
    assert card["embeds"][0]["title"] == "🛠️ Relecture : changes · I8S"
    assert "**Verdict : changes**" in card["embeds"][0]["description"]
    assert "le rapport complet est joint" in card["embeds"][0]["description"]
    assert attached["files"] == {"relecture-I8S.md": report}
    assert attached["payload_json"]["flags"] == nd.SILENT and attached["payload_json"]["allowed_mentions"] == {"parse": []}
    assert f"[rapport](https://discord.com/channels/GUILD/{t['id']}/" in board_text(fake)


def test_an_archived_thread_is_found_reopened_never_duplicated(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, agents=False)
    t = fake.thread("A3 · règles orphelines", [TAG["fait"]], archived=True)
    assert send(launch("elrond A3 · correction")) == 0
    assert len(fake.threads) == 1 and t["posts"] and not t["thread_metadata"]["archived"]
    assert TAG["en correction"] in t["applied_tags"] and TAG["fait"] not in t["applied_tags"]


def test_archived_threads_are_paged_with_an_encoded_timestamp(fake, monkeypatch, tmp_path):
    """N1, F8: the archive timestamp (« +00:00 ») goes into the query encoded."""
    configure(monkeypatch, fake, agents=False)
    fake.thread("B1 · autre", archived=True)
    t = fake.thread("A3 · règles orphelines", [TAG["fait"]], archived=True)
    send(launch("elrond A3 · correction"))
    assert len(fake.threads) == 2 and t["posts"]
    pages = [r["path"] for r in fake.requests if "archived/public" in r["path"] and "before=" in r["path"]]
    assert pages and "before=2026-10-01T00%3A00%3A00%2B00%3A00" in pages[0]


def test_the_trace_keeps_the_fields_names_never_their_values(fake, monkeypatch, tmp_path):
    """What Claude Code really sends, to read after a real run — never a report."""
    configure(monkeypatch, fake)
    w = agent(tmp_path, "elrond A3 · x", tool_use="toolu_w")
    send(launch("elrond A3 · x", tool_use="toolu_w"))
    send(handback(w, "REPORT-TEXT"))
    trace = (tmp_path / "state" / "eregion" / "discord.trace").read_text(encoding="utf-8")
    assert "PreToolUse SubagentHandback agent=elrond-worker bg=0 meta=1 keys=" in trace and "tool_input" in trace
    assert "REPORT-TEXT" not in trace


# ── the hooks can never stop Claude Code ───────────────────────────────────────────

def test_the_hook_queues_and_delivers_in_the_background(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake, bot=False)
    monkeypatch.delenv("EREGION_DISCORD_SYNC")
    start = time.monotonic()
    assert send(launch("elrond A3 · x")) == 0
    assert time.monotonic() - start < 2
    for _ in range(100):
        if fake.messages:
            break
        time.sleep(0.05)
    assert fake.messages


@pytest.mark.parametrize("stdin", ["", "not json", "[]", json.dumps({"hook_event_name": "SubagentStop",
                                                                     "agent_type": "elrond-worker"})])
def test_the_hook_exits_zero_on_anything(fake, monkeypatch, stdin):
    configure(monkeypatch, fake)
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "agents_discord.py"), "hook"],
                         input=stdin, capture_output=True, text=True, env=os.environ, timeout=30)
    assert out.returncode == 0 and out.stdout == ""


def _hooks(home, mode):
    subprocess.run(["bash", str(ROOT / "scripts" / "elrond-hooks.sh"), mode], check=True, capture_output=True,
                   env={**os.environ, "CLAUDE_HOME": str(home)}, timeout=30)
    return json.loads((home / "settings.json").read_text(encoding="utf-8")).get("hooks", {})


def test_the_user_hooks_never_block_and_leave_the_others_alone(tmp_path):
    """The hooks are the operator's (~/.claude/settings.json), never the repository's. Exit 2
    from a PreToolUse hook blocks the tool, from SubagentStop it keeps the agent going — and
    python3 exits 2 on a missing file: every command of ours ends in `|| true`. PreToolUse and
    SubagentStop wait for their hook (it only queues): a hand-back is queued before its
    SubagentStop, and that one before elrond can resume the agent."""
    home = tmp_path / "claude"
    home.mkdir()
    rtk = {"matcher": "Bash", "hooks": [{"type": "command", "command": "rtk hook claude"}]}
    n1 = {"matcher": "Agent", "hooks": [{"type": "command", "async": True,
                                         "command": 'python3 "/x/scripts/notify_discord.py" hook || true'}]}
    (home / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [rtk, n1]}}), encoding="utf-8")
    _hooks(home, "install")
    hooks = _hooks(home, "install")                         # twice: still one of each
    ours = [(event, g["matcher"], h) for event, groups in hooks.items() for g in groups
            for h in g["hooks"] if "rtk" not in h["command"]]
    assert sorted((e, m, "agents_discord" in h["command"]) for e, m, h in ours) == [
        ("Notification", "permission_prompt", True), ("PostToolUse", "AskUserQuestion", True),
        ("PreToolUse", "Agent|SendMessage|SubagentHandback|AskUserQuestion", True),
        ("Stop", "", False), ("Stop", "", True),
        ("SubagentStop", "", False), ("SubagentStop", "elrond-worker|elrond-reviewer", True)]
    assert all(h["command"].endswith("|| true") for _, _, h in ours)
    waits = {("PreToolUse", True), ("SubagentStop", True)}
    assert all(h.get("async") is (None if (e, "agents_discord" in h["command"]) in waits else True) for e, _, h in ours)
    assert rtk in hooks["PreToolUse"] and "notify_discord" not in json.dumps(hooks)
    assert _hooks(home, "uninstall") == {"PreToolUse": [rtk]}


# ── after the review of 28/10 ──────────────────────────────────────────────────────

def test_a_late_stop_of_a_past_stretch_never_ends_a_resumed_agent(fake, monkeypatch, tmp_path):
    """Review, 3: a SubagentStop that comes after elrond resumed the agent is not its return:
    an agent that hands back is never read from its stop."""
    configure(monkeypatch, fake)
    r = agent(tmp_path, "elrond H1 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    send(launch("elrond H1 · relecture", "elrond-reviewer", "toolu_r"))
    send(handback(r, "**Verdict : blocking**", "elrond-reviewer"))
    send(resume("r1"))
    send(stop(r, "elrond-reviewer", last="Rapport envoyé."))   # late: the first stretch's
    (t,) = fake.threads
    assert titles(t)[-1] == "🔎 Relecture lancée" and "`H1` relecture" in board_text(fake)


def test_a_resume_queued_behind_its_agents_hand_back_is_followed(fake, monkeypatch, tmp_path):
    """Review, 4: the saved state does not know the agent yet (its hand-back still queued); the
    queue is delivered in order, so the resume finds it."""
    configure(monkeypatch, fake)
    w = agent(tmp_path, "elrond A3 · règles", aid="w1", tool_use="toolu_w")
    send(launch("elrond A3 · règles", tool_use="toolu_w"))
    ad.enqueue(handback(w, "Fait."))                            # queued, not delivered yet
    send(resume("w1", transcript=main_transcript(tmp_path)))
    (t,) = fake.threads
    assert titles(t) == ["🚀 Lancé", "📦 Rendu", "🔧 Correction lancée"] and "`A3` correction" in board_text(fake)


def test_a_hand_back_said_again_counts_only_since_the_last_return(fake, monkeypatch, tmp_path):
    """Review, 6: a second hand-back with no launch between (a retried one) does not count the
    fallback of the stretch already said: no « relecture non obtenue » that pings."""
    configure(monkeypatch, fake)
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    ad.main(["clear", "A3"])
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    (t,) = fake.threads
    assert titles(t)[-1] == "✅ Relecture ok" and pings(fake) == []


def test_a_review_not_obtained_then_the_lot_blocked_is_one_ping(fake, monkeypatch, tmp_path):
    """Review, 7: elrond stops a lot whose review fell back; one thing waits, one ping."""
    configure(monkeypatch, fake)
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    ad.main(["lot", "A3", "blocked", "--note", "relecture non obtenue : à toi"])
    assert [p["embeds"][0]["title"] for p in pings(fake)] == ["⛔ A3 bloqué"]


def test_a_pull_request_merged_after_the_run_is_seen_by_the_watcher(fake, monkeypatch, tmp_path):
    """Review, 2: elrond is done, no event comes; the detached watcher asks GitHub every five
    minutes while a pull request waits, and stops once none does."""
    configure(monkeypatch, fake)
    fake.gh["pulls"] = [{"number": 255, "state": "open", "merged_at": None}]
    ad.main(["lot", "H1", "merge", "--pr", "255"])
    ad.main(["run-end", "H1 à fusionner"])
    naps = []

    def nap(s):   # Jonathan merges during the second wait
        naps.append(s)
        if len(naps) == 2:
            fake.gh["pulls"][0].update(state="closed", merged_at="2026-10-28T18:00:00Z")
    monkeypatch.setattr(ad.time, "sleep", nap)
    assert ad.main(["watch"]) == 0
    assert naps == [ad.PR_CHECK_S, ad.PR_CHECK_S]
    assert [p["embeds"][0]["title"] for p in pings(fake)] == ["🏁 Fin du run elrond"]
    assert "PR #255 fusionnée" in board_text(fake)
    assert ad.main(["watch"]) == 0 and len(naps) == 2   # nothing waits: no watch


# ── after the Orchestre's review of 28/10 ──────────────────────────────────────────

def test_a_ping_whose_deletion_fails_is_deleted_later(fake, monkeypatch, tmp_path, capsys):
    """C1: Discord refuses the deletion (503): the ping is kept and deleted at a later refresh,
    never forgotten with the thing it was for."""
    configure(monkeypatch, fake)
    ad.main(["lot", "A3", "blocked", "--note", "attend une décision"])
    (pid,) = [k for k, m in fake.messages.items() if m.get("content")]
    fake.fail[f"/api/webhooks/2/{AGENTS_TOKEN}/messages/{pid}"] = 503
    ad.main(["clear", "A3"])
    assert len(pings(fake)) == 1 and "Rien ne t'attend." in board_text(fake) and "HTTP 503" in capsys.readouterr().err
    fake.fail.clear()
    ad.main(["board"])
    assert pings(fake) == []


def test_the_hook_returns_at_once_while_a_delivery_waits(fake, monkeypatch, tmp_path):
    """The hook only queues: a deliverer that holds the state (a slow Discord) never holds Claude
    Code up; the event waits in the queue and goes once the state is free."""
    import fcntl
    configure(monkeypatch, fake, bot=False)
    monkeypatch.delenv("EREGION_DISCORD_SYNC")
    state = tmp_path / "state" / "eregion"
    state.mkdir(parents=True)
    with open(state / "discord.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        start = time.monotonic()
        assert send(launch("elrond A3 · x")) == 0
        assert time.monotonic() - start < 0.5
        time.sleep(0.3)
        assert fake.messages == {}
    for _ in range(100):
        if fake.messages:
            break
        time.sleep(0.05)
    assert "`A3` worker" in board_text(fake)


def test_a_fallback_of_the_last_turns_is_said_at_the_stop(fake, monkeypatch, tmp_path):
    """S3: the reviewer's last turns reach the transcript after its hand-back was read; at its
    stop they are read again, and a fallback there makes the review « non obtenue »."""
    configure(monkeypatch, fake)
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r", at=ts("2026-10-27T13:59:00")))
    send(handback(r, "**Verdict : ok**", "elrond-reviewer"))
    assert pings(fake) == []
    agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r", fallback=True)
    send(stop(r, "elrond-reviewer"))
    (p,) = pings(fake)
    (t,) = fake.threads
    assert p["embeds"][0]["title"] == "⚠️ A3 : relecture non obtenue" and titles(t)[-1] == "⚠️ Relecture non obtenue"
    assert t["applied_tags"] == [TAG["en relecture"]]
    send(stop(r, "elrond-reviewer"))   # said once
    assert len(pings(fake)) == 1 and titles(t).count("⚠️ Relecture non obtenue") == 1


def test_a_huge_report_is_cut_in_its_file(fake, monkeypatch, tmp_path):
    configure(monkeypatch, fake)
    monkeypatch.setattr(ad, "ATTACH_MAX", 3000)
    t = fake.thread("A3 · x", [TAG["en relecture"]])
    r = agent(tmp_path, "elrond A3 · relecture", "elrond-reviewer", aid="r1", tool_use="toolu_r")
    send(launch("elrond A3 · relecture", "elrond-reviewer", "toolu_r"))
    send(handback(r, "**Verdict : ok**\n\n" + "x" * 5000, "elrond-reviewer"))
    (text,) = t["posts"][-1]["files"].values()
    assert len(text) < 3100 and text.endswith("(tronqué : plus de 1 Mo)")


def test_a_deliverer_with_an_empty_queue_writes_nothing(fake, monkeypatch, tmp_path):
    """S5: another deliverer took its event; it rewrites nothing. `board` always does."""
    configure(monkeypatch, fake)
    assert ad.main(["deliver"]) == 0 and fake.requests == []
    ad.main(["board"])
    assert board_text(fake)
