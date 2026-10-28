#!/usr/bin/env python3
"""agents_discord — elrond's lots in Discord: what waits for Jonathan (N3, #262; docs/atelier-discord.md).

  agents_discord.py hook          Claude Code hook: JSON on stdin, queued at once, delivered in the
                                  background (EREGION_DISCORD_SYNC=1: inline)
  agents_discord.py lot ID blocked [--note TEXT]        elrond: a lot it cannot go on with
  agents_discord.py lot ID merge --pr N [--note TEXT]   elrond: a pull request Jonathan merges himself
  agents_discord.py run-end TEXT  elrond: the end-of-run summary
  agents_discord.py clear ID|all  what waits on a lot, settled by hand (its pings deleted)
  agents_discord.py board         the board rewritten, merged pull requests dropped

#agents is what waits for Jonathan, and nothing else. One board, rewritten in place: 🙋 what
waits for him, 🔄 the agents running (resumed ones too), ✅ what came back lately, 🏁 the last
run — each line with its links (the lot's thread, the pull request, the report). For each thing
that waits, a short ping that mentions EREGION_DISCORD_MENTION, deleted once settled: a lot
stopped (blocked, a review not obtained), the elrond session waiting for a permission or an
answer, a pull request to merge by hand, the end of a run. The rest (launched, returned, a
review's verdict, a worker's fallback) goes silently into the lot's thread, with the report.

The hooks (scripts/elrond-hooks.sh): PreToolUse on Agent|SendMessage|SubagentHandback|AskUserQuestion
and SubagentStop, synchronous — the event is queued before the tool runs or the agent is done, so
a hand-back comes before its SubagentStop, and that one before elrond can resume the agent —,
PostToolUse on AskUserQuestion, Notification and Stop. A hook only appends to a local queue and
returns; one process at a time delivers the queue, in order. A pull request waiting to be merged
is asked of GitHub by a detached watcher too, every five minutes, two days at most: Jonathan
merges it after the run, when no event is left to see it.
Configuration: notify_discord.load_config. What is not configured is not sent; a Discord error
never fails the caller.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

import notify_discord as nd

ROOT = Path(__file__).resolve().parents[1]
ELROND_AGENTS = ("elrond-worker", "elrond-reviewer")
STEP_STATE = {"worker": "en cours", "correction": "en correction", "relecture": "en relecture"}
REPO = "Vanyar53/eregion"
ASK_DELAY_S = 30         # a question answered within it never pings: Jonathan was there
STALE_S = 86400          # a launch refused after the hook saw it never comes back: gone after a day
RECENT_MAX = 8
PR_CHECK_S = 300         # GitHub asked at most every five minutes whether a pull request was merged
WATCH_MAX_S = 2 * 86400  # the watcher of pull requests to merge gives up after two days
REPORT_HEAD = 1500       # the report's head in the thread's card; the whole report comes as a file
ICON = {"blocked": "⛔", "not-obtained": "⚠️", "merge": "🔀", "question": "❓", "permission": "🔐"}


# ── the queue and the state ─────────────────────────────────────────────────────────

def _dir() -> Path:
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "eregion"


@contextmanager
def _locked(name: str):
    import fcntl  # POSIX: the hosts elrond runs on
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    with open(d / name, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield d


def enqueue(event: dict) -> None:
    """Appended in the hooks' order; a hook never waits on a delivery."""
    with _locked("discord.queue.lock") as d, open(d / "discord.queue", "a", encoding="utf-8") as q:
        q.write(json.dumps({**event, "at": event.get("at") or int(time.time())}, ensure_ascii=False) + "\n")


def _dequeue() -> list[dict]:
    with _locked("discord.queue.lock") as d:
        path = d / "discord.queue"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        path.write_text("", encoding="utf-8")
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def _peek() -> dict:
    """The state as last saved, read without the lock: enough to tell what is worth queuing."""
    try:
        return json.loads((_dir() / "discord.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


@contextmanager
def board_state():
    """One deliverer at a time; saved even when a delivery fails, so no ping id is lost."""
    with _locked("discord.lock") as d:
        path = d / "discord.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        for key, empty in (("running", {}), ("agents", {}), ("threads", {}), ("waiting", []),
                           ("recent", []), ("sessions", [])):
            data.setdefault(key, empty)
        try:
            yield data
        finally:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, path)


def _trace(e: dict) -> None:
    """One line per hook event, its fields' names only: what Claude Code really sends, read
    after a real run (the payloads come from its documentation, not all measured)."""
    path = _dir() / "discord.trace"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 100_000:
            path.write_text("".join(path.read_text(encoding="utf-8").splitlines(True)[-200:]), encoding="utf-8")
        with open(path, "a", encoding="utf-8") as f:
            found = ""   # its meta found from the hook's fields; the SendMessage's `to` a known agent
            if e.get("hook_event_name") == "SubagentStop" or e.get("tool_name") == "SubagentHandback":
                found = f" meta={int(bool(agent_of(e)[1]))}"
            elif e.get("tool_name") == "SendMessage":
                found = f" known={int(str((e.get('tool_input') or {}).get('to')) in _peek().get('agents', {}))}"
            f.write(f"{datetime.now().isoformat(timespec='seconds')} {e.get('hook_event_name')} "
                    f"{e.get('tool_name') or e.get('notification_type') or ''} agent={e.get('agent_type', '')} "
                    f"bg={len(e.get('background_tasks') or [])}{found} keys={','.join(sorted(e))}\n")
    except OSError:
        pass


# ── elrond's agents ─────────────────────────────────────────────────────────────────

def _palantir():
    path = ROOT / ".claude" / "skills" / "elrond" / "palantir.py"
    spec = importlib.util.spec_from_file_location("palantir", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_description(desc: str) -> tuple[str, str, str] | None:
    """« elrond <ID> · <title> » → (ID, step, title); step: worker, correction or relecture."""
    m = re.match(r"\s*elrond\s+(\S+)\s+·\s+(.+)", desc or "")
    if not m or m.group(1) == "plan":
        return None
    lot, rest = m.group(1), m.group(2).strip()
    for step in ("relecture", "correction"):
        if rest.lower().startswith(step):
            return lot, step, ""
    return lot, "worker", rest


def verdict_of(text: str) -> str:
    m = re.search(r"(?i)verdict\W{0,8}(ok|changes|blocking)\b", text or "")
    return m.group(1).lower() if m else ""


def agent_of(e: dict) -> tuple[str, dict, Path | None]:
    """(agent id, its meta, its transcript), from the hook's fields: a subagent's own hook names
    the main transcript, SubagentStop names the agent's."""
    path = Path(str(e["agent_transcript_path"])).expanduser() if e.get("agent_transcript_path") else None
    aid = str(e.get("agent_id") or (path.stem.removeprefix("agent-") if path else ""))
    if path is None and aid and e.get("transcript_path"):
        main = Path(str(e["transcript_path"])).expanduser()
        path = (main.parent if main.parent.name == "subagents" else main.with_suffix("") / "subagents") / f"agent-{aid}.jsonl"
    return aid, (_palantir().meta_of(path) if path else {}), path


def _elrond_session(e: dict, state: dict) -> bool:
    if e.get("session_id") in state.get("sessions", []):
        return True
    return bool(e.get("transcript_path")) and _palantir().has_elrond_agents(Path(str(e["transcript_path"])).expanduser())


def wanted(e: dict) -> bool:
    """elrond's agents, and its session waiting for Jonathan; nothing else is queued."""
    event, tool, inp = e.get("hook_event_name"), e.get("tool_name"), e.get("tool_input") or {}
    if event == "PreToolUse" and tool == "Agent":
        return inp.get("subagent_type") in ELROND_AGENTS and parse_description(inp.get("description", "")) is not None
    if event == "SubagentStop" or (event == "PreToolUse" and tool == "SubagentHandback"):
        return (e.get("agent_type") or agent_of(e)[1].get("agentType")) in ELROND_AGENTS
    state = _peek()
    if event == "PreToolUse" and tool == "SendMessage":
        # The saved state may not hold the agent yet (its hand-back still queued): whether `to`
        # is elrond's is decided when the queue is delivered, in order.
        return str(inp.get("to") or "") in state.get("agents", {}) or _elrond_session(e, state)
    if event == "Stop":
        return any(w.get("session") == e.get("session_id") for w in state.get("waiting", []))
    if (event in ("PreToolUse", "PostToolUse") and tool == "AskUserQuestion"
            or event == "Notification" and e.get("notification_type") == "permission_prompt"):
        return _elrond_session(e, state)
    return False


# ── links, the board, the pings ─────────────────────────────────────────────────────

def _repo() -> str:
    return os.environ.get("GITHUB_REPOSITORY") or REPO


def _thread_url(state: dict, lot: str) -> str:
    t, guild = state["threads"].get(lot) or {}, state.get("guild")
    return f"https://discord.com/channels/{guild}/{t['id']}" if t.get("id") and guild else ""


def _links(state: dict, w: dict) -> str:
    out = []
    if w.get("pr"):
        out.append(f"[PR #{w['pr']}](https://github.com/{_repo()}/pull/{w['pr']})")
    if url := _thread_url(state, w.get("lot", "")):
        out.append(f"[fil du lot]({url})")
    if issue := (state["threads"].get(w.get("lot", "")) or {}).get("issue"):
        out.append(f"[#{issue}](https://github.com/{_repo()}/issues/{issue})")
    return " · ".join(out)


def board_card(state: dict, now: int) -> dict:
    lines = ["**🙋 T'attend**"]
    lines += [f"{ICON[w['kind']]} {w['title']}" + (f" — {nd._cut(w['text'], 120)}" if w.get("text") else "")
              + f" · <t:{w['since']}:R>" + (f" · {links}" if (links := _links(state, w)) else "")
              for w in state["waiting"]] or ["Rien ne t'attend."]
    rows = sorted(state["running"].values(), key=lambda r: r.get("since", 0))
    lines += ["", "**🔄 En cours**"]
    lines += [f"`{r['lot']}` {r['step']} · <t:{r['since']}:R>" + (f" · {nd._cut(r['title'], 60)}" if r.get("title") else "")
              + (f" · [fil]({url})" if (url := _thread_url(state, r["lot"])) else "")
              for r in rows] or ["Rien ne tourne."]
    if state["recent"]:
        lines += ["", "**✅ Rendu récemment**"]
        lines += [f"`{r['lot']}` {r['text']} · <t:{r['at']}:t>" + (f" · [{r['label']}]({r['url']})" if r.get("url") else "")
                  for r in reversed(state["recent"])]
    if run := state.get("last_run"):
        text = run["text"] if len(run["text"]) <= 600 else run["text"][:599] + "…"   # its lines kept
        lines += ["", f"**🏁 Dernier run** · <t:{run['at']}:f>", text]
    color = nd.ORANGE if state["waiting"] else nd.BLUE if rows else nd.GREY
    card = nd.embed("📋 elrond", "\n".join(lines), color)
    card["timestamp"] = datetime.fromtimestamp(now, timezone.utc).isoformat()
    return card


def _post_ping(cfg: nd.Config, card: dict) -> str:
    return nd.post_webhook(cfg.agents, nd.message(card, silent=False, mention=cfg.mention), "webhook #agents")


def _unping(cfg: nd.Config, mid: str | None) -> None:
    if mid and cfg.agents:
        try:
            nd.fetch("DELETE", f"{cfg.agents}/messages/{mid}", "webhook #agents")
        except nd.Failure as f:
            if f.code != 404:   # 404: deleted by hand already
                nd.say(f)


def await_(cfg: nd.Config, state: dict, item: dict, delay: int = 0) -> None:
    """Something waits for Jonathan: on the board at once, pinged at the next refresh after `delay`.
    Said again, it keeps its ping: one push per thing."""
    if old := next((w for w in state["waiting"] if w["key"] == item["key"]), None):
        old.update(title=item["title"], text=item.get("text", ""))
        return
    state["waiting"].append({**item, "ping_at": item["since"] + delay})
    if delay:
        _later("tick", str(delay))
    if item["kind"] == "merge":
        _later("watch")


def _later(*args: str) -> None:
    """A detached run of this script (inline delivery, the tests: none)."""
    if not os.environ.get("EREGION_DISCORD_SYNC"):
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), *args], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def settle(cfg: nd.Config, state: dict, pred) -> None:
    """What no longer waits leaves the board, and its ping leaves the channel."""
    keep = []
    for w in state["waiting"]:
        if pred(w):
            _unping(cfg, w.get("ping"))
        else:
            keep.append(w)
    state["waiting"] = keep


def _recent(state: dict, lot: str, text: str, at: int, url: str = "", label: str = "fil") -> None:
    state["recent"] = (state["recent"] + [{"lot": lot, "text": text, "at": at, "url": url, "label": label}])[-RECENT_MAX:]


def _merged_prs(cfg: nd.Config, state: dict, now: int, force: bool) -> None:
    """A pull request merged (or closed) by Jonathan no longer waits; GitHub is asked, never often."""
    items = [w for w in state["waiting"] if w["kind"] == "merge"]
    if not items or (not force and now - state.get("prs_checked", 0) < PR_CHECK_S):
        return
    state["prs_checked"] = now
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    auth = {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"} if os.environ.get("GITHUB_TOKEN") else {}
    for w in items:
        try:
            pr = nd.fetch("GET", f"{api}/repos/{_repo()}/pulls/{w['pr']}", "GitHub API",
                          headers={"Accept": "application/vnd.github+json", **auth})
        except nd.Failure as f:
            nd.say(f)
            continue
        if pr.get("merged_at") or pr.get("state") == "closed":
            settle(cfg, state, lambda x: x is w)
            _recent(state, w["lot"], f"PR #{w['pr']} {'fusionnée' if pr.get('merged_at') else 'fermée'}", now,
                    f"https://github.com/{_repo()}/pull/{w['pr']}", "PR")


def refresh(cfg: nd.Config, state: dict, now: int | None = None, force: bool = False) -> None:
    """The pings that are due, then the board rewritten in place (a new one if it was deleted)."""
    now = now or int(time.time())
    state["running"] = {k: r for k, r in state["running"].items() if now - r.get("since", 0) < STALE_S}
    _merged_prs(cfg, state, now, force)
    if not cfg.agents:
        return
    for w in state["waiting"]:
        if not w.get("ping") and w["ping_at"] <= now:
            card = nd.embed(f"{ICON[w['kind']]} {w['title']}", "\n".join(x for x in (w.get("text"), _links(state, w)) if x),
                            nd.RED if w["kind"] == "blocked" else nd.ORANGE, _thread_url(state, w.get("lot", "")))
            try:
                w["ping"] = _post_ping(cfg, card)
            except nd.Failure as f:
                nd.say(f)
    payload = {"embeds": [board_card(state, now)], "allowed_mentions": {"parse": []}}
    mid = state.setdefault("board", state.pop("status_message", ""))   # N1's « en cours » message becomes the board
    if mid:
        try:
            nd.fetch("PATCH", f"{cfg.agents}/messages/{mid}", "webhook #agents", payload)
            return
        except nd.Failure as f:
            if f.code != 404:
                raise
    state["board"] = nd.post_webhook(cfg.agents, {**payload, "flags": nd.SILENT}, "webhook #agents")


def to_thread(cfg: nd.Config, state: dict, forum, lot: str, card: dict, *, title: str = "", st: str | None = None,
              report: str = "", name: str = "") -> str:
    """The lot's thread gets the card, silent, and the whole report as a file; a link to the card.
    A thread that fails is said, never in the way of #agents: what waits is still on the board."""
    if forum is None:
        return ""
    try:
        t, mid = forum.post(nd.Notice(card, ci=False, lot=lot, title=title, state=st), nd.message(card))
        if t is None:
            return ""
        state["guild"] = str(forum.channel().get("guild_id") or state.get("guild") or "")
        issue = re.search(r"· #(\d+)$", t.get("name", ""))
        state["threads"][lot] = {"id": str(t["id"]), "issue": issue.group(1) if issue else ""}
        if len(report) > REPORT_HEAD:
            forum.attach(t["id"], f"{name or 'rapport'}-{re.sub(r'[^A-Za-z0-9-]', '', lot)}.md", report)
    except nd.Failure as f:
        nd.say(f)
        return ""
    return f"https://discord.com/channels/{state['guild']}/{t['id']}/{mid}" if state["guild"] and mid else ""


def _head(report: str) -> str:
    if len(report) <= REPORT_HEAD:
        return report
    return report[:REPORT_HEAD].rsplit("\n\n", 1)[0] + "\n\n… (le rapport complet est joint)"


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _when(ts: str) -> str:
    try:
        return f"<t:{int(datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp())}:t>"
    except (ValueError, AttributeError):
        return ts


# ── what each event does ────────────────────────────────────────────────────────────

def _begin(e: dict, cfg, state, forum, key: str, lot: str, step: str, title: str) -> None:
    """Launched or resumed: on the board, in the thread; what waited on the lot is settled."""
    state["running"][key] = {"lot": lot, "step": step, "since": e["at"], "title": title}
    if (sid := e.get("session_id")) and sid not in state["sessions"]:
        state["sessions"] = (state["sessions"] + [sid])[-20:]
    settle(cfg, state, lambda w: w.get("lot") == lot and w["kind"] in ("blocked", "not-obtained"))
    if (run := state.get("last_run") or {}).get("ping"):   # a new run: the last one's ping goes
        _unping(cfg, run.pop("ping"))
    head = {"worker": "🚀 Lancé", "correction": "🔧 Correction lancée", "relecture": "🔎 Relecture lancée"}[step]
    to_thread(cfg, state, forum, lot, nd.embed(f"{head} · {lot}", title, nd.BLUE), title=title, st=STEP_STATE[step])


def on_launch(e, cfg, state, forum) -> None:
    lot, step, title = parse_description((e.get("tool_input") or {}).get("description", ""))
    _begin(e, cfg, state, forum, e.get("tool_use_id") or f"{lot}:{step}", lot, step, title)


def on_resume(e, cfg, state, forum) -> None:
    """elrond sends the findings to the agent that already ran: a correction, or a review again."""
    aid = str((e.get("tool_input") or {}).get("to"))
    if (a := state["agents"].get(aid)) is None:
        return   # another agent, or another session
    _begin(e, cfg, state, forum, aid, a["lot"], "relecture" if a["kind"] == "elrond-reviewer" else "correction",
           a.get("title", ""))


def on_return(e, cfg, state, forum, report: str, handback: bool = False) -> None:
    """The agent's report: by SubagentHandback (its PreToolUse hook), or the last text of an agent
    that ends without it. Only this stretch of its work counts: since its launch or resume, else
    since its last return (a hand-back said again)."""
    aid, meta, path = agent_of(e)
    parsed = parse_description(meta.get("description", ""))
    if not parsed:
        return
    lot, step, title = parsed
    kind = meta.get("agentType") or e.get("agent_type")
    keys = [k for k in (aid, meta.get("toolUseId")) if k in state["running"]]
    before = state["agents"].get(aid, {})
    since = min((state["running"][k]["since"] for k in keys), default=before.get("returned_at", 0))
    step = state["running"][keys[0]]["step"] if keys else step
    for k in keys:
        state["running"].pop(k)
    state["agents"][aid] = {"lot": lot, "kind": kind, "title": title or before.get("title", ""), "returned_at": e["at"],
                            "handback": handback or before.get("handback", False)}
    pal = _palantir()
    scan = pal.scan(path, pal.EXPECTED) if path and path.is_file() else {}
    episodes = [x for x in scan.get("fallback_episodes") or [] if x.get("to", "") >= _iso(since)]
    stops = [x for x in scan.get("refusals") or [] if x.get("at", "") >= _iso(since)]
    fell = bool(episodes or stops)
    models = ", ".join(f"{m} ×{n}" for m, n in (scan.get("models") or {}).items()) or "—"
    said = "\n".join(f"{x['model']} de {_when(x['from'])} à {_when(x['to'])} ({x['responses']} réponses)"
                     for x in episodes) or f"{len(stops)} arrêt(s) des protections"
    at = e["at"]
    if kind == "elrond-reviewer":
        if fell:
            card = nd.embed(f"⚠️ Relecture non obtenue · {lot}", f"le relecteur a basculé :\n{said}\n\n{_head(report)}",
                            nd.ORANGE)
            link = to_thread(cfg, state, forum, lot, card, report=report, name="relecture")
            await_(cfg, state, {"key": f"not-obtained:{lot}", "kind": "not-obtained", "lot": lot,
                                "title": f"{lot} : relecture non obtenue", "text": said, "since": at})
            _recent(state, lot, "relecture non obtenue", at, link, "rapport")
            return
        verdict = verdict_of(report)
        head, color, st = {"ok": ("✅ Relecture ok", nd.GREEN, "fait"),
                           "changes": ("🛠️ Relecture : changes", nd.ORANGE, "en correction"),
                           "blocking": ("🛠️ Relecture : blocking", nd.RED, "en correction")}.get(
            verdict, ("❔ Relecture sans verdict lisible", nd.GREY, None))
        link = to_thread(cfg, state, forum, lot, nd.embed(f"{head} · {lot}", _head(report) or f"modèles : {models}", color),
                         st=st, report=report, name="relecture")
        _recent(state, lot, f"relecture {verdict or 'sans verdict lisible'}", at, link, "rapport")
        return
    if fell:
        card = nd.embed(f"⚠️ Repli de modèle · {lot}", f"{said}\nrelecture en Opus obligatoire\n\n{_head(report)}",
                        nd.ORANGE)
        _recent(state, lot, f"{'correction rendue' if step == 'correction' else 'rendu'}, avec un repli", at,
                to_thread(cfg, state, forum, lot, card, st="en relecture", report=report, name="rendu"), "rapport")
        return
    card = nd.embed(f"📦 Rendu · {lot}", _head(report) or f"modèles : {models}", nd.GREY)
    _recent(state, lot, "correction rendue" if step == "correction" else "rendu", at,
            to_thread(cfg, state, forum, lot, card, st="en relecture", report=report, name="rendu"), "rapport")


def on_stop(e, cfg, state, forum) -> None:
    aid, meta, _ = agent_of(e)
    if not any(k in state["running"] for k in (aid, meta.get("toolUseId"))):
        return   # handed back already (SubagentHandback), or never seen
    if state["agents"].get(aid, {}).get("handback"):
        return   # its returns come by SubagentHandback: a stop is a pause, or a late one of a past stretch
    if e.get("background_tasks"):
        return   # a pause: it waits for its own background task, and comes back
    on_return(e, cfg, state, forum, str(e.get("last_assistant_message") or ""))


def on_elrond(e, cfg, state, forum) -> None:
    """What only elrond knows: a lot blocked, a pull request to merge by hand, the end of a run."""
    kind, lot, note, at = e.get("kind"), e.get("lot", ""), e.get("note", ""), e["at"]
    if kind == "blocked":
        state["running"] = {k: r for k, r in state["running"].items() if r["lot"] != lot}
        settle(cfg, state, lambda w: w["key"] == f"not-obtained:{lot}")   # the same stop, one ping
        to_thread(cfg, state, forum, lot, nd.embed(f"⛔ Lot bloqué · {lot}", note, nd.RED), st="bloqué")
        await_(cfg, state, {"key": f"blocked:{lot}", "kind": "blocked", "lot": lot, "title": f"{lot} bloqué",
                            "text": note, "since": at})
    elif kind == "merge":
        pr = str(e.get("pr"))
        to_thread(cfg, state, forum, lot, nd.embed(f"🔀 PR #{pr} prête · {lot}", note or "à fusionner par Jonathan",
                                                   nd.PURPLE, f"https://github.com/{_repo()}/pull/{pr}"))
        await_(cfg, state, {"key": f"merge:{pr}", "kind": "merge", "lot": lot, "pr": pr,
                            "title": f"{lot} : PR #{pr} à fusionner", "text": note, "since": at})
    elif kind == "run-end":
        _unping(cfg, (state.get("last_run") or {}).get("ping"))
        state["last_run"] = {"text": note, "at": at}
        if cfg.agents:
            try:
                state["last_run"]["ping"] = _post_ping(cfg, nd.embed("🏁 Fin du run elrond", note, nd.PURPLE))
            except nd.Failure as f:
                nd.say(f)
    elif kind == "clear":
        settle(cfg, state, lambda w: lot == "all" or w.get("lot") == lot)


def handle(e: dict, cfg: nd.Config, state: dict, forum) -> None:
    event, tool = e.get("hook_event_name"), e.get("tool_name")
    if event in ("PreToolUse", "PostToolUse", "Stop") and not e.get("agent_id"):
        # The main session acts again: the permission it waited for was answered.
        settle(cfg, state, lambda w: w["kind"] == "permission" and w.get("session") == e.get("session_id"))
    if event == "PreToolUse" and tool == "Agent":
        on_launch(e, cfg, state, forum)
    elif event == "PreToolUse" and tool == "SendMessage":
        on_resume(e, cfg, state, forum)
    elif event == "PreToolUse" and tool == "SubagentHandback":
        on_return(e, cfg, state, forum, str((e.get("tool_input") or {}).get("message") or ""), handback=True)
    elif event == "SubagentStop":
        on_stop(e, cfg, state, forum)
    elif event == "PreToolUse" and tool == "AskUserQuestion":
        question = ((e.get("tool_input") or {}).get("questions") or [{}])[0].get("question", "")
        await_(cfg, state, {"key": f"question:{e.get('session_id')}", "kind": "question", "session": e.get("session_id"),
                            "title": "elrond te pose une question", "text": question, "since": e["at"]}, ASK_DELAY_S)
    elif event in ("PostToolUse", "Stop"):
        settle(cfg, state, lambda w: w["kind"] == "question" and w.get("session") == e.get("session_id"))
    elif event == "Notification":
        await_(cfg, state, {"key": f"permission:{e.get('session_id')}", "kind": "permission",
                            "session": e.get("session_id"), "title": "elrond attend ta permission",
                            "text": e.get("message", ""), "since": e["at"]})
    elif event == "elrond":
        on_elrond(e, cfg, state, forum)


def drain(cfg: nd.Config, force: bool = False) -> None:
    """Every queued event, in order, then the board once."""
    with board_state() as state:
        forum = nd.Forum(cfg) if cfg.lots else None
        while events := _dequeue():
            for e in events:
                try:
                    handle(e, cfg, state, forum)
                except nd.Failure as f:
                    nd.say(f)
                except Exception as x:   # a transcript or a palantir that changed: said, never raised
                    nd.say(nd.Failure("hook", why=type(x).__name__))
        try:
            refresh(cfg, state, force=force)
        except nd.Failure as f:
            nd.say(f)


def _deliver_later() -> None:
    log = _dir() / "discord.log"
    with open(log, "a") as err:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "deliver"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)


def hook(text: str, environ=os.environ) -> int:
    """Never blocks Claude Code: exit 0 whatever happens; queued at once, Discord reached later."""
    try:
        e = json.loads(text)
        cfg = nd.load_config(environ)
        if not isinstance(e, dict) or not (cfg.agents or cfg.lots):
            return 0
        keep = wanted(e)
        if keep or e.get("hook_event_name") != "Stop":
            _trace(e)
        if not keep:
            return 0
        enqueue(e)
        if environ.get("EREGION_DISCORD_SYNC"):
            drain(cfg)
        else:
            _deliver_later()
    except Exception as x:
        nd.say(nd.Failure("hook", why=type(x).__name__))
    return 0


def watch(cfg: nd.Config) -> int:
    """Detached: GitHub asked every PR_CHECK_S whether the pull requests waiting were merged, as
    long as one waits (two days at most). One watcher at a time; the next one waits its turn,
    then looks again, so a pull request awaited as the last watcher ends is still watched."""
    import fcntl
    d = _dir()
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "discord.watch.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        end = time.time() + WATCH_MAX_S
        while time.time() < end and any(w.get("kind") == "merge" for w in _peek().get("waiting", [])):
            time.sleep(PR_CHECK_S)
            command({}, cfg, force=True)
    return 0


def command(event: dict, cfg: nd.Config, force: bool = False) -> int:
    """elrond's own calls: queued like a hook's event, delivered at once (elrond waits for it)."""
    if not (cfg.agents or cfg.lots):   # nothing configured: nothing written, not even the local state
        return 0
    try:
        if event:
            enqueue({"hook_event_name": "elrond", **event})
        drain(cfg, force)
    except Exception as x:   # a read-only state folder: said, exit 0 (SKILL.md)
        nd.say(x if isinstance(x, nd.Failure) else nd.Failure("elrond", why=type(x).__name__))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("hook")
    sub.add_parser("deliver")
    tick = sub.add_parser("tick")
    tick.add_argument("delay", type=int)
    lot = sub.add_parser("lot")
    lot.add_argument("lot")
    lot.add_argument("event", choices=["blocked", "merge"])
    lot.add_argument("--note", default="")
    lot.add_argument("--pr", type=int)
    end = sub.add_parser("run-end")
    end.add_argument("text")
    clear = sub.add_parser("clear")
    clear.add_argument("lot")
    sub.add_parser("board")
    sub.add_parser("watch")
    a = ap.parse_args(argv)
    if a.mode == "hook":
        return hook(sys.stdin.read())
    cfg = nd.load_config()
    if a.mode == "deliver":
        return command({}, cfg)
    if a.mode == "tick":
        time.sleep(a.delay + 1)
        return command({}, cfg)
    if a.mode == "lot":
        if a.event == "merge" and not a.pr:
            ap.error("merge needs --pr")
        return command({"kind": a.event, "lot": a.lot, "note": a.note, "pr": a.pr}, cfg)
    if a.mode == "run-end":
        return command({"kind": "run-end", "note": a.text}, cfg)
    if a.mode == "clear":
        return command({"kind": "clear", "lot": a.lot}, cfg)
    if a.mode == "watch":
        return watch(cfg) if (cfg.agents or cfg.lots) else 0
    return command({}, cfg, force=True)


if __name__ == "__main__":
    sys.exit(main())
