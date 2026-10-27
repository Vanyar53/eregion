#!/usr/bin/env python3
"""notify_discord — the workshop's news in Discord (N1, #242; docs/atelier-discord.md).

  notify_discord.py github        in GitHub Actions (notify.yml): reads $GITHUB_EVENT_NAME and
                                  $GITHUB_EVENT_PATH — CI results, pull requests, releases, closed
                                  issues to #ci, and a lot's events to its thread as well
  notify_discord.py hook          Claude Code hook (PreToolUse on Agent, SubagentStop): JSON on
                                  stdin, elrond's agents only; returns at once and delivers in
                                  the background (EREGION_DISCORD_SYNC=1: inline)
  notify_discord.py lot ID blocked [--note TEXT]   elrond: a lot it cannot go on with
  notify_discord.py run-end TEXT  elrond: the end-of-run summary
  notify_discord.py check         what is configured (names, never values), what the forum lacks

Where things go. #ci: a pull request opened or merged, a red CI (pull request, main, the
nightly runs), main green again after red, a published release, a closed issue. #lots: one
thread per lot, every event of the lot, its tags (milestone, state) kept true. #agents: one
message rewritten in place (the agents running), and what needs Jonathan — a model fallback,
a review with changes, blocking or not obtained, a blocked lot, the end of a run — which
mentions EREGION_DISCORD_MENTION. Only a red CI, a release and those alerts notify; the rest is silent.

Configuration: the environment, over ~/.config/eregion/discord.env (KEY=value lines; another
file: EREGION_DISCORD_ENV) — EREGION_DISCORD_WEBHOOK_CI, EREGION_DISCORD_WEBHOOK_AGENTS (webhook URLs),
EREGION_DISCORD_BOT_TOKEN and EREGION_DISCORD_LOTS_FORUM (the Eregion bot, the workshop's, never Glorfindel's, and the forum's
id), EREGION_DISCORD_MENTION (a user id). What is not configured is not sent. A Discord error never
fails the caller: one line on stderr, without the URL or the token, and exit 0.
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
import unicodedata
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = ("EREGION_DISCORD_WEBHOOK_CI", "EREGION_DISCORD_WEBHOOK_AGENTS", "EREGION_DISCORD_BOT_TOKEN",
        "EREGION_DISCORD_LOTS_FORUM", "EREGION_DISCORD_MENTION", "EREGION_DISCORD_API")
UA = "DiscordBot (https://github.com/Vanyar53/eregion, 1)"
SILENT = 1 << 12  # SUPPRESS_NOTIFICATIONS: shown in the channel, no push, no sound
RED, GREEN, BLUE, PURPLE, ORANGE, GREY = 0xE5484D, 0x30A46C, 0x3E63DD, 0x8E4EC6, 0xF76B15, 0x8B8D98
RED_CONCLUSIONS = {"failure", "timed_out", "startup_failure"}
STATE_TAGS = ("à faire", "en cours", "en relecture", "en correction", "fait", "bloqué")
MILESTONE_TAGS = ("v0.3", "v0.x", "v1.0", "v1.x")
LOT_ID = r"[A-Z]{1,3}-?\d+[A-Z]?"
ELROND_AGENTS = ("elrond-worker", "elrond-reviewer")
STEP_STATE = {"worker": "en cours", "correction": "en correction", "relecture": "en relecture"}


class Failure(Exception):
    """A request that did not go through. Its text never holds a URL or a token."""

    def __init__(self, label: str, code: int | None = None, why: str = ""):
        super().__init__(f"{label}: " + (f"HTTP {code}" if code else why))
        self.code = code


@dataclass
class Config:
    ci: str = ""
    agents: str = ""
    token: str = ""
    forum: str = ""
    mention: str = ""
    api: str = "https://discord.com/api/v10"

    @property
    def lots(self) -> bool:
        return bool(self.token and self.forum)


def load_config(environ=os.environ) -> Config:
    """The environment over the file: each key from the first place that has it."""
    values: dict[str, str] = {}
    path = Path(environ.get("EREGION_DISCORD_ENV") or Path.home() / ".config" / "eregion" / "discord.env")
    try:
        for line in path.expanduser().read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().removeprefix("export ").partition("=")
            if sep and key.strip() in KEYS:
                values[key.strip()] = value.strip().strip("'\"")
    except OSError:
        pass
    values.update({k: environ[k] for k in KEYS if environ.get(k)})
    mention = values.get("EREGION_DISCORD_MENTION", "")
    return Config(ci=values.get("EREGION_DISCORD_WEBHOOK_CI", "").rstrip("/"),
                  agents=values.get("EREGION_DISCORD_WEBHOOK_AGENTS", "").rstrip("/"),
                  token=values.get("EREGION_DISCORD_BOT_TOKEN", ""), forum=values.get("EREGION_DISCORD_LOTS_FORUM", ""),
                  mention=mention if mention.isdigit() else "",
                  api=(values.get("EREGION_DISCORD_API") or Config.api).rstrip("/"))


def fetch(method: str, url: str, label: str, body=None, headers=None):
    """JSON in, JSON out; one more try after a 429 that asks for 5 s or less."""
    data = json.dumps(body).encode() if body is not None else None
    head = {"User-Agent": UA, "Content-Type": "application/json", **(headers or {})}
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=head)
            with urllib.request.urlopen(req, timeout=8) as r:
                raw = r.read()
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            wait = _retry_after(e)
            if e.code == 429 and attempt == 1 and wait <= 5:
                time.sleep(wait)
                continue
            raise Failure(label, e.code) from None
        except (OSError, ValueError) as e:  # URLError is an OSError
            raise Failure(label, why=type(e).__name__) from None


def _retry_after(e: urllib.error.HTTPError) -> float:
    try:
        return float(e.headers.get("Retry-After") or json.loads(e.read() or b"{}").get("retry_after", 99))
    except (ValueError, TypeError, AttributeError):
        return 99.0


def say(failure: Exception) -> None:
    print(f"atelier: not sent — {failure}", file=sys.stderr)


def _cut(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def embed(title: str, description: str = "", color: int = GREY, url: str = "") -> dict:
    e = {"title": _cut(title, 256), "color": color}
    if description:
        e["description"] = str(description)[:4000]
    if url:
        e["url"] = url
    return e


def message(card: dict, *, silent: bool = True, mention: str = "") -> dict:
    """Never a ping from the text: only the configured user, and only when asked."""
    out = {"embeds": [card], "allowed_mentions": {"parse": []}}
    if mention:
        out["content"] = f"<@{mention}>"
        out["allowed_mentions"]["users"] = [mention]
    if silent:
        out["flags"] = SILENT
    return out


def post_webhook(url: str, payload: dict, label: str) -> str:
    return str(fetch("POST", url + "?wait=true", label, payload).get("id") or "")


def _norm(name: str) -> str:
    return unicodedata.normalize("NFC", name).strip().casefold()


class Forum:
    """The #lots forum, through the Eregion bot: a thread per lot, named « <ID> · <title> »."""

    def __init__(self, cfg: Config):
        self.cfg, self._channel = cfg, None

    def call(self, method: str, path: str, body=None):
        return fetch(method, self.cfg.api + path, "forum #lots", body,
                     {"Authorization": f"Bot {self.cfg.token}"})

    def channel(self) -> dict:
        if self._channel is None:
            self._channel = self.call("GET", f"/channels/{self.cfg.forum}")
        return self._channel

    def tags(self) -> dict[str, str]:
        return {_norm(t["name"]): str(t["id"]) for t in self.channel().get("available_tags") or []}

    def threads(self) -> list[dict]:
        """Active and archived: a lot closed last month keeps its thread."""
        guild = self.channel().get("guild_id")
        found = [t for t in self.call("GET", f"/guilds/{guild}/threads/active").get("threads") or []
                 if str(t.get("parent_id")) == str(self.cfg.forum)]
        before = ""
        for _ in range(5):
            page = self.call("GET", f"/channels/{self.cfg.forum}/threads/archived/public?limit=100{before}")
            found += page.get("threads") or []
            if not page.get("has_more") or not page.get("threads"):
                break
            before = "&before=" + page["threads"][-1]["thread_metadata"]["archive_timestamp"]
        return found

    def find(self, lot: str = "", issue: str = "") -> dict | None:
        for t in self.threads():
            name = t.get("name", "")
            if lot and (name == lot or name.startswith(f"{lot} · ")):
                return t
            if issue and re.search(rf"#{issue}\b", name):
                return t
        return None

    def apply(self, current: list, state: str | None, milestone: str | None) -> list:
        """One state and one milestone at most; the other tags stay."""
        names, out = self.tags(), [str(x) for x in current]
        for group, want in ((STATE_TAGS, state), (MILESTONE_TAGS, milestone)):
            if want:
                ids = {names[_norm(n)] for n in group if _norm(n) in names}
                out = [x for x in out if x not in ids]
                if _norm(want) in names:
                    out.append(names[_norm(want)])
        return out[:5]

    def post(self, n: "Notice", payload: dict) -> None:
        t = self.find(n.lot, n.issue)
        if t is None:
            if not n.create:
                return
            name = _cut(" · ".join(x for x in (n.lot or f"#{n.issue}", n.title) if x), 100)
            t = self.call("POST", f"/channels/{self.cfg.forum}/threads",
                          {"name": name, "applied_tags": self.apply([], n.state, n.milestone),
                           "message": payload})
        else:
            change = {}
            tags = self.apply(t.get("applied_tags") or [], n.state, n.milestone)
            if tags != [str(x) for x in t.get("applied_tags") or []]:
                change["applied_tags"] = tags
            if (t.get("thread_metadata") or {}).get("archived"):
                change["archived"] = False
            if change:
                self.call("PATCH", f"/channels/{t['id']}", change)
            self.call("POST", f"/channels/{t['id']}/messages", payload)
        if n.archive:
            self.call("PATCH", f"/channels/{t['id']}", {"archived": True})


@dataclass
class Notice:
    """One event: a card for #ci (or not), and for the lot's thread when it has one."""
    card: dict
    silent: bool = True
    ci: bool = True
    lot: str = ""
    issue: str = ""
    title: str = ""
    state: str | None = None
    milestone: str | None = None
    create: bool = True
    archive: bool = False


def deliver(notices: list[Notice], cfg: Config) -> None:
    """Each piece on its own: a thread that fails does not keep #ci from its card."""
    forum = Forum(cfg) if cfg.lots else None
    for n in notices:
        if n.ci and cfg.ci:
            try:
                post_webhook(cfg.ci, message(n.card, silent=n.silent), "webhook #ci")
            except Failure as e:
                say(e)
        if forum and (n.lot or n.issue):
            try:
                forum.post(n, message(n.card))
            except Failure as e:
                say(e)


# ── GitHub ───────────────────────────────────────────────────────────────────────────

def lot_of(*, branch: str = "", title: str = "", body: str = "") -> tuple[str, str]:
    """(lot id, issue number) from elrond's branch (lot/<id>-…), a title, a closing keyword."""
    lot = issue = ""
    if m := re.match(r"lot/([a-z]{1,3}-?\d+[a-z]?)(?:-|$)", branch or ""):
        lot = m.group(1).upper()
    elif m := re.match(r"lot/(\d+)(?:-|$)", branch or ""):
        issue = m.group(1)
    if not lot and (m := re.match(rf"\s*({LOT_ID})\b", title or "")
                    or re.search(rf"\(({LOT_ID})(?:\s*,\s*#\d+)?\)", title or "")):
        lot = m.group(1)
    if not issue and (m := re.search(r"\((?:[^()]*,\s*)?#(\d+)\)", title or "")
                      or re.search(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s+#(\d+)", body or "")):
        issue = m.group(1)
    return lot, issue


def previous_conclusion(run: dict, environ) -> str:
    """The conclusion of the run before this one, same workflow and branch, pushes only."""
    api = environ.get("GITHUB_API_URL", "https://api.github.com")
    url = (f"{api}/repos/{environ.get('GITHUB_REPOSITORY', '')}/actions/workflows/{run.get('workflow_id')}"
           f"/runs?branch={run.get('head_branch')}&event=push&status=completed&per_page=20")
    auth = {"Authorization": f"Bearer {environ['GITHUB_TOKEN']}"} if environ.get("GITHUB_TOKEN") else {}
    runs = fetch("GET", url, "GitHub API", headers={"Accept": "application/vnd.github+json", **auth})
    for r in runs.get("workflow_runs") or []:
        if r.get("run_number", 0) < run.get("run_number", 0) and r.get("conclusion") in RED_CONCLUSIONS | {"success"}:
            return r["conclusion"]
    return ""


def github_notices(name: str, event: dict, previous=lambda run: "") -> list[Notice]:
    """What a GitHub event is worth saying; [] for the rest (a green PR, a cancelled run…)."""
    if name == "workflow_run":
        run = event.get("workflow_run") or {}
        concl, kind, wf = run.get("conclusion"), run.get("event"), run.get("name", "?")
        red, url = concl in RED_CONCLUSIONS, run.get("html_url", "")
        title = run.get("display_title", "")
        if kind == "pull_request":
            if not red:
                return []
            pr = (run.get("pull_requests") or [{}])[0]
            lot, issue = lot_of(branch=(pr.get("head") or {}).get("ref") or run.get("head_branch", ""), title=title)
            num = f"#{pr['number']} " if pr.get("number") else ""
            return [Notice(embed(f"🔴 {wf} · {num}{title}", f"rouge ({concl})", RED, url),
                           silent=False, lot=lot, issue=issue, create=False)]
        default = (event.get("repository") or {}).get("default_branch", "main")
        if kind == "push" and run.get("head_branch") == default:
            if red:
                return [Notice(embed(f"🔴 {wf} · {default} rouge", title, RED, url), silent=False)]
            if concl == "success" and previous(run) in RED_CONCLUSIONS:
                return [Notice(embed(f"🟢 {wf} · {default} de nouveau verte", title, GREEN, url))]
            return []
        if kind in ("schedule", "workflow_dispatch") and red:
            return [Notice(embed(f"🔴 {wf} · run {'de nuit' if kind == 'schedule' else 'manuel'} rouge",
                                 f"sur {run.get('head_branch', '')} ({concl})", RED, url), silent=False)]
        return []
    if name in ("pull_request_target", "pull_request"):
        pr, action = event.get("pull_request") or {}, event.get("action")
        lot, issue = lot_of(branch=(pr.get("head") or {}).get("ref", ""), title=pr.get("title", ""),
                            body=pr.get("body") or "")
        milestone = (pr.get("milestone") or {}).get("title")
        head = f"#{pr.get('number')} {pr.get('title', '')}"
        if action == "opened":
            return [Notice(embed(f"📬 PR ouverte · {head}", "", BLUE, pr.get("html_url", "")),
                           lot=lot, issue=issue, title=pr.get("title", ""), milestone=milestone)]
        if action == "closed" and pr.get("merged"):
            return [Notice(embed(f"🔀 PR fusionnée · {head}", "", PURPLE, pr.get("html_url", "")),
                           lot=lot, issue=issue, title=pr.get("title", ""), state="fait", milestone=milestone)]
        return []
    if name == "release" and event.get("action") == "published":
        rel = event.get("release") or {}
        pre = " (pré-version)" if rel.get("prerelease") else ""
        return [Notice(embed(f"🏷️ {rel.get('tag_name', '?')} publiée{pre}", rel.get("name") or "", GREEN,
                             rel.get("html_url", "")), silent=False)]
    if name == "issues" and event.get("action") == "closed":
        it = event.get("issue") or {}
        lot, _ = lot_of(title=it.get("title", ""))
        why = " (abandonnée)" if it.get("state_reason") == "not_planned" else ""
        return [Notice(embed(f"✅ #{it.get('number')} fermée{why} · {it.get('title', '')}", "", GREEN,
                             it.get("html_url", "")),
                       lot=lot, issue=str(it.get("number", "")), title=it.get("title", ""), state="fait",
                       milestone=(it.get("milestone") or {}).get("title"), archive=True)]
    return []


def github(environ=os.environ) -> int:
    cfg = load_config(environ)
    if not (cfg.ci or cfg.lots):
        return 0
    try:
        event = json.loads(Path(environ.get("GITHUB_EVENT_PATH", "")).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        say(Failure("GitHub event", why=type(e).__name__))
        return 0

    def previous(run):
        try:
            return previous_conclusion(run, environ)
        except Failure as e:
            say(e)
            return ""
    deliver(github_notices(environ.get("GITHUB_EVENT_NAME", ""), event, previous), cfg)
    return 0


# ── elrond's agents (Claude Code hooks) ─────────────────────────────────────────────

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


def _state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / "eregion" / "discord.json"


@contextmanager
def running_state():
    """The agents running and the id of the « en cours » message; one writer at a time."""
    import fcntl  # POSIX: the hosts elrond runs on
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_suffix(".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        data.setdefault("running", {})
        yield data
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)


def refresh_status(cfg: Config, data: dict) -> None:
    """Rewrites the one « en cours » message of #agents; a new one if it was deleted."""
    if not cfg.agents:
        return
    # A launch refused after the hook saw it never stops: gone after a day, not shown forever.
    data["running"] = {k: r for k, r in data["running"].items() if time.time() - r.get("since", 0) < 86400}
    rows = sorted(data["running"].values(), key=lambda r: r.get("since", 0))
    lines = [f"`{r['lot']}` {r['step']} · <t:{r['since']}:R>" + (f" · {_cut(r['title'], 60)}" if r.get("title") else "")
             for r in rows]
    payload = {"embeds": [embed("🔄 En cours", "\n".join(lines) or "Rien ne tourne.", BLUE)],
               "allowed_mentions": {"parse": []}}
    mid = data.get("status_message")
    if mid:
        try:
            fetch("PATCH", f"{cfg.agents}/messages/{mid}", "webhook #agents", payload)
            return
        except Failure as e:
            if e.code != 404:
                raise
    data["status_message"] = post_webhook(cfg.agents, {**payload, "flags": SILENT}, "webhook #agents")


def alert(cfg: Config, card: dict) -> None:
    if cfg.agents:
        try:
            post_webhook(cfg.agents, message(card, silent=False, mention=cfg.mention), "webhook #agents")
        except Failure as e:
            say(e)


def _when(ts: str) -> str:
    try:
        return f"<t:{int(datetime.fromisoformat(ts.replace('Z', '+00:00')).timestamp())}:t>"
    except (ValueError, AttributeError):
        return ts


def on_launch(data: dict, cfg: Config, state: dict) -> list[Notice]:
    lot, step, title = parse_description((data.get("tool_input") or {}).get("description", ""))
    state["running"][data.get("tool_use_id") or f"{lot}:{step}"] = {
        "lot": lot, "step": step, "since": int(time.time()), "title": title}
    head = {"worker": "🚀 Lancé", "correction": "🔧 Correction lancée", "relecture": "🔎 Relecture lancée"}[step]
    return [Notice(embed(f"{head} · {lot}", title, BLUE), ci=False, lot=lot, title=title, state=STEP_STATE[step])]


def on_stop(data: dict, cfg: Config, state: dict) -> list[Notice]:
    transcript = Path(str(data.get("agent_transcript_path") or "")).expanduser()
    pal = _palantir()
    meta = pal.meta_of(transcript)
    parsed = parse_description(meta.get("description", ""))
    if not parsed:
        return []
    lot, step, _ = parsed
    key = meta.get("toolUseId")
    if key not in state["running"]:
        key = next((k for k, r in state["running"].items() if (r["lot"], r["step"]) == (lot, step)), None)
    state["running"].pop(key, None)
    scan = pal.scan(transcript, pal.EXPECTED) if transcript.is_file() else {}
    models = ", ".join(f"{m} ×{n}" for m, n in (scan.get("models") or {}).items()) or "—"
    fell = scan.get("verdict") == "review-needed"
    episodes = "\n".join(f"{e['model']} de {_when(e['from'])} à {_when(e['to'])} ({e['responses']} réponses)"
                         for e in scan.get("fallback_episodes") or [])
    stops = len(scan.get("refusals") or [])
    if step == "relecture":
        if fell:
            card = embed(f"⚠️ Relecture non obtenue · {lot}", f"le relecteur a basculé :\n{episodes or f'{stops} arrêt(s)'}",
                         ORANGE)
            alert(cfg, card)
            return [Notice(card, ci=False, lot=lot)]
        verdict = verdict_of(data.get("last_assistant_message", ""))
        if verdict == "ok":
            return [Notice(embed(f"✅ Relecture ok · {lot}", f"modèles : {models}", GREEN), ci=False, lot=lot,
                           state="fait")]
        card = (embed(f"🛠️ Relecture : {verdict} · {lot}", "le lot repart en correction", RED) if verdict
                else embed(f"❔ Relecture sans verdict lisible · {lot}", "lire son rapport", ORANGE))
        alert(cfg, card)
        return [Notice(card, ci=False, lot=lot, state="en correction" if verdict else None)]
    if fell:
        card = embed(f"⚠️ Repli de modèle · {lot}",
                     f"{episodes or f'{stops} arrêt(s) des protections'}\nrelecture en Opus obligatoire", ORANGE)
        alert(cfg, card)
        return [Notice(card, ci=False, lot=lot, state="en relecture")]
    return [Notice(embed(f"📦 Rendu · {lot}", f"modèles : {models}", GREY), ci=False, lot=lot, state="en relecture")]


def wanted(data: dict) -> bool:
    if data.get("hook_event_name") == "PreToolUse":
        inp = data.get("tool_input") or {}
        return (data.get("tool_name") == "Agent" and inp.get("subagent_type") in ELROND_AGENTS
                and parse_description(inp.get("description", "")) is not None)
    return data.get("hook_event_name") == "SubagentStop" and data.get("agent_type") in ELROND_AGENTS


def deliver_hook(data: dict, cfg: Config) -> None:
    with running_state() as state:
        try:
            notices = (on_launch if data["hook_event_name"] == "PreToolUse" else on_stop)(data, cfg, state)
        except Exception as e:  # a transcript or a palantir that changed: said, never raised
            say(Failure("hook", why=type(e).__name__))
            notices = []
        deliver(notices, cfg)
        try:
            refresh_status(cfg, state)
        except Failure as e:
            say(e)


def hook(text: str, environ=os.environ) -> int:
    """Never blocks Claude Code: exit 0 whatever happens, Discord reached in the background."""
    try:
        data = json.loads(text)
        cfg = load_config(environ)
        if not isinstance(data, dict) or not wanted(data) or not (cfg.agents or cfg.lots):
            return 0
        if environ.get("EREGION_DISCORD_SYNC"):
            deliver_hook(data, cfg)
            return 0
        log = _state_path().with_suffix(".log")
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a") as err:
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "deliver"],
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=err,
                                     start_new_session=True)
        child.stdin.write(json.dumps(data).encode())
        child.stdin.close()
    except Exception as e:
        say(Failure("hook", why=type(e).__name__))
    return 0


# ── elrond's own calls, and the setup check ─────────────────────────────────────────

def lot_blocked(lot: str, note: str, cfg: Config) -> int:
    card = embed(f"⛔ Lot bloqué · {lot}", note, RED)
    alert(cfg, card)
    with running_state() as state:
        for k in [k for k, r in state["running"].items() if r["lot"] == lot]:
            state["running"].pop(k)
        deliver([Notice(card, ci=False, lot=lot, state="bloqué")], cfg)
        try:
            refresh_status(cfg, state)
        except Failure as e:
            say(e)
    return 0


def check(cfg: Config) -> int:
    names = {"EREGION_DISCORD_WEBHOOK_CI": cfg.ci, "EREGION_DISCORD_WEBHOOK_AGENTS": cfg.agents,
             "EREGION_DISCORD_BOT_TOKEN": cfg.token, "EREGION_DISCORD_LOTS_FORUM": cfg.forum, "EREGION_DISCORD_MENTION": cfg.mention}
    for k, v in names.items():
        print(f"  {'✓' if v else '·'} {k}")
    if cfg.lots:
        try:
            have = Forum(cfg).tags()
            missing = [t for t in STATE_TAGS + MILESTONE_TAGS if _norm(t) not in have]
            print("  ✓ forum #lots lisible" + (f" — étiquettes manquantes : {', '.join(missing)}" if missing else ""))
        except Failure as e:
            print(f"  ✗ {e}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("github")
    sub.add_parser("hook")
    sub.add_parser("deliver")
    lot = sub.add_parser("lot")
    lot.add_argument("lot")
    lot.add_argument("event", choices=["blocked"])
    lot.add_argument("--note", default="")
    end = sub.add_parser("run-end")
    end.add_argument("text")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    if a.mode == "github":
        return github()
    if a.mode == "hook":
        return hook(sys.stdin.read())
    cfg = load_config()
    if a.mode == "deliver":
        deliver_hook(json.loads(sys.stdin.read()), cfg)
        return 0
    if a.mode == "lot":
        return lot_blocked(a.lot, a.note, cfg)
    if a.mode == "run-end":
        alert(cfg, embed("🏁 Fin du run elrond", a.text, PURPLE))
        return 0
    return check(cfg)


if __name__ == "__main__":
    sys.exit(main())
