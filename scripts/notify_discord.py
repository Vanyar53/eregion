#!/usr/bin/env python3
"""notify_discord — the workshop's news in Discord (N1, #242; docs/atelier-discord.md).

  notify_discord.py github        in GitHub Actions (notify.yml): reads $GITHUB_EVENT_NAME and
                                  $GITHUB_EVENT_PATH — CI results, pull requests, releases, closed
                                  issues to #ci, and a lot's events to its thread as well
  notify_discord.py check         what is configured (names, never values), what the forum lacks

Where things go. #ci: a pull request opened or merged, a red CI (pull request, main, the
nightly runs), main green again after red, a published release, a closed issue. #lots: one
thread per lot, every event of the lot, its tags (milestone, state) kept true. Only a red CI
and a release notify; the rest is silent. elrond's lots and #agents: scripts/agents_discord.py
(N3), which shares this module's plumbing; a published release deletes its draft's line and
ping there (REL1, EREGION_DISCORD_WEBHOOK_AGENTS).

Configuration: the environment, over ~/.config/eregion/discord.env (KEY=value lines; another
file: EREGION_DISCORD_ENV) — EREGION_DISCORD_WEBHOOK_CI, EREGION_DISCORD_WEBHOOK_AGENTS (webhook URLs),
EREGION_DISCORD_BOT_TOKEN and EREGION_DISCORD_LOTS_FORUM (the Eregion bot, the workshop's, never Glorfindel's, and the forum's
id), EREGION_DISCORD_MENTION (a user id). What is not configured is not sent. A Discord error never
fails the caller: one line on stderr, without the URL or the token, and exit 0.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEYS = ("EREGION_DISCORD_WEBHOOK_CI", "EREGION_DISCORD_WEBHOOK_AGENTS", "EREGION_DISCORD_BOT_TOKEN",
        "EREGION_DISCORD_LOTS_FORUM", "EREGION_DISCORD_MENTION", "EREGION_DISCORD_API",
        "EREGION_DISCORD_ROADMAP_CHANNEL", "EREGION_DISCORD_WEBHOOK_DEPLOY")
UA = "DiscordBot (https://github.com/Vanyar53/eregion, 1)"
SILENT = 1 << 12  # SUPPRESS_NOTIFICATIONS: shown in the channel, no push, no sound
RED, GREEN, BLUE, PURPLE, ORANGE, GREY = 0xE5484D, 0x30A46C, 0x3E63DD, 0x8E4EC6, 0xF76B15, 0x8B8D98
RETRY_MAX_S = 5.0  # the longest 429 wait taken; a batch (roadmap_discord.py) can wait longer
RED_CONCLUSIONS = {"failure", "timed_out", "startup_failure"}
STATE_TAGS = ("à faire", "en cours", "en relecture", "en correction", "fait", "bloqué")
MILESTONE_TAGS = ("v0.3", "v0.x", "v1.0", "v1.x")
LOT_ID = r"[A-Z]{1,3}-?\d+[A-Z]?"
# Who may move a lot's thread through an issue (SEC6, N-11): its author holds a role in the
# repository. Anyone may open an issue, and close their own.
MEMBERS = {"OWNER", "MEMBER", "COLLABORATOR"}


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
    roadmap: str = ""
    deploy: str = ""   # #deploy's webhook: the CD of H0 posts with it (H1), never the bot's token
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
    # Stripped: a value ending in a newline made http.client quote the URL — token and all.
    values.update({k: environ[k].strip() for k in KEYS if (environ.get(k) or "").strip()})
    mention = values.get("EREGION_DISCORD_MENTION", "")
    return Config(ci=values.get("EREGION_DISCORD_WEBHOOK_CI", "").rstrip("/"),
                  agents=values.get("EREGION_DISCORD_WEBHOOK_AGENTS", "").rstrip("/"),
                  token=values.get("EREGION_DISCORD_BOT_TOKEN", ""), forum=values.get("EREGION_DISCORD_LOTS_FORUM", ""),
                  mention=mention if mention.isdigit() else "",
                  roadmap=values.get("EREGION_DISCORD_ROADMAP_CHANNEL", ""),
                  deploy=values.get("EREGION_DISCORD_WEBHOOK_DEPLOY", "").rstrip("/"),
                  api=(values.get("EREGION_DISCORD_API") or Config.api).rstrip("/"))


def fetch(method: str, url: str, label: str, body=None, headers=None, raw: bytes | None = None):
    """JSON in (or `raw`, typed by `headers`), JSON out; one more try after a 429 that asks for
    RETRY_MAX_S or less."""
    data = raw if raw is not None else json.dumps(body).encode() if body is not None else None
    head = {"User-Agent": UA, "Content-Type": "application/json", **(headers or {})}
    for attempt in (1, 2):
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=head)
            with urllib.request.urlopen(req, timeout=8) as r:
                raw = r.read()
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            wait = _retry_after(e)
            if e.code == 429 and attempt == 1 and wait <= RETRY_MAX_S:
                time.sleep(wait)
                continue
            raise Failure(label, e.code) from None
        except Exception as e:  # URLError, http.client's errors: InvalidURL quotes the URL, token and all
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


def clean_title(title: str, lot: str = "") -> str:
    """A thread's title: no commit prefix (feat(x):), no lot id ahead, no (ID, #n) at the end."""
    t = re.sub(r"^\s*\w+(?:\([^)]*\))?!?:\s+", "", title or "")
    t = re.sub(r"\s*\((?:[A-Z0-9-]+\s*,\s*)?#\d+\)\s*$", "", t)
    if lot:
        t = re.sub(rf"^\s*{re.escape(lot)}\b\s*(?:[—:·-]\s*)?", "", t)
    return t.strip()


def thread_name(lot: str, issue: str, title: str) -> str:
    """« <ID> · <title> · #<n> » — the issue's number last, so two issues of one lot id differ."""
    tail = f" · #{issue}" if issue and lot else ""
    head = " · ".join(x for x in (lot or (f"#{issue}" if issue else ""), clean_title(title, lot)) if x)
    return _cut(head, 100 - len(tail)) + tail


def same_tags(a: list, b: list) -> bool:
    """Discord gives a thread's tags back in its own order: compared as a set, never in order."""
    return sorted(map(str, a)) == sorted(map(str, b))


def match_thread(threads: list[dict], lot: str = "", issue: str = "") -> dict | None:
    """The issue's own thread first; else the lot's, unless that one names another issue."""
    if issue:
        for t in threads:
            # Its number where a name puts it — last (« <ID> · <title> · #<n> ») or first (« #<n> · … »),
            # never a « #70 » quoted inside a lot's title.
            if re.search(rf"^#{issue} · |· #{issue}$", t.get("name", "")):
                return t
    if lot:
        for t in threads:
            name = t.get("name", "")
            other = re.search(r"#(\d+)\b", name)
            if (name == lot or name.startswith(f"{lot} · ")) and not (issue and other and other.group(1) != issue):
                return t
    return None


class Forum:
    """The #lots forum, through the Eregion bot: a thread per lot, named « <ID> · <title> »."""

    def __init__(self, cfg: Config):
        self.cfg, self._channel = cfg, None

    def call(self, method: str, path: str, body=None, label: str = "forum #lots"):
        return fetch(method, self.cfg.api + path, label, body,
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
            before = "&before=" + urllib.parse.quote(page["threads"][-1]["thread_metadata"]["archive_timestamp"],
                                                     safe="")
        return found

    def find(self, lot: str = "", issue: str = "") -> dict | None:
        return match_thread(self.threads(), lot, issue)

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

    def post(self, n: "Notice", payload: dict) -> tuple[dict | None, str]:
        """The thread and the id of the message posted in it (a forum post's first message has the
        thread's id); (None, "") when there is no thread and none to create."""
        t = self.find(n.lot, n.issue)
        if t is None:
            if not n.create:
                return None, ""
            t = self.call("POST", f"/channels/{self.cfg.forum}/threads",
                          {"name": thread_name(n.lot, n.issue, n.title),
                           "applied_tags": self.apply([], n.state, n.milestone),
                           "message": payload})
            mid = str(t["id"])
        else:
            change = {}
            tags = self.apply(t.get("applied_tags") or [], n.state, n.milestone)
            if not same_tags(tags, t.get("applied_tags") or []):
                change["applied_tags"] = tags
            if (t.get("thread_metadata") or {}).get("archived"):
                change["archived"] = False
            if change:
                self.call("PATCH", f"/channels/{t['id']}", change)
            mid = str(self.call("POST", f"/channels/{t['id']}/messages", payload).get("id") or "")
        if n.archive:
            self.call("PATCH", f"/channels/{t['id']}", {"archived": True})
        return t, mid

    def attach(self, thread: str, filename: str, text: str) -> None:
        """A text file in a thread, silent: an agent's whole report, too long for a card."""
        boundary = "eregion-" + os.urandom(8).hex()
        payload = {"flags": SILENT, "allowed_mentions": {"parse": []},
                   "attachments": [{"id": 0, "filename": filename}]}
        raw = (f'--{boundary}\r\nContent-Disposition: form-data; name="payload_json"\r\n'
               f'Content-Type: application/json\r\n\r\n{json.dumps(payload)}\r\n'
               f'--{boundary}\r\nContent-Disposition: form-data; name="files[0]"; filename="{filename}"\r\n'
               f'Content-Type: text/markdown; charset=utf-8\r\n\r\n').encode() + text.encode() + f"\r\n--{boundary}--\r\n".encode()
        fetch("POST", f"{self.cfg.api}/channels/{thread}/messages", "forum #lots", raw=raw,
              headers={"Authorization": f"Bot {self.cfg.token}",
                       "Content-Type": f"multipart/form-data; boundary={boundary}"})


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


def own_run(run: dict) -> bool:
    """A run of this repository's own branch. A fork's pull request runs here too
    (workflow_run), on the fork's head: its branch name and title are the fork's to choose."""
    head = (run.get("head_repository") or {}).get("full_name")
    return bool(head) and head == (run.get("repository") or {}).get("full_name")


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
            if not own_run(run):
                lot = issue = ""   # a fork's red run: #ci only, never a lot's thread
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
        repo = lambda side: (((pr.get(side) or {}).get("repo")) or {}).get("full_name")  # noqa: E731
        if repo("head") != repo("base"):
            lot = issue = ""   # a fork's pull request: #ci only, never a lot's thread (its title names any lot)
        milestone = (pr.get("milestone") or {}).get("title")
        head = f"#{pr.get('number')} {pr.get('title', '')}"
        if action == "opened":
            return [Notice(embed(f"📬 PR ouverte · {head}", "", BLUE, pr.get("html_url", "")),
                           lot=lot, issue=issue, title=pr.get("title", ""), milestone=milestone, create=bool(lot))]
        if action == "closed" and pr.get("merged"):
            return [Notice(embed(f"🔀 PR fusionnée · {head}", "", PURPLE, pr.get("html_url", "")),
                           lot=lot, issue=issue, title=pr.get("title", ""), state="fait", milestone=milestone,
                           create=bool(lot))]
        return []
    if name == "release" and event.get("action") == "published":
        rel = event.get("release") or {}
        pre = " (pré-version)" if rel.get("prerelease") else ""
        return [Notice(embed(f"🏷️ {rel.get('tag_name', '?')} publiée{pre}", rel.get("name") or "", GREEN,
                             rel.get("html_url", "")), silent=False)]
    if name == "issues" and event.get("action") == "closed":
        it = event.get("issue") or {}
        lot, _ = lot_of(title=it.get("title", ""))
        number = str(it.get("number", ""))
        if it.get("author_association") not in MEMBERS:
            lot = number = ""   # an outsider's issue: #ci only — no lot's thread tagged nor archived
        why = " (abandonnée)" if it.get("state_reason") == "not_planned" else ""
        return [Notice(embed(f"✅ #{it.get('number')} fermée{why} · {it.get('title', '')}", "", GREEN,
                             it.get("html_url", "")),
                       lot=lot, issue=number, title=it.get("title", ""), state="fait",
                       milestone=(it.get("milestone") or {}).get("title"), archive=True, create=bool(lot))]
    return []


BOARD_TITLE = "📋 elrond"   # #agents' board (scripts/agents_discord.py)


def release_waiting(tag: str) -> str:
    """A draft's line on #agents' board (scripts/agents_discord.py), and its ping's title."""
    return f"release {tag} en brouillon, à publier"


def _titled(cfg: Config, mid: str, title: str) -> dict | None:
    """The webhook's message `mid` if its card bears `title`; None otherwise (another message,
    or gone). Ids from a release's notes may name any message the webhook posted."""
    try:
        msg = fetch("GET", f"{cfg.agents}/messages/{mid}", "webhook #agents")
    except Failure as f:
        if f.code != 404:   # 404: deleted already, by the board's refresh or by hand
            say(f)
        return None
    card = (msg.get("embeds") or [{}])[0]
    return msg if isinstance(card, dict) and card.get("title") == title else None


def release_published(event: dict, cfg: Config) -> None:
    """A release published: its draft's ping and its line on #agents' board go (REL1). This job
    has no local state: scripts/release.py wrote where they are in the draft's notes, an HTML
    comment (`<!-- #agents (REL1) : ping=<id> board=<id> … -->`). Ids only, digits: nothing else
    from the notes reaches a URL. Each message is read first: the ping is deleted only if it is this
    draft's ping (its card's title), the board rewritten only if it is the board, and only this
    draft's line taken out. A board deleted or rewritten meanwhile: left to the next refresh."""
    rel = event.get("release") or {}
    tag = str(rel.get("tag_name") or "")
    marker = re.search(r"<!-- #agents \(REL1\) : ping=(\d{0,20}) board=(\d{0,20}) ", rel.get("body") or "")
    if not (cfg.agents and marker and re.fullmatch(r"v\d+\.\d+\.\d+", tag)):
        return
    ping, board = marker.groups()
    if ping and _titled(cfg, ping, "🙋 " + release_waiting(tag)):
        try:
            fetch("DELETE", f"{cfg.agents}/messages/{ping}", "webhook #agents")
        except Failure as f:
            if f.code != 404:
                say(f)
    msg = _titled(cfg, board, BOARD_TITLE) if board else None
    if msg is None:
        return
    try:
        card = dict(msg["embeds"][0])
        lines = str(card.get("description") or "").split("\n")
        kept = [x for x in lines if release_waiting(tag) not in x]
        if kept == lines:
            return
        at = kept.index("**🙋 T'attend**") + 1 if "**🙋 T'attend**" in kept else -1
        if at > 0 and (at == len(kept) or not kept[at].strip()):
            kept.insert(at, "Rien ne t'attend.")
            card["color"] = GREY if "Rien ne tourne." in kept else BLUE
        card["description"] = "\n".join(kept)
        fetch("PATCH", f"{cfg.agents}/messages/{board}", "webhook #agents",
              {"embeds": [card], "allowed_mentions": {"parse": []}})
    except Failure as f:
        if f.code != 404:
            say(f)


def github(environ=os.environ) -> int:
    cfg = load_config(environ)
    if not (cfg.ci or cfg.lots or cfg.agents):
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
    name = environ.get("GITHUB_EVENT_NAME", "")
    deliver(github_notices(name, event, previous), cfg)
    if name == "release" and event.get("action") == "published":
        release_published(event, cfg)
    return 0


# ── the setup check ────────────────────────────────────────────────────────────────

def check(cfg: Config) -> int:
    names = {"EREGION_DISCORD_WEBHOOK_CI": cfg.ci, "EREGION_DISCORD_WEBHOOK_AGENTS": cfg.agents,
             "EREGION_DISCORD_BOT_TOKEN": cfg.token, "EREGION_DISCORD_LOTS_FORUM": cfg.forum,
             "EREGION_DISCORD_MENTION": cfg.mention, "EREGION_DISCORD_ROADMAP_CHANNEL": cfg.roadmap}
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
    sub.add_parser("check")
    a = ap.parse_args(argv)
    if a.mode == "github":
        return github()
    return check(load_config())

if __name__ == "__main__":
    sys.exit(main())
