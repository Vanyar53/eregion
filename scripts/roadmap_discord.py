#!/usr/bin/env python3
"""roadmap_discord — the road to 1.0 in Discord (N2, #243; docs/atelier-discord.md).

  roadmap_discord.py             in GitHub Actions (roadmap.yml): every push on main, every day,
                                 and when an issue or a pull request opens or closes
  roadmap_discord.py --dry-run   prints the message and what the forum would get; writes nothing

#roadmap — one message of the Eregion bot, rewritten in place (found among the channel's pins,
then its last 50 messages; posted when there is none): a bar per milestone (its issues closed
over all of them), the lots in progress, blocked and still to do, the 1.0 criteria and the five
indicators (ROADMAP.md). A ROADMAP.md that changed shape loses that section, and the message
says so; the run goes on.

#lots — a thread per OPEN issue of the four milestones, « <ID> · <title> · #<n> », created when
missing, its tags true; a closed issue gets no thread, and its open one is tagged « fait » and
archived. The state: « fait » for a closed issue; an open pull request naming the lot makes it
at least « en cours »; elrond's finer states (en relecture, en correction, bloqué, « fait »
while its pull request is open — written by notify_discord.py) are kept; else « à faire ».

Configuration (notify_discord.load_config): EREGION_DISCORD_BOT_TOKEN, EREGION_DISCORD_LOTS_FORUM,
EREGION_DISCORD_ROADMAP_CHANNEL; GITHUB_REPOSITORY, GITHUB_TOKEN, GITHUB_API_URL. What is not
configured is skipped. A Discord or GitHub error is one line on stderr, and exit 0.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import notify_discord as nd

ROOT = Path(__file__).resolve().parents[1]
TITLE = "🗺️ Eregion — vers la 1.0"
WORKING = ("en cours", "en relecture", "en correction")
KEPT = WORKING + ("bloqué",)
DESCRIPTION_MAX, EMBED_MAX = 4096, 6000


@dataclass
class Lot:
    number: str
    title: str
    open: bool
    milestone: str
    lot: str
    url: str
    pr: bool = False

    @property
    def key(self) -> str:
        return self.lot or f"#{self.number}"


# ── GitHub ───────────────────────────────────────────────────────────────────────────

def github_get(path: str, environ) -> list | dict:
    api = environ.get("GITHUB_API_URL", "https://api.github.com")
    auth = {"Authorization": f"Bearer {environ['GITHUB_TOKEN']}"} if environ.get("GITHUB_TOKEN") else {}
    return nd.fetch("GET", f"{api}/repos/{environ.get('GITHUB_REPOSITORY', 'Vanyar53/eregion')}{path}",
                    "GitHub API", headers={"Accept": "application/vnd.github+json", **auth})


def load_github(environ) -> tuple[list, list, list]:
    milestones = github_get("/milestones?state=all&per_page=100", environ)
    issues = []
    for page in range(1, 11):
        batch = github_get(f"/issues?state=all&per_page=100&page={page}", environ)
        issues += batch
        if len(batch) < 100:
            break
    pulls = github_get("/pulls?state=open&per_page=100", environ)
    return milestones, issues, pulls


def lots_of(issues: list, pulls: list) -> list[Lot]:
    """The issues of the four milestones; `pr` when an open pull request names the lot or the issue."""
    refs = [nd.lot_of(branch=(p.get("head") or {}).get("ref", ""), title=p.get("title", ""),
                      body=p.get("body") or "") for p in pulls]
    pr_lots, pr_issues = {lot for lot, _ in refs if lot}, {i for _, i in refs if i}
    out = []
    for i in issues:
        milestone = (i.get("milestone") or {}).get("title")
        if "pull_request" in i or milestone not in nd.MILESTONE_TAGS:   # the issues API lists PRs too
            continue
        n, lot = str(i["number"]), nd.lot_of(title=i.get("title", ""))[0]
        is_open = i.get("state") == "open"
        out.append(Lot(n, i.get("title", ""), is_open, milestone, lot, i.get("html_url", ""),
                       is_open and (n in pr_issues or bool(lot and lot in pr_lots))))
    return sorted(out, key=lambda x: (nd.MILESTONE_TAGS.index(x.milestone), int(x.number)))


# ── #lots ────────────────────────────────────────────────────────────────────────────

def wanted_state(lot: Lot, current: str) -> str:
    if not lot.open:
        return "fait"
    if current in KEPT or (current == "fait" and lot.pr):   # elrond's, kept until GitHub says more
        return current
    return "en cours" if lot.pr else "à faire"


def state_of(thread: dict | None, names: dict[str, str]) -> str:
    for tag in (thread or {}).get("applied_tags") or []:
        name = names.get(str(tag), "")
        if name in (nd._norm(s) for s in nd.STATE_TAGS):
            return next(s for s in nd.STATE_TAGS if nd._norm(s) == name)
    return ""


def card(lot: Lot) -> dict:
    return nd.message(nd.embed(f"{lot.key} · {nd.clean_title(lot.title, lot.lot)}", f"jalon {lot.milestone} · "
                               f"issue #{lot.number}", nd.BLUE, lot.url))


def sync_forum(forum: nd.Forum, lots: list[Lot], dry: bool = False) -> tuple[list[str], dict[str, str]]:
    """One pass over the forum: each open lot's thread made true; (what was done, state by issue)."""
    threads = forum.threads()
    names = {v: k for k, v in forum.tags().items()}
    done, states = [], {}

    def write(what: str, method: str, path: str, body: dict) -> dict:
        done.append(what)
        if dry:
            return {}
        try:
            return forum.call(method, path, body)
        except nd.Failure as e:
            nd.say(e)
            return {}

    for lot in lots:
        t = nd.match_thread(threads, lot.lot, lot.number)
        want = wanted_state(lot, state_of(t, names))
        states[lot.number] = want
        if not lot.open:
            if t and not (t.get("thread_metadata") or {}).get("archived"):
                tags = forum.apply(t.get("applied_tags") or [], want, lot.milestone)
                if not nd.same_tags(tags, t.get("applied_tags") or []):
                    write(f"{lot.key} → fait", "PATCH", f"/channels/{t['id']}", {"applied_tags": tags})
                write(f"{lot.key} archivé", "PATCH", f"/channels/{t['id']}", {"archived": True})
            continue
        name = nd.thread_name(lot.lot, lot.number, lot.title)
        if t is None:
            made = write(f"{name} créé ({want})", "POST", f"/channels/{forum.cfg.forum}/threads",
                         {"name": name, "applied_tags": forum.apply([], want, lot.milestone), "message": card(lot)})
            if made:
                threads.append(made)
            continue
        change = {}
        tags = forum.apply(t.get("applied_tags") or [], want, lot.milestone)
        if not nd.same_tags(tags, t.get("applied_tags") or []):
            change["applied_tags"] = tags
        if (t.get("thread_metadata") or {}).get("archived"):
            change["archived"] = False
        if t.get("name") != name:
            change["name"] = name
        if change:
            write(f"{name} : {', '.join(change)}", "PATCH", f"/channels/{t['id']}", change)
    return done, states


# ── #roadmap ─────────────────────────────────────────────────────────────────────────

def criteria(roadmap: str) -> list[str] | None:
    """« **Critères de la 1.0** : » and its bullets, each cut to its first clause."""
    lines = roadmap.splitlines()
    start = next((i for i, x in enumerate(lines) if x.startswith("**Critères de la 1.0**")), None)
    if start is None:
        return None
    out = []
    for x in lines[start + 1:]:
        if not x.startswith("- "):
            break
        head = re.split(r" : |\. | \(", x[2:].replace("✅", ""), maxsplit=1)[0].strip().rstrip(".")
        out.append(("✅ " if "✅" in x else "☐ ") + nd._cut(head, 80))
    return out or None


def _plain(cell: str) -> str:
    return re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", cell).replace("`", "").strip()


def indicators(roadmap: str) -> list[tuple[str, str]] | None:
    """The five indicators: their name and their « Aujourd'hui »."""
    lines = roadmap.splitlines()
    start = next((i for i, x in enumerate(lines) if x.startswith("| Indicateur |")), None)
    if start is None:
        return None
    out = []
    for x in lines[start + 2:]:
        if not x.startswith("|"):
            break
        cells = [c.strip() for c in x.strip().strip("|").split("|")]
        if len(cells) >= 3:
            out.append((_plain(cells[0]), nd._cut(_plain(cells[2]), 110)))
    return out or None


def bar(done: int, total: int, width: int = 20) -> str:
    full = round(width * done / total) if total else 0
    return "█" * full + "░" * (width - full)


def _keys(lots: list[Lot], limit: int) -> str:
    shown = " · ".join(f"[{x.key}]({x.url})" for x in lots[:limit])
    return shown + (f" … +{len(lots) - limit}" if len(lots) > limit else "")


def render(milestones: list, lots: list[Lot], states: dict[str, str], roadmap: str, *,
           repo: str = "Vanyar53/eregion", sha: str = "", now: str = "") -> dict:
    by_title = {m.get("title"): m for m in milestones}
    out = ["**Jalons**"]
    for m in nd.MILESTONE_TAGS:
        mine = [x for x in lots if x.milestone == m]
        closed = sum(not x.open for x in mine)
        what = re.split(r"\s*[:;]\s*", (by_title.get(m) or {}).get("description") or "", maxsplit=1)[0]
        out.append(f"`{m:<4}` `{bar(closed, len(mine))}` **{closed}/{len(mine)}** · {nd._cut(what, 48)}")
    working = [x for x in lots if x.open and states.get(x.number) in WORKING]
    blocked = [x for x in lots if x.open and states.get(x.number) == "bloqué"]
    ready = [x for x in lots if x.open and states.get(x.number) == "fait"]
    todo = [x for x in lots if x.open and states.get(x.number, "à faire") == "à faire"]
    out += ["", "**En cours** — " + (" · ".join(
        f"[{x.key}]({x.url})" + ("" if states[x.number] == "en cours" else f" ({states[x.number]})")
        for x in working) or "rien")]
    if ready:
        out.append("**Relus, à fusionner** — " + _keys(ready, 15))
    if blocked:
        out.append("**Bloqués** — " + _keys(blocked, 15))
    out.append("**À faire**")
    for m in nd.MILESTONE_TAGS:
        mine = [x for x in todo if x.milestone == m]
        if mine:
            out.append(f"`{m:<4}` ({len(mine)}) " + _keys(mine, 18))
    crit = criteria(roadmap)
    out += ["", "**Pour la 1.0**"] + (crit if crit is not None else ["_section introuvable dans ROADMAP.md_"])
    ind = indicators(roadmap)
    out += ["", "**Les cinq indicateurs** — aujourd'hui"]
    out += [f"• **{name}** — {today}" for name, today in ind] if ind is not None \
        else ["_tableau introuvable dans ROADMAP.md_"]
    text = "\n".join(out)
    if len(text) > DESCRIPTION_MAX - 100:   # Discord refuses the whole message beyond its limits
        text = text[: DESCRIPTION_MAX - 120].rsplit("\n", 1)[0] + "\n… (tronqué : voir ROADMAP.md)"
    e = nd.embed(TITLE, text, nd.PURPLE, f"https://github.com/{repo}/milestones")
    e["footer"] = {"text": nd._cut(f"main {sha[:7]} · jalons GitHub et ROADMAP.md", 200)}
    if now:
        e["timestamp"] = now
    return e


def upsert(forum: nd.Forum, channel: str, card_: dict) -> str:
    """The bot's own roadmap message: pinned first, else among the last 50; else a new one."""
    me = str(forum.call("GET", "/users/@me", label="#roadmap").get("id"))
    payload = {"embeds": [card_], "allowed_mentions": {"parse": []}}
    for where in ("pins", "messages?limit=50"):
        try:
            found = forum.call("GET", f"/channels/{channel}/{where}", label="#roadmap")
        except nd.Failure:
            continue
        for m in found if isinstance(found, list) else []:
            title = ((m.get("embeds") or [{}])[0] or {}).get("title", "")
            if str((m.get("author") or {}).get("id")) == me and title.startswith(TITLE):
                forum.call("PATCH", f"/channels/{channel}/messages/{m['id']}", payload, label="#roadmap")
                return "edited"
    forum.call("POST", f"/channels/{channel}/messages", {**payload, "flags": nd.SILENT}, label="#roadmap")
    return "posted"


def main(argv=None, environ=os.environ) -> int:
    dry = "--dry-run" in (sys.argv[1:] if argv is None else argv)
    cfg = nd.load_config(environ)
    if not dry and not (cfg.token and (cfg.forum or cfg.roadmap)):
        return 0
    nd.RETRY_MAX_S = 30.0   # a batch: wait out Discord's rate limit rather than skip
    try:
        milestones, issues, pulls = load_github(environ)
    except nd.Failure as e:
        nd.say(e)
        return 0
    lots = lots_of(issues, pulls)
    try:
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
    except OSError:
        roadmap = ""
    forum = nd.Forum(cfg)
    done, states = [], {x.number: wanted_state(x, "") for x in lots}
    if cfg.lots:
        try:
            done, states = sync_forum(forum, lots, dry)
        except nd.Failure as e:
            nd.say(e)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    message = render(milestones, lots, states, roadmap, repo=environ.get("GITHUB_REPOSITORY", "Vanyar53/eregion"),
                     sha=environ.get("GITHUB_SHA", ""), now=now)
    if dry:
        print(message["description"])
        print("\n#lots :\n" + ("\n".join(f"  {x}" for x in done) or "  rien à changer"))
        return 0
    if cfg.roadmap and cfg.token:
        try:
            print(f"#roadmap : {upsert(forum, cfg.roadmap, message)} · #lots : {len(done)} changement(s)")
        except nd.Failure as e:
            nd.say(e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
