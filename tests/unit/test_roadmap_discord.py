"""roadmap_discord (N2, #243) — the road to 1.0 in Discord, against a fake Discord and GitHub.

The fake (tests/unit/fake_discord.py) serves the bot's #roadmap and #lots and GitHub's
milestones, issues and pull requests on the loopback: nothing leaves the machine.
"""
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from .fake_discord import BOT_ID, TAG, FakeDiscord

ROOT = Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod   # roadmap_discord imports notify_discord; dataclasses look up their module
    spec.loader.exec_module(mod)
    return mod


nd = _load("notify_discord")
rd = _load("roadmap_discord")

ROADMAP = """# Roadmap

| Indicateur | Ce qu'il mesure | Aujourd'hui |
|---|---|---|
| Temps pour contenir | de la première action à l'action vérifiée | 84 s à 3 min 30 |
| Part contenue seule | sans humain | non mesurée |
| Couverture | sur le catalogue | 6 TTPs validés (`technique_catalog.yaml`) |

**Critères de la 1.0** :
- Critères de maturité de Glorfindel remplis (liste « Critères avant le mode autonome ») : l'autonomie est permise.
- Contrats publics figés et versionnés : signaux, schéma.
- ✅ Les profils s'installent et tournent, prouvé en CI.

La suite.
"""


def issue(n, title, state="open", milestone="v0.x"):
    return {"number": n, "title": title, "state": state, "html_url": f"https://x/issues/{n}",
            "milestone": {"title": milestone} if milestone else None}


def pull(n, title, branch, body=""):
    return {"number": n, "title": title, "head": {"ref": branch}, "body": body}


@pytest.fixture
def fake(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("EREGION_DISCORD_") or k.startswith("GITHUB_"):
            monkeypatch.delenv(k)
    monkeypatch.setenv("EREGION_DISCORD_ENV", str(tmp_path / "absent.env"))
    monkeypatch.setattr(rd, "ROOT", tmp_path)
    (tmp_path / "ROADMAP.md").write_text(ROADMAP, encoding="utf-8")
    f = FakeDiscord()
    f.gh["milestones"] = [{"title": "v0.3", "description": "La boucle tourne : Orodruin…"},
                          {"title": "v0.x", "description": "La mesure ; la preuve"}]
    f.gh["issues"] = [
        issue(10, "O1 — Orodruin", "closed", "v0.3"), issue(11, "H0 — Glorfindel hébergé", "open", "v0.3"),
        issue(73, "A3 — Retrait des règles orphelines"), issue(67, "B1 — Mistral"),
        issue(226, "I1F : un NSG modifié", "closed"), issue(231, "I1F suite : une carte"),
        issue(200, "Sans jalon", milestone=None),
        {"number": 247, "title": "une PR", "state": "open", "pull_request": {}, "milestone": {"title": "v0.x"}},
    ]
    f.gh["pulls"] = [pull(247, "feat(isolation): orphelines (A3, #73)", "lot/a3-orphelines")]
    yield f
    f.close()


def configure(monkeypatch, f, *, forum=True, roadmap=True):
    monkeypatch.setenv("EREGION_DISCORD_API", f.base + "/api")
    monkeypatch.setenv("GITHUB_API_URL", f.base + "/gh")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("EREGION_DISCORD_BOT_TOKEN", "BOT-SECRET")
    if forum:
        monkeypatch.setenv("EREGION_DISCORD_LOTS_FORUM", "FORUM")
    if roadmap:
        monkeypatch.setenv("EREGION_DISCORD_ROADMAP_CHANNEL", "ROADMAP")


def by_number(f):
    return {t["name"].rsplit("#", 1)[-1]: t for t in f.threads}


# ── nothing configured, nothing broken ─────────────────────────────────────────────

def test_nothing_configured_sends_nothing(fake, capsys):
    assert rd.main([]) == 0
    assert fake.requests == [] and capsys.readouterr().err == ""


def test_a_github_or_discord_error_is_said_never_raised(fake, monkeypatch, capsys):
    configure(monkeypatch, fake)
    fake.fail["/gh/"] = 502
    assert rd.main([]) == 0
    fake.fail = {"/api/channels/ROADMAP": 500}
    assert rd.main([]) == 0
    err = capsys.readouterr().err
    assert "GitHub API: HTTP 502" in err and "#roadmap: HTTP 500" in err and "BOT-SECRET" not in err


def test_a_dry_run_reads_but_never_writes(fake, monkeypatch, capsys):
    configure(monkeypatch, fake)
    fake.thread("A3 · vieux nom", [TAG["à faire"]])
    assert rd.main(["--dry-run"]) == 0
    assert fake.writes() == []
    out = capsys.readouterr().out
    assert "**Jalons**" in out and "B1 · Mistral · #67 créé (à faire)" in out


# ── #roadmap: one message, the bot's, rewritten in place ───────────────────────────

def test_the_message_is_posted_once_then_rewritten_in_place(fake, monkeypatch):
    configure(monkeypatch, fake, forum=False)
    rd.main([])
    rd.main([])
    posts = [r for r in fake.writes("/api/channels/ROADMAP") if r["method"] == "POST"]
    edits = [r for r in fake.writes("/api/channels/ROADMAP") if r["method"] == "PATCH"]
    assert len(posts) == 1 and len(edits) == 1 and len(fake.roadmap) == 1
    assert posts[0]["body"]["flags"] == nd.SILENT and posts[0]["body"]["allowed_mentions"] == {"parse": []}


def test_the_pinned_message_is_found_and_someone_elses_never_edited(fake, monkeypatch):
    configure(monkeypatch, fake, forum=False)
    mine = fake.roadmap_message(rd.TITLE, pinned=True)
    for _ in range(60):                                 # pushed out of the last 50 by chatter
        fake.roadmap_message("bavardage", author="someone")
    theirs = fake.roadmap_message(rd.TITLE, author="someone")
    rd.main([])
    (edit,) = [r for r in fake.writes("/api/channels/ROADMAP")]
    assert edit["method"] == "PATCH" and edit["path"].endswith(f"/messages/{mine['id']}")
    assert theirs["embeds"] == [{"title": rd.TITLE}]


def test_someone_elses_message_is_never_taken_for_the_bots(fake, monkeypatch):
    configure(monkeypatch, fake, forum=False)
    theirs = fake.roadmap_message(rd.TITLE, author="someone", pinned=True)
    rd.main([])
    assert [r["method"] for r in fake.writes("/api/channels/ROADMAP")] == ["POST"]
    assert theirs["embeds"] == [{"title": rd.TITLE}]


def test_a_deleted_message_is_posted_again(fake, monkeypatch):
    configure(monkeypatch, fake, forum=False)
    rd.main([])
    fake.roadmap.clear()
    rd.main([])
    assert [r["method"] for r in fake.writes("/api/channels/ROADMAP")] == ["POST", "POST"]


# ── what the message says ──────────────────────────────────────────────────────────

def test_a_bar_per_milestone_counts_its_closed_issues(fake):
    lots = rd.lots_of(fake.gh["issues"], fake.gh["pulls"])
    states = {x.number: rd.wanted_state(x, "") for x in lots}
    text = rd.render(fake.gh["milestones"], lots, states, ROADMAP)["description"]
    assert f"`v0.3` `{rd.bar(1, 2)}` **1/2** · La boucle tourne" in text
    assert f"`v0.x` `{rd.bar(1, 4)}` **1/4** · La mesure" in text         # the PR and the issue without milestone left out
    assert "`v1.0` `░░░░░░░░░░░░░░░░░░░░` **0/0**" in text


def test_in_progress_blocked_and_to_do(fake):
    lots = rd.lots_of(fake.gh["issues"], fake.gh["pulls"])
    states = {x.number: rd.wanted_state(x, "") for x in lots} | {"231": "bloqué"}
    text = rd.render(fake.gh["milestones"], lots, states, ROADMAP)["description"]
    assert "**En cours** — [A3](https://x/issues/73)" in text       # an open PR names it
    assert "**Bloqués** — [I1F](https://x/issues/231)" in text
    todo = text.split("**À faire**")[1].split("**Pour la 1.0**")[0]
    assert "[B1]" in todo and "[H0]" in todo and "[A3]" not in todo and "[O1]" not in todo


def test_the_criteria_and_the_indicators_come_from_the_roadmap(fake):
    text = rd.render([], [], {}, ROADMAP)["description"]
    assert "☐ Critères de maturité de Glorfindel remplis\n☐ Contrats publics figés et versionnés\n" \
           "✅ Les profils s'installent et tournent, prouvé en CI" in text
    assert "• **Couverture** — 6 TTPs validés (technique_catalog.yaml)" in text


def test_a_roadmap_that_changed_shape_loses_a_section_not_the_run(fake, monkeypatch):
    configure(monkeypatch, fake, forum=False)
    (rd.ROOT / "ROADMAP.md").write_text("# Roadmap\n\nTout a changé.\n", encoding="utf-8")
    assert rd.main([]) == 0
    text = fake.roadmap[0]["embeds"][0]["description"]
    assert "_section introuvable dans ROADMAP.md_" in text and "_tableau introuvable dans ROADMAP.md_" in text


def test_the_message_stays_under_discords_limits(fake):
    lots = [rd.Lot(str(n), f"Z{n} — " + "un titre long " * 8, True, "v0.x", f"Z{n}", f"https://x/{n}")
            for n in range(1, 400)]
    states = {x.number: "en cours" for x in lots}
    e = rd.render(fake.gh["milestones"], lots, states, ROADMAP * 3)
    assert len(e["description"]) <= rd.DESCRIPTION_MAX
    assert len(e["title"]) + len(e["description"]) + len(e["footer"]["text"]) <= rd.EMBED_MAX
    assert e["description"].endswith("(tronqué : voir ROADMAP.md)")


# ── #lots: a thread per open lot, its tags true ────────────────────────────────────

def test_open_lots_get_a_thread_closed_ones_none(fake, monkeypatch):
    configure(monkeypatch, fake, roadmap=False)
    rd.main([])
    threads = by_number(fake)
    assert sorted(threads) == ["11", "231", "67", "73"]               # O1 and I1F (#226) are closed
    assert threads["73"]["name"] == "A3 · Retrait des règles orphelines · #73"
    assert sorted(threads["73"]["applied_tags"]) == sorted([TAG["en cours"], TAG["v0.x"]])
    assert sorted(threads["67"]["applied_tags"]) == sorted([TAG["à faire"], TAG["v0.x"]])
    assert threads["67"]["posts"][0]["flags"] == nd.SILENT
    rd.main([])
    assert len(fake.threads) == 4 and not [r for r in fake.writes("/api/channels/") if r["method"] == "PATCH"]


def test_elronds_finer_states_are_kept(fake, monkeypatch):
    configure(monkeypatch, fake, roadmap=False)
    review = fake.thread("B1 · Mistral · #67", [TAG["en relecture"], TAG["v0.x"]])
    blocked = fake.thread("H0 · Glorfindel hébergé · #11", [TAG["bloqué"], TAG["v0.3"]])
    rd.main([])
    assert TAG["en relecture"] in review["applied_tags"] and TAG["bloqué"] in blocked["applied_tags"]


def test_a_closed_lot_is_done_and_archived_a_reopened_one_comes_back(fake, monkeypatch):
    configure(monkeypatch, fake, roadmap=False)
    gone = fake.thread("O1 · Orodruin · #10", [TAG["en cours"], TAG["v0.3"]])
    back = fake.thread("B1 · Mistral · #67", [TAG["fait"], TAG["v0.x"]], archived=True)
    rd.main([])
    assert gone["thread_metadata"]["archived"] and sorted(gone["applied_tags"]) == sorted([TAG["fait"], TAG["v0.3"]])
    assert not back["thread_metadata"]["archived"] and TAG["à faire"] in back["applied_tags"]


def test_the_thread_elrond_made_is_found_and_renamed_not_doubled(fake, monkeypatch):
    configure(monkeypatch, fake, roadmap=False)
    t = fake.thread("A3 · règles orphelines", [TAG["en relecture"]])
    rd.main([])
    assert len([x for x in fake.threads if x["name"].startswith("A3 ·")]) == 1
    assert t["name"] == "A3 · Retrait des règles orphelines · #73"
    assert sorted(t["applied_tags"]) == sorted([TAG["en relecture"], TAG["v0.x"]])


def test_two_issues_of_one_lot_id_get_two_threads(fake, monkeypatch):
    configure(monkeypatch, fake, roadmap=False)
    old = fake.thread("I1F · un NSG modifié · #226", [TAG["fait"]], archived=True)
    rd.main([])
    new = by_number(fake)["231"]
    assert new is not old and new["name"] == "I1F · suite : une carte · #231"
    assert old["name"] == "I1F · un NSG modifié · #226" and old["thread_metadata"]["archived"]


@pytest.mark.parametrize("lot, issue, title, name", [
    ("A3", "73", "A3 — Retrait des règles orphelines", "A3 · Retrait des règles orphelines · #73"),
    ("A3", "", "règles orphelines", "A3 · règles orphelines"),
    ("I1F", "226", "fix(glorfindel): un NSG modifié (I1F, #226)", "I1F · un NSG modifié · #226"),
    ("", "222", "Console : finitions", "#222 · Console : finitions"),
    ("UI-2", "206", "Console Eregion (UI-2) : les indicateurs", "UI-2 · Console Eregion (UI-2) : les indicateurs · #206"),
])
def test_a_thread_is_named_id_title_number(lot, issue, title, name):
    assert nd.thread_name(lot, issue, title) == name


def test_a_long_title_keeps_its_number():
    name = nd.thread_name("C3", "200", "C3 — " + "Charges IA d'Azure " * 10)
    assert len(name) <= 100 and name.endswith(" · #200")


def test_the_bot_is_the_author_it_looks_for():
    assert BOT_ID == "BOT"   # the fake's /users/@me — upsert matches on it, never on a name
