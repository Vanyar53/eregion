"""The Eregion console (docs/design/console.md): its pages, the former addresses, the token and
its former name, and the sections — Glorfindel always, Annatar and Gothmog when this host
holds their runs, or as --sections chooses.

No Azure, no LLM: runs/ is a tmp directory, the windows are written there.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from click.testing import CliRunner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from .console_client import ORIGIN, TOKEN, WS, console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_console import sections  # noqa: E402

PAGES = ("/", "/glorfindel", "/annatar", "/gothmog", "/config")
NOW = datetime.now(timezone.utc)


@pytest.fixture()
def runs(tmp_path, monkeypatch):
    """runs/ in tmp, the console's working directory; the windows where the conftest puts them."""
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    d = tmp_path / "runs"
    d.mkdir()
    return d


@pytest.fixture()
def client(runs):
    return console()


def _window(tmp_path, run_id, injector, kind="technique"):
    exercises = tmp_path / "exercises"
    exercises.mkdir(exist_ok=True)
    start = NOW - timedelta(minutes=30)
    (exercises / f"{run_id}.json").write_text(json.dumps({
        "run_id": run_id, "injector": injector, "kind": kind, "experiment": "x y",
        "targets": ["/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"],
        "start": start.isoformat(), "end": (start + timedelta(minutes=3)).isoformat(),
        "expires": (start + timedelta(hours=2)).isoformat()}))


# ── Pages ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path, page", [("/", "overview.html"), ("/glorfindel", "glorfindel.html"),
                                        ("/config", "glorfindel.html"), ("/annatar", "injector.html"),
                                        ("/gothmog", "injector.html")])
def test_each_section_has_its_page(client, path, page):
    r = client.get(path)
    assert r.status_code == 200
    assert r.text == (api._STATIC / page).read_text(encoding="utf-8")
    assert 'id="console-header"' in r.text and "/static/console.js" in r.text


def test_pages_and_their_scripts_revalidate_on_each_load(client):
    """A page left in the browser's cache showed the old console on H0 after a redeployment
    (#197): pages and scripts revalidate (ETag), the API is left alone."""
    for path in (*PAGES, "/static/console.js"):
        assert client.get(path).headers.get("cache-control") == "no-cache", path
    assert "cache-control" not in client.get("/api/sections").headers


def test_every_response_carries_the_content_security_policy(client, monkeypatch):
    """M568: never framed by another page (Approve & execute under a decoy), never talking to
    another origin — pages, scripts, API, and the token page a browser gets without its token."""
    for path in (*PAGES, "/static/console.js", "/api/sections"):
        csp = client.get(path).headers.get("content-security-policy", "")
        assert "frame-ancestors 'none'" in csp and "connect-src 'self'" in csp, path
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "s3cret")
    page = console(token=None).get("/", headers={"accept": "text/html"})
    assert page.status_code == 401 and "frame-ancestors 'none'" in page.headers["content-security-policy"]


# ── The former addresses ──────────────────────────────────────────────────────────────

def test_the_atelier_leads_to_the_overview_with_its_query(client):
    """M400, M401: a bookmark of the atelier still opens the console."""
    r = client.get("/atelier?since=30d", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/?since=30d"
    assert client.get("/atelier", follow_redirects=False).headers["location"] == "/"


def test_the_atelier_api_redirects_to_its_resource_with_its_query(client):
    """Until 1.0: a page left in a browser's cache still reads (M401)."""
    r = client.get("/api/atelier/exercises?since=7d", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "/api/exercises?since=7d"
    r = client.get("/api/atelier/channel/detections/run-a", follow_redirects=False)
    assert r.headers["location"] == "/api/channel/detections/run-a"
    assert client.get("/api/atelier/exercises?since=7d").json() == {"exercises": []}


def test_a_run_opens_in_the_section_of_its_injector(client, runs, tmp_path):
    """A card knows only its run id: /runs/<id> finds the injector in the window, else in the
    report (Gothmog's names itself), else Annatar."""
    _window(tmp_path, "g-1", "gothmog", kind="fault")
    _window(tmp_path, "a-1", "annatar")
    (runs / "g-2.json").write_text(json.dumps({"metrics": {"injector": "gothmog"}}))
    go = lambda rid: client.get(f"/runs/{rid}", follow_redirects=False)  # noqa: E731
    assert go("g-1").headers["location"] == "/gothmog?run=g-1"
    assert go("a-1").headers["location"] == "/annatar?run=a-1"
    assert go("g-2").headers["location"] == "/gothmog?run=g-2"
    assert go("unknown").headers["location"] == "/annatar?run=unknown"
    assert go("g-1").status_code == 302


def test_a_run_id_is_a_plain_name(client):
    """M405: the id names a file (the window, the report) — never a path."""
    for rid in ("..x", "a..b", "%2E%2E"):     # a bare ".." never reaches the route: the client resolves it
        assert client.get(f"/runs/{rid}", follow_redirects=False).status_code == 400, rid


# ── The token, and its former name ────────────────────────────────────────────────────

def test_every_page_is_behind_the_token(runs, monkeypatch):
    """M404: a new page is no way around the token — a browser gets the token page, a
    script the JSON refusal."""
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "s3cret")
    c = console(token=None)
    for path in (*PAGES, "/atelier", "/runs/a-1", "/api/sections", "/api/exercises"):
        browser = c.get(path, headers={"accept": "text/html"}, follow_redirects=False)
        assert browser.status_code == 401 and 'name="token"' in browser.text, path
        script = c.get(path, headers={"accept": "application/json"}, follow_redirects=False)
        assert script.status_code == 401 and "error" in script.json(), path
    assert c.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_the_token_page_names_the_console_and_its_variable(runs, monkeypatch):
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "s3cret")
    page = console(token=None).get("/", headers={"accept": "text/html"}).text
    assert "EREGION_CONSOLE_TOKEN" in page and 'lang="en"' in page
    assert "War Room" not in page


@pytest.mark.parametrize("new, old, works, refused", [
    ("s3cret", None, "s3cret", "other"),       # the new name
    (None, "legacy", "legacy", "other"),       # the former name alone (H0's host.env)
    ("", "legacy", "legacy", ""),              # compose passes ${VAR:-}: empty is not set (M402)
    ("s3cret", "legacy", "s3cret", "legacy"),  # both: the new one wins
])
def test_the_token_under_its_new_name_or_its_former_one(runs, monkeypatch, new, old, works, refused):
    for name, value in (("EREGION_CONSOLE_TOKEN", new), ("GLORFINDEL_WARROOM_TOKEN", old)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    assert api.console_token() == works
    c = console(token=None)
    assert c.get("/api/sections", headers={"Authorization": f"Bearer {works}"}).status_code == 200
    assert c.get("/api/sections", headers={"Authorization": f"Bearer {refused}"}).status_code == 401


def test_two_tokens_that_differ_are_said_at_startup(runs, monkeypatch, capsys):
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "new")
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "old")
    with console():
        pass
    assert "the console takes EREGION_CONSOLE_TOKEN" in capsys.readouterr().out


# ── Sections ──────────────────────────────────────────────────────────────────────────

def _status(client):
    return {s["id"]: s for s in client.get("/api/sections").json()["sections"]}


def test_glorfindel_is_always_active_even_unconfigured(client):
    """Glorfindel is the product: active before anything is set up — its page says what is
    missing; the injectors are greyed on a host without their runs."""
    s = _status(client)
    assert s["glorfindel"]["active"] is True and s["glorfindel"]["always"] is True
    assert s["glorfindel"]["setup"]["configured"] is False
    assert s["annatar"]["active"] is False and s["gothmog"]["active"] is False


def test_an_injector_is_active_once_this_host_holds_its_runs(client, runs, tmp_path):
    """A window, a run report or a campaign of the injector; a purged window's tombstone
    names no injector and counts for none."""
    (tmp_path / "exercises").mkdir()
    (tmp_path / "exercises" / "old.json").write_text(json.dumps({"run_id": "old", "purged_at": "x"}))
    assert _status(client)["annatar"]["active"] is False
    _window(tmp_path, "g-1", "gothmog", kind="fault")
    sections._cache["key"] = None
    s = _status(client)
    assert s["gothmog"]["active"] is True and s["gothmog"]["found"]["windows"] == 1
    assert s["annatar"]["active"] is False
    (runs / "campaigns" / "c1").mkdir(parents=True)
    (runs / "campaigns" / "c1" / "manifest.json").write_text("{}")
    sections._cache["key"] = None
    assert _status(client)["annatar"]["active"] is True


def test_sections_chosen_at_start_win_and_never_remove_glorfindel(client, runs, tmp_path, monkeypatch):
    """M406, M407: --sections fixes the injectors shown, whatever the host holds; Glorfindel
    stays, listed or not."""
    _window(tmp_path, "g-1", "gothmog", kind="fault")
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar")
    body = client.get("/api/sections").json()
    s = {x["id"]: x for x in body["sections"]}
    assert s["annatar"]["active"] is True and s["annatar"]["why"] == "listed in --sections"
    assert s["gothmog"]["active"] is False
    assert s["glorfindel"]["active"] is True
    assert body["override"] == ["annatar"]


def test_an_unknown_section_is_refused_by_name(monkeypatch):
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,saruman")
    with pytest.raises(ValueError, match="saruman"):
        sections.override()
    with pytest.raises(ValueError, match="saruman"):
        api.serve()                      # refused before anything listens
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "glorfindel, ANNATAR")
    assert sections.override() == {"annatar"}


def test_the_sections_say_whether_the_console_only_reads(client, monkeypatch):
    monkeypatch.setenv("GLORFINDEL_READ_ONLY", "1")
    assert client.get("/api/sections").json()["read_only"] is True


# ── What each injector's section reads ────────────────────────────────────────────────

def test_the_exercises_of_one_injector(client, tmp_path):
    _window(tmp_path, "g-1", "gothmog", kind="fault")
    _window(tmp_path, "a-1", "annatar")
    ids = lambda q: [w["run_id"] for w in client.get(f"/api/exercises{q}").json()["exercises"]]  # noqa: E731
    assert sorted(ids("")) == ["a-1", "g-1"]
    assert ids("?injector=gothmog") == ["g-1"]
    assert ids("?injector=annatar") == ["a-1"]


def test_the_catalog_of_one_kind(client):
    kinds = lambda q: {e["kind"] for e in client.get(f"/api/catalog{q}").json()["entries"]}  # noqa: E731
    assert kinds("") == {"technique", "fault"}
    assert kinds("?kind=technique") == {"technique"}
    assert kinds("?kind=fault") == {"fault"}


# ── The shipped rules ─────────────────────────────────────────────────────────────────

def test_the_console_finds_the_shipped_rules_outside_the_repo_root(client, monkeypatch):
    """M409: the console left glorfindel/ (26/10). Its lookup beside its own module found no rule
    outside the repo's root (an editable install launched elsewhere): the configuration listed
    no rule and approve-rule answered « detection_rules.yaml not found » (found by P1's review).
    The working directory here is tmp: only the lookup beside the glorfindel package finds it.
    An approved rule says where it went — the client's layer (P1), never the base."""
    from pathlib import Path
    import glorfindel
    shipped = Path(glorfindel.__file__).parent / "rules" / "azure" / "detection_rules.yaml"
    assert api._base_rules_path().resolve() == shipped.resolve()
    seen = {}

    def _approve(proposal_id, rules_path):
        seen["path"] = Path(rules_path)
        return {"rule_name": "r", "rules_file": "/tmp/x/client_rules.yaml", "rule_write": "added",
                "rule_bound": True}
    monkeypatch.setattr("glorfindel.proposed_rules.approve", _approve)
    body = client.post("/api/action/approve-rule/p1", json={}).json()
    assert body == {"ok": True, "rule_name": "r", "rules_file": "/tmp/x/client_rules.yaml",
                    "rule_write": "added", "rule_bound": True, "rule_unbound_reason": None}
    assert seen["path"].resolve() == shipped.resolve()


# ── The version, beside the logo ──────────────────────────────────────────────────────

@pytest.fixture()
def fresh_version(monkeypatch):
    monkeypatch.setattr(sections, "_version_cache", {})
    monkeypatch.setattr(sections, "checkout_revision", lambda: "")
    monkeypatch.delenv("EREGION_REF", raising=False)
    monkeypatch.delenv("EREGION_REVISION", raising=False)


def test_a_deployed_tag_is_the_version_shown(fresh_version, monkeypatch):
    """M567: H0 deployed a tag — the header says the tag, the commit on hover."""
    monkeypatch.setenv("EREGION_REF", "v0.3.1")
    monkeypatch.setenv("EREGION_REVISION", "79f220f2c1d0e9a8b7c6d5e4f3a2b1c0d9e8f7a6")
    v = sections.version()
    assert v["label"] == "v0.3.1" and v["source"] == "deployed" and v["revision"].startswith("79f220f")


def test_a_deployed_commit_shows_the_package_and_the_short_commit(fresh_version, monkeypatch):
    from importlib.metadata import version as pkg_version
    commit = "79f220f2c1d0e9a8b7c6d5e4f3a2b1c0d9e8f7a6"
    monkeypatch.setenv("EREGION_REF", commit)
    monkeypatch.setenv("EREGION_REVISION", commit)
    v = sections.version()
    assert v["label"] == f"v{pkg_version('eregion')} · 79f220f" and v["ref"] == ""


def test_a_local_console_shows_its_checkout(fresh_version, client, monkeypatch):
    """Run from the repository (no deployment): the checkout's commit; and /api/sections
    carries it to the header."""
    monkeypatch.setattr(sections, "checkout_revision", lambda: "a" * 40)
    v = client.get("/api/sections").json()["version"]
    assert v["source"] == "checkout" and len(v["revision"]) == 40 and " · " in v["label"]


# ── The command ───────────────────────────────────────────────────────────────────────

def test_eregion_console_starts_the_console(monkeypatch):
    from eregion_console import cli
    served = []
    monkeypatch.setattr(api, "serve", lambda host, port: served.append((host, port)))
    r = CliRunner().invoke(cli.cli, ["console", "--sections", "gothmog", "--port", "7010"])
    assert r.exit_code == 0, r.output
    assert served == [("127.0.0.1", 7010)]
    assert sections.override() == {"gothmog"}


def test_eregion_console_reaches_the_managed_identity(monkeypatch):
    """M408: compose passes AZURE_CLIENT_ID & co. empty on H0. The glorfindel command drops
    them; `eregion console` did not, and azure-identity stopped on an empty secret before the
    VM's managed identity — every read of the console failed (H0, 26/10: no NSG, no vault,
    every window NOT ENROLLED, the return channel unreadable). A real one stays."""
    import os
    from eregion_console import cli
    monkeypatch.setenv("AZURE_CLIENT_ID", "")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", " ")
    monkeypatch.setenv("AZURE_TENANT_ID", "tenant")
    seen = {}
    monkeypatch.setattr(api, "serve", lambda host, port: seen.update(
        {k: os.environ.get(k) for k in ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")}))
    r = CliRunner().invoke(cli.cli, ["console"])
    assert r.exit_code == 0, r.output
    assert seen == {"AZURE_CLIENT_ID": None, "AZURE_CLIENT_SECRET": None, "AZURE_TENANT_ID": "tenant"}


def test_eregion_console_refuses_an_unknown_section(monkeypatch):
    from eregion_console import cli
    monkeypatch.setattr(api, "serve", lambda **k: pytest.fail("served"))
    r = CliRunner().invoke(cli.cli, ["console", "--sections", "saruman"])
    assert r.exit_code != 0 and "saruman" in r.output


def test_glorfindel_war_room_is_still_the_console(monkeypatch):
    """The former command keeps working (H0, habits, docs of the time), hidden from the help."""
    from glorfindel.cli import cli as gcli
    served = []
    monkeypatch.setattr(api, "serve", lambda host, port: served.append((host, port)))
    r = CliRunner().invoke(gcli, ["war-room"])
    assert r.exit_code == 0, r.output
    assert served == [("127.0.0.1", 7007)]
    assert "war-room" not in CliRunner().invoke(gcli, ["--help"]).output


# ── The cards of I1F, AL1, C2 and A3 (#248) ───────────────────────────────────────────

def _glorfindel_page() -> str:
    from pathlib import Path
    return (Path(api.__file__).parent / "static" / "glorfindel.js").read_text()


def _js_set(name: str) -> set[str]:
    import re
    m = re.search(rf"const {name} = new Set\(\[(.*?)\]\);", _glorfindel_page(), re.S)
    assert m, name
    return set(re.findall(r"'([a-z_]+)'", m.group(1)))


def test_every_card_type_has_a_label_in_the_console():
    """A new type showed under its raw name (quarantine_altered, control_plane_change…)."""
    import re
    from glorfindel import escalations
    block = re.search(r"const ESC_LABELS = \{(.*?)\n\};", _glorfindel_page(), re.S).group(1)
    labelled = set(re.findall(r"^\s*([a-z_]+)\s*:", block, re.M))
    assert set(escalations._ESCALATION_LABELS) <= labelled, set(escalations._ESCALATION_LABELS) - labelled


def test_the_console_anchors_the_cards_glorfindel_anchors():
    """No Restore, no command aimed at a VM the detection does not name (AL1, C2): the same
    types as the bot's. Read from bot.py's source — it imports discord."""
    import ast
    from pathlib import Path
    import glorfindel
    tree = ast.parse((Path(glorfindel.__file__).parent / "bot.py").read_text())
    bot = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "_ANCHORED_TYPES" for t in n.targets))
    assert _js_set("_ANCHORED_TYPES") == bot


def test_the_console_leaves_out_of_to_judge_what_glorfindel_does():
    from glorfindel import escalations
    assert _js_set("_NOT_DECISIONS") == escalations._NOT_DECISIONS


def test_the_feed_says_what_held_a_decision_without_action():
    entry = api._parse({"action": "", "escalate": True, "held_by": "control_plane",
                        "signal": {"ttp": "T1562.007", "resource_id": "/x/vm-a"}}, "action")
    assert entry["held_by"] == "control_plane" and entry["action"] == ""


def _resolved(store, rid, note, hours_ago):
    from glorfindel import escalations
    eid = escalations.record("s-" + note[:6], rid, "remove_orphan_rule", "orphan_rule", "r")
    escalations.resolve(eid, note=note)
    lines = [json.loads(x) for x in store.read_text().splitlines() if x.strip()]
    for e in lines:
        if e["id"] == eid:
            e["resolved_at"] = (NOW - timedelta(hours=hours_ago)).isoformat()
    store.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    return eid


def test_what_glorfindel_closed_with_a_note_shows_for_a_day(client):
    """A3: an orphan rule taken off alone leaves its card resolved, with a note — no open
    card says it. Shown a day; a card closed without a note (a human's ack) never."""
    from glorfindel import escalations
    vm = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
    recent = _resolved(escalations._STORE, vm, "Règle glorfindel-block-x retirée par Glorfindel (A3).", 3)
    _resolved(escalations._STORE, vm, "Règle glorfindel-block-y retirée par Glorfindel (A3).", 25)
    acked = escalations.record("s-ack", vm, "isolate_vm", "mode_hold", "r")
    escalations.resolve(acked)
    handled = client.get("/api/state").json()["handled"]
    assert [h["id"] for h in handled] == [recent]
    assert handled[0]["resolution"].startswith("Règle glorfindel-block-x")

def test_a_cards_detail_escapes_what_azure_or_the_model_wrote():
    """A card's reason, steps and proposed query come from Azure (an Entra application's display
    name, an NSG rule's name) or from the model: written raw into innerHTML, a name such as
    `<img src=x onerror=…>` ran in the operator's console — and could call its routes."""
    page = _glorfindel_page()
    assert "${_attr(e.reason || '')}" in page
    assert "• ${_attr(s)}" in page
    assert "${_attr(e.proposed_query.trim())}" in page
    for raw in ("${e.reason || ''}", "• ${s}<", "${e.proposed_query.trim()}"):
        assert raw not in page, raw


def test_an_anchored_card_never_offers_restore_nor_a_command_on_its_vm():
    """The page offers no Restore on an anchored card; the server refuses one too (SEC1, N-12:
    test_the_restore_route_refuses_an_anchored_card)."""
    page = _glorfindel_page()
    assert "const isRestore = e.action === 'restore_from_backup' && !_isAnchored(e);" in page
    assert "if (_isAnchored(esc)) return `glorfindel ack ${id}`;" in page


# ── The boundary (SEC1): a token always, this console's host and origin, JSON changes ──────
# The checks of the external audit's lab, replayed: a change from another origin (L-01), a
# foreign Host (L-02, rebinding), the live feed from another origin (L-03) or under a foreign
# Host, a change without a body (L-14) — each refused before it reaches a route.

FOREIGN = "http://evil.example"


def _browser(client=None, origin=ORIGIN):
    """A browser holding the console's cookie (set as ?token= sets it), on one of its pages."""
    c = client or console(token=None)
    c.cookies.set(api._TOKEN_COOKIE, api._session(TOKEN))
    if origin:
        c.headers["Origin"] = origin
    return c


@pytest.fixture()
def acked(monkeypatch):
    """What the ack route did: a change refused at the boundary never gets here."""
    from glorfindel import escalations
    seen = []
    monkeypatch.setattr(escalations, "resolve", lambda eid, **kw: seen.append(eid))
    return seen


def test_a_change_from_another_origin_is_refused(runs, acked):
    """L-01, M1172: a page elsewhere posting to the console — without the token, with the
    operator's cookie, or with the token itself — is refused (403); nothing is executed."""
    for c in (console(token=None), _browser(), console()):
        for origin in (FOREIGN, "null", "http://localhost:8080", "http://127.0.0.1:7007"):
            r = c.post("/api/action/ack/e1", json={}, headers={"Origin": origin})
            assert r.status_code == 403 and "origin" in r.json()["error"], origin
        r = c.post("/api/action/ack/e1", content=b"{}", headers={"Origin": FOREIGN, "Content-Type": "text/plain"})
        assert r.status_code == 403
    assert acked == []
    assert _browser().post("/api/action/ack/e1", json={}).json() == {"ok": True} and acked == ["e1"]


def test_the_origin_is_the_consoles_exactly(runs, acked):
    """M1174: the same host name on another port is another origin (a page another local
    service serves); http or https on the Host the console was asked under is its own."""
    assert _browser(origin="http://localhost:7008").post("/api/action/ack/e1", json={}).status_code == 403
    assert _browser(origin="https://localhost:7007").post("/api/action/ack/e1", json={}).status_code == 200
    assert acked == ["e1"]


def test_a_browsers_change_without_its_origin_is_refused(runs, acked):
    """M1175: the cookie is a browser's, and a browser says where a change comes from; a script
    with the token sends none."""
    assert _browser(origin=None).post("/api/action/ack/e1", json={}).status_code == 403
    assert console().post("/api/action/ack/e1", json={}).status_code == 200
    assert acked == ["e1"]


def test_a_foreign_host_is_refused_everywhere(runs):
    """L-02, M1170, M1171: a page that rebinds its own name to this machine reaches the console
    under that name — refused (403), the token page too, whatever the token or the cookie."""
    for host in ("evil.example:7007", "evil.example", "localhost.evil.example:7007",
                 "evil-localhost:7007", "127.0.0.1.evil.example", "", "localhost@evil.example"):
        for c in (console(), console(token=None), _browser()):
            for path in ("/", "/api/sections", "/api/config", "/static/console.js"):
                r = c.get(path, headers={"Host": host, "Accept": "text/html"})
                assert r.status_code == 403 and 'name="token"' not in r.text, (host, path)


def test_a_loopback_name_or_a_listed_one_is_the_consoles(runs, monkeypatch):
    """Any port: a tunnel or a team's console publishes another one. A name of the network is
    listed in EREGION_CONSOLE_HOSTS; the console is then its own origin under it too."""
    c = console()
    for host in ("localhost:7007", "127.0.0.1:7007", "[::1]:7007", "localhost:17007", "LOCALHOST:7007"):
        assert c.get("/api/sections", headers={"Host": host}).status_code == 200, host
    assert c.get("/api/sections", headers={"Host": "eregion.example:7007"}).status_code == 403
    monkeypatch.setenv("EREGION_CONSOLE_HOSTS", "eregion.example, other.example")
    assert c.get("/api/sections", headers={"Host": "eregion.example:7007"}).status_code == 200
    assert c.get("/api/sections", headers={"Host": "evil.example:7007"}).status_code == 403
    r = c.post("/api/escalations/x/verdict", json={"verdict": "?"},
               headers={"Host": "eregion.example", "Origin": "https://eregion.example"})
    assert r.status_code == 200


async def _echo(scope, receive, send):
    """A route behind the boundary that says it was reached — the live feed itself never ends,
    so a feed the boundary let through would hang the test instead of failing it."""
    if scope["type"] == "websocket":
        await receive()
        await send({"type": "websocket.accept"})
        await send({"type": "websocket.send", "text": "reached"})
        await send({"type": "websocket.close", "code": 1000})
        return
    from starlette.responses import JSONResponse
    await JSONResponse({"reached": True})(scope, receive, send)


def _feed(token=TOKEN, cookie=False):
    """The boundary in front of `_echo`, as the app puts it in front of the feed."""
    c = TestClient(api._TokenAuthMiddleware(_echo), base_url=ORIGIN,
                   headers={"Authorization": f"Bearer {token}"} if token else {})
    if cookie:
        c.cookies.set(api._TOKEN_COOKIE, api._session(TOKEN))
    return c


def test_the_live_feed_refuses_another_origin_and_a_foreign_host(runs):
    """L-03, M1173: the WebSocket is a change — from another origin, under a foreign Host, or a
    browser's without its origin, it closes before it opens, cookie or token."""
    from starlette.websockets import WebSocketDisconnect
    assert any(m.cls is api._TokenAuthMiddleware for m in api.app.user_middleware)
    for c, headers in ((_feed(None, cookie=True), {"Origin": FOREIGN}),
                       (_feed(), {"Origin": FOREIGN}),
                       (_feed(None, cookie=True), {"Origin": "http://localhost:8080"}),
                       (_feed(None, cookie=True), {"Origin": ORIGIN, "Host": "evil.example:7007"}),
                       (_feed(), {"Host": "evil.example:7007"}),
                       (_feed(None, cookie=True), {}),
                       (_feed(None), {"Origin": ORIGIN})):
        with pytest.raises(WebSocketDisconnect) as refused:
            with c.websocket_connect(WS, headers=headers) as ws:
                ws.receive_text()
        assert refused.value.code == 1008, headers


def test_the_live_feed_opens_for_the_consoles_own_page(runs):
    """The page's WebSocket — its origin, its cookie — and a script's, with the token."""
    with _feed(None, cookie=True).websocket_connect(WS, headers={"Origin": ORIGIN}) as ws:
        assert ws.receive_text() == "reached"
    with _feed().websocket_connect(WS) as ws:
        assert ws.receive_text() == "reached"


def test_a_change_carries_a_json_object(runs, monkeypatch):
    """L-14, M1182, M1183: a POST without a body on /api/activate was executed. A change carries
    a JSON object, `Content-Type: application/json` — the console's own page included."""
    seen = []
    monkeypatch.setattr(api, "_assess_vm", lambda vm: seen.append(vm) or {"error": "stub"})
    for c in (_browser(), console()):
        assert c.post("/api/activate/vm").status_code == 415
        assert c.post("/api/activate/vm", content=b'{"acknowledged": []}',
                      headers={"Content-Type": "text/plain"}).status_code == 415
        assert c.post("/api/activate/vm", content=b'{"acknowledged": []}',
                      headers={"Content-Type": "application/x-www-form-urlencoded"}).status_code == 415
        for body in (b"", b"[]", b'"x"', b"null", b"{not json"):
            r = c.post("/api/activate/vm", content=body, headers={"Content-Type": "application/json"})
            assert r.status_code == 400, body
        assert c.patch("/api/config/autonomy/default").status_code == 415
        assert c.post("/api/activate/vm", content=b"{" + b" " * api._MAX_BODY + b"}",
                      headers={"Content-Type": "application/json"}).status_code == 413
    assert seen == []
    assert _browser().post("/api/activate/vm", json={"acknowledged": []}).json() == {"error": "stub"}
    assert console().post("/api/activate/vm", content=b"{}",
                          headers={"Content-Type": "application/json; charset=utf-8"}).json() == {"error": "stub"}
    assert seen == ["vm", "vm"]


# ── A token always (SEC1) ──────────────────────────────────────────────────────────────

def test_the_first_start_without_a_token_draws_one(runs, monkeypatch, capsys):
    """M1177, M1178: no EREGION_CONSOLE_TOKEN (the local default): the console draws a token,
    keeps it in the operator's file, mode 600, says it once with the URL, and takes it at the
    next start; nothing opens without it."""
    import stat
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api.serve(port=7007)
    token = api._TOKEN_FILE.read_text().strip()
    assert len(token) >= 32 and stat.S_IMODE(api._TOKEN_FILE.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert f"http://localhost:7007/?token={token}" in out and str(api._TOKEN_FILE) in out
    assert console(token=None).get("/api/sections").status_code == 401
    assert console(token=token).get("/api/sections").status_code == 200
    api._local_token["value"] = ""
    api._TOKEN_FILE.chmod(0o644)
    assert api.ensure_token() == (token, "file")          # the next start: the same token
    assert stat.S_IMODE(api._TOKEN_FILE.stat().st_mode) == 0o600


def test_a_deployments_token_is_never_printed_nor_written(runs, monkeypatch, capsys):
    """H0's mode is unchanged: the token comes from its environment, the URL names the variable."""
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api.serve(port=7007)
    out = capsys.readouterr().out
    assert "?token=$EREGION_CONSOLE_TOKEN" in out and TOKEN not in out
    assert not api._TOKEN_FILE.exists()


def test_no_token_at_all_refuses_everything(runs, monkeypatch):
    """M1176: neither the deployment's token nor a drawn one (the file unreadable): every
    request is refused, never served open."""
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    for path in ("/", "/api/sections", "/api/config"):
        assert console(token=None).get(path).status_code == 503, path
        assert console(token="").get(path).status_code == 503, path


# ── The cookie: a session, not the token (SEC1) ────────────────────────────────────────

def test_the_cookie_is_a_session_derived_from_the_token(runs):
    """M1179, M1180: ?token= sets a cookie that is not the token (HttpOnly, SameSite=Strict); the
    token as a cookie, or the session as a bearer, opens nothing."""
    c = console(token=None)
    r = c.get(f"/?token={TOKEN}", follow_redirects=False)
    cookie = r.headers["set-cookie"]
    assert r.status_code == 303 and TOKEN not in cookie
    assert f"{api._TOKEN_COOKIE}={api._session(TOKEN)}" in cookie and api._session(TOKEN) != TOKEN
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()
    assert "secure" not in cookie.lower()                 # http://localhost: the SSH tunnel
    assert c.get("/api/sections").status_code == 200
    stolen = console(token=None)
    stolen.cookies.set(api._TOKEN_COOKIE, TOKEN)
    assert stolen.get("/api/sections").status_code == 401
    assert console(token=api._session(TOKEN)).get("/api/sections").status_code == 401
    assert api._session("another") != api._session(TOKEN)


def test_the_cookie_is_secure_over_https(runs):
    """M1181: served in HTTPS (a proxy that terminates it), the cookie never travels in clear."""
    r = console(token=None, base_url="https://localhost:7007").get(f"/?token={TOKEN}", follow_redirects=False)
    assert "secure" in r.headers["set-cookie"].lower()


def test_the_token_in_the_url_never_leads_to_another_host(runs):
    r = console(token=None).get(f"{ORIGIN}//evil.example/x?token={TOKEN}", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/evil.example/x"


# ── What every response says, and what is not served (SEC1) ────────────────────────────

def test_every_response_carries_the_boundarys_headers(runs):
    """M1184, M1185: the pages, their scripts, the API, the token page and the refusals — the
    CSP from this origin only, no sniffing, no Referer."""
    responses = [console().get(p) for p in (*PAGES, "/static/console.js", "/static/glorfindel.js",
                                             "/api/sections")]
    responses += [console(token=None).get("/", headers={"accept": "text/html"}),
                  console().get("/", headers={"Host": "evil.example"}),
                  _browser(origin=FOREIGN).post("/api/action/ack/x", json={})]
    for r in responses:
        directives = dict(d.strip().split(" ", 1) for d in r.headers["content-security-policy"].split(";"))
        assert directives["default-src"] == "'self'" and directives["script-src"] == "'self'"
        assert directives["object-src"] == "'none'" and directives["frame-ancestors"] == "'none'"
        assert "unsafe" not in directives["script-src"] and "http" not in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"


def test_the_api_schema_and_its_pages_are_not_served(runs):
    """M1186: what the routes are is not served to whoever asks — even with the token."""
    for path in ("/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"):
        assert console().get(path).status_code == 404, path


def test_the_config_masks_the_azure_identifiers(runs, monkeypatch):
    """N-13, M1187: Config shows a subscription, a tenant, a client by their ends; the page needs
    no more, and no workspace id."""
    ids = {"AZURE_SUBSCRIPTION_ID": "sub0123456789abcdefsubzz", "AZURE_TENANT_ID": "ten0123456789abcdeftenzz",
           "AZURE_CLIENT_ID": "cli0123456789abcdefclizz"}
    for name, value in ids.items():
        monkeypatch.setenv(name, value)
    body = console().get("/api/config")
    az = body.json()["azure"]
    assert az["subscription_id"] == "sub01234…ubzz" and az["configured"] is True
    for value in ids.values():
        assert value not in body.text
    assert "workspace_id" not in body.text
    assert "function mask(s) {\n  return s || '—';\n}" in _glorfindel_page()


def test_a_name_in_a_routes_path_is_encoded(runs):
    """N-14, M1189: a VM name or a card id in an API path goes through encodeURIComponent — a `?`
    or `#` in it would send the request elsewhere; every change goes through _post (JSON)."""
    import re
    js = (api._STATIC / "glorfindel.js").read_text()
    assert "function _seg(s) { return encodeURIComponent(String(s ?? '')); }" in js
    paths = re.findall(r"`(/api/[^`]*)`", js)
    assert len(paths) >= 15
    for path in paths:
        for expr in re.findall(r"\$\{([^}]*)\}", path.split("?")[0]):
            assert expr.startswith(("_seg(", "encodeURIComponent(")), path
    assert "method: 'POST'" not in js and "method: 'PATCH'" not in js
    assert ("  return fetch(url, { method, headers: { 'Content-Type': 'application/json' },\n"
            "                      body: JSON.stringify(body ?? {}) });") in js


# ── Restore from the console: its card's, never an anchored one (SEC1, N-12) ────────────

@pytest.fixture()
def restores(monkeypatch):
    seen = []

    async def _bg(resource_id, vm_name=""):
        seen.append(resource_id)
    monkeypatch.setattr(api, "_bg_restore", _bg)
    monkeypatch.setattr(api, "_restore_start", lambda vm, rid: None)
    return seen


@pytest.mark.parametrize("etype", sorted({"control_plane_change", "identity_change", "unattributed_signal"}))
def test_the_restore_route_refuses_an_anchored_card(client, restores, etype):
    """M1188: the page and the bot never offer Restore on a card anchored on a VM the detection
    does not name; the route refused nothing."""
    from glorfindel import escalations
    vm = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
    eid = escalations.record("s1", vm, "restore_from_backup", etype, "r")
    r = client.post("/api/action/restore/vm-a", json={"escalation": eid}).json()
    assert "anchored" in r["error"] and restores == []


def test_the_restore_route_takes_its_card_only(client, restores):
    from glorfindel import escalations
    vm = "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-a"
    held = escalations.record("s1", vm, "restore_from_backup", "destructive_action", "r")
    other = escalations.record("s2", vm, "isolate_vm", "mode_hold", "r")
    assert "card" in client.post("/api/action/restore/vm-a", json={}).json()["error"]
    assert "not found" in client.post("/api/action/restore/vm-a", json={"escalation": "nope"}).json()["error"]
    assert "restore" in client.post("/api/action/restore/vm-a", json={"escalation": other}).json()["error"]
    assert "vm-b" in client.post("/api/action/restore/vm-b", json={"escalation": held}).json()["error"]
    assert restores == []
    assert client.post("/api/action/restore/vm-a", json={"escalation": held}).json() == {
        "status": "started", "resource_id": vm}
    assert restores == [vm]


def test_the_consoles_anchored_types_are_the_bots():
    import ast
    from pathlib import Path
    import glorfindel
    tree = ast.parse((Path(glorfindel.__file__).parent / "bot.py").read_text())
    bot = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "_ANCHORED_TYPES" for t in n.targets))
    assert api._ANCHORED_TYPES == bot
