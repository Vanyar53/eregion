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
    return TestClient(api.app)


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
    page = TestClient(api.app).get("/", headers={"accept": "text/html"})
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
    c = TestClient(api.app)
    for path in (*PAGES, "/atelier", "/runs/a-1", "/api/sections", "/api/exercises"):
        browser = c.get(path, headers={"accept": "text/html"}, follow_redirects=False)
        assert browser.status_code == 401 and 'name="token"' in browser.text, path
        script = c.get(path, headers={"accept": "application/json"}, follow_redirects=False)
        assert script.status_code == 401 and "error" in script.json(), path
    assert c.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_the_token_page_names_the_console_and_its_variable(runs, monkeypatch):
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "s3cret")
    page = TestClient(api.app).get("/", headers={"accept": "text/html"}).text
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
    c = TestClient(api.app)
    assert c.get("/api/sections", headers={"Authorization": f"Bearer {works}"}).status_code == 200
    assert c.get("/api/sections", headers={"Authorization": f"Bearer {refused}"}).status_code == 401


def test_two_tokens_that_differ_are_said_at_startup(runs, monkeypatch, capsys):
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", "new")
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "old")
    with TestClient(api.app):
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
    body = client.post("/api/action/approve-rule/p1").json()
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
    return (Path(api.__file__).parent / "static" / "glorfindel.html").read_text()


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
