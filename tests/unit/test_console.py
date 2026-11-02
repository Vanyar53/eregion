"""The Eregion console (docs/design/console.md): its pages, the former addresses, the token and
its former name, and the sections — Glorfindel always, Annatar and Gothmog when this host
holds their runs, or as --sections chooses.

No Azure, no LLM: runs/ is a tmp directory, the windows are written there.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from click.testing import CliRunner  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from .console_client import ORIGIN, TOKEN, WS, console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_console import sections  # noqa: E402

PAGES = ("/", "/glorfindel", "/dagorlad", "/dagorlad?view=runs", "/config", "/annatar", "/gothmog")
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    """NOW is the clock when each test starts, not when this file was imported: a long suite
    (the CI's) no longer ages it past the windows and heartbeats the code under test compares
    with its own clock (SEC6, P-08)."""
    global NOW
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
                                        ("/config", "glorfindel.html"), ("/dagorlad", "dagorlad.html"),
                                        ("/dagorlad?view=runs", "injector.html"),
                                        ("/dagorlad?view=board", "dagorlad.html")])
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


def test_a_run_opens_in_dagorlads_runs(client, runs, tmp_path):
    """A card knows only its run id: /runs/<id> opens it in Dagorlad's Runs, where both
    injectors' windows are (§7, 30/10)."""
    _window(tmp_path, "g-1", "gothmog", kind="fault")
    go = lambda rid: client.get(f"/runs/{rid}", follow_redirects=False)  # noqa: E731
    assert go("g-1").headers["location"] == "/dagorlad?view=runs&run=g-1"
    assert go("unknown").headers["location"] == "/dagorlad?view=runs&run=unknown"
    assert go("g-1").status_code == 302


def test_annatars_and_gothmogs_pages_lead_to_dagorlads_runs_with_what_they_asked(client):
    """Until 1.0, the former pages lead to the Runs, filtered on their injector, the query kept
    (a card's ?run=, a campaign's ?campaign=)."""
    go = lambda path: client.get(path, follow_redirects=False)  # noqa: E731
    assert go("/annatar").headers["location"] == "/dagorlad?view=runs&injector=annatar"
    assert go("/gothmog?run=g-1").headers["location"] == "/dagorlad?view=runs&injector=gothmog&run=g-1"
    assert go("/annatar?campaign=c-1").headers["location"] == "/dagorlad?view=runs&injector=annatar&campaign=c-1"
    assert go("/gothmog").status_code == 308
    # Never another view or injector than its own, and never off the console.
    assert go("/annatar?view=board&run=r-1").headers["location"] == "/dagorlad?view=runs&injector=annatar&run=r-1"
    assert go("/gothmog?injector=annatar").headers["location"] == "/dagorlad?view=runs&injector=gothmog"
    for odd in ("/annatar?next=//evil.com", "/gothmog?x=%0d%0aLocation:%20//evil.com", "/annatar?r=%2F%2Fevil.com"):
        assert go(odd).headers["location"].startswith("/dagorlad?"), odd


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


def test_an_isolation_whose_original_is_unknown_says_it_on_its_card():
    """SEC4b, second review: a NIC in our quarantine whose original nothing recorded — its
    release, autonomous too, will ask for our tag. /api/state carries it, the card says it."""
    import inspect
    nic = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/vm-nic"
    assert api._original_unknown_nics([{"nic_id": nic, "kind": "quarantine"}]) == ["vm-nic"]
    assert api._original_unknown_nics([{"nic_id": nic, "kind": "quarantine", "original_nsg_id": None}]) == []
    assert '"original_unknown": _original_unknown_nics(' in inspect.getsource(api)
    page = _glorfindel_page()
    chip = page[page.index("if (Array.isArray(s.original_unknown) && s.original_unknown.length) {"):][:900]
    assert "⚠ original unknown" in chip and "_attr(why)" in chip


def test_a_card_about_the_local_state_makes_no_vm_tile():
    """SEC4b: the `state_unreadable` card's resource is the local state (`~/.glorfindel`),
    no VM — it made a tile `.glorfindel`, counted among the unprotected VMs. Neither the
    pending cards nor the ones Glorfindel closed make one for it; Azure ids still do."""
    import re
    from glorfindel.reassert_cards import _STATE_RESOURCE
    page = _glorfindel_page()
    m = re.search(r"function _isLocalState\(rid\) \{ return /(.*?)/\.test\(rid \|\| ''\); \}", page)
    assert m, "no _isLocalState"
    local = re.compile(m.group(1).replace("\\/", "/"))
    assert local.match(_STATE_RESOURCE)
    assert not local.match("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm")
    tiles = page[page.index("  vmEscs.forEach(e => {"):]
    assert tiles.splitlines()[1].strip() == "if (_isLocalState(e.resource_id)) return;"
    handled = page[page.index("(_state.handled || []).forEach(h => {"):][:400]
    assert "!_isLocalState(h.resource_id)" in handled


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
    """The page offers no Restore on an anchored card; the server refuses one too (SEC1:
    test_the_restore_route_refuses_an_anchored_card)."""
    page = _glorfindel_page()
    assert "const isRestore = e.action === 'restore_from_backup' && !_isAnchored(e);" in page
    assert "if (_isAnchored(esc)) return `glorfindel ack ${id}`;" in page


# ── The boundary (SEC1): a token always, this console's host and origin, JSON changes ──────
# What the boundary refuses before any route: a change from another origin, a Host the console
# does not know, the live feed from another origin or under such a Host, a change without a JSON
# body.

FOREIGN = "http://evil.example"
COOKIE = "eregion_console_7007"     # the session cookie of the console reached on port 7007


def _browser(client=None, origin=ORIGIN):
    """A browser holding the console's cookie (set as ?token= sets it), on one of its pages."""
    c = client or console(token=None)
    c.cookies.set(COOKIE, api._session(TOKEN))
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
    """M1172: a change from another origin — without the token, with the cookie, or with the
    token itself — is refused (403); nothing is executed."""
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
    """M1170, M1171: under a host name the console does not know, everything is refused (403),
    the token page too, whatever the token or the cookie."""
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
        c.cookies.set(COOKIE, api._session(TOKEN))
    return c


def test_the_live_feed_refuses_another_origin_and_a_foreign_host(runs):
    """M1173: the WebSocket is a change — from another origin, under a foreign Host, or a
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
    """M1182, M1183: a change carries a JSON object, `Content-Type: application/json` — the
    console's own page included; anything else is refused before the route."""
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
    keeps it in its own file, mode 600, says where — never the token (SEC10: a container's
    output is kept in its logs) — and takes it at the next start; nothing opens without it."""
    import stat
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api.serve(port=7007)
    token = api._TOKEN_FILE.read_text().strip()
    assert len(token) >= 32 and stat.S_IMODE(api._TOKEN_FILE.stat().st_mode) == 0o600
    out = capsys.readouterr().out
    assert token not in out and "http://localhost:7007/" in out and "make console-url" in out
    assert str(api._TOKEN_FILE) in out
    assert console(token=None).get("/api/sections").status_code == 401
    assert console(token=token).get("/api/sections").status_code == 200
    api._local_token.update(value="", key=None)
    api._TOKEN_FILE.chmod(0o644)
    assert api.ensure_token() == (token, "file")          # the next start: the same token
    assert stat.S_IMODE(api._TOKEN_FILE.stat().st_mode) == 0o600


def test_a_deployments_token_is_never_printed_nor_written(runs, monkeypatch, capsys):
    """H0's mode is unchanged: the token comes from its environment, the URL names the variable."""
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api.serve(port=7007)
    out = capsys.readouterr().out
    assert "make console-url" in out and "EREGION_CONSOLE_TOKEN" in out and TOKEN not in out
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
    assert f"{COOKIE}={api._session(TOKEN)}" in cookie and api._session(TOKEN) != TOKEN
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()
    assert "secure" not in cookie.lower()                 # http://localhost: the SSH tunnel
    assert c.get("/api/sections").status_code == 200
    stolen = console(token=None)
    stolen.cookies.set(COOKIE, TOKEN)
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
    """M1187: Config shows a subscription, a tenant, a client by their ends; the page needs
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
    """M1189: a VM name or a card id in an API path goes through encodeURIComponent — a `?` or
    `#` in it would change the route; every change goes through _post (JSON)."""
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


# ── Restore from the console: its card's, never an anchored one (SEC1) ─────────────────

@pytest.fixture()
def restores(monkeypatch):
    seen = []

    async def _bg(resource_id, vm_name="", before="", esc_id=""):
        seen.append(resource_id)
    monkeypatch.setattr(api, "_bg_restore", _bg)
    monkeypatch.setattr(api, "_restore_start", lambda vm, rid: None)
    return seen


@pytest.mark.parametrize("etype", sorted({"control_plane_change", "identity_change", "unattributed_signal"}))
def test_the_restore_route_refuses_an_anchored_card(client, restores, etype):
    """M1188: a card anchored on a VM the detection does not name is never restored from the
    console — the route refuses it, as the page and the bot."""
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
    # The moment is asked (SEC4c): without it, refused — never the newest point.
    assert "required" in client.post("/api/action/restore/vm-a", json={"escalation": held}).json()["error"]
    assert restores == []
    assert client.post("/api/action/restore/vm-a", json={"escalation": held,
                                                          "before": "2026-10-29T08:00:00Z"}).json() == {
        "status": "started", "resource_id": vm, "before": "2026-10-29T08:00:00+00:00"}
    assert restores == [vm]


def test_the_consoles_anchored_types_are_the_bots():
    import ast
    from pathlib import Path
    import glorfindel
    tree = ast.parse((Path(glorfindel.__file__).parent / "bot.py").read_text())
    bot = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "_ANCHORED_TYPES" for t in n.targets))
    assert api._ANCHORED_TYPES == bot


# ── The relecture of SEC1 ───────────────────────────────────────────────────────────────

def test_each_console_has_its_own_cookie(runs):
    """M1302: a browser keeps one jar for every port of a host — the session cookie is named by
    the port it reached, so a team's console on 7008 never overwrites the local one's."""
    assert api._cookie_name("localhost:7007", "http") == "eregion_console_7007"
    assert api._cookie_name("eregion.example", "https") == "eregion_console_443"
    team = console(token=None, base_url="http://localhost:7008")
    r = team.get(f"/?token={TOKEN}", follow_redirects=False)
    assert r.headers["set-cookie"].startswith(f"eregion_console_7008={api._session(TOKEN)}")
    local = console(token=None, base_url="http://localhost:7008")
    local.cookies.set("eregion_console_7007", api._session(TOKEN))
    assert local.get("/api/sections").status_code == 401        # 7007's cookie is not 7008's
    assert team.get("/api/sections").status_code == 200


def test_a_token_file_behind_a_link_is_refused(runs, monkeypatch, tmp_path):
    """M1303: the token file is never read through a symbolic link: the console refuses every
    request instead (no token), and says why at startup."""
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("a-token-kept-elsewhere-0123456789\n")
    api._TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    api._TOKEN_FILE.symlink_to(elsewhere)
    with pytest.raises(OSError):
        api.ensure_token()
    assert api._local_token["value"] == ""
    assert console(token="a-token-kept-elsewhere-0123456789").get("/api/sections").status_code == 503


def test_the_url_reaches_a_containers_log(runs, tmp_path):
    """M1304: in a container stdout is a pipe — the URL is flushed at once, or `docker compose
    logs` shows nothing while the console runs."""
    import os
    import select
    import subprocess
    import sys
    code = ("import uvicorn, time; uvicorn.run = lambda *a, **k: time.sleep(30); "
            "from eregion_console import api; api.serve(port=7007)")
    env = {**os.environ, "HOME": str(tmp_path), "EREGION_CONSOLE_TOKEN": TOKEN,
           "PYTHONPATH": str(api._STATIC.parents[1])}
    env.pop("PYTHONUNBUFFERED", None)
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, env=env, cwd=tmp_path)
    try:
        ready, _, _ = select.select([proc.stdout], [], [], 20)
        assert ready, "nothing written on the pipe"
        line = proc.stdout.readline().decode()
        assert "http://localhost:7007/" in line and "make console-url" in line and TOKEN not in line
    finally:
        proc.kill()
        proc.wait()


def test_make_console_url_says_where_the_token_is(tmp_path):
    """`make glorfindel-start` and its neighbours print the console's URL with its token: the
    environment's, else the file the console wrote at its first start."""
    import os
    import shutil
    import subprocess
    if shutil.which("make") is None:
        pytest.skip("make not installed")
    root = api._STATIC.parents[1]
    env = {k: v for k, v in os.environ.items() if k not in ("EREGION_CONSOLE_TOKEN", "GLORFINDEL_WARROOM_TOKEN",
                                                             "EREGION_CONSOLE_PORT", "MAKEFLAGS")}

    def url(home, **extra):
        r = subprocess.run(["make", "-s", "-C", str(root), "console-url", f"HOME={home}", "CONSOLE_WAIT=0"],
                           env={**env, **extra}, capture_output=True, text=True, cwd=tmp_path)
        return r.returncode, r.stdout.strip(), r.stderr
    (tmp_path / ".eregion" / "console").mkdir(parents=True)
    (tmp_path / ".eregion" / "console" / "token").write_text("drawn-token\n")
    (tmp_path / ".glorfindel").mkdir()
    (tmp_path / ".glorfindel" / "console_token").write_text("a-former-token\n")   # never read again
    if (root / ".env").exists():
        pytest.skip("a .env in the checkout gives compose its token")
    assert url(tmp_path)[1] == "Console   →  http://localhost:7007/?token=drawn-token"
    assert url(tmp_path, EREGION_CONSOLE_PORT="7008")[1].endswith("localhost:7008/?token=drawn-token")
    assert url(tmp_path, EREGION_CONSOLE_TOKEN="set-token")[1].endswith("?token=set-token")
    code, out, err = url(tmp_path / "nothing")
    assert code != 0 and ".eregion/console/token" in err


def test_read_only_greys_the_buttons_that_write(runs):
    """M1300, M1301: in read-only (H0) the buttons that write are disabled — named by their
    action since #257 (data-on-click), the modals' own included; never read from `onclick`."""
    import re
    js = (api._STATIC / "glorfindel.js").read_text()
    assert "getAttribute('onclick')" not in js
    guard = js[js.index("function _applyReadOnlyGuards"):js.index("\n}\n", js.index("function _applyReadOnlyGuards"))]
    assert "const action = b.getAttribute('data-on-click') || '';" in guard
    assert "if (_WRITE_HANDLERS.includes(action)) {" in guard
    names = set(re.findall(r"'(\w+)'", js[js.index("const _WRITE_HANDLERS = ["):js.index("];", js.index("const _WRITE_HANDLERS = ["))]))
    assert names == {"doApproveAction", "confirmRestore", "doSnapshot", "confirmRelease", "confirmUnblock",
                     "confirmReset", "confirmExtendSubnet", "approveActionAndClose", "approveScoped",
                     "snapshotAndClose"}
    table = js[js.index("const ACTIONS = {"):js.index("\n};", js.index("const ACTIONS = {"))]
    assert all(re.search(rf"\b{n}\b", table) for n in names)


# ── The console's token, the console's alone (SEC10) ───────────────────────────────────────

def _default_token_file(home):
    """Where the console keeps its drawn token for this HOME, as the module says it (not the
    conftest's tmp)."""
    import os
    import subprocess
    import sys
    env = {**os.environ, "HOME": str(home), "PYTHONPATH": str(api._STATIC.parents[1])}
    out = subprocess.run([sys.executable, "-c", "from eregion_console import api; print(api._TOKEN_FILE)"],
                         env=env, capture_output=True, text=True, cwd=home, check=True)
    return Path(out.stdout.strip())


def test_the_drawn_token_lives_where_only_the_console_mounts(tmp_path):
    """The watch and the bot mount Glorfindel's state; the console's token is in the console's own
    directory, which no other service mounts (docker-compose.yml) — so a process that takes the
    watch or the bot never reads it."""
    import yaml
    home = tmp_path / "home"
    home.mkdir()
    token = _default_token_file(home)
    assert token == home / ".eregion" / "console" / "token"
    compose = yaml.safe_load((api._STATIC.parents[1] / "docker-compose.yml").read_text())
    reach = []
    for name, svc in compose["services"].items():
        for vol in svc.get("volumes") or []:
            src = str(vol).split(":")[0].replace("${HOME}", str(home))
            if src.startswith(str(home)) and (token == Path(src) or Path(src) in token.parents):
                reach.append(name)
    assert reach == ["war-room"], reach


def test_the_former_token_file_is_retired_and_a_new_token_drawn(runs, monkeypatch, capsys):
    """Its former place, beside Glorfindel's state: removed at the first start, never read nor
    carried over — a new token is drawn, and the start says it."""
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    api._LEGACY_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    api._LEGACY_TOKEN_FILE.write_text("the-former-token-0123456789abcdef\n")
    api.serve(port=7007)
    assert not api._LEGACY_TOKEN_FILE.exists()
    token = api._TOKEN_FILE.read_text().strip()
    assert token and token != "the-former-token-0123456789abcdef"
    out = capsys.readouterr().out
    assert str(api._LEGACY_TOKEN_FILE) in out and "removed" in out and "a new token is drawn" in out
    assert token not in out
    assert console(token="the-former-token-0123456789abcdef").get("/api/sections").status_code == 401


def test_the_former_token_file_is_retired_under_a_deployments_token_too(runs):
    api._LEGACY_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    api._LEGACY_TOKEN_FILE.write_text("old\n")
    assert api.ensure_token() == (TOKEN, "env")
    assert not api._LEGACY_TOKEN_FILE.exists() and not api._TOKEN_FILE.exists()


def test_a_former_token_file_that_is_a_link_is_removed_never_what_it_points_to(runs, tmp_path):
    kept = tmp_path / "someone-elses-file"
    kept.write_text("not ours\n")
    api._LEGACY_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    api._LEGACY_TOKEN_FILE.symlink_to(kept)
    api.ensure_token()
    assert not api._LEGACY_TOKEN_FILE.is_symlink() and kept.read_text() == "not ours\n"


def _cookie_client(value):
    c = console(token=None)
    c.cookies.set(COOKIE, value)
    return c


def test_a_session_lasts_its_time_and_says_when_it_began(runs):
    """The cookie: its date of issue, signed with it; refused once older than SESSION_TTL_S, or
    dated ahead of the clock; a date rewritten is refused."""
    import time
    now = int(time.time())
    assert _cookie_client(api._session(TOKEN)).get("/api/sections").status_code == 200
    almost = api._session(TOKEN, now - api.SESSION_TTL_S + 60)
    assert _cookie_client(almost).get("/api/sections").status_code == 200
    expired = api._session(TOKEN, now - api.SESSION_TTL_S - 60)
    assert _cookie_client(expired).get("/api/sections").status_code == 401
    ahead = api._session(TOKEN, now + 3600)
    assert _cookie_client(ahead).get("/api/sections").status_code == 401
    _, _, mac = expired.split(".")
    assert _cookie_client(f"v2.{now}.{mac}").get("/api/sections").status_code == 401
    assert api.SESSION_TTL_S == 12 * 3600


def test_a_rotation_refuses_every_session_of_the_former_token_at_once(runs, monkeypatch):
    """`eregion rotate-token`: a new token in the console's file, read at the next request —
    no restart — and every cookie of the former one refused; the deployment's token is rotated
    where it is set."""
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    first, _ = api.ensure_token()
    c = console(token=None)
    assert c.get(f"/?token={first}", follow_redirects=False).status_code == 303
    assert c.get("/api/sections").status_code == 200
    api.rotate_token()
    second = api._TOKEN_FILE.read_text().strip()
    assert second != first
    assert c.get("/api/sections").status_code == 401
    assert console(token=first).get("/api/sections").status_code == 401
    assert console(token=second).get("/api/sections").status_code == 200
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", TOKEN)
    with pytest.raises(RuntimeError):
        api.rotate_token()
    assert api._TOKEN_FILE.read_text().strip() == second


def test_a_token_file_turned_into_a_link_while_it_runs_refuses_everything(runs, monkeypatch, tmp_path):
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    token, _ = api.ensure_token()
    elsewhere = tmp_path / "elsewhere-token"
    elsewhere.write_text(token + "\n")
    api._TOKEN_FILE.unlink()
    api._TOKEN_FILE.symlink_to(elsewhere)
    assert console(token=token).get("/api/sections").status_code == 503


def test_eregion_rotate_token_says_where_never_what(runs, monkeypatch):
    from click.testing import CliRunner

    from eregion_console.cli import cli
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    api.ensure_token()
    res = CliRunner().invoke(cli, ["rotate-token"])
    assert res.exit_code == 0, res.output
    assert api._TOKEN_FILE.read_text().strip() not in res.output and "make console-url" in res.output
    monkeypatch.setenv("EREGION_CONSOLE_TOKEN", TOKEN)
    res = CliRunner().invoke(cli, ["rotate-token"])
    assert res.exit_code != 0 and "EREGION_CONSOLE_TOKEN is set" in res.output


# ── SEC10, its review: the token page, the cookie's digits, the live feed, what a start says ────

def test_the_token_page_says_where_the_token_is_now():
    """An operator without a session (after a rotation, after 12 h) is sent to `make console-url`,
    never to the file the console no longer keeps."""
    assert "make console-url" in api._TOKEN_PAGE and "~/.eregion/console/token" in api._TOKEN_PAGE
    assert "console_token" not in api._TOKEN_PAGE


def _asgi(cookie: bytes, kind: str = "http") -> list:
    """The boundary called as the server calls it: the Cookie header's raw bytes (a client sends
    what it wants; the server decodes them as latin-1), nothing else in front."""
    import asyncio
    sent = []

    async def app(scope, receive, send):
        sent.append("reached")
    scope = {"type": kind, "path": "/api/sections", "raw_path": b"/api/sections", "query_string": b"",
             "headers": [(b"host", b"localhost:7007"), (b"origin", ORIGIN.encode()), (b"cookie", cookie)],
             "scheme": "http" if kind == "http" else "ws", "server": ("localhost", 7007),
             "client": ("127.0.0.1", 50000), "root_path": "", "http_version": "1.1"}
    if kind == "http":
        scope["method"] = "GET"

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False} if kind == "http" else {"type": "websocket.connect"}

    async def send(message):
        sent.append(message)
    asyncio.run(api._TokenAuthMiddleware(app)(scope, receive, send))
    return sent


@pytest.mark.parametrize("value", [b"v2.\xb2.x", b"v2.\xb9\xb2.x", b"v2.1e3.x", b"v2..x", b"v2.\xc2\xb2.x"])
def test_a_cookie_of_any_digits_is_refused_never_an_error(runs, value):
    """A session cookie read before any authentication: digits of another script (« ² », the raw
    byte a server decodes as latin-1), a number written otherwise — 401, never an exception, on
    HTTP and on the live feed (1008)."""
    cookie = COOKIE.encode() + b"=" + value
    http = _asgi(cookie)
    assert "reached" not in http and http[0]["type"] == "http.response.start" and http[0]["status"] == 401
    ws = _asgi(cookie, "websocket")
    assert "reached" not in ws and ws[0] == {"type": "websocket.close", "code": 1008}


def test_a_session_cookie_of_the_former_format_opens_nothing(runs):
    """SEC1's cookie (an HMAC of the token, no date) is refused by construction since SEC10."""
    import hashlib
    import hmac
    v1 = hmac.new(TOKEN.encode(), b"eregion-console-session/v1", hashlib.sha256).hexdigest()
    assert _cookie_client(v1).get("/api/sections").status_code == 401


@pytest.mark.parametrize("ends", ["rotation", "expiry"])
def test_the_live_feed_ends_with_its_session(runs, monkeypatch, ends):
    """A WebSocket opened with a session holds it again at each turn: the token rotated, or its
    time over, the feed is closed (1008), as a refusal at its opening."""
    from starlette.websockets import WebSocketDisconnect
    monkeypatch.setattr(api, "_FEED_POLL_S", 0.05)
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    token, _ = api.ensure_token()
    if ends == "expiry":
        monkeypatch.setattr(api, "SESSION_TTL_S", 1)
    import time
    c = console(token=None)
    c.cookies.set(COOKIE, api._session(token))
    feed = Path("runs") / "watch-x_signals.jsonl"
    feed.write_text("")
    with c.websocket_connect(WS, headers={"Origin": ORIGIN}) as ws:
        if ends == "rotation":
            api.rotate_token()
        # Something to send at every turn: a feed that stays open says so here, never hangs.
        deadline = time.monotonic() + 5
        with pytest.raises(WebSocketDisconnect) as closed:
            while time.monotonic() < deadline:
                with feed.open("a") as f:
                    f.write(json.dumps({"event": "detection", "ttp": "T1110.001"}) + "\n")
                ws.receive_json()
            pytest.fail("the live feed still open past its session")
    assert closed.value.code == 1008


def test_what_a_start_says_of_the_former_file_is_what_happened(runs, monkeypatch, capsys):
    """Its own token there already: the former file removed, and the console keeps its own — never
    « a new token is drawn ». The former file not removable: said, never read."""
    import os
    monkeypatch.delenv("EREGION_CONSOLE_TOKEN")
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    token, _ = api.ensure_token()
    api._LEGACY_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    api._LEGACY_TOKEN_FILE.write_text("old\n")
    api.serve(port=7007)
    out = capsys.readouterr().out
    assert "is removed" in out and "the console keeps its own" in out and "a new token is drawn" not in out
    assert api._TOKEN_FILE.read_text().strip() == token
    if os.geteuid() == 0:
        pytest.skip("root removes a file from a read-only directory")
    api._LEGACY_TOKEN_FILE.write_text("old\n")
    api._LEGACY_TOKEN_FILE.parent.chmod(0o500)
    try:
        api.serve(port=7007)
    finally:
        api._LEGACY_TOKEN_FILE.parent.chmod(0o700)
    out = capsys.readouterr().out
    assert "could not be removed" in out and "is removed" not in out


# ── SEC15: the console reads runs/ as the watch reads it ──────────────────────────────────────

def _guarded(fn, *args, guard_s=5.0):
    import threading
    box = []

    def run():
        try:
            box.append(fn(*args))
        except BaseException as exc:  # noqa: BLE001 — the test reads it
            box.append(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(guard_s)
    return (not t.is_alive()), (box[0] if box else None)


def _release_fifo(path, stop):
    """Whoever opened the pipe for reading, blocked, is released from 5 s on — a red test fails,
    never hangs."""
    import errno
    import os
    if stop.wait(5.0):
        return
    while not stop.is_set():
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        except OSError as exc:
            if exc.errno not in (errno.ENXIO, errno.ENOENT):
                return
        stop.wait(0.05)


def _runs_with_traps(tmp_path):
    import os
    import threading
    runs = tmp_path / "runs"
    runs.mkdir(exist_ok=True)
    (runs / "r1_signals.jsonl").write_text(json.dumps({"timestamp": "2026-11-02T10:00:00+00:00",
                                                       "event": "attack_started", "ttp": "T1110.001",
                                                       "resource_id": "/x/vm-a"}) + "\n")
    fifo = runs / "r2_signals.jsonl"
    os.mkfifo(fifo)
    # A link, to a file elsewhere: never followed (never /dev/zero here — a reader that follows it
    # would read without end; tests/unit/test_runs_channel.py holds that case, bounded).
    (tmp_path / "elsewhere.jsonl").write_text(json.dumps({"timestamp": "2026-11-02T09:00:00+00:00",
                                                          "action": "isolate_vm"}) + "\n")
    (runs / "r3_debug.jsonl").symlink_to(tmp_path / "elsewhere.jsonl")
    stop = threading.Event()
    threading.Thread(target=_release_fifo, args=(fifo, stop), daemon=True).start()
    return runs, stop


def test_the_feeds_history_reads_runs_never_blocking_a_refusal_said_once(runs, tmp_path, capsys):
    """A named pipe and a link to a device that never ends, in runs/: the history comes back at
    once with the regular file's lines; each refusal said once, never at every read."""
    _, stop = _runs_with_traps(tmp_path)
    try:
        c = console()
        finished, got = _guarded(lambda: c.get("/api/feed/history").json())
        assert finished, "the history blocked"
        assert [e["event"] for e in got["entries"]] == ["attack_started"]
        _guarded(lambda: c.get("/api/feed/history").json())
        out = capsys.readouterr().out
        assert out.count("r2_signals.jsonl") == 1 and out.count("r3_debug.jsonl") == 1
        assert "un tube nommé" in out and "un lien, jamais suivi" in out
    finally:
        stop.set()


def test_the_live_feed_reads_runs_never_blocking(runs, tmp_path, monkeypatch):
    """The live feed, a pipe beside a run's file: the run's new line arrives, the pipe never
    stops the console's loop."""
    monkeypatch.setattr(api, "_FEED_POLL_S", 0.05)
    runs_dir, stop = _runs_with_traps(tmp_path)

    def follow():
        with console().websocket_connect(WS) as ws:
            first = ws.receive_json()                        # the history
            with open(runs_dir / "r1_signals.jsonl", "a") as f:
                f.write(json.dumps({"timestamp": "2026-11-02T10:01:00+00:00", "event": "detection",
                                    "ttp": "T1110.001", "resource_id": "/x/vm-a"}) + "\n")
            return first, ws.receive_json()
    try:
        finished, got = _guarded(follow)
        assert finished, "the live feed blocked"
        assert not isinstance(got, BaseException), got
        assert got[0]["event"] == "attack_started" and got[1]["event"] == "detection"
    finally:
        stop.set()
