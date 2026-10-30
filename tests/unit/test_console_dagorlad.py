"""Dagorlad's board in the console (docs/design/console.md, §7, phase a): the red cards, the blue
ones, and the plan of the wires drawn between them — read only.

No Azure, no model: the bench's VMs are a list the test hands to the route (``READ_TARGETS``), the
watch's gate is stubbed, the catalogue and the rules are the shipped ones. Requires the console
extra.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import console  # noqa: E402

import eregion_console.api as api  # noqa: E402
from eregion_console import board  # noqa: E402
from eregion_core import watch_gate  # noqa: E402
from eregion_core.exercise_plan import load_catalog  # noqa: E402

BOARD_RULES = api._board_rules     # the route's own reading, before a test replaces it
RG = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, BREE, SENTINEL = RG + "vm-celebrimbor-gondolin", RG + "vm-celebrimbor-bree", RG + "vm-sentinel"
BENCH_RG = {"eregion-target": "celebrimbor"}


def _vm(rid, tags):
    return {"resource_id": rid, "name": rid.rsplit("/", 1)[-1], "resource_group": "rg-celebrimbor",
            "rg_tags": dict(BENCH_RG), "tags": tags}


VMS = [
    _vm(GONDOLIN, {"eregion-target": "celebrimbor", "eregion-zone": "bench"}),
    _vm(SENTINEL, {"eregion-target": "celebrimbor", "eregion-zone": "production"}),
    _vm(BREE, {}),                     # the VM with a real load: never enrolled, never a card
]
# Glorfindel's rules as a configured watch loads them (the shipped ones, bound to a backend).
ACTIVE_RULES = [
    {"name": "ssh-brute-force", "ttp": "T1110.001", "enabled": True, "backend": "", "expected_latency_s": 120, "layer": "base"},
    {"name": "ransomware-disk-write", "ttp": "T1486", "enabled": True, "backend": "", "expected_latency_s": 90, "layer": "base"},
]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,gothmog")
    monkeypatch.delenv("EREGION_BENCH", raising=False)
    monkeypatch.setattr(api, "READ_TARGETS", lambda subscription: VMS)
    api._targets_cache.update(at=0.0, value=None)
    monkeypatch.setattr(api, "_board_rules", lambda: ACTIVE_RULES)
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None: "")
    return console()


def test_without_a_configured_backend_the_shipped_rules_detect_nothing_and_the_board_says_so():
    """The rules as the watch loads them on a host without its configuration (the conftest's): each
    one listed, none enabled — a wire then expects a miss, never a detection the watch cannot make."""
    rules = BOARD_RULES()
    assert {"ssh-brute-force", "ransomware-disk-write"} <= {r["name"] for r in rules}
    assert not any(r["enabled"] for r in rules)
    out = board.expected(load_catalog()["T1110.001"], {"mode": "human_only"}, rules, 0.7)
    assert out["summary"] == "no rule: blind, expect a miss"


def _plan(client, *wires, **extra):
    params = [("wire", w) for w in wires] + list(extra.items())
    r = client.get("/api/dagorlad/plan", params=params)
    assert r.status_code == 200
    return r.json()


def test_the_board_reads_the_catalogue_and_only_the_enrolled_targets(client):
    b = client.get("/api/dagorlad/board").json()
    reds = {r["id"]: r for r in b["reds"]}
    assert reds["T1110.001"]["available"] and reds["T1110.001"]["injector"] == "annatar"
    assert reds["vm-shutdown"]["kind"] == "fault" and reds["vm-shutdown"]["injector"] == "gothmog"
    assert reds["T1486"]["destructive"] is True
    assert not any(r["available"] for r in b["reds"] if r["status"] != "implemented")
    names = [t["name"] for t in b["targets"]]
    assert names == ["vm-celebrimbor-gondolin", "vm-sentinel"]          # bree: no card
    assert {t["name"]: t["zone"] for t in b["targets"]} == {"vm-celebrimbor-gondolin": "bench",
                                                            "vm-sentinel": "production"}
    assert b["glorfindel"]["rules"] > 0 and b["targets_error"] == ""
    assert {t["type"] for t in b["other_types"]} >= {"azure_storage", "entra_id"}


def test_an_injector_not_set_up_leaves_its_cards_without_a_handle(client, monkeypatch):
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar")
    reds = {r["id"]: r for r in client.get("/api/dagorlad/board").json()["reds"]}
    assert reds["T1110.001"]["available"]
    assert not reds["vm-shutdown"]["available"] and "Gothmog" in reds["vm-shutdown"]["why"]


def test_targets_unreadable_are_said_never_invented(client, monkeypatch):
    def fail(subscription):
        raise RuntimeError("HTTP 403 listing resourcegroups")
    monkeypatch.setattr(api, "READ_TARGETS", fail)
    api._targets_cache.update(at=0.0, value=None)
    b = client.get("/api/dagorlad/board").json()
    assert b["targets"] == [] and "403" in b["targets_error"]
    p = _plan(client, f"T1110.001@{GONDOLIN}")
    assert p["wires"][0]["code"] == "not_enrolled"
    assert any(c["ok"] is False and "403" in c["text"] for c in p["checks"])


def test_a_plan_judges_each_wire_as_orodruin_would(client):
    p = _plan(client, f"T1110.001@{GONDOLIN}", f"T1486@{SENTINEL}", f"vm-shutdown@{GONDOLIN}",
              f"T1110.001@{BREE}")
    w = p["wires"]
    assert [(x["experiment"], x["code"], x["order"]) for x in w] == [
        ("T1110.001", "", 1), ("T1486", "zone_forbids", None), ("vm-shutdown", "", 2),
        ("T1110.001", "not_enrolled", None)]
    assert w[0]["expected"]["rules"] and "card" in w[0]["expected"]["summary"]   # human_only here
    assert w[2]["expected"]["summary"] == "nothing disruptive"
    assert "expected" not in w[1]
    assert p["total"] == {"wires": 4, "allowed": 2, "refused": 2, "estimate_s": w[0]["estimate_s"] + w[2]["estimate_s"]}
    assert p["phase"] == "a"


def test_the_browser_says_two_identifiers_never_the_verdict(client):
    """What is destructive, the zone, the status: the server reads them — a parameter that would
    say otherwise is not even read."""
    p = _plan(client, f"T1486@{SENTINEL}", destructive="false", zone="bench", status="ok")
    assert p["wires"][0]["code"] == "zone_forbids"


def test_never_without_glorfindel(client, monkeypatch):
    monkeypatch.setattr(watch_gate, "refusal", lambda now=None: "no heartbeat for 12 min")
    p = _plan(client, f"T1110.001@{GONDOLIN}")
    assert p["wires"][0]["code"] == "no_watch"
    assert p["checks"][0]["ok"] is False and "12 min" in p["checks"][0]["text"]


def test_a_destructive_wire_on_the_bench_asks_for_the_name(client):
    w = _plan(client, f"T1486@{GONDOLIN}")["wires"][0]
    assert w["code"] == "" and "typed_name" in [x["code"] for x in w["warnings"]]
    assert "restore is never autonomous" in w["expected"]["glorfindel"]


def test_glorfindels_side_warns_what_only_it_knows(client):
    """Gondolin is not among the watch's discovered assets here: not seen."""
    w = _plan(client, f"T1110.001@{GONDOLIN}")["wires"][0]
    assert "not_seen" in [x["code"] for x in w["warnings"]] and w["status"] == "warn"


def test_a_malformed_or_oversized_request_is_refused(client):
    assert "error" in _plan(client, "T1110.001")
    assert "error" in _plan(client, *[f"T1110.001@{GONDOLIN}"] * (api.MAX_WIRES + 1))


def test_the_plan_writes_nothing_and_calls_no_model(client, tmp_path, monkeypatch):
    import glorfindel.config as gconfig

    def before():
        return sorted((str(p), p.stat().st_mtime_ns) for p in tmp_path.rglob("*") if p.is_file())

    litellm = pytest.importorskip("litellm")
    monkeypatch.setattr(litellm, "completion", lambda *a, **k: pytest.fail("the model was called"))
    seen = before()
    _plan(client, f"T1110.001@{GONDOLIN}", f"T1486@{GONDOLIN}", f"vm-shutdown@{GONDOLIN}")
    client.get("/api/dagorlad/board")
    assert before() == seen
    assert gconfig  # the configuration was only read


def test_the_page_is_served_behind_the_token_with_its_scripts_as_files(client):
    page = client.get("/dagorlad").text
    assert '<script src="/static/dagorlad.js"></script>' in page
    assert console(token=None).get("/dagorlad").status_code == 401


# --- what to expect: an envelope from the configuration, never the model's forecast ---------

CAT = load_catalog()
RULES = [{"name": "ssh-brute-force", "ttp": "T1110.001", "enabled": True, "backend": "law",
          "expected_latency_s": 120}]


def test_expected_follows_the_targets_mode():
    e = CAT["T1110.001"]
    base = {"backend": "law", "mode": "human_only", "hold": "", "read_only": False}
    assert board.expected(e, base, RULES, 0.7)["summary"] == "detected ~2 min · card"
    nd = board.expected(e, {**base, "mode": "non_disruptive"}, RULES, 0.7)
    assert nd["summary"] == "detected ~2 min · may contain alone" and "70 %" in nd["glorfindel"]
    ro = board.expected(e, {**base, "mode": "non_disruptive", "read_only": True}, RULES, 0.7)
    assert ro["summary"] == "detected ~2 min · recommends"
    held = board.expected(e, {**base, "hold": "not_ready"}, RULES, 0.7)
    assert "held: not_ready" in held["glorfindel"]


def test_without_a_rule_glorfindel_is_blind_and_the_page_says_so():
    out = board.expected(CAT["T1110.001"], {"backend": "other-law", "mode": "human_only"}, RULES, 0.7)
    assert out["summary"] == "no rule: blind, expect a miss" and out["rules"] == []


def test_a_technique_and_its_sub_technique_are_the_same():
    assert board.same_technique("T1110", "T1110.001") and board.same_technique("t1110.001", "T1110.001")
    assert not board.same_technique("T1110", "T1111") and not board.same_technique("", "T1110")


def test_a_technique_without_a_rule_is_said_blind(client):
    w = _plan(client, f"T1136.001@{GONDOLIN}")["wires"][0]
    assert w["code"] == "" and "no_rule" in [x["code"] for x in w["warnings"]]
    assert w["expected"]["summary"] == "no rule: blind, expect a miss"


def test_the_page_dispatches_to_a_closed_table_with_primitive_arguments():
    """As on Glorfindel's page (#257): an element names its action, the dispatcher calls it from
    ACTIONS only, with names or indexes — never window[name], never an object."""
    import re
    from pathlib import Path
    js = (Path(api.__file__).parent / "static" / "dagorlad.js").read_text()
    assert "if (!Object.hasOwn(ACTIONS, action)) return;" in js
    assert "if (!Array.isArray(args) || !args.every(a => a === null || ['string', 'number', 'boolean']" \
           ".includes(typeof a))) return;" in js
    assert "document.addEventListener(type, ev => _dispatch(ev, name), true);" in js
    assert "window[" not in js and "eval(" not in js and "new Function" not in js
    table = js[js.index("const ACTIONS = {"):js.index("\n};", js.index("const ACTIONS = {"))]
    named = set(re.findall(r"^  (\w+)\(", table, re.M))
    used = set(re.findall(r"_on\('[a-z]+', '(\w+)'", js))
    assert used and used <= named, sorted(used - named)


def test_a_wire_is_removed_by_its_own_cross_never_by_drawing_it_again():
    """Several wires go to one target: drawing a pair again removes nothing, the page says it is
    drawn already; a wire is removed by its ✕, on its pill and on its plan line (Jonathan, 30/10)."""
    from pathlib import Path
    js = (Path(api.__file__).parent / "static" / "dagorlad.js").read_text()
    start = js.index("function addWire(")
    add = js[start:js.index("\n}\n", start)]
    assert "already drawn" in add and "splice" not in add
    assert js.count("_on('click', 'unwire', k)") == 2


# --- the end of DG-a: the Runs, the redirects, the tab, the last proof (#347) ---------------

def test_a_red_card_carries_its_last_proof_from_the_coverage_matrix(client, monkeypatch):
    """The coverage matrix (C1) gives each entry its state and the age of its last proof; an
    entry it does not hold was never run here."""
    matrix = {"techniques": [{"id": "T1110.001", "state": "proven", "last_proof": {"age_s": 518400, "run_id": "r-1"},
                              "last_run": {"run_id": "r-1", "at": "2026-10-24T08:00:00+00:00"}}],
              "faults": [{"id": "vm-shutdown", "state": "regressed", "last_proof": None,
                          "last_run": {"run_id": "g-2", "at": "2026-10-29T08:00:00+00:00"}}]}
    monkeypatch.setattr(api, "coverage_matrix", lambda now=None: matrix)
    reds = {r["id"]: r for r in client.get("/api/dagorlad/board").json()["reds"]}
    assert reds["T1110.001"]["proof"] == {"state": "proven", "proof_age_s": 518400, "last_run": "r-1",
                                          "last_run_at": "2026-10-24T08:00:00+00:00"}
    assert reds["vm-shutdown"]["proof"]["state"] == "regressed"
    assert reds["T1486"]["proof"]["state"] == "never"


def test_the_header_has_three_tabs_dagorlad_in_place_of_the_injectors():
    """Overview, Glorfindel, Dagorlad: Annatar's and Gothmog's pages became its Runs (30/10)."""
    from pathlib import Path
    js = (Path(api.__file__).parent / "static" / "console.js").read_text()
    tabs = js[js.index("const TABS = ["):js.index("];", js.index("const TABS = ["))]
    assert "{ id: 'dagorlad'" in tabs and "href: '/dagorlad'" in tabs
    assert "'/annatar'" not in tabs and "'/gothmog'" not in tabs


def test_a_run_link_in_the_runs_stays_in_the_runs():
    """A link to a run opens its row in the Runs, never the Board (?run= alone is the Board)."""
    from pathlib import Path
    js = (Path(api.__file__).parent / "static" / "injector.js").read_text()
    assert 'href="?view=runs&run=' in js and 'href="?run=' not in js
