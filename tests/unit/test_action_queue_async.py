"""FS1c (#571, docs/design/file-actions-signee.md §9): the signed action queue, asynchronous — the
console's write routes deposit a request and answer at once with its id; ``GET /api/queue/<id>``
says its receipt (``received``, ``accepted``, ``done``, ``failed``, refused), and no thread waits
for the watch; the bot says each receipt in the VM's thread; the write buttons follow the status the
watch signs. And FS1b's review: what remains synchronous bounded, a receipt of another key told
apart from no receipt, ``proposal_consumed`` after a failure, the ``signal_id`` of a card born of the
queue, the routes without the flag, the bot out of ``runs/console``, the gesture of the keys.

On the in-memory Azure (tests/unit/fake_azure.py) through the world of test_action_queue_watch.py:
a throwaway HOME, runs/ in tmp, keys from fixed seeds or drawn in tmp — never a real key, no Azure,
no network, no model. The default of EREGION_ACTION_QUEUE stays off: nothing here sets it but a
test, by monkeypatch. Mutants M4040–M4069 (scripts/mutants/FS1c.py).
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import eregion_core.action_queue as aq
import eregion_core.watch_key as watch_key
from eregion_core import runs_layout
from glorfindel import escalations
from glorfindel.actions import AzureConnector

from .fake_azure import ATTACKER
from .test_action_queue_watch import (
    BOT, CONSOLE, STRANGER, WATCH, WEB, _ask, _card, _console, _flows, _followed, _Picker, _receipt, _Thread,
)
from .test_action_queue_watch import make_world

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("host_env_fs1c", ROOT / "infra" / "glorfindel-host" / "host_env.py")
host_env = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(host_env)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """FS1b's world (test_action_queue_watch.py): web on the in-memory Azure, the watch's queue."""
    return make_world(tmp_path, monkeypatch)


@pytest.fixture
def queue_on(world, monkeypatch):
    """The flag set for this test, the console's key drawn and pinned at the watch; the console's
    answers settled before forgotten."""
    pytest.importorskip("fastapi")
    api, client = _console(world, monkeypatch)
    monkeypatch.setattr(api, "_SETTLED", {})
    monkeypatch.setenv(aq.FLAG_ENV, "1")
    monkeypatch.delenv(watch_key.KEY_ENV, raising=False)
    key = aq.load_service_key("console")
    world["q"].pins = {"console": key.public, "bot": BOT.public}
    return {"api": api, "client": client, "key": key}


def _lines(world, hand="console") -> list[dict]:
    path = world["root"] / hand / "manual_actions.jsonl"
    return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


# ── The routes answer at once; the page follows the receipt ──────────────────────────

def test_a_route_deposits_and_answers_at_once_with_its_request(world, queue_on):
    """No watch at all: the route never waits for one — its request's id, at once."""
    world["conn"].isolate_vm(WEB)
    started = time.monotonic()
    out = queue_on["client"].post("/api/action/release/web", json={}).json()
    assert time.monotonic() - started < 2, "the route waited for the watch"
    assert out["pending"] is True and out["via"] == "queue" and out["state"] == "deposited", out
    assert (aq.request_dir("console", world["root"]) / f"{out['request']}.json").exists()
    got = queue_on["client"].get(f"/api/queue/{out['request']}").json()
    assert got["pending"] is True and got["state"] == "waiting", got


def test_the_receipt_followed_until_done_and_the_gesture_noted_once(world, queue_on):
    client, api = queue_on["client"], queue_on["api"]
    card = _card()
    out = client.post(f"/api/action/approve/{card['id']}", json={}).json()
    with _Picker(world["q"]):
        got = _followed(client, out)
    assert got["ok"] and got["state"] == "done" and got["action"] == "isolate_vm", got
    assert got["verification"]["verified"] is True and not _flows(world)
    assert client.get(f"/api/queue/{out['request']}").json() == got, "settled once, said the same"
    api._SETTLED.clear()                             # a console restarted: read again
    again = client.get(f"/api/queue/{out['request']}").json()
    assert again["ok"] and again["state"] == "done"
    noted = _lines(world)
    assert len(noted) == 1, "the gesture noted once"
    assert noted[0]["outcome"]["via"] == "queue" and noted[0]["outcome"]["approved_escalation"] == card["id"]


def test_a_page_closed_before_its_receipt_has_its_gesture_noted_all_the_same(world, queue_on):
    """The page's state settles every request of the console whose receipt came."""
    client = queue_on["client"]
    out = client.post(f"/api/action/approve/{_card()['id']}", json={}).json()
    assert out["pending"]
    world["q"].poll()
    assert _lines(world) == []
    client.get("/api/state")
    assert len(_lines(world)) == 1
    assert not (aq.request_dir("console", world["root"]) / f"{out['request']}.json").exists(), "withdrawn"


def test_a_refusal_and_a_failure_come_back_as_the_routes_error(world, queue_on, monkeypatch):
    client = queue_on["client"]
    world["q"].read_only = True
    out = client.post(f"/api/action/approve/{_card()['id']}", json={}).json()
    with _Picker(world["q"]):
        got = _followed(client, out)
    assert got["refused"] == "read_only" and got["error"] and got["state"] == "refused"
    world["q"].read_only = False
    monkeypatch.setattr(AzureConnector, "isolate_vm", lambda self, rid: (_ for _ in ()).throw(RuntimeError("down")))
    out = client.post(f"/api/action/approve/{_card(etype='low_confidence')['id']}", json={}).json()
    with _Picker(world["q"]):
        got = _followed(client, out)
    assert got["state"] == "failed" and "down" in got["error"], got


def test_a_request_the_watch_never_takes_is_said_not_taken(world, queue_on, monkeypatch):
    out = queue_on["client"].post(f"/api/action/approve/{_card()['id']}", json={}).json()
    monkeypatch.setattr(aq, "TAKE_S", -1)
    got = queue_on["client"].get(f"/api/queue/{out['request']}").json()
    assert got["state"] == "not_taken" and "did not take the request" in got["error"], got
    assert not got.get("pending")


def test_an_unknown_request_is_said_unknown(world, queue_on):
    got = queue_on["client"].get(f"/api/queue/{'0' * 32}").json()
    assert got["state"] == "unknown" and got["error"]
    assert queue_on["client"].get("/api/queue/not-a-nonce").json()["state"] == "unknown"


def test_a_promotion_an_unblock_a_snapshot_answer_as_before_once_settled(world, queue_on, monkeypatch):
    client = queue_on["client"]
    world["conn"].block_suspicious_ip(ATTACKER, WEB, "vm")
    with _Picker(world["q"]):
        got = _followed(client, client.post("/api/action/block-promote/web", json={}, params={"ip": ATTACKER}).json())
        assert got["ok"] and got["scope"] == "subnet" and isinstance(got["said"], list) and "whole" in got, got
        got = _followed(client, client.post("/api/action/unblock/web", json={}, params={"ip": ATTACKER}).json())
        assert got["ok"] and got["ip"] == ATTACKER, got
    monkeypatch.setattr("glorfindel.config.resolve_backup_vault", lambda *a: ("vault", "rg-vault", ""))
    monkeypatch.setattr("glorfindel.jobs.start_snapshot", lambda *a, **k: {"job_id": "job-1"})
    world["conn"].isolate_vm(WEB)
    with _Picker(world["q"]):
        got = _followed(client, client.post("/api/action/snapshot/web", json={}).json())
    assert got["ok"] and (got["status"], got["job_id"], got["resource_id"]) == ("started", "job-1", WEB), got


# ── A receipt of another key is told apart from no receipt ─────────────────────────────

def test_a_receipt_signed_by_another_key_is_said_with_both_fingerprints(world, queue_on, monkeypatch):
    client = queue_on["client"]
    out = client.post(f"/api/action/approve/{_card()['id']}", json={}).json()
    world["q"].poll()
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(STRANGER.public))
    got = client.get(f"/api/queue/{out['request']}").json()
    assert got["state"] == "untrusted", got
    assert watch_key._short(WATCH.fingerprint) in got["error"] and watch_key._short(STRANGER.fingerprint) in got["error"]
    assert watch_key.KEY_ENV in got["error"] and "did not take" not in got["error"]
    assert _lines(world) == [], "a receipt not believed notes nothing"


def test_ask_says_a_receipt_of_another_key_never_not_taken(world, monkeypatch):
    world["q"].pins = {"console": aq.load_service_key("console").public, "bot": BOT.public}
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(STRANGER.public))
    with _Picker(world["q"]):
        out = aq.ask("console", "isolate_vm", WEB, by={"via": "console-token"}, root=world["root"],
                     card=(c := _card())["id"] and (c["id"], aq.digest(c["proposal"])), take_s=1.0, poll_s=0.05)
    assert "another key" in out["error"] or "not signed by this watch" in out["error"], out
    assert aq.NOT_TAKEN not in out["error"]


def test_without_the_watchs_key_pinned_the_receipt_is_believed_from_the_mount(world):
    doc = _ask(world, "isolate_vm", card=_card())
    world["q"].poll()
    got = aq.follow("console", doc["id"], root=world["root"], watch_public=None)
    assert got["state"] == "done" and got["final"]


# ── The posture: the write buttons follow the watch's signed status ────────────────────

def _status(world, now=None, **changes):
    world["q"].status(now or datetime.now(timezone.utc), force=True)
    if changes:
        path = aq.receipts_dir(world["root"]) / aq.STATUS_NAME
        doc = json.loads(path.read_text())
        doc.update(changes)
        path.write_text(json.dumps(aq.sign_watch("status", doc, WATCH)))


def test_the_posture_holds_only_a_fresh_writing_status_that_pins_this_key(world):
    own = CONSOLE.fingerprint
    assert aq.posture("console", root=world["root"], fingerprint=own)["ok"] is False      # no status yet
    _status(world)
    assert aq.posture("console", root=world["root"], fingerprint=own) == {
        "ok": True, "why": "", "status": aq.posture("console", root=world["root"], fingerprint=own)["status"]}
    later = datetime.now(timezone.utc) + timedelta(seconds=aq.STATUS_STALE_S + 5)
    assert "s old" in aq.posture("console", root=world["root"], fingerprint=own, now=later)["why"]
    world["q"].read_only = True
    _status(world)
    assert "read-only" in aq.posture("console", root=world["root"], fingerprint=own)["why"]
    world["q"].read_only = False
    world["q"].pins = {"bot": BOT.public}
    _status(world)
    assert "pins no key for the console" in aq.posture("console", root=world["root"], fingerprint=own)["why"]
    world["q"].pins = {"console": STRANGER.public, "bot": BOT.public}
    _status(world)
    why = aq.posture("console", root=world["root"], fingerprint=own)["why"]
    assert "another key" in why and aq.KEYS_ENV in why


def test_a_status_of_another_key_is_not_believed_when_the_watchs_key_is_pinned(world):
    world["q"].pins = {"console": CONSOLE.public, "bot": BOT.public}
    _status(world)
    path = aq.receipts_dir(world["root"]) / aq.STATUS_NAME
    forged = aq.sign_watch("status", json.loads(path.read_text()), STRANGER)
    path.write_text(json.dumps(forged))
    assert aq.posture("console", root=world["root"], fingerprint=CONSOLE.fingerprint)["ok"] is True   # the mount
    held = aq.posture("console", root=world["root"], watch_public=WATCH.public, fingerprint=CONSOLE.fingerprint)
    assert held["ok"] is False and "pin the watch's new key" in held["why"]


def test_the_page_state_says_the_queue_off_or_what_the_watch_says(world, monkeypatch):
    pytest.importorskip("fastapi")
    api, client = _console(world, monkeypatch)
    monkeypatch.delenv(aq.FLAG_ENV, raising=False)
    assert client.get("/api/state").json()["queue"] == {"on": False, "ok": True, "why": ""}
    monkeypatch.setenv(aq.FLAG_ENV, "1")
    key = aq.load_service_key("console")
    world["q"].pins = {"console": STRANGER.public}
    _status(world)
    q = client.get("/api/state").json()["queue"]
    assert q["on"] is True and q["ok"] is False and "another key" in q["why"], q
    world["q"].pins = {"console": key.public}
    _status(world)
    assert client.get("/api/state").json()["queue"]["ok"] is True


def test_the_page_greys_its_write_buttons_by_the_queues_posture_and_follows_the_receipt():
    js = (ROOT / "eregion_console" / "static" / "glorfindel.js").read_text()
    blocked = js.split("function _writesBlocked()", 1)[1].split("\n}\n", 1)[0]
    assert "q.on && !q.ok" in blocked and "q.why" in blocked
    guards = js.split("function _applyReadOnlyGuards(root)", 1)[1].split("\n}\n", 1)[0]
    assert "_writesBlocked()" in guards and "b.title = why" in guards
    assert "/api/queue/${_seg(d.request)}" in js.split("async function _settled(d)", 1)[1].split("\n}\n", 1)[0]
    for handler in ("doRelease", "doUnblockIp", "doBlockPromote", "doRevert", "doSnapshot", "doApproveAction"):
        body = js.split(f"async function {handler}(", 1)[1].split("\n}\n", 1)[0]
        assert "await _settled(await r.json())" in body, handler


# ── What remains synchronous, bounded ─────────────────────────────────────────────────

def _full(api, monkeypatch):
    slots = threading.BoundedSemaphore(1)
    slots.acquire()
    monkeypatch.setattr(api, "_GESTURE_SLOTS", slots)


def _no_subprocess(api, monkeypatch, ran):
    monkeypatch.setattr(api.subprocess, "run", lambda args, **k: ran.append(args) or
                        subprocess.CompletedProcess(args, 0, "ok", ""))


@pytest.mark.parametrize("route, setup", [
    ("/api/action/release/web", "isolate"), ("/api/action/revert/web", "isolate"),
    (f"/api/action/unblock/web?ip={ATTACKER}", "block"), (f"/api/action/block-promote/web?ip={ATTACKER}", "block"),
    ("/api/action/snapshot/web", "isolate"), ("approve", "card"),
])
def test_every_gesture_slot_taken_refuses_at_once_and_writes_nothing(world, monkeypatch, route, setup):
    """FS1b's review: a burst of clicks never takes the server's threads — past the console's
    slots, a gesture is refused (503), the direct call never made."""
    pytest.importorskip("fastapi")
    api, client = _console(world, monkeypatch)
    monkeypatch.delenv(aq.FLAG_ENV, raising=False)
    if setup == "isolate":
        world["conn"].isolate_vm(WEB)
    elif setup == "block":
        world["conn"].block_suspicious_ip(ATTACKER, WEB, "vm")
    if route == "approve":
        route = f"/api/action/approve/{_card()['id']}"
    ran, wrote = [], []
    _no_subprocess(api, monkeypatch, ran)
    monkeypatch.setattr("glorfindel.config.resolve_backup_vault", lambda *a: ("vault", "rg-vault", ""))
    monkeypatch.setattr("glorfindel.jobs.start_snapshot", lambda *a, **k: wrote.append("snapshot") or {"job_id": "j"})
    for name in ("isolate_vm", "block_suspicious_ip"):
        monkeypatch.setattr(AzureConnector, name, lambda self, *a, _n=name, **k: wrote.append(_n) or {"status": "ok"})
    _full(api, monkeypatch)
    r = client.post(route, json={})
    assert r.status_code == 503 and r.json()["busy"] is True, (route, r.text)
    assert ran == [] and wrote == [], route


def test_with_the_flag_a_deposit_past_the_slots_is_refused_and_nothing_written(world, queue_on, monkeypatch):
    world["conn"].isolate_vm(WEB)
    _full(queue_on["api"], monkeypatch)
    r = queue_on["client"].post("/api/action/release/web", json={})
    assert r.status_code == 503
    assert not list(aq.request_dir("console", world["root"]).glob("*.json"))


def test_a_slot_is_given_back_after_each_gesture(world, monkeypatch):
    pytest.importorskip("fastapi")
    api, client = _console(world, monkeypatch)
    monkeypatch.delenv(aq.FLAG_ENV, raising=False)
    world["conn"].isolate_vm(WEB)
    ran: list = []
    _no_subprocess(api, monkeypatch, ran)
    for _ in range(api.GESTURES_IN_FLIGHT + 2):
        assert client.post("/api/action/release/web", json={}).json()["ok"] is True
    assert len(ran) == api.GESTURES_IN_FLIGHT + 2


# ── Without the flag, the routes call as before (FS1b's review) ────────────────────────

@pytest.mark.parametrize("route, setup, want", [
    ("/api/action/release/web", "isolate", ("cli", "release")),
    ("/api/action/revert/web", "isolate", ("cli", "reset")),
    (f"/api/action/unblock/web?ip={ATTACKER}", "block", ("cli", "unblock")),
    (f"/api/action/block-promote/web?ip={ATTACKER}", "block", ("connector", "block_suspicious_ip")),
    ("/api/action/snapshot/web", "isolate", ("connector", "snapshot")),
])
def test_without_the_flag_each_route_calls_as_before_and_deposits_nothing(world, monkeypatch, route, setup, want):
    pytest.importorskip("fastapi")
    api, client = _console(world, monkeypatch)
    monkeypatch.delenv(aq.FLAG_ENV, raising=False)
    monkeypatch.setattr(aq, "deposit_request", lambda *a, **k: pytest.fail("deposited without the flag"))
    if setup == "isolate":
        world["conn"].isolate_vm(WEB)
    else:
        world["conn"].block_suspicious_ip(ATTACKER, WEB, "vm")
    ran, wrote = [], []
    _no_subprocess(api, monkeypatch, ran)
    monkeypatch.setattr("glorfindel.config.resolve_backup_vault", lambda *a: ("vault", "rg-vault", ""))
    monkeypatch.setattr("glorfindel.jobs.start_snapshot", lambda *a, **k: wrote.append("snapshot") or {"job_id": "j"})
    monkeypatch.setattr(AzureConnector, "block_suspicious_ip",
                        lambda self, *a, **k: wrote.append("block_suspicious_ip") or {"status": "blocked"})
    out = client.post(route, json={}).json()
    assert "via" not in out and not out.get("pending"), out
    if want[0] == "cli":
        assert [a[1] for a in ran] == [want[1]], ran
    else:
        assert wrote == [want[1]], wrote
    assert not aq.request_dir("console", world["root"]).exists()


# ── The watch: proposal_consumed after a failure, the card born of the queue ───────────

def test_a_proposal_consumed_says_done_or_failed_and_what_to_do():
    said = aq.REFUSALS["proposal_consumed"]
    assert "done or failed" in said and "detection" in said and "CLI" in said


def test_a_check_that_fails_leaves_a_card_bearing_the_requests_signal(world, monkeypatch):
    monkeypatch.setattr(AzureConnector, "verify_isolation", lambda self, rid: (_ for _ in ()).throw(RuntimeError("x")))
    doc = _ask(world, "isolate_vm", card=_card())
    world["q"].poll()
    assert _receipt(world, doc)["state"] == "done"
    failed = [e for e in escalations.pending() if e["escalation_type"] == "verification_failed"]
    assert [e["signal_id"] for e in failed] == [f"queue-console-{doc['id']}"], failed


def test_the_console_keeps_its_own_signal_for_its_direct_call():
    from glorfindel import approval
    seen = []
    monkey = type("C", (), {"verify_isolation": lambda self, rid: (_ for _ in ()).throw(RuntimeError("x"))})()
    import glorfindel.escalations as esc
    real = esc.record
    try:
        esc.record = lambda **k: seen.append(k["signal_id"]) or "id"
        approval.verify_approved(monkey, {"id": "card-1"}, "isolate_vm", WEB, {})
        approval.verify_approved(monkey, {"id": "card-1"}, "isolate_vm", WEB, {}, signal_id="queue-console-ab")
    finally:
        esc.record = real
    assert seen == ["approve-card-1", "queue-console-ab"]


def test_the_watch_says_at_its_start_each_key_that_is_missing(monkeypatch):
    from glorfindel import queue_watch
    said: list[str] = []
    monkeypatch.setenv(aq.FLAG_ENV, "1")
    monkeypatch.setenv(aq.KEYS_ENV, f"console=ed25519:{watch_key.public_text(CONSOLE.public).split(':', 1)[1]}")
    monkeypatch.setattr(queue_watch.QueueWatch, "start", lambda self: None)
    queue_watch.start(object(), lambda: WATCH, say=said.append)
    assert any("no key pinned for the bot" in s for s in said), said
    assert not any("no key pinned for the console" in s for s in said), said


def test_pin_problems_says_each_service_without_its_key_and_each_wrong_pin():
    pins, wrong = aq.parse_pins("console=ed25519:nope")
    lines = aq.pin_problems(pins, wrong)
    assert any("console's key is not one" in x for x in lines)
    assert any("no key pinned for the console" in x for x in lines) and any("for the bot" in x for x in lines)
    assert aq.pin_problems({"console": CONSOLE.public}, (), ("console",)) == []


# ── The bot says the receipt ──────────────────────────────────────────────────────────

def _scripted(monkeypatch, states):
    from glorfindel import bot
    rid = "ab" * 16
    monkeypatch.setattr(bot, "_deposit_reset", lambda esc, user: {"request": rid})
    seq = iter(states)

    def follow(service, request_id, **k):
        state = next(seq)
        out = {"request": request_id, "state": state, "final": state in aq.FINAL_STATES}
        if state in ("received", "accepted", "done", "refused"):
            out["receipt"] = {"state": state, "code": "guard" if state == "refused" else "",
                              "reason": "no" if state == "refused" else "", "result": {"status": "clean"}}
        return out
    monkeypatch.setattr(aq, "follow", follow)
    return bot, rid


def test_the_bot_says_each_state_of_its_receipt_and_holds_no_thread(world, monkeypatch):
    pytest.importorskip("discord")
    bot, rid = _scripted(monkeypatch, ["waiting", "received", "received", "accepted", "done"])
    thread = _Thread()
    code, said = asyncio.run(bot._queue_revert({"id": "c1"}, None, thread, poll_s=0))
    assert code == 0 and "done" in said and "reset → clean" in said
    assert [s.split(" : ")[0] for s in thread.said] == [f"📨 File d'actions ({rid[:8]})",
                                                       f"📥 File d'actions ({rid[:8]})",
                                                       f"⚙️ File d'actions ({rid[:8]})"], thread.said


def test_the_bot_says_a_refusal_and_its_card_stays_open(world, monkeypatch):
    pytest.importorskip("discord")
    bot, _ = _scripted(monkeypatch, ["received", "refused"])
    code, said = asyncio.run(bot._queue_revert({"id": "c1"}, None, _Thread(), poll_s=0))
    assert code == 1 and "refused — guard : no" in said


def test_the_bot_never_waits_past_the_requests_life_and_its_run(world, monkeypatch):
    pytest.importorskip("discord")
    bot, _ = _scripted(monkeypatch, ["accepted"] * 5)
    monkeypatch.setattr(aq, "TAKE_S", 0)
    monkeypatch.setattr(aq, "RUN_S", -1)
    code, said = asyncio.run(bot._queue_revert({"id": "c1"}, None, _Thread(), poll_s=0))
    assert code == 1 and "la carte reste ouverte" in said


def test_a_card_without_proposal_is_refused_by_the_bot_before_any_deposit(world, monkeypatch):
    pytest.importorskip("discord")
    from glorfindel import bot
    monkeypatch.setattr(aq, "deposit_request", lambda *a, **k: pytest.fail("deposited"))
    code, said = asyncio.run(bot._queue_revert({"id": "c1", "resource_id": WEB}, None, _Thread(), poll_s=0))
    assert code == 1 and "proposal_missing" in said


# ── The bot out of runs/console ──────────────────────────────────────────────────────

def test_the_cli_the_bot_runs_notes_its_gestures_in_runs_bot(world, monkeypatch):
    pytest.importorskip("discord")
    from glorfindel import bot
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda args, **k: seen.update(k) or subprocess.CompletedProcess(args, 0, "", ""))
    bot._run_cli(["revert", WEB, "--yes"])
    assert seen["env"][runs_layout.WRITER_ENV] == runs_layout.BOT


def test_a_gesture_of_the_bots_hand_goes_to_runs_bot_and_is_read_from_there(world, monkeypatch):
    from analysis import containment
    from glorfindel.cli import _record_manual_action
    monkeypatch.setenv(runs_layout.WRITER_ENV, "bot")
    _record_manual_action("release_isolation", WEB, {"status": "released", "verified": True})
    assert _lines(world, "bot") and not _lines(world, "console")
    lifts = containment.read_liftings(world["root"] / "annatar")
    assert [x[0] for x in lifts] == [WEB], lifts
    monkeypatch.delenv(runs_layout.WRITER_ENV)
    _record_manual_action("release_isolation", WEB, {"status": "released", "verified": True})
    assert len(_lines(world, "console")) == 1 and len(_lines(world, "bot")) == 1


def test_the_console_reads_the_bots_gestures_for_its_feed_and_its_indicators(world, monkeypatch):
    pytest.importorskip("fastapi")
    from glorfindel.cli import _record_manual_action
    api, client = _console(world, monkeypatch)
    monkeypatch.setenv(runs_layout.WRITER_ENV, "bot")
    _record_manual_action("release_isolation", WEB, {"status": "released", "verified": True})
    assert any(e.get("vm") == "web" or WEB in json.dumps(e) for e in client.get("/api/feed/history").json()["entries"])
    assert [x[0] for x in api._manual_liftings(0)] == [WEB]


def test_the_bot_no_longer_mounts_the_consoles_directory_and_the_console_reads_the_bots():
    import yaml
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    bot_vols, console_vols = compose["bot"]["volumes"], compose["war-room"]["volumes"]
    assert not [v for v in bot_vols if "/app/runs/console" in v]
    assert "${EREGION_RUNS:-./runs}/bot:/app/runs/bot" in bot_vols
    assert "${EREGION_RUNS:-./runs}/bot:/app/runs/bot:ro" in console_vols
    assert compose["bot"]["environment"][runs_layout.WRITER_ENV] == "bot"


# ── The keys before the flag: the gesture, host.env, the check ────────────────────────

def test_pin_draw_draws_the_services_key_and_pin_alone_never(capsys):
    assert aq.main(["pin", "bot"]) == 1                     # none drawn yet: never drawn here
    assert not (aq.service_key_dir("bot") / watch_key.SERVICE_KEY_FILE).exists()
    assert aq.main(["pin", "bot", "--draw"]) == 0
    line = capsys.readouterr().out.strip().splitlines()[-1]
    pins, wrong = aq.parse_pins(line)
    assert not wrong and pins["bot"] == aq.load_service_key("bot").public
    assert aq.main(["pin", "bot"]) == 0
    assert aq.main(["pin", "bot", "--other"]) == 2


def test_the_hosts_gesture_draws_both_keys_and_says_a_bot_that_does_not_run():
    make = (ROOT / "Makefile").read_text()
    recipe = make.split("\nglorfindel-host-queue-keys:", 1)[1].split("\n\n", 1)[0]
    assert "pin console --draw) || exit 1" in recipe
    assert "pin bot --draw 2>/dev/null) ||" in recipe and "le bot ne tourne pas" in recipe
    assert 'echo "EREGION_QUEUE_KEYS=$$c$${b:+,$$b}"' in recipe


def _host_env(tmp_path, *lines) -> str:
    path = tmp_path / "host.env"
    path.write_text("EREGION_CONSOLE_TOKEN=fake-token\nGLORFINDEL_LLM_MODEL=ollama/llama3.1\n"
                    "GLORFINDEL_LLM_BASE_URL=http://ollama:11434\n" + "".join(f"{x}\n" for x in lines), encoding="utf-8")
    return str(path)


def test_check_refuses_the_flag_without_the_keys_it_needs(tmp_path):
    console_pin = f"console={watch_key.public_text(CONSOLE.public)}"
    bot_pin = f"bot={watch_key.public_text(BOT.public)}"
    assert host_env.check(_host_env(tmp_path)) == 0                                   # no flag: nothing
    assert host_env.check(_host_env(tmp_path, f"EREGION_QUEUE_KEYS={console_pin}")) == 0   # keys first
    with pytest.raises(SystemExit) as exc:
        host_env.check(_host_env(tmp_path, "EREGION_ACTION_QUEUE=1"))
    assert "no key pinned for the console" in str(exc.value) and "glorfindel-host-queue-keys" in str(exc.value)
    assert host_env.check(_host_env(tmp_path, "EREGION_ACTION_QUEUE=1", f"EREGION_QUEUE_KEYS={console_pin}")) == 0
    with pytest.raises(SystemExit) as exc:
        host_env.check(_host_env(tmp_path, "EREGION_ACTION_QUEUE=1", f"EREGION_QUEUE_KEYS={console_pin}",
                                 "DISCORD_BOT_TOKEN=fake-bot"))
    assert "no key pinned for the bot" in str(exc.value) and "fake-bot" not in str(exc.value)
    assert host_env.check(_host_env(tmp_path, "EREGION_ACTION_QUEUE=1", "DISCORD_BOT_TOKEN=fake-bot",
                                    f"EREGION_QUEUE_KEYS={console_pin},{bot_pin}")) == 0
    with pytest.raises(SystemExit) as exc:
        host_env.check(_host_env(tmp_path, "EREGION_ACTION_QUEUE=true"))
    assert "« 1 » only" in str(exc.value)


def test_host_env_never_copies_this_workstations_queue(monkeypatch):
    env = {"AZURE_SUBSCRIPTION_ID": "s", "GLORFINDEL_LLM_MODEL": "ollama/llama3.1",
           "GLORFINDEL_LLM_BASE_URL": "http://ollama:11434", "EREGION_ACTION_QUEUE": "1",
           "EREGION_QUEUE_KEYS": f"console={watch_key.public_text(CONSOLE.public)}"}
    out = host_env.host_env(env)
    assert "EREGION_ACTION_QUEUE" not in out and "EREGION_QUEUE_KEYS" not in out


def test_the_default_of_the_flag_stays_off():
    """FS1c prepares the switch, never makes it: the flag is « 1 » only, empty by default."""
    assert aq.enabled({}) is False
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "EREGION_ACTION_QUEUE: ${EREGION_ACTION_QUEUE:-}" in compose
    assert "\nEREGION_ACTION_QUEUE=\n" in (ROOT / "infra" / "glorfindel-host" / "host.env.example").read_text()
