"""SEC4c (#275), the correction — a restore from the console, the bot or the TUI asks for its
moment.

`glorfindel restore` no longer takes the newest point when nothing says when the attack began:
the three faces that launched it without `--before` now ask. Each fills the field with the
moment the runs/ channel gives for the VM (an exercise), else the card's first detection —
the attack began before, the operator can go back —, shows the recovery points before it
(read only), and runs the command with `--before` once confirmed. What the command says
when it refuses is shown: on the card in the console, in the thread for the bot, on screen
for the TUI — never silence. The bot acknowledges the card only once the restore started.

No Azure call, no model call: the recovery points and the command are faked. Identifiers
made up. Mutants M1396–M1409 (scripts/mutation_check.py) are measured here and in
tests/unit/test_entries_calls.py.
"""
from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from glorfindel import escalations, restore_plan

SUB = "00000000-0000-0000-0000-0000000000cc"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example-a/providers/Microsoft.Compute/virtualMachines/vm-example-01"
POINTS = [{"name": "rp-1", "time": "2026-10-29T07:00:00+00:00", "vault_tier": True},
          {"name": "rp-0", "time": "2026-10-28T07:00:00+00:00", "vault_tier": True}]


def _card() -> str:
    return escalations.record("rule-ransomware-0123abcd", VM, "restore_from_backup",
                              "destructive_action", "restore needs a human", ttp="T1486")


def _pending(esc_id: str) -> dict:
    return next(e for e in escalations.pending() if e["id"] == esc_id)


def _first_seen(esc_id: str) -> str:
    e = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
    return restore_plan.parse_moment(e["first_seen"])


@pytest.fixture()
def points(monkeypatch):
    asked = []

    def fake(rid, before, connector=None):
        asked.append((rid, before))
        return [p for p in POINTS if p["time"] < before]
    monkeypatch.setattr(restore_plan, "points_before", fake)
    return asked


@pytest.fixture()
def ran(monkeypatch):
    """The glorfindel command each face runs: recorded, answered with `answer` (code, text)."""
    calls = SimpleNamespace(args=[], answer=(0, "✓ Restore job started."))

    def run(argv, **kw):
        calls.args.append(list(argv[1:]))
        code, text = calls.answer
        return SimpleNamespace(returncode=code, stdout=text, stderr="")
    calls.run = run
    return calls


# ── The console ───────────────────────────────────────────────────────────────────────

@pytest.fixture()
def console(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    from .console_client import console as client
    return client()


def test_the_console_proposes_the_card_s_first_detection_and_its_points(console, points):
    esc_id = _card()
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}").json()
    assert d["source"] == "card" and d["before"] == _first_seen(esc_id) == d["moment"]
    assert "l'attaque a commencé avant" in d["why"]
    assert [p["name"] for p in d["points"]] == ["rp-1", "rp-0"]
    # A moment given: the points before it, read only.
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}&before=2026-10-28T12:00:00Z").json()
    assert d["moment"] == "2026-10-28T12:00:00+00:00" and [p["name"] for p in d["points"]] == ["rp-0"]
    assert "ISO 8601" in console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}&before=hier").json()["error"]
    # The card's own rules first (SEC1): another VM's, or no card, refused.
    assert "error" in console.get(f"/api/restore/plan/vm-other?escalation={esc_id}").json()


def test_the_console_proposes_the_exercise_s_moment_when_runs_gives_it(console, points, tmp_path):
    import json
    t0 = time.time() - 600
    line = {"signal_id": "20261029T100000Z_attack_started", "timestamp": "2026-10-29T10:00:00+00:00",
            "provider": "azure", "resource_id": VM, "resource_type": "vm", "ttp": "T1486", "severity": "high",
            "event": "attack_started", "raw_signal": {"attack_time": t0},
            "context": {"run_id": "20261029T100000Z", "scenario": "s"}}
    (tmp_path / "runs" / "20261029T100000Z_signals.jsonl").write_text(json.dumps(line) + "\n")
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={_card()}").json()
    assert d["source"] == "exercise" and "attack_started de runs/20261029T100000Z_signals.jsonl" in d["why"]


def test_unreadable_points_are_said_and_the_restore_stays_possible(console, monkeypatch):
    def boom(rid, before, connector=None):
        raise RuntimeError("vault unreachable")
    monkeypatch.setattr(restore_plan, "points_before", boom)
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={_card()}").json()
    assert d["points"] == [] and "vault unreachable" in d["points_error"] and d["moment"]


def test_the_console_runs_the_restore_with_its_moment_and_keeps_a_refusal_on_the_card(console, ran, monkeypatch):
    import eregion_console.api as api
    monkeypatch.setattr(api.subprocess, "run", ran.run)
    esc_id = _card()
    ran.answer = (1, "Glorfindel — Restore from Backup\n✗ No recovery point found before attack time")
    asyncio.run(api._bg_restore(VM, "vm-example-01", "2026-10-29T08:00:00+00:00", esc_id))
    assert ran.args == [["restore", VM, "--yes", "--before", "2026-10-29T08:00:00+00:00"]]
    failure = console.get("/api/state").json()["restore_failures"][esc_id]
    assert "No recovery point found before attack time" in failure["error"]
    # The page shows it on the card, escaped.
    js = (api._STATIC / "glorfindel.js").read_text()
    assert "${_restoreFailure(e)}" in js and "✗ Restore refused or failed: ${_attr(f.error)}" in js
    ran.answer = (0, "✓ Restore job started.")
    asyncio.run(api._bg_restore(VM, "vm-example-01", "2026-10-29T08:00:00+00:00", esc_id))
    assert esc_id not in console.get("/api/state").json()["restore_failures"]


def test_a_command_that_does_not_run_is_said_too(console, monkeypatch):
    import eregion_console.api as api

    def missing(argv, **kw):
        raise FileNotFoundError("glorfindel")
    monkeypatch.setattr(api.subprocess, "run", missing)
    esc_id = _card()
    asyncio.run(api._bg_restore(VM, "vm-example-01", "2026-10-29T08:00:00+00:00", esc_id))
    assert "FileNotFoundError" in console.get("/api/state").json()["restore_failures"][esc_id]["error"]


def test_the_page_asks_the_moment_and_sends_it():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "eregion_console" / "static" / "glorfindel.js").read_text()
    restore = js[js.index("async function confirmRestore("):js.index("function confirmAck(")]
    assert "/api/restore/plan/${_seg(vmName)}?escalation=${_seg(escId)}" in restore
    assert 'id="restore-before" type="text" value="${_attr(d.before)}"' in restore
    assert "doRestore(vmName, escId, before)" in restore
    assert "{ escalation: escId, before }" in js


# ── The bot ───────────────────────────────────────────────────────────────────────────

class _Thread:
    def __init__(self):
        self.posted = []

    async def send(self, text, view=None):
        self.posted.append((text, view))

    async def edit(self, **kw):
        pass


class _Card:
    def __init__(self):
        self.edits = []

    async def edit(self, **kw):
        self.edits.append(kw)


class _Interaction:
    def __init__(self, bot, channel, card=None, allowed=True):
        self.user = SimpleNamespace(id=111 if allowed else 222, display_name="operator", roles=[])
        self.client = SimpleNamespace(button_policy=bot.ButtonPolicy(users=frozenset({111})))
        self.channel, self.message, self.data = channel, card, {"custom_id": "x"}
        self.modals, self.ephemeral, self.edits = [], [], []
        outer = self

        class _Response:
            async def send_modal(self, modal):
                outer.modals.append(modal)

            async def send_message(self, text, ephemeral=False):
                outer.ephemeral.append(text)

            async def defer(self, **kw):
                pass

            async def edit_message(self, **kw):
                outer.edits.append(kw)
        self.response = _Response()


async def _settle():
    others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    await asyncio.gather(*others)


def _bot_restore(monkeypatch, ran, answer, moment=None):
    """Restore → the form → confirm, through the bot's own objects. Returns (card id, thread,
    card message, form)."""
    bot = pytest.importorskip("glorfindel.bot")
    monkeypatch.setattr(bot, "_run_cli", lambda args: (ran.args.append(args), answer)[1])
    esc_id = _card()
    esc = next(e for e in escalations.pending() if e["id"] == esc_id)
    thread, card = _Thread(), _Card()

    async def go():
        view = bot.EscalationView(esc)
        button = next(i for i in view.children if isinstance(i, bot._RestoreButton))
        click = _Interaction(bot, thread, card)
        await button.callback(click)
        form = click.modals[0]
        if moment is not None:
            form.moment._value = moment
        else:
            form.moment._value = form.moment.default
        await form.on_submit(_Interaction(bot, thread, card))
        text, confirm = thread.posted[-1]
        await confirm.confirm.callback(_Interaction(bot, thread, card))
        await _settle()
        return form, text
    form, text = asyncio.run(go())
    return esc_id, thread, card, form, text


def test_the_bot_asks_the_moment_shows_the_points_then_runs_with_it(monkeypatch, ran, points):
    esc_id, thread, card, form, text = _bot_restore(monkeypatch, ran, (0, "✓ Restore job started."))
    assert form.moment.default == _first_seen(esc_id) and "1re détection" in form.field.text
    assert "l'attaque a commencé avant" in form.field.description
    assert "Points avant ce moment (lecture seule)" in text and "2026-10-29T07:00:00+00:00" in text
    assert ran.args == [["restore", VM, "--yes", "--before", _first_seen(esc_id)]]
    stored = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
    assert stored["status"] != "pending"                      # acknowledged: the restore started


def test_the_bot_says_a_refusal_and_keeps_the_card_open(monkeypatch, ran, points):
    esc_id, thread, card, form, text = _bot_restore(
        monkeypatch, ran, (1, "✗ No recovery point found before attack time"), moment="2026-10-01T00:00:00Z")
    assert ran.args == [["restore", VM, "--yes", "--before", "2026-10-01T00:00:00+00:00"]]
    said = " ".join(t for t, _ in thread.posted)
    assert "No recovery point found" in said and "la carte reste ouverte" in said
    assert next(e for e in escalations.all_escalations() if e["id"] == esc_id)["status"] == "pending"
    assert card.edits and not any(i.disabled for i in card.edits[-1]["view"].children)   # buttons back


def test_the_bot_s_form_refuses_a_moment_that_is_not_one(monkeypatch, ran, points):
    bot = pytest.importorskip("glorfindel.bot")
    esc = _pending(_card())
    form = bot._RestoreModal(esc, restore_plan.proposed_moment(VM, esc))
    form.moment._value = "hier"
    click = _Interaction(bot, _Thread())
    asyncio.run(form.on_submit(click))
    assert click.ephemeral and "ISO 8601" in click.ephemeral[0] and ran.args == []


def test_the_bot_s_form_and_confirmation_check_who_clicks(monkeypatch, ran):
    bot = pytest.importorskip("glorfindel.bot")
    esc = _pending(_card())
    stranger = _Interaction(bot, _Thread(), allowed=False)
    assert asyncio.run(bot._RestoreModal(esc, {}).interaction_check(stranger)) is False
    assert asyncio.run(bot._RestoreConfirmView(esc, "2026-10-29T08:00:00+00:00").interaction_check(stranger)) is False
    assert len(stranger.ephemeral) == 2 and ran.args == []


def test_a_revert_from_the_bot_is_acknowledged_only_once_it_succeeded(monkeypatch):
    bot = pytest.importorskip("glorfindel.bot")
    esc_id = escalations.record("rule-x-0123abcd", VM, "isolate_vm", "verification_failed", "r")
    esc = next(e for e in escalations.pending() if e["id"] == esc_id)
    thread = _Thread()
    asyncio.run(bot._execute_and_report(esc, ["revert", VM, "--yes"], thread, lambda: (1, "✗ refused")))
    assert next(e for e in escalations.all_escalations() if e["id"] == esc_id)["status"] == "pending"
    asyncio.run(bot._execute_and_report(esc, ["revert", VM, "--yes"], thread, lambda: (0, "ok")))
    assert next(e for e in escalations.all_escalations() if e["id"] == esc_id)["status"] != "pending"


# ── The TUI ───────────────────────────────────────────────────────────────────────────

def _wait(cond, s=5.0):
    deadline = time.monotonic() + s
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert cond()


def test_the_tui_asks_the_moment_shows_the_points_and_says_a_refusal(monkeypatch, ran, points):
    from datetime import datetime, timezone

    from rich.console import Console

    from glorfindel import tui
    monkeypatch.setattr(tui.subprocess, "run", ran.run)
    tui._last_restore.clear()
    esc_id = _card()
    esc = next(e for e in escalations.pending() if e["id"] == esc_id)
    pending = tui._restore_pending(esc)
    assert pending["buffer"] == _first_seen(esc_id) and pending["stage"] == "moment"
    for _ in range(len(pending["buffer"])):
        pending = tui._restore_key(pending, "\x7f")
    for ch in "hier":
        pending = tui._restore_key(pending, ch)
    pending = tui._restore_key(pending, "\r")
    assert pending["stage"] == "moment" and "ISO 8601" in pending["error"]
    for _ in range(4):
        pending = tui._restore_key(pending, "\x7f")
    for ch in "2026-10-29T08:00:00Z":
        pending = tui._restore_key(pending, ch)
    pending = tui._restore_key(pending, "\r")
    assert pending["stage"] == "points"
    _wait(lambda: pending.get("points") is not None)
    screen = Console(width=160, record=True)
    screen.print(tui._escalations_renderable(datetime.now(timezone.utc), pending, True))
    shown = screen.export_text()
    assert "2026-10-29T07:00:00+00:00" in shown and "← restored" in shown
    ran.answer = (1, "✗ No recovery point found before attack time")
    assert tui._restore_key(pending, "y") is None
    _wait(lambda: tui._last_restore.get("ok") is False)
    assert ran.args == [["restore", VM, "--yes", "--before", "2026-10-29T08:00:00+00:00"]]
    screen = Console(width=200, record=True)
    screen.print(tui._escalations_renderable(datetime.now(timezone.utc), None, True))
    shown = " ".join(screen.export_text().split())
    assert "refused or failed" in shown and "No recovery point found" in shown


def test_the_tui_s_escape_cancels_without_running(monkeypatch, ran):
    from glorfindel import tui
    monkeypatch.setattr(tui.subprocess, "run", ran.run)
    esc = _pending(_card())
    assert tui._restore_key(tui._restore_pending(esc), "\x1b") is None and ran.args == []


# ── The second correction ─────────────────────────────────────────────────────────────

_BAD_MOMENTS = ["2999-01-01T00:00:00Z", "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"]


@pytest.mark.parametrize("text", _BAD_MOMENTS)
def test_the_console_refuses_such_a_moment_with_an_answer_not_a_500(console, points, text):
    from urllib.parse import quote
    esc_id = _card()
    r = console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}&before={quote(text)}")
    assert r.status_code == 200 and "error" in r.json()
    r = console.post("/api/action/restore/vm-example-01", json={"escalation": esc_id, "before": text})
    assert r.status_code == 200 and "required" in r.json()["error"]


def test_the_console_says_a_moment_after_the_isolation(console, points, monkeypatch):
    monkeypatch.setattr("glorfindel.actions._load_isolation_state",
                        lambda rid: {"isolated_at": "2026-10-28T06:00:00+00:00"})
    esc_id = _card()
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}&before=2026-10-28T12:00:00Z").json()
    assert "postérieur à l'isolation" in d["warning"]
    d = console.get(f"/api/restore/plan/vm-example-01?escalation={esc_id}").json()
    assert d["before"] == "2026-10-28T06:00:00+00:00" and d["warning"] == ""      # the isolation, first


def test_the_failures_kept_are_the_pending_cards_newest_under_the_lock(console, monkeypatch):
    import json

    import eregion_console.api as api
    locked = []
    real = __import__("glorfindel.response.locks", fromlist=["_file_lock"])._file_lock

    def spy(path):
        locked.append(str(path))
        return real(path)
    monkeypatch.setattr("glorfindel.response.locks._file_lock", spy)
    monkeypatch.setattr(api, "_RESTORE_FAILURES_KEPT", 3)
    ids = [escalations.record(f"rule-x-{i:08d}", VM.replace("vm-example-01", f"vm-{i}"), "restore_from_backup",
                              "destructive_action", "r") for i in range(5)]
    for i, esc_id in enumerate(ids):
        api._note_restore_failure(esc_id, f"vm-{i}", f"refused {i}")
    kept = json.loads(api._RESTORE_FAILURES.read_text())
    assert list(kept) == ids[2:]                                   # the newest 3
    escalations.resolve(ids[3])
    api._note_restore_failure(ids[4], "vm-4", None)              # cleared on success
    assert list(json.loads(api._RESTORE_FAILURES.read_text())) == [ids[2]]   # resolved card gone
    assert any(p.endswith("restore_failures.lock") for p in locked)


def test_the_page_never_fills_a_window_that_is_no_longer_its_own():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "eregion_console" / "static" / "glorfindel.js").read_text()
    restore = js[js.index("async function confirmRestore("):js.index("function _renderRestorePoints(")]
    wait = restore.index("await (await fetch(")
    check = restore.index("if (!_stillMine()) return;")
    assert wait < check < restore.index("body.innerHTML = `")          # read, checked, then filled
    assert "modal.dataset.owner === 'restore-' + mine" in restore
    close = js[js.index("function closeModal()"):js.index("function openModal(")]
    assert "dataset.owner = ''" in close


def test_a_second_confirmation_of_one_card_is_refused(monkeypatch, ran, points):
    bot = pytest.importorskip("glorfindel.bot")
    release = asyncio.Event()

    def slow(args):
        ran.args.append(args)
        return 0, "✓ Restore job started."
    monkeypatch.setattr(bot, "_run_cli", slow)
    esc = _pending(_card())
    thread = _Thread()

    async def go():
        first = bot._RestoreConfirmView(esc, "2026-10-29T07:30:00+00:00")
        second = bot._RestoreConfirmView(esc, "2026-10-29T07:30:00+00:00")      # a second form
        a, b = _Interaction(bot, thread), _Interaction(bot, thread)
        await first.confirm.callback(a)
        await second.confirm.callback(b)                     # before the first has ended
        assert b.ephemeral and "déjà en cours" in b.ephemeral[0]
        await _settle()
        release.set()
        c = _Interaction(bot, thread)
        await bot._RestoreConfirmView(esc, "2026-10-29T07:30:00+00:00").confirm.callback(c)
        await _settle()
        return c
    c = asyncio.run(go())
    assert len(ran.args) == 2 and c.ephemeral == []            # the lock is given back at the end
    assert esc["id"] not in bot._RESTORING


def test_the_bot_answers_within_discord_s_three_seconds(monkeypatch):
    bot = pytest.importorskip("glorfindel.bot")
    real = restore_plan.proposed_moment

    def slow(rid, esc=None, runs_dir="runs", read_runs=True):
        if read_runs:
            time.sleep(4)
        return real(rid, esc, runs_dir=runs_dir, read_runs=read_runs)
    monkeypatch.setattr(restore_plan, "proposed_moment", slow)
    esc_id = _card()
    esc = _pending(esc_id)

    async def go():
        view = bot.EscalationView(esc)
        button = next(i for i in view.children if isinstance(i, bot._RestoreButton))
        click = _Interaction(bot, _Thread(), _Card())
        t0 = time.monotonic()
        await button.callback(click)
        return time.monotonic() - t0, click
    took, click = asyncio.run(go())
    assert took < 3.0 and click.modals and click.modals[0].moment.default == _first_seen(esc_id)


@pytest.mark.parametrize("text", _BAD_MOMENTS)
def test_the_bot_s_form_refuses_such_a_moment(monkeypatch, ran, text):
    bot = pytest.importorskip("glorfindel.bot")
    esc = _pending(_card())
    form = bot._RestoreModal(esc, {})
    form.moment._value = text
    click = _Interaction(bot, _Thread())
    asyncio.run(form.on_submit(click))
    assert click.ephemeral and ran.args == []


@pytest.mark.parametrize("text", _BAD_MOMENTS)
def test_the_tui_does_not_crash_on_such_a_moment(monkeypatch, ran, text):
    from datetime import datetime, timezone

    from rich.console import Console

    from glorfindel import tui
    monkeypatch.setattr(tui.subprocess, "run", ran.run)
    pending = tui._restore_pending(_pending(_card()))
    pending["buffer"] = text
    pending = tui._restore_key(pending, "\r")
    assert pending["stage"] == "moment" and pending["error"] and ran.args == []
    screen = Console(width=160, record=True)
    screen.print(tui._escalations_renderable(datetime.now(timezone.utc), pending, True))
    assert "✗" in screen.export_text()
