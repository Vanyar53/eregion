"""The Discord bot says what happened, shows the evidence, and takes a verdict.

The first real card of the pre-observation (16/10) read « IP suspecte bloquée » for a block
that human_only had held, with neither the IP nor the model's explanation, and Discord had
no way to judge it.
"""
import asyncio

import pytest

pytest.importorskip("discord")

from glorfindel import bot, escalations  # noqa: E402

VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"


def _held_block(**kw):
    e = {"id": "c3227fe7-0000", "action": "block_suspicious_ip", "escalation_type": "mode_hold",
         "resource_id": VM, "signal_id": "rule-ssh-brute-force-0123abcd",
         "reason": "Mode human_only — action retenue", "ttp": "T1110.001", "severity": "high",
         "confidence": 0.95, "rule_name": "ssh-brute-force",
         "action_params": {"ip": "198.51.100.7", "port": 22},
         "explanation": "13 failed SSH logins from an external IP, none succeeded."}
    e.update(kw)
    return e


def test_a_held_recommendation_never_reads_as_done():
    title = bot._embed_title(_held_block())
    assert "Recommandé" in title and "non exécuté" in title and "bloquée" not in title


def test_what_ran_or_was_tried_says_so():
    assert bot._embed_title({"action": "isolate_vm", "escalation_type": "verification_failed"}) \
        == "🚨 VM isolée du réseau — vérification échouée"
    assert "écriture refusée" in bot._embed_title({"action": "isolate_vm", "escalation_type": "write_blocked"})
    assert bot._embed_title({"action": "posture_gap", "escalation_type": "posture_gap",
                             "signal_id": "posture-x"}) == "🚨 Gap de posture"


def test_the_body_carries_the_evidence_then_why_nothing_ran():
    description, fields = bot._embed_body(_held_block())
    names = dict((n, v) for n, v, _ in fields)
    assert description.startswith("13 failed SSH logins")
    assert names["Cible"] == "`198.51.100.7:22`"
    assert names["Règle"] == "`ssh-brute-force`" and names["Confiance"] == "95 %"
    # escaped for Discord (SEC6: tests/unit/test_chat_escaping.py): it shows « human_only »
    assert names["Pourquoi rien n'est exécuté"] == "Mode human\\_only — action retenue"
    # an older card without an explanation falls back on its reason
    assert bot._embed_body(_held_block(explanation=""))[0] == "Mode human\\_only — action retenue"


def _verdict_buttons(esc):
    async def build():
        return [i for i in bot.EscalationView(esc).children if isinstance(i, bot._VerdictButton)]
    return asyncio.run(build())


def test_decision_cards_get_verdict_buttons_posture_cards_do_not():
    assert [b.verdict for b in _verdict_buttons(_held_block())] == ["right", "wrong", "unsure"]
    assert _verdict_buttons({"id": "p1", "action": "posture_gap", "escalation_type": "posture_gap",
                             "resource_id": VM, "signal_id": "posture-x"}) == []


def test_a_verdict_from_discord_is_recorded():
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip",
                                "mode_hold", "held", confidence=0.95)
    esc = {**_held_block(), "id": esc_id}

    class _Response:
        async def edit_message(self, **kw):
            self.edited = kw

        async def send_message(self, *a, **kw):
            raise AssertionError("no error expected")

    class _Followup:
        sent = []

        async def send(self, text):
            self.sent.append(text)

    class _Interaction:
        response, followup = _Response(), _Followup()
        channel = None
        user = type("U", (), {"display_name": "jonathan"})()

    async def click():
        view = bot.EscalationView(esc)
        button = next(i for i in view.children if isinstance(i, bot._VerdictButton) and i.verdict == "right")
        await button.callback(_Interaction())
        return view

    view = asyncio.run(click())
    stored = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
    assert stored["verdict"] == "right"
    assert stored["status"] == "resolved"          # one click: judged and acknowledged
    assert all(b.disabled for b in view.children)
    assert _Followup.sent and "jugé par **jonathan**" in _Followup.sent[0]


def test_a_posted_message_is_remembered_and_its_buttons_come_back_after_a_restart():
    """Every button posted before a redeploy answered « interaction failed »: the bot now
    keeps each card's message id and gives it its view back at startup (16/10)."""
    from datetime import datetime, timedelta, timezone

    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip",
                                "mode_hold", "held", confidence=0.95)

    class _Message:
        id = 4242

    class _Thread:
        async def send(self, **kw):
            return _Message()

    async def post_then_restart():
        first = bot.GlorfindelBot(channel_id=1, ping_role=None)

        async def thread(channel, rid):
            return _Thread()
        first._get_or_create_thread = thread
        esc = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
        await first._post_escalation(None, esc)

        second = bot.GlorfindelBot(channel_id=1, ping_role=None)   # a restart: reads the store
        added = []
        second.add_view = lambda view, message_id=None: added.append((view.esc_id, message_id))
        second._restore_views()
        return added

    assert asyncio.run(post_then_restart()) == [(esc_id, 4242)]

    # Old cards are left alone: only the last two weeks come back.
    old = {"id": "old", "first_seen": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()}
    recent = {"id": "new", "first_seen": datetime.now(timezone.utc).isoformat()}
    assert [e["id"] for e, _ in bot._views_to_restore([old, recent], {"old": 1, "new": 2})] == ["new"]


def test_card_state_line_says_what_became_of_it():
    assert bot._card_state_line({"status": "pending"}) == "en attente"
    assert bot._card_state_line({"status": "resolved", "verdict": "right"}) == "jugée right · acquittée"
    line = bot._card_state_line({"status": "pending", "occurrences": 3, "last_seen": "2026-10-16T14:05:00+00:00"})
    assert line == "en attente · 3× (dernière : 14:05 UTC)"


def test_a_card_handled_in_the_war_room_updates_its_discord_message():
    """Acknowledged or judged in the War Room, a card kept live buttons in Discord; repeats
    never showed. The bot now edits the message and archives the VM's thread (16/10)."""
    import discord
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip",
                                "mode_hold", "held", confidence=0.95)

    class _Partial:
        def __init__(self, log):
            self.log = log

        async def edit(self, embed, view):
            self.log.append((embed, view))

    class _Thread(discord.Thread):
        def __init__(self):            # no Discord state: only what the sync uses
            self.edits, self.archived, self.archive_calls = [], False, 0

        def get_partial_message(self, mid):
            return _Partial(self.edits)

        async def edit(self, archived, reason):
            self.archived, self.archive_calls = archived, self.archive_calls + 1

    async def scenario():
        b = bot.GlorfindelBot(channel_id=1, ping_role=None)
        thread = _Thread()
        b._threads = {VM: 99}
        b.get_channel = lambda tid: thread
        b._messages = {esc_id: 4242}
        esc = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
        b._synced = {esc_id: bot._card_signature(esc)}
        assert await b._sync_messages() == 0           # nothing changed: no edit
        escalations.set_verdict(esc_id, "right", "")   # judged + acknowledged in the War Room
        escalations.resolve(esc_id)
        assert await b._sync_messages() == 1
        assert await b._sync_messages() == 0           # synced once
        return thread

    thread = asyncio.run(scenario())
    embed, view = thread.edits[0]
    state = next(f.value for f in embed.fields if f.name == "État")
    assert state == "jugée right · acquittée"
    assert all(item.disabled for item in view.children)
    assert thread.archived and thread.archive_calls == 1


def test_the_weekly_summary_is_due_on_monday_morning_once():
    from datetime import datetime, timezone
    monday_7 = datetime(2026, 10, 19, 7, 59, tzinfo=timezone.utc)
    monday_8 = datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc)
    tuesday = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
    assert not bot._weekly_due(monday_7, None)
    assert bot._weekly_due(monday_8, None)
    assert not bot._weekly_due(monday_8, "2026-10-19")          # already sent today
    assert bot._weekly_due(monday_8, "2026-10-12")
    assert not bot._weekly_due(tuesday, None)


def test_the_weekly_summary_says_the_week():
    from datetime import datetime, timezone
    report = {"cards": 4, "judged": 3, "exercises": 1,
              "disruptive": {"false_rate": 0.25},
              "by_rule": {"ssh-brute-force": {"right": 3, "wrong": 1, "unsure": 0, "unjudged": 0}}}
    text = bot._weekly_summary(report, 1, datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc))
    assert "semaine du 12/10 au 19/10" in text and "**25 %**" in text
    assert "`ssh-brute-force` : 3 right · 1 wrong" in text and "1 carte(s) à juger" in text
    empty = bot._weekly_summary({"cards": 0, "judged": 0, "disruptive": {"false_rate": None}}, 0,
                                datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc))
    assert "**—**" in empty and "Rien à juger" in empty


def test_the_weekly_summary_is_posted_once_on_monday(monkeypatch):
    from datetime import datetime, timezone

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 19, 8, 30, tzinfo=timezone.utc)

    monkeypatch.setattr("datetime.datetime", _FixedDatetime)

    class _Channel:
        sent = []

        async def send(self, text):
            self.sent.append(text)

    async def twice():
        b = bot.GlorfindelBot(channel_id=1, ping_role=None)
        ch = _Channel()
        return await b._post_weekly(ch), await b._post_weekly(ch), ch.sent

    first, second, sent = asyncio.run(twice())
    assert first and not second and len(sent) == 1
    assert bot.GlorfindelBot(channel_id=1, ping_role=None)._weekly_last == "2026-10-19"  # survives a restart


def test_the_embed_says_the_ip_was_seen_before_and_the_week_counts_attackers():
    from datetime import datetime, timezone
    _, fields = bot._embed_body(_held_block(recurrence={"previous": 2, "last_seen": "2026-10-17T07:35:00+00:00",
                                                        "last_verdict": "right"}))
    seen = dict((n, v) for n, v, _ in fields)["Déjà vue"]
    assert seen == "↻ même IP 2× en 7 jours — dernière le 2026-10-17 07:35 UTC, jugée right"
    text = bot._weekly_summary({"cards": 4, "judged": 4, "disruptive": {"false_rate": 0.0},
                                "blocks": {"cards": 4, "distinct_ips": 2}}, 0,
                               datetime(2026, 10, 19, 8, 0, tzinfo=timezone.utc))
    assert "4 carte(s) pour 2 IP distincte(s)" in text


def _sync_bot(thread, esc_id):
    b = bot.GlorfindelBot(channel_id=1, ping_role=None)
    b._threads = {VM: 99}
    b.get_channel = lambda tid: thread
    b._messages = {esc_id: 4242}
    b._synced = {esc_id: "stale"}
    return b


def test_a_card_in_an_archived_thread_is_updated_then_the_thread_closed_again():
    """Discord archives an idle thread: the edit failed (50083) and was retried every 15 s —
    10 800 errors in a day (19/10). The thread is reopened, the message edited, closed again."""
    import discord
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")
    escalations.set_verdict(esc_id, "right", "")
    escalations.resolve(esc_id)

    class _Thread(discord.Thread):
        def __init__(self):
            self.archived, self.calls, self.edited = True, [], 0

        def get_partial_message(self, mid):
            thread = self

            class _P:
                async def edit(self, embed, view):
                    assert not thread.archived, "edited in an archived thread"
                    thread.edited += 1
            return _P()

        async def edit(self, archived, reason):
            self.archived = archived
            self.calls.append(archived)

    thread = _Thread()
    b = _sync_bot(thread, esc_id)
    assert asyncio.run(b._sync_messages()) == 1
    assert thread.edited == 1 and thread.calls == [False, True] and thread.archived


def test_a_failing_edit_is_tried_once_and_a_deleted_message_forgotten():
    from unittest.mock import MagicMock

    import discord
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")

    def thread_raising(exc):
        class _Thread(discord.Thread):
            def __init__(self):
                self.archived, self.attempts = False, 0

            def get_partial_message(self, mid):
                thread = self

                class _P:
                    async def edit(self, embed, view):
                        thread.attempts += 1
                        raise exc
                return _P()

            async def edit(self, archived, reason):
                self.archived = archived
        return _Thread()

    gone = thread_raising(discord.NotFound(MagicMock(status=404, reason="Not Found"),
                                           {"code": 10008, "message": "Unknown Message"}))
    b = _sync_bot(gone, esc_id)
    asyncio.run(b._sync_messages())
    asyncio.run(b._sync_messages())
    assert gone.attempts == 1 and esc_id not in b._messages

    refused = thread_raising(discord.HTTPException(MagicMock(status=400, reason="Bad Request"),
                                                   {"code": 50001, "message": "Missing Access"}))
    b = _sync_bot(refused, esc_id)
    asyncio.run(b._sync_messages())
    asyncio.run(b._sync_messages())
    assert refused.attempts == 1                       # once per state change, never a loop


def test_a_card_resolved_while_discord_archived_its_thread_is_still_greyed(monkeypatch):
    """#169 — on H0 (20/10), a card acknowledged in the War Room: « Sync d1dde0fd: 400 Bad
    Request (error code: 50083): Thread is archived ». Discord archives an idle thread without
    telling the bot (no THREAD_UPDATE): the cached thread still reads open, so the reopen of
    19/10 was skipped and the edit refused. On a 50083 the thread is reopened and the edit
    tried again, once; the thread is closed after."""
    import io
    from unittest.mock import MagicMock

    import discord
    from rich.console import Console

    log = io.StringIO()
    monkeypatch.setattr(bot, "_console", Console(file=log, width=200))
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")
    escalations.resolve(esc_id)                        # acknowledged in the War Room

    class _Thread(discord.Thread):
        def __init__(self):
            self.archived = False                      # the cache: still open
            self.on_discord_archived = True            # Discord: archived when idle
            self.calls, self.edits, self.refused = [], [], 0

        def get_partial_message(self, mid):
            thread = self

            class _P:
                async def edit(self, embed, view):
                    if thread.on_discord_archived:     # what Discord answers
                        thread.refused += 1
                        raise discord.HTTPException(MagicMock(status=400, reason="Bad Request"),
                                                    {"code": 50083, "message": "Thread is archived"})
                    thread.edits.append((embed, view))
            return _P()

        async def edit(self, archived, reason):
            self.archived = self.on_discord_archived = archived
            self.calls.append(archived)

    thread = _Thread()
    b = _sync_bot(thread, esc_id)
    assert asyncio.run(b._sync_messages()) == 1
    assert thread.refused == 1 and len(thread.edits) == 1   # reopened, then edited once
    embed, view = thread.edits[0]
    assert next(f.value for f in embed.fields if f.name == "État") == "acquittée"
    # Acknowledged: its action, ack and command greyed; its verdict still to give (V-08).
    acts = [i for i in view.children if not isinstance(i, bot._VerdictButton)]
    assert acts and all(item.disabled for item in acts)
    assert not any(i.disabled for i in view.children if isinstance(i, bot._VerdictButton))
    assert thread.calls == [False, True] and thread.archived  # reopened, then closed again
    assert "Sync" not in log.getvalue() and "50083" not in log.getvalue()
    assert asyncio.run(b._sync_messages()) == 0             # synced: no second attempt


# ── M-3 (#183) : qui clique ─────────────────────────────────────────────────────────────
# The buttons set verdicts, acknowledge cards and run restores; Discord shows them to whoever
# reads the channel. Each click goes through discord.py's own dispatch (View._scheduled_task:
# the view's interaction_check, then the callback), so a refusal is proven where it acts.

ALLOWED, STRANGER, MEMBER, ROLE = 111, 222, 333, 900


class _Role:
    def __init__(self, rid):
        self.id = rid


class _User:
    def __init__(self, uid, roles=()):
        self.id, self.display_name, self.roles = uid, f"user-{uid}", [_Role(r) for r in roles]


class _Client:
    def __init__(self, policy):
        if policy is not None:
            self.button_policy = policy


class _Click:
    """What a click on a card's button hands to the view: the clicker, the bot, the replies."""

    def __init__(self, user, policy, custom_id="glorfindel_verdict_right"):
        click = self
        self.user, self.client, self.data = user, _Client(policy), {"custom_id": custom_id}
        self.ephemeral, self.edits, self.sent = [], [], []
        self.card_edits, self.posted = [], []        # the card's message, the thread
        self.modals = []                             # a form the click opens (the restore, SEC4c)

        class _Message:
            async def edit(self, **kw):
                click.card_edits.append(kw)

        class _Channel:
            async def send(self, text):
                click.posted.append(text)

        # A click that passes must be able to run to its end: without them, an allowed
        # restore crashed in its callback (into View.on_error) before running anything,
        # and a refusal that let it through looked like one that stopped it (review of M-3).
        self.message, self.channel = _Message(), _Channel()

        class _Response:
            async def send_message(self, text, ephemeral=False):
                click.ephemeral.append((text, ephemeral))

            async def edit_message(self, **kw):
                click.edits.append(kw)

            async def send_modal(self, modal):
                click.modals.append(modal)

            async def defer(self):
                pass

        class _Followup:
            async def send(self, text):
                click.sent.append(text)

        self.response, self.followup = _Response(), _Followup()


def _press(esc, user, policy, pick):
    """One click through discord.py's dispatch. A callback's failure is raised, not left to
    View.on_error (which only logs it); what the callback started (the restore's
    asyncio.create_task) is awaited before the loop closes."""
    async def go():
        view = bot.EscalationView(esc)

        async def on_error(interaction, error, item):
            raise error
        view.on_error = on_error
        item = pick(view)
        click = _Click(user, policy, getattr(item, "custom_id", "?"))
        await view._scheduled_task(item, click)
        started = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        await asyncio.gather(*started)
        return click
    return asyncio.run(go())


def _verdict_right(view):
    return next(i for i in view.children if isinstance(i, bot._VerdictButton) and i.verdict == "right")


def _stored(esc_id):
    return next(e for e in escalations.all_escalations() if e["id"] == esc_id)


def test_a_click_from_someone_not_allowed_is_refused_said_and_logged(monkeypatch):
    import io

    from rich.console import Console

    log = io.StringIO()
    monkeypatch.setattr(bot, "_console", Console(file=log, width=200))
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip",
                                "mode_hold", "held", confidence=0.95)
    policy = bot.ButtonPolicy(users=frozenset({ALLOWED}))

    click = _press(_stored(esc_id), _User(STRANGER), policy, _verdict_right)
    stored = _stored(esc_id)
    assert stored.get("verdict") is None and stored["status"] == "pending"   # nothing happened
    assert click.edits == [] and click.sent == []
    assert len(click.ephemeral) == 1 and click.ephemeral[0][1] is True
    assert "refusé" in click.ephemeral[0][0] and "DISCORD_ALLOWED_USERS" in click.ephemeral[0][0]
    logged = log.getvalue()
    assert "Button refused" in logged and str(STRANGER) in logged and esc_id[:8] in logged
    assert "error" not in logged.lower()       # glorfindel-host-status counts errors

    click = _press(_stored(esc_id), _User(ALLOWED), policy, _verdict_right)
    assert _stored(esc_id)["verdict"] == "right" and click.ephemeral == []


def test_a_role_allows_its_members_and_no_one_else():
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")
    policy = bot.ButtonPolicy(roles=frozenset({ROLE}))
    _press(_stored(esc_id), _User(STRANGER, roles=(ROLE + 1,)), policy, _verdict_right)
    assert _stored(esc_id).get("verdict") is None
    _press(_stored(esc_id), _User(MEMBER, roles=(ROLE,)), policy, _verdict_right)
    assert _stored(esc_id)["verdict"] == "right"


def test_without_a_list_every_button_refuses():
    """Closed by default: no DISCORD_ALLOWED_USERS nor DISCORD_ALLOWED_ROLES, nobody — and a
    bot without a policy at all, nobody either."""
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")
    for policy in (bot.ButtonPolicy(), None):
        click = _press(_stored(esc_id), _User(ALLOWED), policy, _verdict_right)
        assert "fermé par défaut" in click.ephemeral[0][0]
        click = _press(_stored(esc_id), _User(ALLOWED), policy,
                       lambda v: next(i for i in v.children if getattr(i, "custom_id", "") == "glorfindel_ack"))
        assert click.ephemeral and click.sent == []
    assert _stored(esc_id)["status"] == "pending" and _stored(esc_id).get("verdict") is None
    assert bot.GlorfindelBot(channel_id=1, ping_role=None).button_policy.configured is False


def test_a_refused_restore_never_runs(monkeypatch):
    esc_id = escalations.record("rule-ransomware-0123abcd", VM, "restore_from_backup",
                                "destructive_action", "restore needs a human")
    ran = []
    monkeypatch.setattr(bot, "_run_cli", lambda args: ran.append(args) or (0, "ok"))
    policy = bot.ButtonPolicy(users=frozenset({ALLOWED}))

    def restore(view):
        return next(i for i in view.children if isinstance(i, bot._RestoreButton))

    click = _press(_stored(esc_id), _User(STRANGER), policy, restore)
    assert ran == [] and click.ephemeral and _stored(esc_id)["status"] == "pending"
    assert click.card_edits == [] and click.posted == [] and click.modals == []

    # The witness: the same click by an allowed user opens the restore's form, which asks
    # for the moment (SEC4c) — so the refusal above is what stopped it, not the fake click.
    # Nothing runs, nothing is acknowledged, until the moment is confirmed.
    click = _press(_stored(esc_id), _User(ALLOWED), policy, restore)
    assert len(click.modals) == 1 and click.ephemeral == [] and ran == []
    assert _stored(esc_id)["status"] == "pending"


def test_the_allowed_ids_come_from_the_environment(monkeypatch):
    policy, bad = bot.ButtonPolicy.from_env({"DISCORD_ALLOWED_USERS": "111, 112;113",
                                             "DISCORD_ALLOWED_ROLES": "900 jonathan"})
    assert policy.users == {111, 112, 113} and policy.roles == {900}
    assert bad == ["jonathan"]                 # a name is never matched
    assert not bot.ButtonPolicy.from_env({})[0].configured

    import io

    from rich.console import Console

    for env, said in (({}, "fermé par défaut"), ({"DISCORD_ALLOWED_USERS": "111"}, "1 utilisateur(s)")):
        log = io.StringIO()
        monkeypatch.setattr(bot, "_console", Console(file=log, width=200))
        for k in ("DISCORD_ALLOWED_USERS", "DISCORD_ALLOWED_ROLES"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("DISCORD_BOT_TOKEN", "t")
        monkeypatch.setenv("DISCORD_CHANNEL_ID", "1")
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        started = []
        monkeypatch.setattr(bot.GlorfindelBot, "run", lambda self, token, **kw: started.append(self.button_policy))
        bot.run()
        assert said in log.getvalue()
        assert started[0].users == ({111} if env else frozenset())


# ── V-08 : un bouton périmé ne lance rien ────────────────────────────────────────────────
# After a restart, only a card that still waits gets its buttons back — pending, or a decision
# still to judge. At the click the card is read again: settled since (acknowledged, judged),
# expired, or its VM gone from the discovery, the button answers « carte réglée » and runs
# nothing.

def _card(**kw):
    from datetime import datetime, timezone
    e = {**_held_block(), "id": kw.pop("id"), "status": "pending",
         "first_seen": datetime.now(timezone.utc).isoformat()}
    e.update(kw)
    return e


def test_only_a_card_that_still_waits_gets_its_buttons_back_after_a_restart():
    from datetime import datetime, timedelta, timezone
    old = (datetime.now(timezone.utc) - timedelta(days=bot._RESTORE_DAYS + 1)).isoformat()
    gone = VM.replace("bree", "razed")
    cards = [
        _card(id="pending"),
        _card(id="to-judge", status="resolved"),                       # acked, verdict to give
        _card(id="settled", status="resolved", verdict="right"),       # acked and judged
        _card(id="posture", status="resolved", escalation_type="posture_gap", action="posture_gap",
              signal_id="posture-x"),                                    # acked, nothing to judge
        _card(id="expired", first_seen=old),
        _card(id="vm-gone", resource_id=gone),
    ]
    messages = {c["id"]: i + 1 for i, c in enumerate(cards)}
    restored = [e["id"] for e, _ in bot._views_to_restore(cards, messages, known_vms={VM.lower()})]
    assert restored == ["pending", "to-judge"]
    # The discovery knows no VM (empty or unreadable): a VM is never said gone.
    assert "vm-gone" in [e["id"] for e, _ in bot._views_to_restore(cards, messages, known_vms=None)]
    # The sync still keeps every posted card in line (to grey the settled ones), expired aside.
    assert "settled" in [e["id"] for e, _ in bot._posted_within(cards, messages)]


def _revert_card():
    return escalations.record("verify-0123abcd", VM, "isolate_vm", "verification_failed",
                              "isolation not verified", confidence=0.9)


def _revert(view):
    return next(i for i in view.children if getattr(i, "custom_id", "").startswith("glorfindel_exec_"))


def _ack(view):
    return next(i for i in view.children if getattr(i, "custom_id", "") == "glorfindel_ack")


def test_a_button_of_a_card_settled_since_its_view_was_built_runs_nothing(monkeypatch):
    ran = []
    monkeypatch.setattr(bot, "_run_cli", lambda args: ran.append(args) or (0, "ok"))
    policy = bot.ButtonPolicy(users=frozenset({ALLOWED}))
    esc_id = _revert_card()
    built = _stored(esc_id)                          # the view as it was posted: pending
    escalations.resolve(esc_id)                      # acknowledged in the console since

    click = _press(built, _User(ALLOWED), policy, _revert)
    assert ran == [] and click.posted == [] and click.card_edits == []
    assert len(click.ephemeral) == 1 and "Carte réglée" in click.ephemeral[0][0]
    assert "acquittée" in click.ephemeral[0][0] and click.ephemeral[0][1] is True
    click = _press(built, _User(ALLOWED), policy, _ack)
    assert click.sent == [] and "Carte réglée" in click.ephemeral[0][0]

    # A restore's form opened before the card was settled: its confirmation runs nothing either.
    rid = escalations.record("rule-ransomware-0123abcd", VM, "restore_from_backup",
                             "destructive_action", "restore needs a human")
    card = _stored(rid)
    escalations.resolve(rid)

    async def confirm():
        view = bot._RestoreConfirmView(card, "2026-10-29T07:30:00+00:00")
        click = _Click(_User(ALLOWED), policy, "confirm")
        assert await view.interaction_check(click) is False
        return click
    click = asyncio.run(confirm())
    assert ran == [] and "Carte réglée" in click.ephemeral[0][0]

    # The witness: the same click on a card still pending runs the command.
    live = _revert_card()
    click = _press(_stored(live), _User(ALLOWED), policy, _revert)
    assert ran == [["revert", VM, "--yes"]] and click.ephemeral == []


def test_a_verdict_given_already_is_not_given_again():
    policy = bot.ButtonPolicy(users=frozenset({ALLOWED}))
    esc_id = escalations.record("rule-ssh-brute-force-0123abcd", VM, "block_suspicious_ip", "mode_hold", "held")
    built = _stored(esc_id)
    escalations.set_verdict(esc_id, "wrong", "")     # judged in the console since
    click = _press(built, _User(ALLOWED), policy, _verdict_right)
    assert _stored(esc_id)["verdict"] == "wrong" and "déjà jugée (wrong)" in click.ephemeral[0][0]


def test_a_card_whose_vm_left_the_discovery_has_no_live_button(monkeypatch):
    from datetime import datetime, timezone

    from glorfindel.discovery import AssetRegistry, DiscoveredAsset
    ran = []
    monkeypatch.setattr(bot, "_run_cli", lambda args: ran.append(args) or (0, "ok"))
    policy = bot.ButtonPolicy(users=frozenset({ALLOWED}))
    other = VM.replace("bree", "gondolin")
    AssetRegistry().update([DiscoveredAsset("vm-celebrimbor-gondolin", other, "law",
                                            datetime.now(timezone.utc).isoformat())])
    esc_id = _revert_card()
    click = _press(_stored(esc_id), _User(ALLOWED), policy, _revert)
    assert ran == [] and "n'est plus dans la découverte" in click.ephemeral[0][0]
    assert all(i.disabled for i in bot._build_view(_stored(esc_id), bot._known_vms()).children)
