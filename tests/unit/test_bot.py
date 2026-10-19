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
    assert names["Pourquoi rien n'est exécuté"] == "Mode human_only — action retenue"
    # an older card without an explanation falls back on its reason
    assert bot._embed_body(_held_block(explanation=""))[0] == "Mode human_only — action retenue"


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
