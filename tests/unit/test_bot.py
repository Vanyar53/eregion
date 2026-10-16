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
        user = type("U", (), {"display_name": "jonathan"})()

    async def click():
        view = bot.EscalationView(esc)
        button = next(i for i in view.children if isinstance(i, bot._VerdictButton) and i.verdict == "right")
        await button.callback(_Interaction())
        return view

    view = asyncio.run(click())
    stored = next(e for e in escalations.all_escalations() if e["id"] == esc_id)
    assert stored["verdict"] == "right"
    assert all(b.disabled for b in view.children if isinstance(b, bot._VerdictButton))
    assert _Followup.sent and "jugé par **jonathan**" in _Followup.sent[0]
