"""SEC6 (N-09): what Glorfindel posts to a chat carries no Markdown, link or mention of its own.

An Entra application's display name is chosen by whoever registers it; the model's words come
from the logs an attacker may write. Both end on a card: the Discord bot's embed and the
webhook's line (glorfindel/chat_text.py). Tested from an identity detection's row as Azure
would return it (glorfindel/providers/azure/entra.py, describe) to what is posted.
"""
import re

import pytest

from glorfindel import chat_text, escalations
from glorfindel.chat_text import ZWSP, discord_code, discord_text, webhook_code, webhook_text

HOSTILE = ("[Support Microsoft](https://evil.example/login) @everyone @here <@&123> <!channel> "
           "<https://evil.example|portail> **gras** __souligné__ ~~barré~~ ||caché|| `x` ```bloc```")
LINE_STARTS = "# titre\n> citation\n- liste\n-# petit\n+ plus"


def _unescaped(text: str, chars: str) -> list[str]:
    """The characters of `chars` that no backslash escapes (Discord reads them)."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] in chars:
            out.append(text[i])
        i += 1
    return out


def _starts(text: str) -> list[str]:
    return [line.lstrip()[:1] for line in text.splitlines() if line.lstrip()[:1] in "#>-+"]


# ── the functions ──────────────────────────────────────────────────────────────────────────

def test_discord_text_escapes_every_mark_discord_reads():
    s = discord_text(HOSTILE + "\n" + LINE_STARTS)
    assert _unescaped(s, "[]()<>*_~|`\\") == []
    assert _starts(s) == []                                  # each one escaped: \# \> \- \+
    assert "@everyone" not in s and "@here" not in s and f"@{ZWSP}everyone" in s


def test_discord_text_shows_what_was_written():
    """Escaping changes nothing a reader sees: remove each backslash escape, get the text back."""
    text = HOSTILE + "\n" + LINE_STARTS + " \\ C:\\chemin"
    s = discord_text(text)
    assert re.sub(r"\\(.)", r"\1", s).replace(ZWSP, "") == text


def test_discord_code_cannot_close_its_backticks():
    s = discord_code("a`b ```c``` \n d @everyone")
    assert s.startswith("`") and s.endswith("`") and s.count("`") == 2
    assert "\n" not in s and f"@{ZWSP}everyone" in s


def test_webhook_text_one_line_no_link_nor_mention():
    s = webhook_text(HOSTILE + "\n" + LINE_STARTS)
    assert "\n" not in s and "<" not in s and ">" not in s
    assert "](" not in s and "@everyone" not in s and "@here" not in s
    assert "evil.example" in s                               # shown, never hidden behind a word
    assert "`" not in webhook_code("a`b")


def test_none_and_numbers_are_text():
    assert discord_text(None) == "" and discord_text(3) == "3" and webhook_text(None) == ""


# ── from Azure's row to the card ──────────────────────────────────────────────────────────

def _identity_card():
    from glorfindel.providers.azure import entra
    row = {"EntraKind": "consent", "EntraOperation": "Consent to application",
           "TargetName": HOSTILE, "TargetId": "00000000-0000-0000-0000-00000000abcd",
           "TargetType": "ServicePrincipal", "ActorName": "[admin](https://evil.example) @everyone",
           "ActorIp": "203.0.113.9", "Permissions": "Mail.Read [lire](https://evil.example)",
           "AdminConsent": "true"}
    what, steps = entra.describe(row)
    return {"id": "e5c0ffee-0000", "action": "escalate", "escalation_type": "identity_change",
            "resource_id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-x",
            "reason": what, "explanation": what, "suggested_steps": steps, "run_id": "watch-1",
            "ttp": "T1098", "severity": "high", "rule_name": "entra-consent [x](https://evil.example)"}


def test_an_entra_name_reaches_the_bots_card_inert():
    pytest.importorskip("discord")
    from glorfindel import bot
    esc = _identity_card()
    description, fields = bot._embed_body(esc)
    for text in [description] + [v for _, v, _ in fields]:
        # inside Glorfindel's own backticks a value is code (never rendered); elsewhere, escaped
        prose = re.sub(r"(?<!\\)`[^`\n]*`", "", text)
        assert _unescaped(prose, "[]()<>*_~|`") == [], text
        assert "@everyone" not in text and "@here" not in text, text


@pytest.mark.parametrize("etype", ["verification_failed", "write_blocked", "mode_hold", "[t](https://evil.example)"])
def test_an_action_the_model_named_reaches_the_title_inert(etype):
    """The model may name any action; a title shows it as written."""
    pytest.importorskip("discord")
    from glorfindel import bot
    title = bot._embed_title({"action": "[Restaurer](https://evil.example) @everyone", "escalation_type": etype})
    if etype in ("verification_failed", "write_blocked"):
        assert "estaurer" in title                           # shown (capitalized, as before)
    assert _unescaped(title, "[]<") == [] and "](" not in title and "@everyone" not in title


def test_the_bot_mentions_no_one_but_its_role():
    pytest.importorskip("discord")
    from glorfindel import bot
    allowed = bot.GlorfindelBot(channel_id=1, ping_role=None).allowed_mentions
    assert allowed is not None
    assert (allowed.everyone, allowed.users, allowed.roles, allowed.replied_user) == (False, False, False, False)


@pytest.mark.parametrize("post", ["escalation", "autonomous action"])
def test_an_entra_name_reaches_the_webhook_inert(monkeypatch, post):
    sent = []

    class _Requests:
        @staticmethod
        def post(url, json=None, timeout=None):
            sent.append(json["text"])

    import sys
    monkeypatch.setitem(sys.modules, "requests", _Requests)
    monkeypatch.setenv("GLORFINDEL_WEBHOOK_URL", "https://hooks.example.invalid/x")
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    monkeypatch.delenv("GLORFINDEL_DISCORD_BOT", raising=False)
    esc = _identity_card()
    if post == "escalation":
        escalations._notify(esc)
        lines = 4
    else:
        escalations.notify_action(esc["action"] + " [x](https://evil.example)", esc["resource_id"],
                                  esc["run_id"], 0.9, esc["explanation"], True, ttp="T1098",
                                  severity="high", note=HOSTILE)
        lines = 5
    (text,) = sent
    assert len(text.splitlines()) == lines                   # nothing from outside breaks a line
    for marker in ("<!", "<@", "<http", "](", "@everyone", "@here"):
        assert marker not in text, marker
    # Glorfindel's own backticks stay paired: no value closes one early
    assert all(line.count("`") % 2 == 0 for line in text.splitlines())


def test_a_steps_command_keeps_its_code_style_and_nothing_else_renders():
    s = chat_text.discord_steps("Lister : `az ad app credential list --id 0000` (application) [x](https://e.example)")
    assert "`az ad app credential list --id 0000`" in s
    assert _unescaped(re.sub(r"(?<!\\)`[^`\n]+`", "", s), "[]()<>*_~|`") == []


@pytest.mark.parametrize("text", [
    "a``[x](https://e.example)`",            # a span beside a backtick: not a span
    "``[x](https://e.example)``",            # double backticks: not ours
    "`a\n[x](https://e.example)`",           # across lines
    "`` `@everyone` ``",
    "`a`b`[x](https://e.example)`",
])
def test_a_step_never_lets_a_span_be_read_two_ways(text):
    """What is left unescaped are single-backtick spans with no backtick beside or inside them:
    Discord can read them only as code. Everything else is escaped prose."""
    s = chat_text.discord_steps(text)
    spans = list(re.finditer(r"(?<!\\)`([^`\n]*)`", s))
    for m in spans:
        assert m.group(1) and s[m.start() - 1:m.start()] != "`" and s[m.end():m.end() + 1] != "`"
    prose = re.sub(r"(?<!\\)`[^`\n]+`", "", s)
    assert _unescaped(prose, "[]()<>*_~|`") == [] and "@everyone" not in s


def test_the_ping_alone_may_mention_and_only_its_role():
    """The message that opens a VM's thread pings DISCORD_PING_ROLE: that role, nothing else
    (the client allows no mention otherwise)."""
    pytest.importorskip("discord")
    import asyncio

    from glorfindel import bot
    sent = []

    class _Thread:
        id, name = 7, "🔴 vm-x"

        async def send(self, content=None, **kw):
            sent.append((content, kw))

    class _Channel:
        async def create_thread(self, **kw):
            return _Thread()

    b = bot.GlorfindelBot(channel_id=1, ping_role=4242)
    b._threads = {}
    asyncio.run(b._get_or_create_thread(_Channel(), "/subscriptions/s/resourceGroups/rg/providers/"
                                        "Microsoft.Compute/virtualMachines/vm-[x](https://e.example)"))
    ((content, kw),) = sent
    assert content.startswith("<@&4242> ")
    allowed = kw["allowed_mentions"]
    assert [r.id for r in allowed.roles] == [4242]
    assert (allowed.everyone, allowed.users, allowed.replied_user) == (False, False, False)
    merged = b.allowed_mentions.merge(allowed).to_dict()          # what discord.py sends
    assert merged == {"parse": [], "roles": [4242]}
    assert _unescaped(re.sub(r"(?<!\\)`[^`\n]+`", "", content), "[]()") == []


def test_the_module_imports_nothing_of_discord():
    """The watch posts the webhook without discord.py installed (an image without the bot)."""
    import ast
    tree = ast.parse(open(chat_text.__file__, encoding="utf-8").read())
    names = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
             for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any(str(x).startswith("discord") for x in names)
