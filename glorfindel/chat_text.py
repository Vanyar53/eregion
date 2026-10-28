"""Text from outside, made inert before it reaches a chat (SEC6, N-09).

What a card says comes in part from outside: the model's explanation and steps, the names
Azure returns (an Entra application's display name is chosen by whoever registers it), a
rule's name, a VM's. Written raw, such a text could carry Discord's Markdown — a masked link
(``[Support](https://…)``) that shows one thing and opens another, a heading, a quote —,
a mention (``@everyone``, ``<@&id>``), or close the backticks Glorfindel put around it.

- ``discord_text``: prose for the Discord bot (embeds, messages). Every character Discord's
  Markdown reads is escaped with a backslash (Discord shows the character, never applies it),
  the marks a line may start with too; ``@everyone`` and ``@here`` get a zero-width space.
- ``discord_code``: a value Glorfindel shows in backticks — one line, no backtick of its own.
- ``webhook_text`` / ``webhook_code``: the webhook speaks Slack's format (Slack, Teams, or
  Discord's ``/slack`` endpoint), where a backslash is shown as is. One line, so the text stays
  in its quote; no ``<…>`` (Slack's links and mentions: ``<!channel>``, ``<url|text>``,
  Discord's ``<@id>``): the angle brackets become ‹ ›; a masked link is broken by a
  zero-width space; ``@everyone`` / ``@here`` as above.

The bot also posts with no mention allowed but the role it is configured to ping
(``glorfindel/bot.py``, ``allowed_mentions``): escaping is what the reader sees, the allowed
mentions what Discord does.
"""
from __future__ import annotations

import re

ZWSP = "​"
_INLINE = re.compile(r"([\\`*_~|\[\]()<>])")
_LINE_START = re.compile(r"(?m)^([ \t]*)([#\-+])")
_MENTION = re.compile(r"@(everyone|here)\b", re.IGNORECASE)


def _no_mention(text: str) -> str:
    return _MENTION.sub("@" + ZWSP + r"\1", text)


def discord_text(text) -> str:
    """Prose shown as it is written: nothing of it is Markdown, a link or a mention."""
    s = "" if text is None else str(text)
    s = _INLINE.sub(r"\\\1", s)
    s = _LINE_START.sub(r"\1\\\2", s)
    return _no_mention(s)


def discord_code(text) -> str:
    """A value in Glorfindel's own backticks: on one line, no backtick to close them early."""
    s = " ".join(("" if text is None else str(text)).split()).replace("`", "ˋ")
    return f"`{_no_mention(s)}`"


# A span between single backticks, alone: neither its neighbours nor its content is a backtick,
# on one line. Discord can read it only one way — as code, where nothing renders.
_SPAN = re.compile(r"(?<!`)`([^`\n]+)`(?!`)")


def discord_steps(text) -> str:
    """A step for a human: its commands between backticks keep their code style
    (``discord_code``), everything else is ``discord_text``. A backtick that does not make
    such a span is escaped like any other mark."""
    s = "" if text is None else str(text)
    out, i = [], 0
    for m in _SPAN.finditer(s):
        out += [discord_text(s[i:m.start()]), discord_code(m.group(1))]
        i = m.end()
    return "".join(out) + discord_text(s[i:])


def webhook_text(text) -> str:
    """Prose for the webhook (Slack's format): one line, no link nor mention of its own."""
    s = " ".join(("" if text is None else str(text)).split())
    s = s.replace("<", "‹").replace(">", "›").replace("](", "]" + ZWSP + "(")
    return _no_mention(s)


def webhook_code(text) -> str:
    """A value in the webhook's backticks."""
    return webhook_text(text).replace("`", "ˋ")
