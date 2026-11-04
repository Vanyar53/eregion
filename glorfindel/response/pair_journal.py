"""Glorfindel's own journal of its writes of perimeter pairs (L1W, #492):
~/.glorfindel/perimeter_writes.jsonl, beside the blocks' states.

A perimeter block writes one rule pair per IP and subnet, the pair every block entry of that IP
and subnet names. Another VM's block writes it again over a pair the first VM's card said gone;
taken off again before any pass, Azure reads as the card read, and the acknowledged card of the
first VM stayed silent on a new episode. No reading of Azure can show a write between two passes:
this journal does. Glorfindel's writes only — never the customer's, never Azure's reading.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


def _pair_journal() -> Path:
    """Beside the blocks' states, read from `_BLOCK_STATE_DIR` at each call: wherever the states go
    (a test's tmp, through the facade), the journal goes too."""
    from glorfindel.response import state
    return state._BLOCK_STATE_DIR.parent / "perimeter_writes.jsonl"


def note_pair_write(nsg: str, rule: str) -> None:
    """A perimeter pair (`nsg` « rg/name », `rule` its inbound name) about to be written by
    Glorfindel. Noted before the write — one that reached Azure and then raised (a crash, a 429
    after it) is noted too: a card more, never one less. Appended, no lock: two writers at once
    each add theirs; each begins on a line of its own, so one cut by a full disk never takes the
    next with it. Never in the way of the block, never refused in silence: logged."""
    line = "\n" + json.dumps({"pair": f"{nsg}/{rule}".lower(), "at": datetime.now(timezone.utc).isoformat()})
    path = _pair_journal()
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
    except OSError as exc:
        log.warning("perimeter pair %s/%s written unnoted (%s)", nsg, rule, exc)


def pair_written_since(pairs: set[str], since: str) -> bool:
    """One of these pairs (`rg/nsg/rule`, in lowercase — `reassert_said._pair_keys`) noted at
    `since` or after (an ISO time; empty or unreadable: ever — a card more). Unread (no journal,
    an unreadable one): no."""
    try:
        text = _pair_journal().read_text()
    except (OSError, UnicodeDecodeError):
        return False
    try:
        floor = datetime.fromisoformat(since) if since else None
    except ValueError:
        floor = None
    for line in text.splitlines():
        try:
            e = json.loads(line)
            if e.get("pair") in pairs and (floor is None or datetime.fromisoformat(e["at"]) >= floor):
                return True
        except (ValueError, KeyError, TypeError, AttributeError):
            continue                     # a line cut by a full disk, or not ours
    return False
