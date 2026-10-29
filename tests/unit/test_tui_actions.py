"""SEC5 (V-35): the TUI's keys do what they say, on the cards the bot and the console allow.

« unblock » removes the VM's IP blocks — never its isolation (it used to run a full reset);
Restore is offered and run only on a restore card that is not anchored (``_ANCHORED_TYPES``:
the card's VM may not be the one the detection concerns). The set is compared here with the
bot's; tests/unit/test_console.py compares the console's with the bot's too.
No subprocess is started: ``_commands`` is what ``_execute`` would run.
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

import pytest

import glorfindel
from glorfindel import tui

RID = ("/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute"
       "/virtualMachines/vm-celebrimbor-gondolin")


def _card(**kw):
    return {"id": "abcd1234ef", "resource_id": RID, "action": "isolate_vm",
            "escalation_type": "verification_failed", "timestamp": "", **kw}


def test_unblock_removes_the_ip_blocks_and_nothing_else(monkeypatch):
    """M1279: `u` is « unblock {vm} (IP blocks only) » — one `glorfindel unblock` per IP of
    that VM, never `reset` (which releases the isolation too)."""
    blocks = [{"resource_id": RID, "ip": "203.0.113.7"}, {"resource_id": RID.upper(), "ip": "198.51.100.2"},
              {"resource_id": RID.replace("gondolin", "other"), "ip": "192.0.2.9"}]
    import glorfindel.actions as actions
    monkeypatch.setattr(actions, "active_blocks", lambda: blocks)
    cmds = tui._commands("u", _card())
    assert cmds == [["unblock", "198.51.100.2", RID, "--yes"], ["unblock", "203.0.113.7", RID, "--yes"]]
    assert all(c[0] not in ("reset", "revert", "release") for c in cmds)
    assert tui._commands("v", _card()) == [["reset", RID, "--yes"]]
    assert tui._commands("x", _card()) == [["release", RID, "--yes"]]


@pytest.mark.parametrize("esc_type", sorted(tui._ANCHORED_TYPES))
def test_no_restore_nor_undo_on_an_anchored_card(esc_type):
    """M1266: Restore refused on the cards the console and the bot refuse it on."""
    card = _card(action="restore_from_backup", escalation_type=esc_type)
    assert not tui._can_restore(card) and tui._commands("r", card) == []
    for key in "xuv":
        assert tui._commands(key, {**card, "action": "isolate_vm"}) == []


def test_restore_on_a_restore_card_only():
    # With the moment the operator gave, never without (SEC4c).
    card = _card(action="restore_from_backup", escalation_type="destructive_action")
    assert tui._commands("r", card, before="2026-10-29T07:00:00Z") == [
        ["restore", RID, "--yes", "--before", "2026-10-29T07:00:00+00:00"]]
    assert tui._commands("r", card) == []
    assert tui._commands("r", _card(action="snapshot", escalation_type="low_confidence"),
                         before="2026-10-29T07:00:00Z") == []


def test_the_hint_offers_only_the_keys_that_act():
    from datetime import datetime, timezone
    anchored = _card(action="restore_from_backup", escalation_type="identity_change")
    with patch("glorfindel.escalations.pending", return_value=[anchored]):
        text = tui._escalations_renderable(datetime.now(timezone.utc), None, True).renderable.plain
    assert "[r] restore" not in text and "glorfindel restore" not in text
    assert "glorfindel ack abcd1234" in text
    low = _card(action="snapshot", escalation_type="low_confidence")
    with patch("glorfindel.escalations.pending", return_value=[low]):
        text = tui._escalations_renderable(datetime.now(timezone.utc), None, True).renderable.plain
    assert "[r] restore" not in text


def test_the_tui_anchors_the_cards_the_bot_anchors():
    """The same set as the bot's (read from its source: it imports discord), as the console's."""
    tree = ast.parse((Path(glorfindel.__file__).parent / "bot.py").read_text())
    bot = next(ast.literal_eval(n.value) for n in ast.walk(tree) if isinstance(n, ast.Assign)
               and any(getattr(t, "id", "") == "_ANCHORED_TYPES" for t in n.targets))
    assert tui._ANCHORED_TYPES == bot
