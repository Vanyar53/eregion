"""The « Verify » of an identity card (IR1a), answered by the watch: the console writes the request
on the card (`escalations.request_identity_check`) — it never reads Graph itself —, the watch reads
it at its housekeeping, reads Graph read only (`entra_check.verify`), and notes the result on the
card's thread (`escalations.note_identity_check`): held, not held, or unreadable, each item said.

Graph unreadable — a right missing (H0 today), an error, a delay — the thread says « unreadable »,
with why, never « held ».
"""
from __future__ import annotations


def run_requested(reader=None) -> list[dict]:
    """Every request waiting, answered; the results, with their card's id. `reader`: Graph (the
    watch's, `graph.default_reader()` when None)."""
    from glorfindel import escalations
    from glorfindel.providers.azure import entra_check, graph
    cards = escalations.identity_checks_requested()
    if not cards:
        return []
    reader = reader if reader is not None else graph.default_reader()
    out = []
    for card in cards:
        result = entra_check.verify(card.get("identity_plan") or {}, reader,
                                    requested_at=str(card.get("identity_check_requested") or ""))
        escalations.note_identity_check(card["id"], result)
        out.append({"id": card["id"], **result})
    return out
