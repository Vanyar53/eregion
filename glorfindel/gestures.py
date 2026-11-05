"""FS1b (#563, docs/design/file-actions-signee.md §2.9): the operator's lifts of a containment — a
release, a reset — out of glorfindel/cli.py as callables, so the watch runs a request of the queue
with the CLI's own code (glorfindel/queue_watch.py), never a copy of it. The CLI keeps its prompt
and its words around them (``release``, ``reset``); what they do is here.
"""
from __future__ import annotations


def release_needed(connector, resource_id: str) -> bool:
    """False when no NIC still carries an isolation rule — then the stale state is cleared, so the
    console updates. A partially isolated VM (one NIC still cut off) needs its release: the former
    test (``not verify_isolation()``) cleared its state, the rule left orphaned."""
    verification = connector.verify_release(resource_id)
    if verification.get("verified"):
        from glorfindel.actions import _clear_isolation_state
        _clear_isolation_state(resource_id)      # by id: two VMs may share a name
        return False
    return True


def reset_targets(resource_id: str) -> tuple[list[dict], list[dict]]:
    """(the isolations, the blocks) the local state holds on this VM — what a reset lifts.
    Case-insensitive: Azure ARM ids are, Python's == is not (an orphan isolation state was left,
    « Nothing to reset » while `list` still showed ISOLATED). Its isolation state unreadable is
    not « nothing to reset »: the release says what it can't verify, the file kept (I3U, #440)."""
    from glorfindel.actions import _isolation_unreadable, active_blocks, active_isolations
    rid_lower = resource_id.lower()
    isolations = [i for i in active_isolations() if i.get("resource_id", "").lower() == rid_lower]
    blocks = [b for b in active_blocks() if b.get("resource_id", "").lower() == rid_lower]
    isolations = isolations or ([{"resource_id": resource_id}] if _isolation_unreadable(resource_id) else [])
    return isolations, blocks


def reset_apply(connector, resource_id: str, isolations: list[dict], blocks: list[dict],
                say=None) -> list[str]:
    """Lift what ``reset_targets`` found: the isolation released, each block removed. What is
    still in place (each rule a removal could not take off) is returned — empty: the VM is clean.
    ``say``: each step's outcome, as the CLI prints it."""
    leftovers: list[str] = []
    if isolations:
        r = connector.release_isolation(resource_id)
        if say is not None:
            say(f"  [cyan]release_isolation[/cyan] → {r.get('status', '?')}")
        leftovers += r.get("failed", [])
    for b in blocks:
        r = connector.unblock_ip(b["ip"], resource_id)
        if say is not None:
            say(f"  [cyan]unblock {b['ip']}[/cyan] → {r.get('status', '?')}")
        leftovers += r.get("failed", [])
    return leftovers
