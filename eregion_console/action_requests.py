"""FS1b (#563, docs/design/file-actions-signee.md §2.3, §2.10): the console's side of the signed
action queue — behind ``EREGION_ACTION_QUEUE=1`` only. Without it, nothing changes: the routes keep
their direct call (eregion_console/api.py, ``_queue_on``).

With it, a write route no longer calls Azure: it deposits a request signed by the console's key
(``~/.eregion/console/queue_ed25519``, drawn at its first use by the watch's own code) in its
directory of runs/ (``runs/console/queue/<id>.json``). FS1c: it answers at once with the request's
id — never waiting for the watch; the page follows the receipt
(``runs/glorfindel/queue/console-<id>.json``) by ``GET /api/queue/<id>`` (``follow``), and the
answer, once final, is the one the route gave before (``answer``). The watch judges: the console's
own guards still run first, for what it says at once — the watch replays them.

Whether the watch takes the console's gestures now is read from the status it signs
(``posture``): the page greys its write buttons by it, and says why.
"""
from __future__ import annotations

import os

from eregion_core import action_queue as aq
from eregion_core import watch_key

SERVICE = "console"
# A card's verb, and the action its card holds (the page names the action it approved).
ACTION_OF_CARD_VERB = {verb: action for action, verb in aq.VERB_OF_ACTION.items()}
WAITING_MAX = 64            # requests of the console settled per read of the page's state


def deposit(verb: str, resource_id: str, *, root, by: dict, ip: str = "", scope: str = "",
            card: tuple[str, str] | None = None) -> dict:
    """FS1c: the gesture deposited by the console, never awaited (``action_queue.deposit_request``):
    ``{"request": id}`` or ``{"error": …}``."""
    return aq.deposit_request(SERVICE, verb, resource_id, by=by, root=root, ip=ip, scope=scope, card=card)


def ask(verb: str, resource_id: str, *, root, by: dict, ip: str = "", scope: str = "",
        card: tuple[str, str] | None = None, **kw) -> dict:
    """The gesture deposited by the console, its receipt awaited (``action_queue.ask``) — FS1b's
    synchronous way, kept for a script; the routes deposit (``deposit``) since FS1c."""
    return aq.ask(SERVICE, verb, resource_id, by=by, root=root, ip=ip, scope=scope, card=card, **kw)


def follow(request_id: str, *, root, now=None) -> dict:
    """Where a request of the console stands, read once (``action_queue.follow``): its receipt
    believed from the mount — and checked with the watch's key when the console pins it
    (``EREGION_WATCH_KEY``): a receipt of another key is said, never « no receipt »."""
    public, _ = watch_key.pinned()
    return aq.follow(SERVICE, request_id, root=root, watch_public=public, now=now)


def withdraw(request_id: str, *, root) -> bool:
    """The console's own request removed — True for the one read that removed it."""
    return aq.withdraw(SERVICE, request_id, root)


def waiting(*, root) -> list[str]:
    """The ids of the console's requests still in its directory (at most WAITING_MAX)."""
    out = []
    try:
        with os.scandir(aq.request_dir(SERVICE, root)) as it:
            for e in it:
                stem = e.name[:-5] if e.name.endswith(".json") else ""
                if aq._ID.fullmatch(stem):
                    out.append(stem)
                    if len(out) >= WAITING_MAX:
                        break
    except OSError:
        return []
    return out


def posture(*, root, now=None) -> dict:
    """Whether the watch takes the console's gestures now (``action_queue.posture``): its status,
    signed — fresh, writing, pinning the console's own key."""
    public, _ = watch_key.pinned()
    return aq.posture(SERVICE, root=root, watch_public=public, now=now)


def answer(asked: dict, **extra) -> dict:
    """What a route answers from the receipt: ``done`` as its direct call did (``ok``, the result,
    the check), ``failed`` and ``refused`` as an error, with the refusal's code; no receipt to
    believe (``not_taken``, ``untrusted``, ``unknown``): its error, said."""
    out = {"via": "queue", "request": asked.get("request", "")}
    if "receipt" not in asked:
        return {**out, "error": asked.get("error", "")}
    r = asked["receipt"]
    if r["state"] == "refused":
        return {**out, "error": r.get("reason") or r.get("code"), "refused": r.get("code")}
    if r["state"] == "failed":
        return {**out, "error": r.get("reason") or "failed", "result": r.get("result"),
                "code": r.get("code") or ""}
    return {**out, "ok": True, "result": r.get("result"), "verification": r.get("verification"),
            "note": r.get("reason") or "", **extra}
