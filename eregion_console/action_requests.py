"""FS1b (#563, docs/design/file-actions-signee.md §2.3, §2.10): the console's side of the signed
action queue — behind ``EREGION_ACTION_QUEUE=1`` only. Without it, nothing changes: the routes keep
their direct call (eregion_console/api.py, ``_queue_on``).

With it, a write route no longer calls Azure: it deposits a request signed by the console's key
(``~/.eregion/console/queue_ed25519``, drawn at its first use by the watch's own code) in its
directory of runs/ (``runs/console/queue/<id>.json``), then waits for the watch's receipt
(``runs/glorfindel/queue/console-<id>.json``) — ``eregion_core.action_queue.ask``. The route answers
as it did, from the receipt (``answer``). The watch judges: the console's own guards still run
first, for what it says at once — the watch replays them.
"""
from __future__ import annotations

from eregion_core import action_queue as aq

SERVICE = "console"


def ask(verb: str, resource_id: str, *, root, by: dict, ip: str = "", scope: str = "",
        card: tuple[str, str] | None = None, **kw) -> dict:
    """The gesture deposited by the console, its receipt awaited (``action_queue.ask``)."""
    return aq.ask(SERVICE, verb, resource_id, by=by, root=root, ip=ip, scope=scope, card=card, **kw)


def answer(asked: dict, **extra) -> dict:
    """What a route answers from the receipt: ``done`` as its direct call did (``ok``, the result,
    the check), ``failed`` and ``refused`` as an error, with the refusal's code."""
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
