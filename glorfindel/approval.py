"""FS1b (#563, docs/design/file-actions-signee.md §2.9): the guards of a human's gesture — one code,
called by both sides. The console judges a click with them before its direct call (as it always
did: they come from eregion_console/api.py, unchanged); the watch replays them on a request of the
signed action queue (glorfindel/queue_watch.py) before any call to the cloud. Never copied: a
guard changed here is changed for both.

- **The approval in one click** (``approval_refusal``): never a card anchored on a VM the detection
  does not name, only the types one may approve (``action_queue.APPROVABLE_TYPES``), a card younger
  than ``GLORFINDEL_APPROVAL_MAX_AGE_H`` (2 h; zero or less closes the approval), and no restore of
  the VM after the card. The card's date: the one the caller trusts — the console, the card's
  ``last_seen`` (as before FS1b); the watch, the ``issued_at`` it signed on its proposal, never
  ``last_seen``, which the console can write (§7, « Pour FS1b »).
- **An address and a reach** (``address_refusal``, ``scope_refusal``): one host address, never one
  of the never-block list (``blockable_ip``, SEC2); a reach of ``vm`` or ``subnet``.
- **What the watch holds** (``held_isolation``, ``held_block``): a release, a reset, an unblock, a
  promotion act on what the watch's state holds for this VM — a block by its IP on this VM, never
  the VM's first one (CON-K).
- **The perimeter** (``in_perimeter``): a VM the watch knows — discovered, or that it holds or has
  a card for; a VM id, never anything else.
- **The bot's human** (``discord_refusal``): the user a bot's request names, read against the
  watch's own copy of DISCORD_ALLOWED_USERS and DISCORD_ALLOWED_ROLES — a bot badly set is caught,
  a compromised one is not (it can name any allowed user, §3.2).
- **The check after** (``verify_approved``): an approved action verified as the agent verifies
  its own; a check that is not ``True`` leaves a ``verification_failed`` card.

The guards of the model (the confidence gate, the draws, the mode) are not here: a human's
approval is what they wait for (§2.9).
"""
from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone

from eregion_core import action_queue

SCOPES = ("vm", "subnet")
USERS_ENV = "DISCORD_ALLOWED_USERS"
ROLES_ENV = "DISCORD_ALLOWED_ROLES"


def approval_max_age_h() -> float:
    """GLORFINDEL_APPROVAL_MAX_AGE_H, 2 h when unset or malformed. `nan` and `inf` parsed:
    `age > nan` is never true, and a card of any age could be executed (G2) — both are
    2 h. Zero or negative stays as written: one-click approval closed on purpose
    (`approval_refusal` refuses every card), never reopened to 2 h."""
    try:
        value = float(os.environ.get("GLORFINDEL_APPROVAL_MAX_AGE_H") or "2")
    except ValueError:
        return 2.0
    if math.isnan(value) or value == math.inf:
        return 2.0
    return value


def approval_refusal(esc: dict, vm_name: str, *, dated: str | None = None,
                     now: datetime | None = None) -> str | None:
    """Why this card can't be executed in one click any more, or None. ``dated``: the moment the
    card is dated by — the watch passes the ``issued_at`` it signed; by default the card's own
    ``last_seen`` (or ``timestamp``)."""
    etype = esc.get("escalation_type", "")
    if etype == "unattributed_signal":
        return ("Détection non attribuée : la carte est ancrée sur une VM que la détection "
                "ne nomme pas. Identifier la VM concernée, puis agir depuis la CLI.")
    if etype not in action_queue.APPROVABLE_TYPES:
        return f"Ce type de carte ({etype or '?'}) ne s'exécute pas en un clic."
    seen = dated if dated is not None else (esc.get("last_seen") or esc.get("timestamp") or "")
    try:
        seen_dt = datetime.fromisoformat(seen)
        if seen_dt.tzinfo is None:
            raise ValueError(seen)
    except (TypeError, ValueError):
        return "Carte sans date lisible : relancer l'analyse plutôt que l'exécuter."
    max_age_h = approval_max_age_h()
    if max_age_h <= 0:
        # Closed on purpose: no card of any age — a card dated a little ahead of this
        # clock included (`age > 0` let it through) — runs in one click.
        return ("Approbation en un clic fermée (GLORFINDEL_APPROVAL_MAX_AGE_H ≤ 0) : "
                "agir depuis la CLI.")
    age_h = ((now or datetime.now(timezone.utc)) - seen_dt).total_seconds() / 3600
    if age_h > max_age_h:
        return (f"Carte vieille de {age_h:.1f} h : l'état de la VM a pu changer (restore, levée). "
                "Acquitter et laisser la détection se reproduire, ou agir depuis la CLI.")
    from glorfindel import jobs as _jobs
    try:
        text = (_jobs._RECOVERY_DIR / f"{vm_name}.json").read_text()
    except FileNotFoundError:
        return None                     # no restore of this VM recorded
    except OSError as exc:
        return f"Restore illisible ({type(exc).__name__}) : agir depuis la CLI."
    # A record there but unreadable never reads as « no restore » (FS1b review): a list, a date
    # without its zone, a field missing — the approval is refused, as it never ran before (a 500).
    try:
        restored = datetime.fromisoformat(json.loads(text)["last_restore_at"])
        after = restored > seen_dt
    except Exception as exc:
        return f"Restore illisible ({type(exc).__name__}) : agir depuis la CLI."
    if after:
        return ("Un restore a eu lieu après cette carte : l'exécuter agirait sur une VM "
                "restaurée. Acquitter la carte.")
    return None


def address_refusal(ip: str) -> tuple[str, str]:
    """(the address, "") when ``ip`` is one host address Glorfindel may block — else ("", why):
    a range, a tag, a reserved address, one of the never-block list (``blockable_ip``)."""
    from glorfindel.response.policy import blockable_ip
    try:
        return blockable_ip(ip), ""
    except ValueError as exc:
        return "", str(exc)


def scope_refusal(scope: str) -> str:
    """Why this reach of a block is not one — "" when it is ``vm`` or ``subnet``."""
    if scope in SCOPES:
        return ""
    return f"portée inconnue : {str(scope)[:20]!r} (vm ou subnet)"


def _same(a: str, b: str) -> bool:
    return (a or "").rstrip("/").lower() == (b or "").rstrip("/").lower()


def held_isolation(resource_id: str) -> bool:
    """The watch's state holds an isolation of this VM (or cannot read it: then the release says
    what it cannot verify, as the CLI's reset does — I3U)."""
    from glorfindel.actions import _isolation_unreadable, active_isolations
    if any(_same(i.get("resource_id", ""), resource_id) for i in active_isolations()):
        return True
    return bool(_isolation_unreadable(resource_id))


def held_blocks(resource_id: str) -> list[dict]:
    """The blocks the watch's state holds on this VM."""
    from glorfindel.actions import active_blocks
    return [b for b in active_blocks() if _same(b.get("resource_id", ""), resource_id)]


def held_block(resource_id: str, ip: str) -> dict | None:
    """The block of ``ip`` the watch holds on this VM (CON-K): the row's own, never the VM's first
    one; the IP matched against its blocks, never taken as the request gives it."""
    ip = (ip or "").strip()
    if not ip:
        return None
    return next((b for b in held_blocks(resource_id) if b.get("ip") == ip), None)


def is_vm_id(resource_id: str) -> bool:
    parts = (resource_id or "").strip("/").split("/")
    return (len(parts) == 8 and parts[0].lower() == "subscriptions" and parts[2].lower() == "resourcegroups"
            and parts[4].lower() == "providers" and parts[5].lower() == "microsoft.compute"
            and parts[6].lower() == "virtualmachines" and all(parts))


def in_perimeter(resource_id: str) -> bool:
    """A VM the watch knows: discovered, or one whose isolation, blocks or pending card it holds —
    a VM's id, never anything else."""
    if not is_vm_id(resource_id):
        return False
    try:
        from glorfindel.discovery import AssetRegistry
        if any(_same(a.resource_id, resource_id) for a in AssetRegistry().all() if a.resource_id):
            return True
    except Exception:
        pass
    if held_isolation(resource_id) or held_blocks(resource_id):
        return True
    try:
        from glorfindel import escalations
        return any(_same(e.get("resource_id", ""), resource_id) for e in escalations.pending())
    except Exception:
        return False


def parse_ids(raw: str) -> tuple[frozenset[int], list[str]]:
    """Discord ids, comma- or space-separated. What is not an id (a name, a mention) is
    returned apart, never matched."""
    ids, bad = set(), []
    for part in (raw or "").replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isascii() and part.isdigit():
            ids.add(int(part))
        else:
            bad.append(part)
    return frozenset(ids), bad


def discord_refusal(by: dict, environ=None) -> str:
    """Why the watch does not take the human a bot's request names — "" when it does: through
    Discord, a user its own copy of DISCORD_ALLOWED_USERS lists, or any user when it lists roles
    (a role is the bot's to read: the request names no role). Neither copy set: refused, the
    gesture said."""
    environ = os.environ if environ is None else environ
    if (by or {}).get("via") != "discord":
        return "le bot nomme son humain par Discord (by.via = discord)"
    users, _ = parse_ids(environ.get(USERS_ENV, ""))
    roles, _ = parse_ids(environ.get(ROLES_ENV, ""))
    user = str((by or {}).get("user") or "")
    if not users and not roles:
        return (f"la watch n'a pas sa copie de {USERS_ENV} ni de {ROLES_ENV} : le bot ne demande rien "
                "tant qu'elle ne les a pas (les mêmes que le bot, dans l'environnement de la watch)")
    if user.isascii() and user.isdigit() and int(user) in users:
        return ""
    if roles:
        return ""
    return f"l'utilisateur Discord {user[:24]!r} n'est pas dans la copie de {USERS_ENV} de la watch"


def verify_approved(connector, esc: dict, action: str, resource_id: str, result: dict,
                    ip: str = "", record=None) -> dict:
    """Verify an approved action, as the agent verifies its own, and say it: ``record`` (the
    manual action noted, for the feed — the console's; the watch's receipt says it for the
    queue). The approve route used to execute without either (real run, 2026-10-05). A failed
    check becomes a verification_failed card — the approval itself resolved the held one."""
    from glorfindel import escalations as _esc
    from glorfindel.actions import isolation_verdict
    try:
        if action == "isolate_vm":
            verification = isolation_verdict(connector.verify_isolation(resource_id), result)
        elif action == "release_isolation":
            verification = connector.verify_release(resource_id)
        else:
            from glorfindel.response.policy import as_recorded
            verification = as_recorded(connector.verify_block_ip(ip, resource_id))   # L1G: the reassertion's
    except Exception as e:
        verification = {"verified": None, "error": f"vérification impossible : {e}"}
    if record is not None:
        try:
            record(action, resource_id, {**(result or {}), **verification,
                                         "approved_escalation": esc.get("id", "")})
        except Exception:
            pass
    # Not verified is not a success either (fourth review, Q11): a check that couldn't
    # conclude leaves a card too, as the agent's own cycle now does.
    if verification.get("verified") is not True:
        failed = verification.get("verified") is False
        _esc.record(
            signal_id=f"approve-{esc.get('id', '')}", resource_id=resource_id, action=action,
            escalation_type="verification_failed",
            reason=(f"Action '{action}' approuvée et exécutée, mais "
                    + ("la vérification a échoué : " if failed else "elle n'a pas pu être vérifiée : ")
                    + f"{verification.get('error', 'check failed' if failed else 'Azure illisible')}"),
            ttp=esc.get("ttp", ""), severity=esc.get("severity", ""),
        )
    return verification
