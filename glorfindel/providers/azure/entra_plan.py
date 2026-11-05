"""The plan of an identity card (IR1a, docs/design/reponse-identite.md §3.2): what to do about
one finding of C2, written by the code from the row of the log — never by the model —, its
parameters read on Microsoft Graph, read only (glorfindel/providers/azure/graph.py).

        finding                 verbs (the identity executor's, IR1c)    steps for a human
        credential added        entra_remove_credential (that one)       the other credentials, if
                                                                         the author is not expected
        consent                 entra_disable_principal (the CLIENT,     remove the grant or the
                                never the resource's principal)          assignment; revoke the
                                                                         sessions of who consented
        privileged role         —  (a user's verb waits for IDI1b)       remove the assignment;
                                                                         revoke the sessions
        unusual sign-in         entra_remove_credential (the one used,   the other credentials
                                if the row names it), else
                                entra_disable_principal
        Glorfindel's identity   none                                     renew its credentials

Each item says what, on which object, with its exact parameters, the complete command a human
types today (no executor exists before IR1c: every item is done by hand, with the operator's own
account), its side effect, its way back, and what the check reads afterwards (entra_check.py).

What is never done:
  - **a value invented**: a parameter neither in the row nor read on Graph is marked « not read »,
    with why, and the command that needs it says so (`complete: False`);
  - **a value of the log put in a command unchecked**: a command holds only ids that are ids — an
    object id (a GUID), a grant's or an assignment's id (letters, digits, `-`, `_`), a scope of a
    role (`/`, `/administrativeUnits/<GUID>`), a permission's words. A name never: an attacker
    chooses the name of an application; the card shows it as text, escaped (the console's `_attr`,
    the bot's markdown);
  - **a verb of the executor on Glorfindel's identity**, actor or target (§3.5): its plan is
    the renewal of its credentials, and every step a human's;
  - **a verb on a user**: a user is enrolled only by IDI1b (§3.6), not built — its revocation and
    its disabling stay steps.

`never_target` (IDI1, #546, eregion_core/never_target.py): `build` takes a `protected` predicate
(`never_target_protected`, the watch's) which turns an item aimed at one of its ids into a human's
step, its reason said — the first of the three locks of §3.5. The list unreadable (no operator
named), every id is covered: every item a human's. Its whole rule on an identity read from Graph
(`NeverTarget.why`: another tenant's application, a resource's principal) is the executor's
(IR1c), which reads the identity whole before acting.
"""
from __future__ import annotations

from datetime import datetime, timezone

from glorfindel.providers.azure.entra_grants import _consent_items, _role_items
from glorfindel.providers.azure.entra_items import (
    PLAN_VERSION, _GLORFINDEL, _NO_EXECUTOR, _Reads, _credential_items, _item, _signin_items, when,
)


# ── The plan ───────────────────────────────────────────────────────────────────────────────

def never_target_protected(env=None):
    """`protected` from the process's never_target list (IDI1): an id it covers → why. The list
    unreadable, every id is covered, and its reason is the one said."""
    from eregion_core.never_target import NeverTarget
    never = NeverTarget.from_env(env)

    def protected(object_id: str) -> str:
        if not never.covers(object_id):
            return ""
        return ("never_target illisible, aucune identité n'est une cible : " + never.refusal()
                if never.refusal() else
                "une identité jamais ciblée (never_target : Glorfindel, Orodruin, Annatar, un opérateur, "
                "une identité listée)")
    return protected


def _glorfindels(row: dict) -> bool:
    return row.get("GlorfindelIdentity") is True or row.get("GlorfindelManaged") is True


def _ordered(items: list[dict]) -> list[dict]:
    """The executor's verbs first, in their order, then the steps for a human; numbered."""
    out = [i for i in items if i["by"] == "executor"] + [i for i in items if i["by"] != "executor"]
    for n, i in enumerate(out, 1):
        i["n"] = n
    return out


def build(row: dict, reader=None, *, protected=None, now: datetime | None = None) -> dict:
    """The plan of one finding (its row, as `entra.prepare_rows` marked it). `reader`: Graph,
    read only (None: nothing read, each parameter the log does not give marked « not read »).
    `protected(object_id) -> why`: a list of identities never a target (never_target, IDI1)."""
    now = now or datetime.now(timezone.utc)
    kind = str(row.get("EntraKind") or "").strip().lower()
    event_at = when(row.get("TimeGenerated"))
    reads = _Reads(reader)
    note = ""
    items: list[dict] = []
    if row.get("OmittedOperations"):
        note = "carte de synthèse : chaque opération a son plan sur sa propre carte, une fois relevée"
    elif kind == "credential":
        items = _credential_items(row, reads)
    elif kind == "consent":
        items = _consent_items(row, reads, event_at)
    elif kind == "role":
        items = _role_items(row, reads, event_at)
    elif kind == "signin":
        items = _signin_items(row, reads)
    else:
        note = "constat d'un autre type : aucun plan écrit par le code, vérifier dans les journaux d'Entra ID"
    if _glorfindels(row):
        items = [i for i in items if i["verb"] not in ("entra_disable_principal", "entra_disable_user")]
        for i in items:
            i.update(by="human", why_human=_GLORFINDEL)
        items.insert(0, _item("Renouveler les identifiants de Glorfindel, puis revoir ce qu'ils ont fait "
                              "(geste de l'opérateur)", why_human=_GLORFINDEL,
                              unchecked="Graph ne peut pas le vérifier : le renouvellement des identifiants de Glorfindel se dit par l'opérateur"))
    for i in items:
        if i["by"] != "executor":
            continue
        held = protected(i["target"].get("id", "")) if protected and i["target"].get("id") else ""
        if held:          # never a verb of the executor on it: a human's step (§3.5, the first lock)
            i.update(by="human", why_human=held)
        else:
            i["why_human"] = _NO_EXECUTOR
    corr = str(row.get("CorrelationId") or "").strip()[:120]
    return {
        "version": PLAN_VERSION, "kind": kind, "built_at": now.isoformat(), "event_at": event_at,
        "correlation_id": corr,
        "graph": {"read": reader is not None and not reads.why and reads.done > 0,
                  "why": reads.why or ("" if reads.done else "rien à lire")},
        "confirm": ("Vérifier d'abord avec l'auteur ou le propriétaire que ce n'est pas voulu"
                    + (f" (CorrelationId {corr})" if corr else "") + " : légitime (un pipeline connu), "
                    "l'exclure dans la couche du client, et ne rien retirer."),
        "items": _ordered(items), "note": note,
    }


def steps_text(plan: dict) -> list[str]:
    """The plan as the card's steps (Discord, the TUI, `glorfindel pending`): a line per item, its
    command between backticks — only ids in it, never a name."""
    lines = [plan.get("confirm") or ""]
    for i in plan.get("items") or []:
        tag = f"[{i['verb']}] " if i.get("verb") else ""
        cmd = f" : `{i['command']}`" if i.get("command") else ""
        line = f"{i['n']}. {tag}{i['what']}{cmd}"
        unread = [p for p in i.get("params") or [] if not p.get("read")]
        if unread:
            line += " — non lu : " + " ; ".join(f"{p['name']} ({p.get('why') or 'non lu'})" for p in unread)
        if i.get("find"):
            line += f" — pour le trouver : `{i['find']}`"
        if i.get("before"):
            line += f" — avant : `{i['before']}`"
        if i.get("side_effect"):
            line += f" — effet de bord : {i['side_effect']}"
        if i.get("rollback"):
            line += f" — retour : {i['rollback']}"
        lines.append(line)
    if plan.get("note"):
        lines.append(plan["note"])
    graph = plan.get("graph") or {}
    if not graph.get("read") and graph.get("why") and plan.get("items"):
        lines.append(f"Graph non lu ({graph['why']}) : chaque paramètre non lu est marqué, jamais inventé.")
    if any(i.get("check") for i in plan.get("items") or []):
        lines.append("Après le geste : « Verify » sur la carte, dans la console — la watch relit Graph et dit "
                     "tenu, pas tenu ou illisible.")
    return [x for x in lines if x]
