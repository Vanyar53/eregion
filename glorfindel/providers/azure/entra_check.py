"""The check of an identity card's plan (IR1a, the « Verify » button): Graph read again, read only,
and for each item of the plan with a check, « held », « not held » or « unreadable ».

Never « held » without Graph's answer: a right missing, an error, a delay — every `Unreadable` —
is « unreadable », and so is a check the plan could not write (a parameter not read). The verdict
of the card:
  - `not_held` if one item (not optional) is not held: a fact, whatever the others;
  - else `unreadable` if one is unreadable, or if nothing could be checked;
  - else `held`.
An optional item (the author's sessions, « if the author is not expected ») is checked and said,
never counted in the verdict.

Each path is built again from ids checked again here (`entra_plan.guid`, `graph_id`): a plan is
read from the card's store, never trusted to name a path.
"""
from __future__ import annotations

from datetime import datetime, timezone

from glorfindel.providers.azure.entra_items import graph_id, guid, when
from glorfindel.providers.azure.graph import Unreadable

HELD, NOT_HELD, UNREADABLE = "held", "not_held", "unreadable"
_COLLECTIONS = ("applications", "servicePrincipals")


def _r(state: str, why: str) -> dict:
    return {"state": state, "why": why}


def _parse(value: str) -> datetime | None:
    v = when(value)
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _credential_gone(c: dict, reader) -> dict:
    coll, oid, key = c.get("collection"), guid(c.get("id")), guid(c.get("key_id"))
    if coll not in _COLLECTIONS or not (oid and key):
        return _r(UNREADABLE, "vérification mal formée")
    obj = reader.get(f"/{coll}/{oid}", {"$select": "id,passwordCredentials,keyCredentials"})
    if obj is None:
        return _r(HELD, "l'objet n'existe plus dans Graph")
    keys = {guid(k.get("keyId")) for f in ("passwordCredentials", "keyCredentials")
            for k in (obj.get(f) or []) if isinstance(k, dict)}
    return _r(NOT_HELD, f"le keyId {key} est encore sur l'objet") if key in keys else \
        _r(HELD, f"le keyId {key} n'est plus sur l'objet")


def _federated_gone(c: dict, reader) -> dict:
    oid, fic = guid(c.get("id")), guid(c.get("fic_id"))
    if not (oid and fic):
        return _r(UNREADABLE, "vérification mal formée")
    fics = reader.list(f"/applications/{oid}/federatedIdentityCredentials")
    if fics is None:
        return _r(HELD, "l'application n'existe plus dans Graph")
    return _r(NOT_HELD, "l'identifiant fédéré est encore sur l'application") \
        if fic in {guid(f.get("id")) for f in fics} else _r(HELD, "l'identifiant fédéré n'y est plus")


def _disabled(c: dict, reader) -> dict:
    coll, oid = c.get("collection"), guid(c.get("id"))
    if coll not in _COLLECTIONS + ("users",) or not oid:
        return _r(UNREADABLE, "vérification mal formée")
    obj = reader.get(f"/{coll}/{oid}", {"$select": "id,accountEnabled"})
    if obj is None:
        return _r(HELD, "l'objet n'existe plus dans Graph")
    enabled = obj.get("accountEnabled")
    if enabled is False:
        return _r(HELD, "accountEnabled : false")
    if enabled is True:
        return _r(NOT_HELD, "accountEnabled : true — encore actif")
    return _r(UNREADABLE, "accountEnabled non rendu par Graph")


def _sessions_revoked(c: dict, reader) -> dict:
    uid, after = guid(c.get("id")), _parse(c.get("after") or "")
    if not uid:
        return _r(UNREADABLE, "vérification mal formée")
    if after is None:
        return _r(UNREADABLE, "l'heure de l'événement n'est pas lue : une révocation ne peut pas lui être comparée")
    obj = reader.get(f"/users/{uid}", {"$select": "id,signInSessionsValidFromDateTime"})
    if obj is None:
        return _r(HELD, "l'utilisateur n'existe plus dans Graph")
    since = _parse(obj.get("signInSessionsValidFromDateTime") or "")
    if since is None:
        return _r(UNREADABLE, "signInSessionsValidFromDateTime non rendu par Graph")
    if since >= after:
        return _r(HELD, f"sessions valides depuis {since.isoformat()}, après l'événement")
    return _r(NOT_HELD, f"sessions valides depuis {since.isoformat()}, avant l'événement : pas révoquées")


def _grants(client: str, reader):
    return reader.list("/oauth2PermissionGrants", {"$filter": f"clientId eq '{client}'"})


def _grant_gone(c: dict, reader) -> dict:
    client, gid = guid(c.get("client")), graph_id(c.get("grant_id"))
    if not (client and gid):
        return _r(UNREADABLE, "vérification mal formée")
    grants = _grants(client, reader) or []
    return _r(NOT_HELD, "l'octroi est encore là") if gid in {str(g.get("id") or "") for g in grants} \
        else _r(HELD, "l'octroi n'y est plus")


def _assignment_gone(c: dict, reader) -> dict:
    client, aid = guid(c.get("client")), graph_id(c.get("assignment_id"))
    if not (client and aid):
        return _r(UNREADABLE, "vérification mal formée")
    roles = reader.list(f"/servicePrincipals/{client}/appRoleAssignments")
    if roles is None:
        return _r(HELD, "l'application cliente n'existe plus dans Graph")
    return _r(NOT_HELD, "l'attribution est encore là") if aid in {str(a.get("id") or "") for a in roles} \
        else _r(HELD, "l'attribution n'y est plus")


def _consent_gone(c: dict, reader) -> dict:
    client = guid(c.get("client"))
    if not client:
        return _r(UNREADABLE, "vérification mal formée")
    grants = _grants(client, reader) or []
    roles = reader.list(f"/servicePrincipals/{client}/appRoleAssignments") or []
    if grants or roles:
        return _r(NOT_HELD, f"{len(grants)} octroi(s) et {len(roles)} attribution(s) encore là")
    return _r(HELD, "aucun octroi ni attribution pour l'application cliente")


def _role_gone(c: dict, reader) -> dict:
    member = guid(c.get("member"))
    rdef, name = guid(c.get("role_definition_id")), str(c.get("role_name") or "").strip().lower()
    if not member or not (rdef or name):
        return _r(UNREADABLE, "vérification mal formée")
    coll = "roleEligibilitySchedules" if c.get("eligible") else "roleAssignments"
    found = reader.list(f"/roleManagement/directory/{coll}",
                        {"$filter": f"principalId eq '{member}'", "$expand": "roleDefinition"})
    if found is None:
        return _r(HELD, "le membre n'existe plus dans Graph")
    left = [a for a in found if (rdef and guid(a.get("roleDefinitionId")) == rdef)
            or (name and str(((a.get("roleDefinition") or {}).get("displayName")) or "").lower() == name)]
    return _r(NOT_HELD, f"{len(left)} attribution(s) de ce rôle encore là") if left else \
        _r(HELD, "le membre ne tient plus ce rôle")


CHECKS = {"credential_gone": _credential_gone, "federated_gone": _federated_gone, "disabled": _disabled,
          "sessions_revoked": _sessions_revoked, "grant_gone": _grant_gone, "assignment_gone": _assignment_gone,
          "consent_gone": _consent_gone, "role_gone": _role_gone}


def check_item(check: dict | None, reader) -> dict:
    """One check: held, not held, or unreadable — never held on an error."""
    if not isinstance(check, dict):
        return _r(UNREADABLE, "rien à vérifier : un paramètre n'a pas été lu")
    fn = CHECKS.get(str(check.get("kind") or ""))
    if fn is None:
        return _r(UNREADABLE, "vérification inconnue")
    if reader is None:
        return _r(UNREADABLE, "Graph non lu (aucun lecteur)")
    try:
        return fn(check, reader)
    except Unreadable as exc:
        return _r(UNREADABLE, str(exc))
    except Exception as exc:          # a reader's bug, an answer of the wrong shape: never « held »
        return _r(UNREADABLE, f"Graph : {type(exc).__name__}")


def verify(plan: dict, reader, *, requested_at: str = "", now: datetime | None = None) -> dict:
    """The check of every item of the plan that has one, and the card's verdict."""
    now = now or datetime.now(timezone.utc)
    items, counted = [], []
    for i in (plan or {}).get("items") or []:
        if not isinstance(i, dict) or not i.get("verifiable"):
            continue                      # a step nothing can check (« review what the member did »)
        r = {"n": i.get("n"), "what": str(i.get("what") or "")[:300], **check_item(i.get("check"), reader),
             "optional": bool(i.get("optional"))}
        items.append(r)
        if not r["optional"]:
            counted.append(r["state"])
    if NOT_HELD in counted:
        verdict = NOT_HELD
    elif UNREADABLE in counted or not counted:
        verdict = UNREADABLE
    else:
        verdict = HELD
    why = "" if counted else "rien que Graph puisse vérifier dans ce plan"
    return {"at": now.isoformat(), "requested_at": requested_at, "verdict": verdict, "why": why,
            "items": items}
