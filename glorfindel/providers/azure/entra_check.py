"""The check of an identity card's plan (IR1a, the « Verify » button): Graph read again, read only,
and for each item of the plan with a check, « held », « not held » or « unreadable ».

Never « held » without Graph's answer: a right missing, an error, a delay — every `Unreadable` —
is « unreadable », and so is a check the plan could not write (a parameter not read). The verdict
of the card:
  - `not_held` if one item (not optional) is not held: a fact, whatever the others;
  - else `unreadable` if one is unreadable, or if nothing could be checked;
  - else `held`.
An optional item (the author's sessions, « if the author is not expected ») is checked and said,
never counted in the verdict; a review (« review what the member did ») is neither. A step of the
remediation Graph cannot check (identify a consent's client, renew Glorfindel's credentials) is
counted, `unreadable` with its own reason: the card is never held while it waits.

Each path is built again from ids checked again here (`entra_plan.guid`, `graph_id`): a plan is
read from the card's store, never trusted to name a path.
"""
from __future__ import annotations

from datetime import datetime, timezone

from glorfindel.providers.azure.entra_items import graph_id, guid, role_key, when
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
    if not isinstance(obj, dict):
        return _r(UNREADABLE, "l'objet n'est pas rendu par Graph (supprimé ?) : rien ne dit que l'identifiant "
                              "est retiré")
    fields = [obj.get(f) for f in ("passwordCredentials", "keyCredentials")]
    if not all(isinstance(f, list) for f in fields):
        return _r(UNREADABLE, "passwordCredentials ou keyCredentials non rendus par Graph")
    keys = {guid(k.get("keyId")) for f in fields for k in f if isinstance(k, dict)}
    return _r(NOT_HELD, f"le keyId {key} est encore sur l'objet") if key in keys else \
        _r(HELD, f"le keyId {key} n'est plus sur l'objet")


def _federated_gone(c: dict, reader) -> dict:
    oid, fic = guid(c.get("id")), guid(c.get("fic_id"))
    if not (oid and fic):
        return _r(UNREADABLE, "vérification mal formée")
    fics = reader.list(f"/applications/{oid}/federatedIdentityCredentials")
    if not isinstance(fics, list):      # deleted, an application is restored for 30 days, credentials too
        return _r(UNREADABLE, "l'application n'est pas rendue par Graph (supprimée ? elle se restaure 30 jours, "
                              "avec ses identifiants)")
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


class _NotAList(Exception):
    """A collection Graph did not give as a list (or a 404): never read as « empty »."""


def _grants(client: str, reader) -> list:
    grants = reader.list("/oauth2PermissionGrants", {"$filter": f"clientId eq '{client}'"})
    if not isinstance(grants, list):
        raise _NotAList("les octrois de l'application cliente ne sont pas rendus par Graph")
    return grants


def _grant_gone(c: dict, reader) -> dict:
    client, gid = guid(c.get("client")), graph_id(c.get("grant_id"))
    if not (client and gid):
        return _r(UNREADABLE, "vérification mal formée")
    try:
        grants = _grants(client, reader)
    except _NotAList as exc:
        return _r(UNREADABLE, str(exc))
    return _r(NOT_HELD, "l'octroi est encore là") if gid in {str(g.get("id") or "") for g in grants} \
        else _r(HELD, "l'octroi n'y est plus")


def _assignment_gone(c: dict, reader) -> dict:
    client, aid = guid(c.get("client")), graph_id(c.get("assignment_id"))
    if not (client and aid):
        return _r(UNREADABLE, "vérification mal formée")
    roles = reader.list(f"/servicePrincipals/{client}/appRoleAssignments")
    if not isinstance(roles, list):     # deleted, a principal is restored for 30 days, assignments too
        return _r(UNREADABLE, "l'application cliente n'est pas rendue par Graph (supprimée ? elle se restaure "
                              "30 jours)")
    return _r(NOT_HELD, "l'attribution est encore là") if aid in {str(a.get("id") or "") for a in roles} \
        else _r(HELD, "l'attribution n'y est plus")


def _consent_gone(c: dict, reader) -> dict:
    client = guid(c.get("client"))
    if not client:
        return _r(UNREADABLE, "vérification mal formée")
    try:
        grants = _grants(client, reader)
    except _NotAList as exc:
        return _r(UNREADABLE, str(exc))
    roles = reader.list(f"/servicePrincipals/{client}/appRoleAssignments")
    if not isinstance(roles, list):
        return _r(UNREADABLE, "les attributions de l'application cliente ne sont pas rendues par Graph")
    if grants or roles:
        return _r(NOT_HELD, f"{len(grants)} octroi(s) et {len(roles)} attribution(s) encore là")
    return _r(HELD, "aucun octroi ni attribution pour l'application cliente")


def _role_gone(c: dict, reader) -> dict:
    """The member holds no assignment of this role: by the role definition's ids (its id, its
    template's), or by its name, its alias folded (« Company Administrator » is Global
    Administrator). An assignment whose role is not read — its definition not expanded, no name —
    while only the name can tell: unreadable, never held."""
    member = guid(c.get("member"))
    ids = {guid(c.get("role_definition_id")), guid(c.get("template_id"))} - {""}
    name = role_key(c.get("role_name"))
    if not member or not (ids or name):
        return _r(UNREADABLE, "vérification mal formée")
    coll = "roleEligibilitySchedules" if c.get("eligible") else "roleAssignments"
    found = reader.list(f"/roleManagement/directory/{coll}",
                        {"$filter": f"principalId eq '{member}'", "$expand": "roleDefinition"})
    # A filtered collection: an unknown member is a 200 and an empty list, never a 404 — a 404 says
    # nothing of the member.
    if not isinstance(found, list):
        return _r(UNREADABLE, "les attributions du membre ne sont pas rendues par Graph")
    left, unsure = 0, 0
    for a in found:
        if not isinstance(a, dict):
            unsure += 1
            continue
        rd = a.get("roleDefinition") if isinstance(a.get("roleDefinition"), dict) else {}
        theirs = {guid(a.get("roleDefinitionId")), guid(rd.get("id")), guid(rd.get("templateId"))} - {""}
        if ids & theirs or (name and rd.get("displayName") and role_key(rd.get("displayName")) == name):
            left += 1
        elif not ids and not rd.get("displayName"):
            unsure += 1                  # only the name could tell, and it is not read
    if left:
        return _r(NOT_HELD, f"{left} attribution(s) de ce rôle encore là")
    if unsure:
        return _r(UNREADABLE, f"{unsure} attribution(s) du membre sans nom de rôle lisible : rien ne dit "
                              "qu'elles ne sont pas ce rôle")
    return _r(HELD, "le membre ne tient plus ce rôle")


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
        state = (check_item(i.get("check"), reader) if i.get("check") or not i.get("unchecked")
                 else _r(UNREADABLE, str(i["unchecked"])))
        r = {"n": i.get("n"), "what": str(i.get("what") or "")[:300], **state,
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
