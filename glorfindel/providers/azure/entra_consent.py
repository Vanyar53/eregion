"""A consent, as its row of AuditLogs says it (C2b, #607): which permission, for which
application, of which nature, for whom — one line on the card, never the raw diff.

The rule `entra-app-consent` projects `Permissions` from the first of three modified properties:
  - `ConsentAction.Permissions` (« Consent to application »): the delegated grants, old and new,
    as Entra writes them — ``[] => [[Id: <grant>, ClientId: <guid>, PrincipalId: <guid or empty>,
    ResourceId: <guid>, ConsentType: AllPrincipals|Principal, Scope: User.Read openid,
    CreatedDateTime: , LastModifiedDateTime ]]; `` (seen on the bench, 06/11: the card showed it
    raw). An existing grant widened is the same Id on both sides, its new scope larger;
  - `AppRole.Value` (« Add app role assignment to service principal »): an application
    permission's name, `Mail.Read`;
  - `DelegatedPermissionGrant.Scope` (« Add delegated permission grant »): a scope's words.
And `AppOnly` (`ConsentContext.IsAppOnly`), when the row has it.

Every value is from outside: an id is kept only if it is one (`guid`, `graph_id`), a scope only
if it is words (`words`) — the same rule as the plan's (entra_items.py). The line is text: the
bot and the console escape it, as every name of the card.
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.entra_items import graph_id, guid, words

DELEGATED, APPLICATION = "delegated", "application"
_ENTRY = re.compile(r"\[([^\[\]]*:[^\[\]]*)\]")
_FIELD = re.compile(r"([A-Za-z]+)\s*:\s*([^,]*)")
_CONSENT_TYPES = ("AllPrincipals", "Principal")


def _entries(side: str) -> list[dict]:
    return [{k: v.strip() for k, v in _FIELD.findall(m.group(1))} for m in _ENTRY.finditer(side)]


def parse(value) -> dict:
    """`Permissions` as the rule projects it. `grants`: the delegated grants the consent added or
    widened (old → new), each with its id, client, principal, resource, consent type, its whole
    scope and what it added; `words`: a permission's or a scope's words; `format`: `diff`, `words`,
    `none` (empty) or `unknown` (nothing of it is read: never shown raw)."""
    s = str(value or "").strip().strip(";").strip().strip('"').strip().rstrip(";").strip()
    if not s:
        return {"grants": [], "words": "", "format": "none"}
    if "=>" in s:
        old, new = s.split("=>", 1)
        before = {e.get("Id"): set(words(e.get("Scope")).split()) for e in _entries(old)}
        grants, unread = [], 0
        for e in _entries(new):
            scope = words(e.get("Scope"))
            added = [w for w in scope.split() if w not in before.get(e.get("Id"), set())]
            if e.get("Id") in before and not added:
                continue                                   # unchanged: not this consent's
            gid = graph_id(e.get("Id"))
            if not (gid or scope):
                unread += 1                                # neither an id nor a scope: nothing read
                continue
            ctype = e.get("ConsentType") if e.get("ConsentType") in _CONSENT_TYPES else ""
            grants.append({"id": gid, "client": guid(e.get("ClientId")),
                           "principal": guid(e.get("PrincipalId")), "resource": guid(e.get("ResourceId")),
                           "consent_type": ctype, "scope": scope, "added": " ".join(added)})
        empty = re.fullmatch(r"\[\s*\]", new.strip().rstrip(";").strip()) is not None
        if grants or empty or (_entries(new) and not unread):
            return {"grants": grants, "words": "", "format": "diff"}
        return {"grants": [], "words": "", "format": "unknown"}
    w = words(s)
    return {"grants": [], "words": w, "format": "words" if w else "unknown"}


def _flag(value) -> bool | None:
    v = str(value if value is not None else "").strip().strip('"').strip().lower()
    return True if v in ("true", "1") else False if v in ("false", "0") else None


def nature(row: dict, parsed: dict | None = None) -> str:
    """`delegated`, `application`, or "" when the row does not say."""
    parsed = parsed if parsed is not None else parse(row.get("Permissions"))
    op = str(row.get("EntraOperation") or "").strip().lower()
    if "app role assignment" in op:
        return APPLICATION
    if "delegated permission grant" in op:
        return DELEGATED
    app_only = _flag(row.get("AppOnly"))
    if app_only is True:
        return APPLICATION
    if parsed["grants"] or app_only is False:
        return DELEGATED
    return ""


def _name(name, oid: str) -> str:
    name = str(name or "").strip()
    if name and oid and name.lower() != oid:
        return f"{name} ({oid})"
    return name or oid


def line(row: dict) -> str:
    """The consent in one line: the permission (or the delegated scope), the application, its
    nature and for whom. Never the raw diff: what is not read is said so."""
    parsed = parse(row.get("Permissions"))
    kind = nature(row, parsed)
    op = str(row.get("EntraOperation") or "").strip().lower()
    consent_flow = op == "consent to application"
    grants = parsed["grants"]
    # The permission.
    if grants:
        scopes = " ".join(dict.fromkeys(w for g in grants for w in (g["added"] or g["scope"]).split()))
        perm = f"« {scopes} »" if scopes else "portée non reprise (des caractères inattendus)"
    elif parsed["words"]:
        perm = f"« {parsed['words']} »"
    elif parsed["format"] == "unknown":
        perm = "non lue (format du journal non reconnu, voir AuditLogs par son CorrelationId)"
    else:
        perm = "non nommée par le journal"
    label = {DELEGATED: "Permission déléguée", APPLICATION: "Permission d'application"}.get(
        kind, "Permission (déléguée ou d'application : non lu)")
    # The application (the client), and the resource it reaches.
    target = _name(row.get("TargetName"), guid(row.get("TargetId")))
    if consent_flow:
        app = target or "non nommée"
        resources = sorted({g["resource"] for g in grants if g["resource"]})
        on = f" sur la ressource {', '.join(resources)}" if resources else ""
    else:
        clients = {g["client"] for g in grants if g["client"]} | ({guid(row.get("ClientId"))} - {""})
        app = ", ".join(sorted(clients)) or "non nommée par le journal"
        on = f" sur {target}" if target else ""
    # For whom.
    admin = _flag(row.get("AdminConsent")) is True
    types = {g["consent_type"] for g in grants}
    principals = sorted({g["principal"] for g in grants if g["principal"]})
    if kind == APPLICATION:
        who = "sans utilisateur : l'application agit en son propre nom, sur tout le tenant"
    elif "AllPrincipals" in types or (admin and not principals):
        who = "pour tous les utilisateurs du tenant"
    elif principals:
        who = f"pour l'utilisateur {', '.join(principals)} seulement"
    elif consent_flow and not admin and kind == DELEGATED:
        who = "pour l'utilisateur qui consent seulement"
    else:
        who = "pour qui : non lu"
    return f"{label} {perm} accordée à l'application {app}{on}, {who}."
