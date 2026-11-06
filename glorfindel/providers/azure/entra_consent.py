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
_CONSENT_TYPES = ("AllPrincipals", "Principal")
_G = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_FREE = r"[^\[\],=]*"          # a value of the diff: never a bracket, a comma nor an arrow


def _entry(named: bool) -> str:
    """One grant, in the canonical form Entra writes, every field in its place: an entry that
    strays from it — a `]` in a scope that would close it and open a forged `[Id: …]` — is never
    read. `named`: its fields as groups (to read one entry), else plain (to match a whole side)."""
    def g(name: str, body: str) -> str:
        return f"(?P<{name}>{body})" if named else f"(?:{body})"
    return (rf"\[\s*Id:\s*{g('id', '[A-Za-z0-9_-]+')}\s*,\s*ClientId:\s*{g('client', _G)}\s*,\s*"
            rf"PrincipalId:\s*{g('principal', _G + '|')}\s*,\s*ResourceId:\s*{g('resource', _G)}\s*,\s*"
            rf"ConsentType:\s*{g('ctype', 'AllPrincipals|Principal')}\s*,\s*Scope:{g('scope', _FREE)},\s*"
            rf"CreatedDateTime:{_FREE},\s*LastModifiedDateTime(?::{_FREE})?\s*\]")


_SIDE_RE = re.compile(rf"\[\s*(?:{_entry(False)}(?:\s*,\s*{_entry(False)})*)?\s*\]")
_ENTRY_RE = re.compile(_entry(True))
_DIFF_RE = re.compile(r"\s*(?P<old>\[.*\])\s*=>\s*(?P<new>\[.*\])\s*;?\s*", re.DOTALL)


def _side(text: str) -> list[dict] | None:
    """The grants of one side of the diff, or None when the side is not in the canonical form."""
    if not _SIDE_RE.fullmatch(text):
        return None
    return [m.groupdict() for m in _ENTRY_RE.finditer(text)]


def parse(value) -> dict:
    """`Permissions` as the rule projects it. `grants`: the delegated grants the consent added or
    widened (old → new), each with its id, client, principal, resource, consent type, its whole
    scope and what it added; `words`: a permission's or a scope's words; `format`: `diff`, `words`,
    `none` (empty) or `unknown` (nothing of it is read: never shown raw, no id taken from it).
    A diff is read only whole, each side in the canonical form (`_ENTRY`), each scope words."""
    s = str(value or "").strip().strip('"').strip()
    if not s:
        return {"grants": [], "words": "", "format": "none"}
    unknown = {"grants": [], "words": "", "format": "unknown"}
    if "=>" in s:
        m = _DIFF_RE.fullmatch(s)
        old, new = (_side(m.group("old")), _side(m.group("new"))) if m else (None, None)
        if old is None or new is None:
            return unknown
        if any(e["scope"].strip() and not words(e["scope"]) for e in old + new):
            return unknown                                 # a scope that is no words: not read
        before = {e["id"]: set(words(e["scope"]).split()) for e in old}
        grants = []
        for e in new:
            scope = words(e["scope"])
            added = [w for w in scope.split() if w not in before.get(e["id"], set())]
            if e["id"] in before and not added:
                continue                                   # unchanged: not this consent's
            grants.append({"id": graph_id(e["id"]), "client": guid(e["client"]),
                           "principal": guid(e["principal"]), "resource": guid(e["resource"]),
                           "consent_type": e["ctype"], "scope": scope, "added": " ".join(added)})
        return {"grants": grants, "words": "", "format": "diff"}
    w = words(s.rstrip(";").strip())
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
