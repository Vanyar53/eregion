"""The identities of Entra ID that are never a target (IDI1, #546) — of a technique (Annatar, R2)
or, later, of the identity executor of IR1, which will own what is enrolled: owning an application
is being able to act as it. Here, in the shared core, so that both read the same list (D1).

        never a target                         how it is known
        Glorfindel                             GLORFINDEL_OWN_CALLERS, GLORFINDEL_AZURE_CLIENT_ID,
                                               AZURE_CLIENT_ID; the watches' identities, listed
        Orodruin                               the reader's own token (oid, appid); listed
        Annatar                                ANNATAR_AZURE_CLIENT_ID; on Orodruin, Orodruin's own
        the operators                          EREGION_OPERATOR_OBJECT_ID (one at least, required)
        the listed ones                        EREGION_PROTECTED_IDENTITIES (infra/orodruin output)
        Microsoft's applications, and any      registered in another tenant than the bench's
        other tenant's                         (appOwnerOrganizationId)
        the principal of a resource            a managed identity (servicePrincipalType); a principal
                                               that exposes app roles or scopes, or that others hold
                                               app roles on (an API others call)
        whoever owns one of them               the principal's owned objects

Unreadable — no operator named, an id in a list that is no object id — the list refuses every
identity: a typo would leave one unprotected, unsaid. Every id is compared in lower case, as an
object id or an application (client) id, whichever the variable holds.

The interface (IDI1 uses it; IR1a reads it, never rebuilds it):

    never = NeverTarget.from_env()      # the list, from the process's environment (above)
    never.refusal()                     # "" if the list is readable, else why nothing is accepted
    never.covers(object_id)             # True: this id is never a target — and every id is, when
                                        # the list is unreadable (fail closed)
    never.why(identity, tenant=…, token=…)
                                        # the whole rule on an identity read from Graph (its ids,
                                        # type, home tenant, resource, owned objects): "" or why
                                        # it is never a target

Where the ids come from on Orodruin: ``terraform -chdir=infra/orodruin output`` —
``operator_object_id`` → EREGION_OPERATOR_OBJECT_ID, ``protected_identities`` (Orodruin, the
watches) → EREGION_PROTECTED_IDENTITIES — in orodruin.env, never in the repository.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

OPERATOR_ENV = "EREGION_OPERATOR_OBJECT_ID"
PROTECTED_ENV = "EREGION_PROTECTED_IDENTITIES"
# Each a list of object ids or client ids, read strictly: an entry that is no id refuses all.
STRICT_ENVS = (OPERATOR_ENV, PROTECTED_ENV, "ANNATAR_AZURE_CLIENT_ID", "GLORFINDEL_AZURE_CLIENT_ID")
# Glorfindel's own callers (glorfindel/providers/azure/activity.py): a name may sit among the ids
# there, read loosely — only its ids count.
LOOSE_ENVS = ("GLORFINDEL_OWN_CALLERS", "AZURE_CLIENT_ID")
APPLICATION_PRINCIPAL = "Application"
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def guid(value) -> str:
    """``value`` in lower case if it is an object id (a GUID), else ""."""
    v = str(value or "").strip().lower()
    return v if _GUID.fullmatch(v) else ""


def ids(raw: str) -> tuple[set[str], list[str]]:
    """The object ids of a list (commas or spaces), and what in it is no object id."""
    items = [x for x in re.split(r"[,\s]+", raw or "") if x]
    return {guid(x) for x in items if guid(x)}, [x for x in items if not guid(x)]


@dataclass(frozen=True)
class NeverTarget:
    ids: frozenset[str] = frozenset()
    operators: frozenset[str] = frozenset()
    errors: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env=None) -> "NeverTarget":
        env = os.environ if env is None else env
        found: set[str] = set()
        errors = []
        for name in STRICT_ENVS:
            got, bad = ids(env.get(name) or "")
            found |= got
            errors += [f"{name} holds what is no object id: {x[:40]!r}" for x in bad]
        for name in LOOSE_ENVS:
            found |= ids(env.get(name) or "")[0]
        return cls(ids=frozenset(found), operators=frozenset(ids(env.get(OPERATOR_ENV) or "")[0]),
                   errors=tuple(errors))

    def refusal(self) -> str:
        """Why the list cannot be read — every identity then refused — or ""."""
        if not self.operators:
            return (f"no operator named ({OPERATOR_ENV}): the operator's own identity could not be "
                    "told apart — no identity is accepted")
        if self.errors:
            return "; ".join(self.errors)
        return ""

    def covers(self, object_id: str) -> bool:
        """Is this object id (or client id) never a target? Every id is, when the list cannot be
        read (``refusal``); what is no object id is too — it names nothing that can be judged."""
        oid = guid(object_id)
        return bool(self.refusal()) or not oid or oid in self.ids

    def why(self, identity: dict, *, tenant: str, token: dict | None = None) -> str:
        """Why this identity is never a target, or "". ``identity`` as Graph returned it:
        ``application``, ``service_principal`` (with its appRoles and oauth2PermissionScopes),
        ``owned`` and ``assigned_to`` (the object ids it owns, and those that hold an app role on
        it); ``token``, the claims of the reader's own token."""
        why = self.refusal()
        if why:
            return why
        app = identity.get("application") or {}
        sp = identity.get("service_principal") or {}
        never = set(self.ids)
        never |= {x for x in (guid((token or {}).get("oid")), guid((token or {}).get("appid"))) if x}
        if never & {guid(app.get("id")), guid(app.get("appId")), guid(sp.get("id")), guid(sp.get("appId"))} - {""}:
            return "a protected identity (Glorfindel, Orodruin, Annatar, an operator, the reader) is never a target"
        if str(sp.get("servicePrincipalType") or "") != APPLICATION_PRINCIPAL:
            return (f"a principal of type '{sp.get('servicePrincipalType')}', not an application's: the "
                    "principal of a resource (a managed identity) is never a target")
        if not tenant or guid(sp.get("appOwnerOrganizationId")) != tenant:
            return "an application registered in another tenant (Microsoft's, or any other) is never a target"
        if sp.get("appRoles") or sp.get("oauth2PermissionScopes") or identity.get("assigned_to"):
            return "the principal of a resource (an API that exposes roles or scopes, or that others hold roles on) is never a target"
        if never & {guid(o) for o in identity.get("owned") or []}:
            return "the application's principal owns a protected identity"
        return ""
