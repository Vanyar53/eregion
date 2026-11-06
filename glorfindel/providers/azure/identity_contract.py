"""The identity executor's contract (IR1b, #572; docs/design/reponse-identite.md §3.4), read at its
start like Orodruin's (eregion_core/orodruin.py): ``armed`` only if what it holds in Entra ID is
within a closed list, else ``passive`` — and a passive executor refuses to start (``start``).

        what is read (nothing is written)        from
        who it is                                its own Graph token: an application's (no ``scp``),
                                                 of the pinned tenant (``tid``) and client (``appid``)
        its application permissions              the token's ``roles``, and its app role assignments,
                                                 each named by its resource's own list of roles
        its directory roles                      the token's ``wids`` (the tenant-wide ones), and its
                                                 role assignments with their scope, active and eligible
        its memberships                          its groups, transitively: none (a group can carry
                                                 a role)
        what it owns                             its owned objects: never one of Eregion's identities,
                                                 never itself, never anything but an application or
                                                 its principal — and none of them privileged (Q6),
                                                 judged by IDI1's own ``privilege_refusal``: the
                                                 principal of each holds no directory role, active or
                                                 eligible, no group, no application permission (none,
                                                 not even a read), and owns nothing in turn

What it may hold — the closed list (§3.4, decisions of 05/11, Q2 and Q3):
  - in Microsoft Graph, ``Application.ReadWrite.OwnedBy`` (the credentials and the state of the
    applications it owns, those IDI1 enrolls) and ``User.RevokeSessions.All`` (bounded by the code
    to enrolled users, IR1c);
  - Directory Readers at the tenant (a principal uses a scoped role only with it), User
    Administrator at the scope of the bench's administrative unit (its id pinned, never looked up by
    its name), Attribute Assignment Reader at the scope of Eregion's attribute set (pinned) — the
    three given by IDI1b, never here.
Anything else is ``beyond_contract``: a refused right (one that lets it grant itself privileges,
``REFUSED_PERMISSIONS``, ``REFUSED_ROLES``), a right it does not know, an admitted role at another
scope, an eligible role, a permission on another API, an identity of Eregion it owns. A contract it
cannot read — a variable missing, a token not had, a read that fails — is ``contract_unreadable``:
passive too, never armed by default (A0).

A role is known by its definition's id, which for a built-in role is its template's — never by its
name, nor by ``templateId``, which a custom role may set to anything.

Read only by construction: Graph through ``graph.GraphReader`` (a GET and nothing else), the token
from the executor's own credential, its certificate (``executor_credential``; never
``DefaultAzureCredential``: on H0 the VM's token endpoint answers any container, and its identity
is the watch's). No verb is run here: that is IR1c's executor, which calls ``start`` first and
asks ``Verdict.allows`` before each verb.

Hypotheses (§5 of the design, to measure on the bench's tenant): the rights its reads need
(hypothesis 10 — Directory Readers, given by IDI1b, is the one this contract expects, for its own
rights and for those of what it owns: role assignments, eligible role instances (PIM),
memberships, app role assignments; any read it does not allow fails, and the executor stays
passive — if Directory Readers does not read PIM's instances, the contract never arms, and a read
right is to be added after the measure; a tenant without PIM's license answers that read 400
``AadPremiumLicenseRequired``, measured 06/11 by IDI1's guard: no eligible role can exist there, the
read gives none, and the verdict says so, ``Verdict.notes`` — IDI1p, that one answer only); ``wids`` carries the tenant-wide roles only — so User
Administrator or Attribute Assignment Reader seen there is held at the tenant, beyond. The template
ids of the built-in roles below are those of Microsoft's « Microsoft Entra built-in roles ».

What the owned rule does not see: a principal's Azure roles (RBAC) and its delegated grants
(``oauth2PermissionGrants``) — as IDI1's enrollment guard, the same limit accepted on the bench.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field

from eregion_core.inscription import (
    ELIGIBLE_ROLES_PATH,
    NO_PIM_LICENSE_NOTE,
    no_pim_license,
    privilege_refusal,
    token_claims,
)
from eregion_core.never_target import NeverTarget, guid
from eregion_core.orodruin import APP_DEFAULT_WIDS

from glorfindel.providers.azure.graph import SCOPE, GraphReader, Unreadable

ARMED, PASSIVE = "armed", "passive"
BEYOND = "beyond_contract"
UNREADABLE = "contract_unreadable"

# The contract's declaration, in the executor's environment (never in the repository).
TENANT_ENV = "EREGION_TENANT_ID"                         # the bench's tenant (IDI1's name)
CLIENT_ENV = "EREGION_IDENTITY_EXECUTOR_CLIENT_ID"       # its application (client) id
CERTIFICATE_ENV = "EREGION_IDENTITY_EXECUTOR_CERTIFICATE"  # the path of its certificate and key
UNIT_ENV = "EREGION_BENCH_ADMIN_UNIT_ID"                 # the bench's administrative unit (IDI1b)
ATTRIBUTE_SET_ENV = "EREGION_IDENTITY_ATTRIBUTE_SET"     # Eregion's attribute set (IDI1b)

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"     # Microsoft Graph, the same in every tenant

# Microsoft Graph's application permissions it may hold — and none other.
OWNED_BY = "Application.ReadWrite.OwnedBy"
REVOKE_SESSIONS = "User.RevokeSessions.All"
ADMITTED_PERMISSIONS = frozenset({OWNED_BY, REVOKE_SESSIONS})
# Refused to every identity of Eregion (§3.4): each lets it act as another entity or grant itself
# privileges. Unknown rights are refused too; these are named so the reason says why.
REFUSED_PERMISSIONS = frozenset({
    "RoleManagement.ReadWrite.Directory", "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleAssignmentSchedule.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All", "Application.ReadWrite.All", "Directory.ReadWrite.All",
})

# Directory roles, by the template id of the built-in role (Microsoft's « Microsoft Entra built-in
# roles »; to read on the tenant, hypothesis).
DIRECTORY_READERS = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
USER_ADMINISTRATOR = "fe930be7-5e62-47db-91af-98c3a49a38b1"
ATTRIBUTE_ASSIGNMENT_READER = "ffd52fa5-98dc-465c-991d-fc073eb59f8f"
ADMITTED_ROLES = {DIRECTORY_READERS: "Directory Readers", USER_ADMINISTRATOR: "User Administrator",
                  ATTRIBUTE_ASSIGNMENT_READER: "Attribute Assignment Reader"}
REFUSED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}

# What each verb of the executor needs (IDENTITY_ACTIONS, glorfindel/response/policy.py): a verb
# whose right it does not hold is not allowed, even armed. A user's verb needs User Administrator at
# the unit and Directory Readers (a principal uses a scoped role only with it, doc).
_APPS = frozenset({OWNED_BY})
VERB_RIGHTS = {
    "entra_remove_credential": _APPS, "entra_restore_credential": _APPS,
    "entra_disable_principal": _APPS, "entra_enable_principal": _APPS,
    "entra_revoke_sessions": frozenset({REVOKE_SESSIONS}),
    "entra_disable_user": frozenset({"User Administrator", "Directory Readers"}),
    "entra_enable_user": frozenset({"User Administrator", "Directory Readers"}),
}

# What it may own: the applications IDI1 enrolls and their principals, nothing else.
_OWNABLE = frozenset({"#microsoft.graph.application", "#microsoft.graph.serviceprincipal"})
_ATTRIBUTE_SET = re.compile(r"[A-Za-z0-9]{1,32}")
# What it owns is read object by object, about seven reads each, within READ_BUDGET_S: beyond this
# many, it is not read whole — the contract stays passive at its start (to measure at IR1e).
MAX_OWNED = 20
# Its reads have this long in all: a start, not a card being written.
READ_BUDGET_S = 60.0


class Passive(RuntimeError):
    """The executor's contract does not hold: it does not start, nothing is touched."""


@dataclass(frozen=True)
class Declared:
    """What the executor's environment declares: its tenant, its client, the unit and the
    attribute set its scoped roles may name ("" when not declared: that role is then beyond)."""
    tenant: str
    client: str
    unit: str = ""
    attribute_set: str = ""


@dataclass(frozen=True)
class Verdict:
    verdict: str
    missing: tuple[dict, ...] = ()
    # The admitted rights it holds, by name: what its verbs may use.
    held: frozenset[str] = field(default_factory=frozenset)
    # What its reads said that the verdict says too (IDI1p: no PIM license) — never weighed.
    notes: tuple[str, ...] = ()

    @property
    def armed(self) -> bool:
        return self.verdict == ARMED

    def reasons(self) -> str:
        return "; ".join(f"{m['code']}: {m['detail']}" for m in self.missing)

    def allows(self, verb: str) -> bool:
        """May the executor run this verb? Armed, a verb it knows, and every right it needs held."""
        need = VERB_RIGHTS.get(verb)
        return self.armed and bool(need) and need <= self.held


def _miss(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail[:300]}


def declared(env=None) -> tuple[Declared | None, list[dict]]:
    """The contract's declaration from the environment, or why it cannot be read."""
    env = os.environ if env is None else env
    tenant, client = guid(env.get(TENANT_ENV)), guid(env.get(CLIENT_ENV))
    raw_unit = (env.get(UNIT_ENV) or "").strip()
    raw_set = (env.get(ATTRIBUTE_SET_ENV) or "").strip()
    missing = [_miss(UNREADABLE, f"{name} is not an object id")
               for name, value in ((TENANT_ENV, tenant), (CLIENT_ENV, client)) if not value]
    if raw_unit and not guid(raw_unit):
        missing.append(_miss(UNREADABLE, f"{UNIT_ENV} is not an object id"))
    if raw_set and not _ATTRIBUTE_SET.fullmatch(raw_set):
        missing.append(_miss(UNREADABLE, f"{ATTRIBUTE_SET_ENV} is not an attribute set's name"))
    if missing:
        return None, missing
    return Declared(tenant, client, guid(raw_unit), raw_set), []


# ── What it holds, judged — each returns (what is beyond, what is held) ─────────────────────────

def _permission(name: str, where: str) -> tuple[list[dict], set[str]]:
    if name in ADMITTED_PERMISSIONS:
        return [], {name}
    if name in REFUSED_PERMISSIONS:
        return [_miss(BEYOND, f"{name} ({where}): a refused right — it lets an identity grant itself "
                              "privileges or act as another")], set()
    return [_miss(BEYOND, f"{name or 'an unnamed permission'} ({where}): a right outside the contract")], set()


def assess_token(claims: dict, decl: Declared) -> tuple[list[dict], set[str], str]:
    """Who the token says it is, and what it carries: (missing, held, its principal's object id).
    Read from the claims, no call."""
    if not isinstance(claims, dict) or claims.get("scp"):
        return [_miss(UNREADABLE, "not an application's token (a user's scopes): not the executor")], set(), ""
    oid = guid(claims.get("oid"))
    if guid(claims.get("tid")) != decl.tenant:
        return [_miss(UNREADABLE, "a token of another tenant than the declared one")], set(), ""
    if guid(claims.get("appid") or claims.get("azp")) != decl.client or not oid:
        return [_miss(UNREADABLE, "a token of another application than the executor's")], set(), ""
    roles, wids = claims.get("roles", []), claims.get("wids", [])
    if not isinstance(roles, list) or not isinstance(wids, list):
        return [_miss(UNREADABLE, "its token's roles are not lists")], set(), oid
    missing, held = [], set()
    for r in roles:
        m, h = _permission(str(r), "in its token")
        missing += m
        held |= h
    for w in {str(w).lower() for w in wids} - APP_DEFAULT_WIDS:
        if w in REFUSED_ROLES:
            missing.append(_miss(BEYOND, f"{REFUSED_ROLES[w]} in its token: a refused directory role"))
        elif w in ADMITTED_ROLES and w != DIRECTORY_READERS:
            # wids carries the tenant-wide roles only: a scoped role there is held at the tenant.
            missing.append(_miss(BEYOND, f"{ADMITTED_ROLES[w]} in its token: a scoped role held at the tenant"))
        elif w not in ADMITTED_ROLES:
            missing.append(_miss(BEYOND, f"directory role {w} in its token: a role outside the contract"))
    return missing, held, oid


def _admitted_scope(template: str, decl: Declared) -> str:
    """The one scope an admitted role may be held at, or "" (nowhere: not declared)."""
    if template == DIRECTORY_READERS:
        return "/"
    if template == USER_ADMINISTRATOR:
        return f"/administrativeunits/{decl.unit}" if decl.unit else ""
    if template == ATTRIBUTE_ASSIGNMENT_READER:
        return f"/attributesets/{decl.attribute_set.lower()}" if decl.attribute_set else ""
    return ""


def assess_roles(active: list, eligible: list, decl: Declared) -> tuple[list[dict], set[str]]:
    """Its directory role assignments: each an admitted role, by its definition's id, at its one
    scope, a built-in role; none eligible."""
    missing, held = [], set()
    for a in active:
        if not isinstance(a, dict):
            missing.append(_miss(UNREADABLE, "a role assignment that is not an object"))
            continue
        rid = guid(a.get("roleDefinitionId"))
        rd = a.get("roleDefinition") if isinstance(a.get("roleDefinition"), dict) else {}
        scope = str(a.get("directoryScopeId") or "").strip().lower()
        name = REFUSED_ROLES.get(rid) or ADMITTED_ROLES.get(rid) or str(rd.get("displayName") or rid or "?")[:80]
        if rid in REFUSED_ROLES:
            missing.append(_miss(BEYOND, f"{name} at {scope or '?'}: a refused directory role"))
        elif rid not in ADMITTED_ROLES or rd.get("isBuiltIn") is False:
            missing.append(_miss(BEYOND, f"directory role {name} at {scope or '?'}: a role outside the contract"))
        elif a.get("appScopeId") or not scope or scope != _admitted_scope(rid, decl):
            missing.append(_miss(BEYOND, f"{name} at {scope or '?'}: outside the one scope it is admitted at "
                                         f"({_admitted_scope(rid, decl) or 'none declared'})"))
        else:
            held.add(name)
    for a in eligible:
        rid = guid(a.get("roleDefinitionId")) if isinstance(a, dict) else ""
        missing.append(_miss(BEYOND, f"an eligible directory role ({ADMITTED_ROLES.get(rid) or REFUSED_ROLES.get(rid) or rid or '?'}): "
                                     "it could activate it — the executor holds none"))
    return missing, held


def assess_permissions(assignments: list, resources: dict[str, dict]) -> tuple[list[dict], set[str]]:
    """Its app role assignments, each named by its resource's list of roles: Microsoft Graph's,
    admitted. ``resources``: each resource principal read, by its id."""
    missing, held = [], set()
    for a in assignments:
        a = a if isinstance(a, dict) else {}
        rid, role = guid(a.get("resourceId")), guid(a.get("appRoleId"))
        res = resources.get(rid)
        if not rid or not role or not isinstance(res, dict):
            missing.append(_miss(UNREADABLE, "an application permission whose resource or role is not read"))
            continue
        if guid(res.get("appId")) != GRAPH_APP_ID:
            missing.append(_miss(BEYOND, f"a permission on another API than Microsoft Graph "
                                         f"({str(res.get('displayName') or rid)[:60]}): outside the contract"))
            continue
        names = {guid(r.get("id")): str(r.get("value") or "") for r in res.get("appRoles") or [] if isinstance(r, dict)}
        m, h = _permission(names.get(role, ""), "assigned")
        missing += m
        held |= h
    return missing, held


def assess_member_of(member_of: list) -> list[dict]:
    """Its groups, transitively: none — a group can carry a role, and adding a member to one is a
    right of whoever owns it."""
    return [_miss(BEYOND, f"it is a member of {len(member_of)} group(s) or role(s): the executor is "
                          "a member of none (a group can carry a role)")] if member_of else []


def assess_owned(owned: list, decl: Declared, oid: str, never: NeverTarget,
                 privileges: dict[str, dict] | None = None) -> list[dict]:
    """What it owns: applications and their principals only, never itself, never an identity that is
    never a target (Glorfindel's, Orodruin's, an operator's — owning one is acting as it), and none
    privileged: ``privileges``, what the principal of each owned object holds, read (``read``) —
    one not read leaves the contract unreadable."""
    missing = []
    unreadable = never.refusal()
    privileges = privileges or {}
    for o in owned:
        o = o if isinstance(o, dict) else {}
        kind = str(o.get("@odata.type") or "").lower()
        ids = {guid(o.get("id")), guid(o.get("appId"))} - {""}
        if kind not in _OWNABLE or not ids:
            missing.append(_miss(BEYOND, f"it owns {kind or 'an object'} that is no application nor its principal"))
        elif ids & {oid, decl.client}:
            missing.append(_miss(BEYOND, "it owns itself: it could add itself a credential"))
        elif unreadable:
            missing.append(_miss(UNREADABLE, f"never_target unreadable ({unreadable[:120]}): what it owns "
                                             "cannot be told apart from a protected identity"))
        elif ids & never.ids:
            missing.append(_miss(BEYOND, "it owns an identity that is never a target (Glorfindel, Orodruin, "
                                         "Annatar, an operator)"))
        elif not isinstance(privileges.get(guid(o.get("id"))), dict):
            missing.append(_miss(UNREADABLE, "what an object it owns holds is not read"))
        elif why := privilege_refusal(privileges[guid(o.get("id"))]):
            missing.append(_miss(BEYOND, f"it owns a privileged identity ({why}): owning it is acting as it (Q6)"))
    return missing


# ── Reading — through Graph, read only ─────────────────────────────────────────────────────────

def read(reader, oid: str, deadline: float | None = None) -> dict:
    """Its permissions, its roles active and eligible, what it owns — read, never written. Raises
    ``Unreadable`` (a right missing, an error, a delay) or ValueError (an answer not a list); the
    caller takes any failure for passive — but a tenant without PIM's one answer to the read of
    eligible roles (``no_pim_license``, IDI1p): none can exist there, none is read, it is noted."""
    notes: set[str] = set()

    def listed(path, params=None):
        try:
            got = reader.list(path, params, deadline)
        except Unreadable as e:
            if not no_pim_license(path, e.status, e.code, page=e.page):
                raise
            notes.add(NO_PIM_LICENSE_NOTE)
            return []
        if not isinstance(got, list):
            raise ValueError(f"{path.split('?')[0].rsplit('/', 1)[-1]} not given by Graph")
        return got

    resources: dict[str, dict | None] = {}

    def named(assignments):
        """Each application permission's value, read in its resource's list of roles ("": not named)."""
        for rid in {guid(a.get("resourceId")) for a in assignments if isinstance(a, dict)} - {""} - set(resources):
            resources[rid] = reader.get(f"/servicePrincipals/{rid}", {"$select": "id,appId,displayName,appRoles"},
                                        deadline)
        out = []
        for a in assignments:
            res = resources.get(guid((a if isinstance(a, dict) else {}).get("resourceId")))
            names = {guid(r.get("id")): str(r.get("value") or "") for r in (res or {}).get("appRoles") or []
                     if isinstance(r, dict)}
            out.append(names.get(guid(a.get("appRoleId")), "") if isinstance(a, dict) else "")
        return out

    def held_by(principal):
        """What a principal holds: its directory roles active and eligible (every eligible role is
        refused: read without $expand, as IDI1), its memberships, its application permissions."""
        flt = {"$filter": f"principalId eq '{principal}'"}
        return {"roles": listed("/roleManagement/directory/roleAssignments", {**flt, "$expand": "roleDefinition"}),
                "eligible": listed(ELIGIBLE_ROLES_PATH, flt),
                "member_of": listed(f"/servicePrincipals/{principal}/transitiveMemberOf", {"$select": "id"}),
                "assignments": listed(f"/servicePrincipals/{principal}/appRoleAssignments")}

    own = held_by(oid)
    named(own["assignments"])
    owned = listed(f"/servicePrincipals/{oid}/ownedObjects", {"$select": "id,appId"})
    if len(owned) > MAX_OWNED:
        raise ValueError(f"it owns {len(owned)} objects, more than the {MAX_OWNED} its start reads within "
                         f"{READ_BUDGET_S:.0f} s")
    # The principal of each application or principal it owns, and what that principal holds.
    privileges: dict[str, dict] = {}
    for o in owned:
        o = o if isinstance(o, dict) else {}
        kind, obj = str(o.get("@odata.type") or "").lower(), guid(o.get("id"))
        if kind not in _OWNABLE or not obj or obj == oid:
            continue
        principal = obj
        if kind == "#microsoft.graph.application":
            sp = reader.get(f"/servicePrincipals(appId='{guid(o.get('appId'))}')", {"$select": "id"}, deadline) \
                if guid(o.get("appId")) else None
            principal = guid((sp or {}).get("id"))
            if not principal:            # an application without a principal holds nothing
                privileges[obj] = {"directory_roles": [], "member_of": [], "app_roles_held": [],
                                   "owned": [], "assigned_to": []}
                continue
        held = held_by(principal)
        # As IDI1's privilege_refusal reads an identity: what it owns in turn (a principal it owns
        # that holds a role is that role), who holds a role on it, each permission by its value.
        privileges[obj] = {
            "directory_roles": held["roles"] + held["eligible"], "member_of": held["member_of"],
            "app_roles_held": [{"appRoleId": guid(a.get("appRoleId")) if isinstance(a, dict) else "", "value": v}
                               for a, v in zip(held["assignments"], named(held["assignments"]))],
            "owned": listed(f"/servicePrincipals/{principal}/ownedObjects", {"$select": "id"}),
            "assigned_to": listed(f"/servicePrincipals/{principal}/appRoleAssignedTo")}
    return {"assignments": own["assignments"], "resources": resources, "active": own["roles"],
            "eligible": own["eligible"], "member_of": own["member_of"], "owned": owned,
            "privileges": privileges, "notes": tuple(sorted(notes))}


def assess(claims: dict, reader, *, env=None, never: NeverTarget | None = None) -> Verdict:
    """The verdict from its token's claims and what ``reader`` gives (the executor's Graph, or a
    fake one). Fail closed: anything not read leaves it passive."""
    decl, missing = declared(env)
    if decl is None:
        return Verdict(PASSIVE, tuple(missing))
    missing, token_held, oid = assess_token(claims, decl)
    if not oid:
        return Verdict(PASSIVE, tuple(missing))
    try:
        got = read(reader, oid, time.monotonic() + READ_BUDGET_S)
    except Exception as e:      # a right missing, an error, a delay, an answer not a list, a bug
        why = str(e) if isinstance(e, (Unreadable, ValueError)) else f"{type(e).__name__}: {e}"
        return Verdict(PASSIVE, tuple(missing + [_miss(UNREADABLE, f"its own rights not read: {why}")]))
    m, assigned = assess_permissions(got["assignments"], got["resources"])
    r, roles = assess_roles(got["active"], got["eligible"], decl)
    o = assess_owned(got["owned"], decl, oid, never or NeverTarget.from_env(env), got["privileges"])
    missing += m + r + assess_member_of(got["member_of"]) + o
    # A right is held when both its token and its assignments say so: one of them alone, the
    # token is older than the assignment, or the other way round.
    held = (token_held & assigned) | roles
    return Verdict(PASSIVE if missing else ARMED, tuple(missing), frozenset(held), got["notes"])


def executor_credential(env=None):
    """The executor's own credential: its certificate, never ``DefaultAzureCredential``."""
    env = os.environ if env is None else env
    decl, missing = declared(env)
    path = (env.get(CERTIFICATE_ENV) or "").strip()
    if decl is None or not path:
        raise ValueError("; ".join(m["detail"] for m in missing) or f"{CERTIFICATE_ENV} not set")
    from azure.identity import CertificateCredential
    return CertificateCredential(decl.tenant, decl.client, certificate_path=path)


def check(*, env=None, credential=None, reader=None, never: NeverTarget | None = None) -> Verdict:
    """The contract, read now: its token and its rights. Nothing written; any failure is passive."""
    decl, missing = declared(env)
    if decl is None:
        return Verdict(PASSIVE, tuple(missing))
    try:
        credential = credential if credential is not None else executor_credential(env)
        claims = token_claims(credential.get_token(SCOPE).token)
    except Exception as e:
        return Verdict(PASSIVE, (_miss(UNREADABLE, f"its token not had: {type(e).__name__}: {e}"),))
    return assess(claims, reader if reader is not None else GraphReader(credential=credential),
                  env=env, never=never)


def start(**kw) -> Verdict:
    """The executor's start: the contract read, and ``Passive`` raised unless it holds."""
    verdict = check(**kw)
    if not verdict.armed:
        raise Passive(verdict.reasons())
    return verdict
