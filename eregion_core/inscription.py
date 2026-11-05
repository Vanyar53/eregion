"""Inscription and scope — the one target guardrail every injector goes through (O0).

An injector (Annatar today, Gothmog next) may only touch a target that is ENROLLED:

  1. the target sits inside the bench's perimeter — its subscription (a scope names one,
     or refuses everything: SEC11, R-19), its resource groups (an explicit list, or the
     Celebrimbor patterns), its resource ids (when the scope lists them): ``Scope.check``;
  2. the target AND its resource group carry ``eregion-target=<bench id>``, posed by
     Celebrimbor at construction: ``enrollment``;
  3. the target's zone allows the experiment: ``check_zone``.

        zone          what may run there
        bench, twin   techniques, destructive ones, faults
        production    a technique that is not destructive — a fault, never

The scope is checked at synthesis (no Azure call) and everything again at execution,
so a hand-edited manifest or scenario cannot get round it. Anything unknown is refused:
no tag, an empty bench id, a value in another case, a zone missing or not one of the
three, a resource group and a target that disagree on the zone, a destructiveness
nobody stated, in production.

Azure treats tag NAMES case-insensitively and keeps VALUES as written: names are
matched in any case, values exactly.

Migration: ``annatar-test=true`` — the old chaos tag, only ever set on Celebrimbor —
still enrolls a target, in zone ``bench``, as long as it carries no ``eregion-target``.
Drop it once the bench carries the new tags (``infra/terraform/locals.tf``).

An identity of Entra ID (IDI1, #546) carries no ARM tag: it is enrolled by two keys, one per
plane, the way a VM is by its group and itself — ``identity_enrollment``:

  1. Entra: the application's own ``tags`` (Microsoft Graph) name the bench and the zone,
     ``eregion-target=<bench>`` and ``eregion-zone=<zone>``;
  2. ARM: the bench's resource group names the application, ``eregion-identities=<object id …>``,
     and its zone agrees.

Either key alone opens nothing: an application's owner (any member may register one) writes
its tags, but not the bench's group. The tenant is named (``EREGION_TENANT_ID``) and must be
the token's and the application's home (a multi-tenant application reaches other tenants:
refused); the principal is an application's (a managed identity — Glorfindel's, Orodruin's —
never is); the operator's identity is named (``EREGION_OPERATOR_OBJECT_ID``) or nothing is
accepted; the reader itself, the identities listed as protected, and an application that owns
one of them are never targets. A read that fails refuses.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field

TARGET_TAG = "eregion-target"
ZONE_TAG = "eregion-zone"
LEGACY_TAG = "annatar-test"

ZONES = ("bench", "twin", "production")
KINDS = ("technique", "fault")

# The only bench that exists so far; a named Celebrimbor instance is "celebrimbor-<name>".
DEFAULT_BENCH = "celebrimbor"
BENCH_ENV = "EREGION_BENCH"
# The subscription the bench lives in (SEC11, R-19): the one every Eregion process reads.
SUBSCRIPTION_ENV = "AZURE_SUBSCRIPTION_ID"

# A target id must look like a Celebrimbor resource. Belt-and-suspenders next to an
# explicit allowlist: even an empty allowlist won't admit production.
SANDBOX_RG_PATTERNS: tuple[str, ...] = ("rg-celebrimbor", "rg-celebrimbor-*")


@dataclass
class GuardResult:
    allowed: bool
    reason: str = ""
    zone: str = ""
    legacy: bool = False


def _is_known_bench(bench: str) -> bool:
    return bench == DEFAULT_BENCH or bench.startswith(DEFAULT_BENCH + "-")


@dataclass
class Scope:
    """Hard allowlist of where an injector may act: the bench's perimeter."""

    sandbox: str = DEFAULT_BENCH
    subscription_id: str = ""
    allowed_resource_groups: list[str] = field(default_factory=list)
    allowed_resource_ids: list[str] = field(default_factory=list)

    @classmethod
    def for_bench(cls) -> "Scope":
        """The scope of the bench this process works on (``EREGION_BENCH``), in the
        subscription ``AZURE_SUBSCRIPTION_ID`` names. Unset, the scope names none and refuses
        every target (SEC11, R-19): the identity's rights alone would bound it."""
        return cls(sandbox=os.environ.get(BENCH_ENV, DEFAULT_BENCH),
                   subscription_id=(os.environ.get(SUBSCRIPTION_ENV) or "").strip())

    def check(self, resource_id: str, resource_group: str = "") -> GuardResult:
        """Refuse any target not provably inside the bench's perimeter."""
        if not _is_known_bench(self.sandbox):
            return GuardResult(False, f"unknown sandbox '{self.sandbox}' — Celebrimbor only")
        if not resource_id:
            return GuardResult(False, "empty resource_id")

        rid = resource_id.lower()

        # 1. Explicit resource-id allowlist (most specific).
        if self.allowed_resource_ids:
            if not any(rid == a.lower() for a in self.allowed_resource_ids):
                return GuardResult(
                    False,
                    f"resource_id not in allowed_resource_ids: {resource_id}",
                )

        # 2. The subscription the scope names — a perimeter names its own, or it refuses
        # (SEC11, R-19): without it, only the identity's rights bounded the target.
        if not self.subscription_id.strip():
            return GuardResult(
                False,
                "the scope names no subscription: a perimeter names its own "
                f"({SUBSCRIPTION_ENV}, or the campaign's scope)",
            )
        sub = subscription_from_id(resource_id)
        if sub.lower() != self.subscription_id.strip().lower():
            return GuardResult(
                False,
                f"subscription '{sub or '?'}' outside the scope's subscription",
            )

        # 3. Resource-group allowlist (and/or derived from the id).
        rg = (resource_group or rg_from_id(resource_id)).lower()
        if not rg:
            return GuardResult(False, f"cannot determine resource group of {resource_id}")
        rg_ok = any(fnmatch.fnmatch(rg, p.lower()) for p in self.allowed_resource_groups) if \
            self.allowed_resource_groups else False
        sandbox_ok = any(fnmatch.fnmatch(rg, p) for p in SANDBOX_RG_PATTERNS)
        if not (rg_ok or sandbox_ok):
            return GuardResult(
                False,
                f"resource group '{rg}' outside Celebrimbor sandbox allowlist",
            )
        return GuardResult(True)


def _tags(tags: dict | None) -> dict[str, str]:
    """Tag names in lower case (Azure matches them in any case), values as written."""
    return {str(k).lower(): ("" if v is None else str(v)) for k, v in (tags or {}).items()}


def _read(label: str, tags: dict | None, bench: str) -> GuardResult:
    """Is this one resource enrolled for ``bench``? ``zone`` is the one it names, or ""."""
    t = _tags(tags)
    zone = t.get(ZONE_TAG, "")
    if TARGET_TAG in t:
        value = t[TARGET_TAG]
        if not value.strip():
            return GuardResult(False, f"{label} carries an empty '{TARGET_TAG}' tag")
        if value != bench:
            return GuardResult(
                False,
                f"{label} is enrolled for bench '{value}', not '{bench}'",
            )
        return GuardResult(True, zone=zone)
    if t.get(LEGACY_TAG, "").lower() == "true":
        # The old chaos tag: Celebrimbor only, hence the bench (migration).
        return GuardResult(True, zone=zone, legacy=True)
    return GuardResult(
        False,
        f"{label} missing tag '{TARGET_TAG}={bench}'. "
        f"Celebrimbor enrolls its targets at construction; nothing else is tested.",
    )


def enrollment(rg_tags: dict | None, tags: dict | None, *, bench: str) -> GuardResult:
    """Both the resource group and the target must be enrolled for ``bench``.

    The zone is the target's; the resource group may name one too, and must then agree.
    """
    if not bench or not bench.strip():
        return GuardResult(False, "empty bench id — no target can be enrolled for it")
    rg = _read("resource group", rg_tags, bench)
    if not rg.allowed:
        return rg
    target = _read("VM", tags, bench)
    if not target.allowed:
        return target
    # Only the old tag implies a zone: it was only ever set on the bench.
    zone = target.zone or ("bench" if target.legacy else "")
    if not zone:
        return GuardResult(
            False,
            f"VM enrolled without a zone — tag '{ZONE_TAG}' must be one of {', '.join(ZONES)}",
        )
    if rg.zone and rg.zone != zone:
        return GuardResult(
            False,
            f"zones disagree: resource group '{rg.zone}', VM '{zone}'",
        )
    return GuardResult(True, zone=zone, legacy=rg.legacy or target.legacy)


def check_zone(zone: str, *, kind: str, destructive: bool | None) -> GuardResult:
    """May an experiment of this ``kind`` run in ``zone``? ``destructive=None`` is unknown."""
    if zone not in ZONES:
        return GuardResult(False, f"unknown zone '{zone}' — one of {', '.join(ZONES)}")
    if kind not in KINDS:
        return GuardResult(False, f"unknown experiment kind '{kind}' — one of {', '.join(KINDS)}")
    if zone == "production":
        if kind != "technique":
            return GuardResult(False, "a fault never runs in production", zone=zone)
        if destructive is not False:
            what = "a destructive technique" if destructive else "a technique nobody declared non-destructive"
            return GuardResult(False, f"{what} never runs in production", zone=zone)
    return GuardResult(True, zone=zone)


def check_target(
    resource_id: str,
    rg_tags: dict | None,
    tags: dict | None,
    *,
    kind: str,
    destructive: bool | None,
    scope: Scope | None = None,
) -> GuardResult:
    """Everything, at execution time: perimeter, enrollment, zone."""
    scope = scope or Scope.for_bench()
    inside = scope.check(resource_id)
    if not inside.allowed:
        return inside
    enrolled = enrollment(rg_tags, tags, bench=scope.sandbox)
    if not enrolled.allowed:
        return enrolled
    verdict = check_zone(enrolled.zone, kind=kind, destructive=destructive)
    verdict.legacy = enrolled.legacy
    return verdict


def rg_from_id(resource_id: str) -> str:
    """The resourceGroups/<rg> segment of an Azure resource id."""
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "resourcegroups" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


def subscription_from_id(resource_id: str) -> str:
    """The subscriptions/<id> segment of an Azure resource id."""
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "subscriptions" and i + 1 < len(parts):
            return parts[i + 1]
    return ""


# ── The reader's side (H-1): is this VM enrolled, read by the watch itself ─────────────

ARM = "https://management.azure.com"
_ARM_SCOPE = "https://management.azure.com/.default"
_VM_API = "2024-07-01"
_RG_API = "2021-04-01"


class TagEnrollment:
    """Whether a VM is enrolled, by its tags and its resource group's (``enrollment``), read
    through Azure Resource Manager with the reader's own identity — the hosted watch's is
    Reader on the bench (infra/glorfindel-host/main.tf). An exercise window only names its
    targets: the watch checks them here before a window marks a VM (eregion_core/exercise.py,
    H-1), so the VM carrying a real load, never enrolled, is never in an exercise.

    A read that fails (no credential, 403, a VM gone) is « not enrolled »: the window marks
    nothing, the cycle is labelled real. A verdict is cached TTL_S, a failure FAIL_TTL_S —
    the watch labels every cycle, and the tags of a bench seldom change."""

    TTL_S = 600.0
    FAIL_TTL_S = 60.0

    def __init__(self, *, bench: str | None = None, credential=None, get=None, clock=None):
        import threading
        import time
        self.bench = bench or os.environ.get(BENCH_ENV, DEFAULT_BENCH)
        self._credential = credential
        self._get = get
        self._clock = clock or time.monotonic
        self._cache: dict[str, tuple[float, bool, str]] = {}
        self._lock = threading.Lock()
        self._said: dict[str, str] = {}

    def _headers(self) -> dict:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        return {"Authorization": f"Bearer {self._credential.get_token(_ARM_SCOPE).token}"}

    def arm_get(self, path: str, api: str) -> dict:
        """One read of Azure Resource Manager with the reader's identity (Orodruin's, for the
        request it judges: eregion_core/exercise_runner.py, DG-b). An error raises."""
        import requests

        from eregion_core.held import safe_path
        path = safe_path(path)   # no query, no fragment, no escape: the path ARM was asked (DG-b review)
        r = (self._get or requests.get)(f"{ARM}{path}", headers=self._headers(),
                                        params={"api-version": api}, timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} reading {path.rsplit('/', 1)[-1]}")
        return r.json()

    def tags(self, resource_id: str) -> tuple[dict, dict]:
        """(the resource group's tags, the VM's), read now. The two URLs are built from the
        parts of the id — subscription, group, name — never from the id itself, which a window
        names (SEC8): an id not exactly a VM's is refused before any token is asked for."""
        import requests

        from eregion_core.held import vm_parts
        get = self._get or requests.get
        sub, rg, name = vm_parts(resource_id)
        headers = self._headers()
        out = []
        group = f"{ARM}/subscriptions/{sub}/resourceGroups/{rg}"
        for url, api in ((group, _RG_API),
                         (f"{group}/providers/Microsoft.Compute/virtualMachines/{name}", _VM_API)):
            r = get(url, headers=headers, params={"api-version": api}, timeout=15)
            if not r.ok:
                raise RuntimeError(f"HTTP {r.status_code} reading {url.rsplit('/', 1)[-1]}")
            out.append(r.json().get("tags") or {})
        return out[0], out[1]

    def vms(self, subscription: str, *, max_pages: int = 20) -> list[dict]:
        """The VMs of the bench's resource groups (``SANDBOX_RG_PATTERNS``), each with its tags
        and its group's — every one, enrolled or not: ``enrollment`` judges, never this list.
        Read now with the reader's own identity (the console's: Reader on the bench, on H0); a
        group it cannot read, Azure does not list. For the targets of Dagorlad (§7 of
        docs/design/console.md). An error raises: the caller says the targets are unreadable."""
        import requests
        if not subscription:
            raise ValueError("AZURE_SUBSCRIPTION_ID not set: the bench's VMs cannot be listed")
        get = self._get or requests.get
        headers = self._headers()

        def pages(url: str, api: str):
            params: dict | None = {"api-version": api}
            for _ in range(max_pages):
                r = get(url, headers=headers, params=params, timeout=15)
                if not r.ok:
                    raise RuntimeError(f"HTTP {r.status_code} listing {url.rsplit('/', 1)[-1]}")
                body = r.json()
                yield from body.get("value") or []
                url, params = body.get("nextLink") or "", None
                if not url:
                    return
                # The token goes to Azure Resource Manager only (N-15's rule): a next page
                # elsewhere is refused, never followed.
                if not url.startswith(ARM + "/"):
                    raise RuntimeError("a listing's next page outside Azure Resource Manager: refused")

        out = []
        for rg in pages(f"{ARM}/subscriptions/{subscription}/resourcegroups", _RG_API):
            name = str(rg.get("name") or "")
            if not any(fnmatch.fnmatch(name.lower(), p) for p in SANDBOX_RG_PATTERNS):
                continue
            url = (f"{ARM}/subscriptions/{subscription}/resourceGroups/{name}"
                   "/providers/Microsoft.Compute/virtualMachines")
            for vm in pages(url, _VM_API):
                rid = str(vm.get("id") or "")
                if rid:
                    out.append({"resource_id": rid, "name": str(vm.get("name") or rid.rsplit("/", 1)[-1]),
                                "resource_group": name, "rg_tags": rg.get("tags") or {},
                                "tags": vm.get("tags") or {}})
        return out

    def _verdict(self, resource_id: str) -> tuple[bool, str]:
        """(enrolled, its zone — "" when not enrolled), cached."""
        key = resource_id.lower()
        now = self._clock()
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1], hit[2]
        zone = ""
        try:
            rg_tags, tags = self.tags(resource_id)
            verdict = enrollment(rg_tags, tags, bench=self.bench)
            ok, ttl, why = verdict.allowed, self.TTL_S, verdict.reason
            zone = verdict.zone if ok else ""
        except Exception as e:
            ok, ttl, why = False, self.FAIL_TTL_S, f"enrollment unreadable: {e}"
        if not ok and self._said.get(key) != why:
            self._said[key] = why
            print(f"[exercise] {resource_id.rsplit('/', 1)[-1]} not enrolled, no window marks "
                  f"it: {why}")
        with self._lock:
            self._cache[key] = (now + ttl, ok, zone)
        return ok, zone

    def __call__(self, resource_id: str) -> bool:
        return self._verdict(resource_id)[0]

    def zone(self, resource_id: str) -> str:
        """The VM's zone as its tags say — what an exercise window may mark there (SEC5,
        V-20: in production, a non-destructive technique only). "" when not enrolled."""
        return self._verdict(resource_id)[1]


# ── An identity of Entra ID (IDI1, #546): two keys, one per plane ──────────────────────

IDENTITIES_TAG = "eregion-identities"
TENANT_ENV = "EREGION_TENANT_ID"
OPERATOR_ENV = "EREGION_OPERATOR_OBJECT_ID"
PROTECTED_ENV = "EREGION_PROTECTED_IDENTITIES"
BENCH_RG_ENV = "EREGION_BENCH_RG"
# The identity Glorfindel acts under, as it names itself (glorfindel/providers/azure/activity.py).
_GLORFINDEL_ENVS = ("GLORFINDEL_OWN_CALLERS", "AZURE_CLIENT_ID")
# What an application must be to be enrolled: of this tenant only (a multi-tenant one reaches
# other tenants), its principal an application's (a managed identity never is a target).
SINGLE_TENANT = "AzureADMyOrg"
APPLICATION_PRINCIPAL = "Application"
_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _guid(value) -> str:
    """``value`` in lower case if it is an object id (a GUID), else ""."""
    v = str(value or "").strip().lower()
    return v if _GUID.fullmatch(v) else ""


def _ids(raw: str) -> tuple[set[str], list[str]]:
    """The object ids of a list (commas or spaces), and what in it is no object id."""
    items = [x for x in re.split(r"[,\s]+", raw or "") if x]
    return {_guid(x) for x in items if _guid(x)}, [x for x in items if not _guid(x)]


@dataclass(frozen=True)
class IdentityScope:
    """What the reader knows of the bench's tenant before it reads anything: the bench, the
    tenant, the operator, the identities that are never targets — named, or nothing passes."""

    bench: str = DEFAULT_BENCH
    tenant_id: str = ""
    operator_id: str = ""
    protected: frozenset[str] = frozenset()
    subscription_id: str = ""
    resource_group: str = ""
    errors: tuple[str, ...] = ()

    @classmethod
    def for_bench(cls, env=None) -> "IdentityScope":
        """From the environment of the process (orodruin.env on Orodruin: terraform output of
        infra/orodruin). An id written wrong in the protected list refuses everything — a typo
        there would leave an identity unprotected, unsaid."""
        env = os.environ if env is None else env
        bench = (env.get(BENCH_ENV) or DEFAULT_BENCH).strip()
        protected, bad = _ids(env.get(PROTECTED_ENV) or "")
        for name in _GLORFINDEL_ENVS:
            protected |= _ids(env.get(name) or "")[0]
        errors = tuple(f"{PROTECTED_ENV} holds what is no object id: {x[:40]!r}" for x in bad)
        return cls(bench=bench, tenant_id=_guid(env.get(TENANT_ENV)), operator_id=_guid(env.get(OPERATOR_ENV)),
                   protected=frozenset(protected), subscription_id=(env.get(SUBSCRIPTION_ENV) or "").strip(),
                   resource_group=(env.get(BENCH_RG_ENV) or f"rg-{bench}").strip(), errors=errors)


def _scope_refusal(scope: IdentityScope) -> str:
    """Why no identity can be judged in this scope, or ""."""
    if not scope.bench or not _is_known_bench(scope.bench):
        return f"unknown bench '{scope.bench}' — Celebrimbor only"
    if not scope.tenant_id:
        return f"the scope names no tenant ({TENANT_ENV}): no identity is enrolled outside a named tenant"
    if not scope.operator_id:
        return (f"the scope names no operator ({OPERATOR_ENV}): without it, the operator's own identity "
                "could not be told apart — no identity is accepted")
    if scope.errors:
        return "; ".join(scope.errors)
    return ""


def _graph_tags(tags) -> tuple[dict[str, str], str]:
    """An application's tags read as ``name=value`` (names in any case, values as written), and
    why they cannot be read so (a name twice: two benches or two zones on one identity)."""
    out: dict[str, str] = {}
    for tag in tags or []:
        name, sep, value = str(tag).partition("=")
        if not sep:
            continue  # a tag of Entra's own (WindowsAzureActiveDirectoryIntegratedApp…)
        name = name.strip().lower()
        if name in out:
            return {}, f"the application carries '{name}' twice"
        out[name] = value
    return out, ""


def identity_enrollment(identity: dict, rg_tags: dict | None, *, scope: IdentityScope,
                        token: dict) -> GuardResult:
    """Is this application enrolled for the bench? ``identity`` as Graph returned it —
    ``application`` (id, appId, signInAudience, tags), ``service_principal`` (id, appId,
    servicePrincipalType, appOwnerOrganizationId), ``owned`` (the object ids its principal
    owns); ``rg_tags``, the tags of the bench's group; ``token``, the claims of the reader's
    own Graph token (tid, oid, appid). The zone is the application's, the group's agreeing."""
    why = _scope_refusal(scope)
    if why:
        return GuardResult(False, why)
    tenant = scope.tenant_id
    if _guid(token.get("tid")) != tenant:
        return GuardResult(False, "the reader's token is not of the bench's tenant")
    app = identity.get("application") or {}
    sp = identity.get("service_principal") or {}
    app_oid, app_id, sp_oid = _guid(app.get("id")), _guid(app.get("appId")), _guid(sp.get("id"))
    if not (app_oid and app_id and sp_oid) or _guid(sp.get("appId")) != app_id:
        return GuardResult(False, "the application and its service principal cannot be told apart")
    if str(sp.get("servicePrincipalType") or "") != APPLICATION_PRINCIPAL:
        return GuardResult(False, f"a principal of type '{sp.get('servicePrincipalType')}', not an "
                                  "application's: a managed identity is never a target")
    if _guid(sp.get("appOwnerOrganizationId")) != tenant:
        return GuardResult(False, "the application is registered in another tenant")
    if str(app.get("signInAudience") or "") != SINGLE_TENANT:
        return GuardResult(False, f"the application signs in '{app.get('signInAudience')}', not "
                                  f"{SINGLE_TENANT} alone: it reaches other tenants")

    # Never a target: the reader itself, the operator, the identities listed as protected —
    # nor an application whose principal owns one of them (its credentials would rule it).
    never = set(scope.protected) | {scope.operator_id}
    never |= {x for x in (_guid(token.get("oid")), _guid(token.get("appid"))) if x}
    if never & {app_oid, app_id, sp_oid}:
        return GuardResult(False, "a protected identity (the reader, Glorfindel, Orodruin, the "
                                  "operator) is never a target")
    if never & {_guid(o) for o in identity.get("owned") or []}:
        return GuardResult(False, "the application's principal owns a protected identity")

    # The ARM key: the bench's group, enrolled, names this application.
    rg = _tags(rg_tags)
    if rg.get(TARGET_TAG) != scope.bench:
        return GuardResult(False, f"the bench's group does not carry '{TARGET_TAG}={scope.bench}'")
    named, bad = _ids(rg.get(IDENTITIES_TAG, ""))
    if bad:
        return GuardResult(False, f"the group's '{IDENTITIES_TAG}' holds what is no object id")
    if app_oid not in named:
        return GuardResult(False, f"the bench's group does not name the application in "
                                  f"'{IDENTITIES_TAG}': an identity is enrolled by both keys")

    # The Entra key: the application's own tags.
    tags, why = _graph_tags(app.get("tags"))
    if why:
        return GuardResult(False, why)
    if TARGET_TAG not in tags:
        return GuardResult(False, f"the application missing tag '{TARGET_TAG}={scope.bench}'")
    if tags[TARGET_TAG] != scope.bench:
        return GuardResult(False, f"the application is enrolled for bench '{tags[TARGET_TAG]}', "
                                  f"not '{scope.bench}'")
    zone = tags.get(ZONE_TAG, "")
    if zone not in ZONES:
        return GuardResult(False, f"the application's zone '{zone}' — tag '{ZONE_TAG}' must be one "
                                  f"of {', '.join(ZONES)}")
    if rg.get(ZONE_TAG, "") != zone:
        return GuardResult(False, f"zones disagree: resource group '{rg.get(ZONE_TAG, '')}', "
                                  f"application '{zone}'")
    return GuardResult(True, zone=zone)


def check_identity(identity: dict, rg_tags: dict | None, *, scope: IdentityScope, token: dict,
                   kind: str, destructive: bool | None) -> GuardResult:
    """Everything, for an identity: its enrollment by both keys, then its zone."""
    enrolled = identity_enrollment(identity, rg_tags, scope=scope, token=token)
    if not enrolled.allowed:
        return enrolled
    return check_zone(enrolled.zone, kind=kind, destructive=destructive)


GRAPH = "https://graph.microsoft.com"
_GRAPH_SCOPE = f"{GRAPH}/.default"
_GRAPH_V1 = f"{GRAPH}/v1.0"
_SAFE_RG = re.compile(r"[A-Za-z0-9._()-]{1,90}")


def token_claims(token: str) -> dict:
    """The claims of a token this process was issued (its own credential's): read, not
    verified — who it is, never whom to believe."""
    import base64
    import json
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


class GraphEnrollment:
    """Whether an application is enrolled, read now with the reader's own identity: Orodruin's,
    which holds ``Application.Read.All`` in Microsoft Graph and nothing else there (its contract
    checks it: eregion_core/orodruin.py), and Reader on the bench's group. Three Graph reads (the
    application, its principal, what the principal owns) and one of ARM (the group's tags), each
    URL built from an object id checked first. Any failure refuses: never enrolled by default."""

    MAX_PAGES = 10

    def __init__(self, *, scope: IdentityScope | None = None, credential=None, get=None):
        self.scope = scope or IdentityScope.for_bench()
        self._credential = credential
        self._get = get

    def _token(self, resource: str) -> str:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        return self._credential.get_token(resource).token

    def _read(self, url: str, headers: dict, params: dict | None = None) -> dict:
        import requests
        r = (self._get or requests.get)(url, headers=headers, params=params, timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} reading {url.rsplit('/', 1)[-1][:60]}")
        return r.json()

    def read(self, app_object_id: str) -> tuple[dict, dict, dict]:
        """(the identity as Graph says it, the bench group's tags, the reader's token claims)."""
        oid = _guid(app_object_id)
        if not oid:
            raise ValueError("not an application's object id")
        sub, rg = self.scope.subscription_id, self.scope.resource_group
        if not _GUID.fullmatch(sub.lower()) or not _SAFE_RG.fullmatch(rg) \
                or not any(fnmatch.fnmatch(rg.lower(), p) for p in SANDBOX_RG_PATTERNS):
            raise ValueError("the bench's subscription or group is not named as one")
        token = self._token(_GRAPH_SCOPE)
        claims = token_claims(token)
        graph = {"Authorization": f"Bearer {token}"}
        app = self._read(f"{_GRAPH_V1}/applications/{oid}", graph,
                         {"$select": "id,appId,signInAudience,tags"})
        app_id = _guid(app.get("appId"))
        if not app_id:
            raise RuntimeError("the application names no appId")
        sp = self._read(f"{_GRAPH_V1}/servicePrincipals(appId='{app_id}')", graph,
                        {"$select": "id,appId,servicePrincipalType,appOwnerOrganizationId"})
        sp_oid = _guid(sp.get("id"))
        if not sp_oid:
            raise RuntimeError("the service principal names no id")
        owned: list[str] = []
        url, params = f"{_GRAPH_V1}/servicePrincipals/{sp_oid}/ownedObjects", {"$select": "id"}
        for _ in range(self.MAX_PAGES):
            body = self._read(url, graph, params)
            owned += [str(o.get("id") or "") for o in body.get("value") or []]
            url, params = str(body.get("@odata.nextLink") or ""), None
            if not url:
                break
            # The token goes to Microsoft Graph only: a next page elsewhere is refused.
            if not url.startswith(_GRAPH_V1 + "/"):
                raise RuntimeError("a next page outside Microsoft Graph: refused")
        else:
            raise RuntimeError("too many pages of owned objects: not read whole")
        arm = {"Authorization": f"Bearer {self._token(_ARM_SCOPE)}"}
        group = self._read(f"{ARM}/subscriptions/{sub}/resourceGroups/{rg}", arm, {"api-version": _RG_API})
        return ({"application": app, "service_principal": sp, "owned": owned},
                group.get("tags") or {}, claims)

    def check(self, app_object_id: str, *, kind: str, destructive: bool | None) -> GuardResult:
        """The verdict for an experiment on this application, read now. The scope is judged
        before any token is asked for."""
        why = _scope_refusal(self.scope)
        if why:
            return GuardResult(False, why)
        try:
            identity, rg_tags, claims = self.read(app_object_id)
        except Exception as e:
            return GuardResult(False, f"identity unreadable: {type(e).__name__}: {e}"[:300])
        return check_identity(identity, rg_tags, scope=self.scope, token=claims,
                              kind=kind, destructive=destructive)


def main(argv: list[str] | None = None) -> int:
    """``python -m eregion_core.inscription identity <application object id>`` — on Orodruin,
    with its env: is this application enrolled, and what may run on it. Exit 0 if a
    non-destructive technique would pass."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "identity":
        print("usage: python -m eregion_core.inscription identity <application object id>")
        return 2
    reader = GraphEnrollment()
    why, read = _scope_refusal(reader.scope), None
    try:
        read = None if why else reader.read(args[1])
    except Exception as e:
        why = f"identity unreadable: {type(e).__name__}: {e}"[:300]
    if read is None:
        print(f"  refused — {why}")
        return 1
    identity, rg_tags, claims = read
    allowed = False
    for destructive in (False, True):
        v = check_identity(identity, rg_tags, scope=reader.scope, token=claims,
                           kind="technique", destructive=destructive)
        what = "destructive" if destructive else "non-destructive"
        print(f"  {what} technique: " + (f"allowed (zone {v.zone})" if v.allowed else f"refused — {v.reason}"))
        allowed = allowed or (v.allowed and not destructive)
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
