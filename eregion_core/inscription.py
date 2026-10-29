"""Inscription and scope — the one target guardrail every injector goes through (O0).

An injector (Annatar today, Gothmog next) may only touch a target that is ENROLLED:

  1. the target sits inside the bench's perimeter — its subscription (when the scope
     names one), its resource groups (an explicit list, or the Celebrimbor patterns),
     its resource ids (when the scope lists them): ``Scope.check``;
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
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field

TARGET_TAG = "eregion-target"
ZONE_TAG = "eregion-zone"
LEGACY_TAG = "annatar-test"

ZONES = ("bench", "twin", "production")
KINDS = ("technique", "fault")

# The only bench that exists so far; a named Celebrimbor instance is "celebrimbor-<name>".
DEFAULT_BENCH = "celebrimbor"
BENCH_ENV = "EREGION_BENCH"

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
        """The scope of the bench this process works on (``EREGION_BENCH``)."""
        return cls(sandbox=os.environ.get(BENCH_ENV, DEFAULT_BENCH))

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

        # 2. The subscription the scope names, when it names one.
        if self.subscription_id:
            sub = subscription_from_id(resource_id)
            if sub.lower() != self.subscription_id.lower():
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

    def tags(self, resource_id: str) -> tuple[dict, dict]:
        """(the resource group's tags, the VM's), read now."""
        import requests
        get = self._get or requests.get
        sub, rg = subscription_from_id(resource_id), rg_from_id(resource_id)
        if not sub or not rg or "/virtualmachines/" not in resource_id.lower():
            raise ValueError(f"not a VM resource id: {resource_id!r}")
        headers = self._headers()
        out = []
        for url, api in ((f"{ARM}/subscriptions/{sub}/resourceGroups/{rg}", _RG_API),
                         (f"{ARM}{resource_id}", _VM_API)):
            r = get(url, headers=headers, params={"api-version": api}, timeout=15)
            if not r.ok:
                raise RuntimeError(f"HTTP {r.status_code} reading {url.rsplit('/', 1)[-1]}")
            out.append(r.json().get("tags") or {})
        return out[0], out[1]

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
