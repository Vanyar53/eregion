"""Orodruin's contract (O1): the host an injector acts from arms itself only if its
guardrails hold — otherwise the injector stays passive and touches nothing.

        guarantee         checked by (nothing is written)
        identity          its role assignments, at every scope, all inside the bench's
                          resource group (but the two channels'); its effective rights
                          there cover what the injectors ask
        network           a connection outside the perimeter fails
        cap               the declared cap is read and compared to the ceiling
        kill              revoke the identity, cancel the chaos experiments, stop the
                          VM, close the exercise windows — ``kill``
        audit             every injector call is journaled BEFORE it runs — ``Session``

Targets stay the inscription's business (``eregion_core/inscription.py``, O0): the two
are independent and add up. A contract that cannot be read is ``passive``, never
``armed`` by default — fail closed. Run anywhere but on an armed Orodruin (an operator's
laptop: rights on the whole subscription, open egress), the same checks fail, so an
injector there stays passive: the contract itself is the gate, no host flag to forget.

Design: ``docs/design/orodruin-contract.md``.
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from eregion_core.exercise import MAX_DURATION_S

ARMED, PASSIVE = "armed", "passive"

ARM = "https://management.azure.com"
API_VERSION = "2022-04-01"

# What the injectors ask of Azure on the bench: Annatar on a VM (annatar/executors/
# azure_vm.py), Gothmog on a Chaos Studio experiment (gothmog/engines/chaos_studio.py —
# it starts the experiment; the experiment's own identity acts on the VM).
REQUIRED_ACTIONS = (
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Chaos/experiments/read",
    "Microsoft.Chaos/experiments/start/action",
    "Microsoft.Chaos/experiments/cancel/action",
    "Microsoft.Chaos/experiments/executions/read",
)
# The one kind of assignment allowed outside the bench: reading role assignments, so
# the identity can prove it holds nothing else (a read at the bench's scope cannot see
# the subscription's).
AUTHZ_READ_ONLY = frozenset({
    "microsoft.authorization/roleassignments/read",
    "microsoft.authorization/roledefinitions/read",
})

# Outside the perimeter (bench control plane, Entra ID, the model's API): reaching any
# of these means the egress is open. Addresses, not names — DNS stays allowed.
NETWORK_PROBES = (("1.1.1.1", 443), ("9.9.9.9", 443))
PROBE_TIMEOUT_S = 3.0

# Ceilings the declared cap may not exceed. A run outliving an exercise window would
# leave its tail unlabelled (eregion_core/exercise.py).
CEILING_INJECTIONS = 20
CEILING_RUN_S = MAX_DURATION_S

# The exercise channel (eregion_core/exercise_channel.py): the identity writes the windows
# to one blob container of its own. That assignment is allowed outside the bench only if
# its scope IS that container — a scope that bounds it whatever the role.
CHANNEL_SCOPE_ENV = "EREGION_CHANNEL_SCOPE"
_CONTAINER_SCOPE = re.compile(
    r"^/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.storage"
    r"/storageaccounts/[^/]+/blobservices/default/containers/[^/]+$")

# The return channel (eregion_core/watch_channel.py, #159): the hosted watch writes its
# heartbeat and detections to a container the identity may READ, never write — an
# injector never writes what the watch says. Allowed outside the bench only at that
# container's scope, and only with a read-only role.
WATCH_SCOPE_ENV = "EREGION_WATCH_CHANNEL_SCOPE"
BLOB_READ_ONLY = frozenset({
    "microsoft.storage/storageaccounts/blobservices/containers/read",
    "microsoft.storage/storageaccounts/blobservices/generateuserdelegationkey/action",
    "data:microsoft.storage/storageaccounts/blobservices/containers/blobs/read",
})

BENCH_RG_ENV = "EREGION_BENCH_RG"
DEFAULT_BENCH_RG = "rg-celebrimbor"
AUDIT_ENV = "EREGION_AUDIT_FILE"
MAX_INJECTIONS_ENV = "EREGION_MAX_INJECTIONS"
MAX_RUN_S_ENV = "EREGION_MAX_RUN_S"


class Passive(RuntimeError):
    """An injector call without an armed contract — refused, nothing touched."""


class CapReached(RuntimeError):
    """The run already made as many injector calls as its declared cap allows."""


@dataclass
class Verdict:
    verdict: str
    missing: list[dict] = field(default_factory=list)
    cap: dict = field(default_factory=dict)

    @property
    def armed(self) -> bool:
        return self.verdict == ARMED

    def reasons(self) -> str:
        return "; ".join(f"{m['code']}: {m['detail']}" for m in self.missing)


def _miss(code: str, detail: str) -> dict:
    return {"code": code, "detail": detail}


# ── Readers — each returns what is missing (empty: the guarantee holds) ───────────────

def bench_scope(subscription_id: str, bench_rg: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{bench_rg}"


def _inside(scope: str, bench: str) -> bool:
    s, b = scope.lower().rstrip("/"), bench.lower().rstrip("/")
    return s == b or s.startswith(b + "/")


def channel_scope(env=None, name: str = CHANNEL_SCOPE_ENV) -> str:
    """The declared channel container, or "" — anything but a container's scope is ignored
    (a declared subscription must never become an allowed assignment)."""
    env = os.environ if env is None else env
    scope = (env.get(name) or "").strip().rstrip("/")
    return scope if _CONTAINER_SCOPE.match(scope.lower()) else ""


def watch_scope(env=None) -> str:
    """The declared return-channel container (#159), or "" — same shape check."""
    return channel_scope(env, WATCH_SCOPE_ENV)


def _token_oid(token: str) -> str:
    """The principal the token was issued to — who this host IS, read from the token
    itself rather than from a setting that could drift."""
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims["oid"]


def _allowed(action: str, perms: list[dict]) -> bool:
    a = action.lower()
    return any(
        any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("actions") or []))
        and not any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("notActions") or []))
        for p in perms
    )


def assess_identity(assignments: list[dict], role_actions: Callable[[str], list[str]],
                    perms: list[dict], bench: str, *, sees_subscription: bool,
                    channel: str = "", watch: str = "") -> list[dict]:
    """The identity guarantee from what was read: every assignment inside the bench (or a
    pure role-assignment read, the exercise channel's container, a read-only role on the
    return channel's), and the injectors' actions allowed on the bench.

    Azure lists only the assignments the caller may read (measured on the bench, 19/10:
    with read rights on the workspace alone, the listing showed that one and hid the
    bench's). A listing is proof of absence only if the identity reads role assignments
    over the whole subscription — otherwise nothing is proven (``contract_reader``)."""
    missing = []
    if not sees_subscription:
        missing.append(_miss("identity_unprovable",
                             "cannot read role assignments over the subscription: an assignment "
                             "elsewhere would not be listed (contract_reader)"))
    for a in assignments:
        props = a.get("properties") or {}
        scope = props.get("scope") or ""
        if _inside(scope, bench):
            continue
        actions = {x.lower() for x in role_actions(props.get("roleDefinitionId") or "")}
        # Checked before the exercise channel: declared on the same container, the
        # return channel still refuses a writer.
        if watch and scope.lower().rstrip("/") == watch.lower():
            if actions and actions <= BLOB_READ_ONLY:
                continue
            missing.append(_miss("identity_outside_bench",
                                 f"role assignment at {scope} is not read-only (the watch's channel)"))
            continue
        if channel and scope.lower().rstrip("/") == channel.lower():
            continue  # the exercise channel's own container
        if actions and actions <= AUTHZ_READ_ONLY:
            continue
        missing.append(_miss("identity_outside_bench", f"role assignment at {scope}"))
    for action in REQUIRED_ACTIONS:
        if not _allowed(action, perms):
            missing.append(_miss("identity_missing_right", f"{action} on {bench}"))
    return missing


def read_identity(*, credential=None, get=None) -> list[dict]:
    """Role assignments of this host's identity at every scope, and its effective rights
    on the bench — two reads (proving an absence takes the first)."""
    import requests

    if credential is None:
        from azure.identity import DefaultAzureCredential
        credential = DefaultAzureCredential()
    get = get or requests.get
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
    bench = bench_scope(sub, os.environ.get(BENCH_RG_ENV) or DEFAULT_BENCH_RG)
    token = credential.get_token(f"{ARM}/.default").token
    headers = {"Authorization": f"Bearer {token}"}

    def pages(url: str, params: dict | None) -> list[dict]:
        out: list[dict] = []
        while url:
            r = get(url, headers=headers, params=params, timeout=20)
            if not r.ok:
                raise RuntimeError(f"HTTP {r.status_code} on {url.split('?')[0]}")
            body = r.json()
            out += body.get("value") or []
            url, params = body.get("nextLink"), None
        return out

    oid = _token_oid(token)
    assignments = pages(
        f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments",
        {"api-version": API_VERSION, "$filter": f"assignedTo('{oid}')"},
    )

    def role_actions(definition_id: str) -> list[str]:
        r = get(f"{ARM}{definition_id}", headers=headers,
                params={"api-version": API_VERSION}, timeout=20)
        if not r.ok:
            return []  # unreadable: not proven read-only, so it counts as outside
        perms = (r.json().get("properties") or {}).get("permissions") or []
        # Data actions marked "data:": never mistaken for a role-assignment read.
        return [x for p in perms for x in (p.get("actions") or [])] + \
            [f"data:{x}" for p in perms for x in (p.get("dataActions") or [])]

    perms = pages(f"{ARM}{bench}/providers/Microsoft.Authorization/permissions",
                  {"api-version": API_VERSION})
    sub_perms = pages(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/permissions",
                      {"api-version": API_VERSION})
    return assess_identity(
        assignments, role_actions, perms, bench,
        sees_subscription=_allowed("Microsoft.Authorization/roleAssignments/read", sub_perms),
        channel=channel_scope(), watch=watch_scope())


def read_network(*, probes=NETWORK_PROBES, connect=None) -> list[dict]:
    """A TCP connection to each probe outside the perimeter must fail."""
    connect = connect or socket.create_connection
    missing = []
    for host, port in probes:
        try:
            conn = connect((host, port), timeout=PROBE_TIMEOUT_S)
        except OSError:
            continue  # refused or timed out: what the perimeter should do
        conn.close()
        missing.append(_miss("network_open", f"{host}:{port} reachable"))
    return missing


def read_cap(env=None) -> tuple[list[dict], dict]:
    """The declared cap, read and compared to the ceilings."""
    env = os.environ if env is None else env
    missing, cap = [], {}
    for name, key, ceiling in ((MAX_INJECTIONS_ENV, "max_injections", CEILING_INJECTIONS),
                               (MAX_RUN_S_ENV, "max_run_s", CEILING_RUN_S)):
        raw = env.get(name)
        if raw in (None, ""):
            missing.append(_miss("cap_missing", f"{name} not declared"))
            continue
        value = int(raw)
        if not 0 < value <= ceiling:
            missing.append(_miss("cap_exceeded", f"{name}={value}, ceiling {ceiling}"))
            continue
        cap[key] = value
    return missing, cap


READERS = {"identity": read_identity, "network": read_network, "cap": read_cap}


def check(readers: dict | None = None) -> Verdict:
    """``orodruin-check``: every guarantee read, nothing written. Armed only if all hold;
    a reader that fails makes its guarantee missing (fail closed)."""
    readers = readers or READERS
    missing: list[dict] = []
    cap: dict = {}
    for name in ("identity", "network", "cap"):
        try:
            result = readers[name]()
        except Exception as e:
            missing.append(_miss(f"{name}_unreadable", f"{type(e).__name__}: {e}"[:300]))
            continue
        if name == "cap":
            result, cap = result
        missing += result
    return Verdict(PASSIVE if missing else ARMED, missing, cap)


# ── Audit — the journal precedes the call ─────────────────────────────────────────────

def audit_path() -> Path:
    return Path(os.environ.get(AUDIT_ENV) or Path("runs") / "orodruin" / "audit.jsonl")


def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()
        os.fsync(f.fileno())  # on disk before the call: a crash leaves the intent


@dataclass
class Session:
    """An armed run: each injector call goes through ``before_call``, which journals it
    and enforces the cap, before anything reaches Azure."""
    run_id: str
    injector: str
    max_injections: int
    path: Path = field(default_factory=audit_path)
    calls: int = 0

    def before_call(self, action: str, target: str, detail: str = "") -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(), "run_id": self.run_id,
            "injector": self.injector, "action": action, "target": target, "detail": detail,
        }
        if self.calls >= self.max_injections:
            _append(self.path, {**record, "outcome": "refused_cap"})
            raise CapReached(f"{self.calls} injector calls, cap {self.max_injections}")
        _append(self.path, {**record, "outcome": "about_to_call"})
        self.calls += 1


def arm(run_id: str, injector: str, verdict: Verdict | None = None) -> tuple[Verdict, Session | None]:
    """The gate at the start of a run: a session only when the contract holds."""
    verdict = verdict or check()
    if not verdict.armed:
        return verdict, None
    return verdict, Session(run_id, injector, verdict.cap["max_injections"])


# ── Kill — revoke first, then stop ────────────────────────────────────────────────────

def kill(revoke: Callable[[], None], cancel: Callable[[], None], stop: Callable[[], None],
         close: Callable[[], None]) -> list[str]:
    """``orodruin-kill``: revoke the identity, cancel the chaos experiments still running,
    stop the VM, close the open exercise windows — in that order. Revoke first, so a
    running injector loses its rights even if the rest drags (a stopped VM keeps its
    identity); cancel next, since an experiment acts with its own identity and outlives
    the revocation; close last, once nothing of Orodruin's can reopen a window (M-1).
    A failed step does not stop the next ones, and is reported: never a kill that claims
    success while something survives. Returns the failures."""
    failures = []
    for name, step in (("revoke", revoke), ("cancel", cancel), ("stop", stop), ("close", close)):
        try:
            step()
        except Exception as e:
            failures.append(f"{name}: {type(e).__name__}: {e}")
    return failures


def main() -> int:
    """``orodruin-check`` on the host: the verdict and what is missing; exit 0 if armed."""
    verdict = check()
    print(f"orodruin: {verdict.verdict}")
    for m in verdict.missing:
        print(f"  ✗ {m['code']}: {m['detail']}")
    if verdict.armed:
        print(f"  cap: {verdict.cap}")
    return 0 if verdict.armed else 1


if __name__ == "__main__":
    raise SystemExit(main())
