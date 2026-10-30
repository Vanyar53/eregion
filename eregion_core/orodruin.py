"""Orodruin's contract (O1): the host an injector acts from arms itself only if its
guardrails hold — otherwise the injector stays passive and touches nothing.

        guarantee         checked by (nothing is written)
        identity          its role assignments, at every scope, all inside the bench's
                          resource group (but the two channels'); its effective rights
                          there cover what the injectors read; what they write, granted at
                          the scope of a VM or an experiment of it, never on the whole
                          group (which VMs: Terraform's choice, by their tags — the
                          contract does not read their inscription; O0 does, at each run)
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
# SEC5 (V-29, #182): they READ the bench's group; they WRITE only on what is enrolled — each
# VM, each experiment, a role assignment at its own scope (infra/orodruin/main.tf). A write
# right on the whole group (a VM not enrolled, the pre-observation's, would be in reach) is a
# missing guarantee: passive.
READ_ACTIONS = (
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Chaos/experiments/read",
    "Microsoft.Chaos/experiments/executions/read",
)
VM_ACTIONS = (
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/runCommand/action",
)
CHAOS_ACTIONS = (
    "Microsoft.Chaos/experiments/start/action",
    "Microsoft.Chaos/experiments/cancel/action",
)
WRITE_ACTIONS = VM_ACTIONS + CHAOS_ACTIONS
REQUIRED_ACTIONS = READ_ACTIONS + WRITE_ACTIONS
# The resource type each write is granted on — its scope, inside the bench.
_WRITE_SCOPE = {**{a: "/providers/microsoft.compute/virtualmachines/" for a in VM_ACTIONS},
                **{a: "/providers/microsoft.chaos/experiments/" for a in CHAOS_ACTIONS}}
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


# A detail is shown (orodruin-check, a passive run's reasons): a scope or a URL in it never
# names the subscription (seen on the bench, 26/10, in an unreadable listing's URL).
_SUBSCRIPTION_PART = re.compile(r"/subscriptions/[^/\s'\"]+", re.IGNORECASE)


def _miss(code: str, detail: str) -> dict:
    return {"code": code, "detail": _SUBSCRIPTION_PART.sub("/subscriptions/…", detail)}


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


def _grants(action: str, actions: set[str]) -> bool:
    """A role's actions (lower case, as ``role_actions`` lists them) grant ``action``."""
    a = action.lower()
    return any(fnmatch.fnmatch(a, x) for x in actions if not x.startswith("data:"))


def assess_identity(assignments: list[dict], role_actions: Callable[[str], list[str]],
                    perms: list[dict], bench: str, *, sees_subscription: bool,
                    channel: str = "", watch: str = "", experiments: bool = True) -> list[dict]:
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
    granted_on: dict[str, list[str]] = {a: [] for a in WRITE_ACTIONS}
    for a in assignments:
        props = a.get("properties") or {}
        scope = props.get("scope") or ""
        if _inside(scope, bench):
            # SEC5 (V-29): a write on the group itself reaches every VM of it, enrolled or not.
            actions = {x.lower() for x in role_actions(props.get("roleDefinitionId") or "")}
            wide = [w for w in WRITE_ACTIONS if _grants(w, actions)]
            if scope.lower().rstrip("/") == bench.lower().rstrip("/") and wide:
                missing.append(_miss("identity_group_wide",
                                     f"{', '.join(wide)} on the whole of {bench}: a write right "
                                     "goes on each enrolled VM or experiment, never on the group"))
                continue
            for w in wide:
                if _WRITE_SCOPE[w] in scope.lower():
                    granted_on[w].append(scope)
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
    for action in READ_ACTIONS:
        if not _allowed(action, perms):
            missing.append(_miss("identity_missing_right", f"{action} on {bench}"))
    # Read over the group, a write there: from an assignment above it, or one the listing
    # did not show — never on the group (SEC5, V-29).
    wide = [w for w in WRITE_ACTIONS if _allowed(w, perms)]
    if wide and not any(m["code"] == "identity_group_wide" for m in missing):
        missing.append(_miss("identity_group_wide",
                             f"{', '.join(wide)} effective on the whole of {bench}"))
    for action, scopes in granted_on.items():
        # No experiment in the group (Celebrimbor's chaos is off by default): nothing to start
        # or cancel, and Gothmog finds no experiment to run — the chaos rights are not asked.
        if not scopes and (experiments or action not in CHAOS_ACTIONS):
            missing.append(_miss("identity_missing_right",
                                 f"{action} on no enrolled resource of {bench}"))
    return missing


CHAOS_API = "2024-01-01"


# The codes ARM answers for a resource provider the subscription never registered: Chaos Studio
# off on a subscription is no experiment, whatever the status (SEC7: ARM's documented answer is
# MissingSubscriptionRegistration, a 409; NoRegisteredProviderFound, a 400 — to measure).
UNREGISTERED_PROVIDER = ("MissingSubscriptionRegistration", "NoRegisteredProviderFound")


def _error_code(r) -> str:
    try:
        body = r.json()
    except Exception:
        return ""
    err = body.get("error") if isinstance(body, dict) else None
    return str(err.get("code") or "") if isinstance(err, dict) else ""


def _has_experiments(get, headers: dict, bench: str) -> bool:
    """Does the bench's group hold a Chaos Studio experiment? A provider not registered in the
    subscription (UNREGISTERED_PROVIDER, read in the error's code, whatever the status) or no
    such collection (404): none. Any other failure raises — the contract is then unreadable,
    passive."""
    r = get(f"{ARM}{bench}/providers/Microsoft.Chaos/experiments", headers=headers,
            params={"api-version": CHAOS_API}, timeout=20)
    if r.status_code == 404 or (not r.ok and _error_code(r) in UNREGISTERED_PROVIDER):
        return False
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} listing the bench's experiments")
    return bool(r.json().get("value"))


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

    read_roles: dict[str, list[str]] = {}

    def role_actions(definition_id: str) -> list[str]:
        if definition_id in read_roles:  # one read per role: the same on every enrolled VM
            return read_roles[definition_id]
        r = get(f"{ARM}{definition_id}", headers=headers,
                params={"api-version": API_VERSION}, timeout=20)
        if not r.ok:
            return []  # unreadable: not proven read-only, so it counts as outside
        perms = (r.json().get("properties") or {}).get("permissions") or []
        # Data actions marked "data:": never mistaken for a role-assignment read.
        read_roles[definition_id] = [x for p in perms for x in (p.get("actions") or [])] + \
            [f"data:{x}" for p in perms for x in (p.get("dataActions") or [])]
        return read_roles[definition_id]

    perms = pages(f"{ARM}{bench}/providers/Microsoft.Authorization/permissions",
                  {"api-version": API_VERSION})
    sub_perms = pages(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/permissions",
                      {"api-version": API_VERSION})
    return assess_identity(
        assignments, role_actions, perms, bench,
        sees_subscription=_allowed("Microsoft.Authorization/roleAssignments/read", sub_perms),
        channel=channel_scope(), watch=watch_scope(),
        experiments=_has_experiments(get, headers, bench))


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


# ── The verdict, published for the console (DG-b) ─────────────────────────────────────

CONTRACT_BLOB = "orodruin/contract.json"
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")


def contract_doc(verdict: Verdict, now: datetime | None = None) -> dict:
    """What Orodruin publishes of its contract: armed or passive, the codes of what is missing,
    the time — never a detail (a scope, a group, a subscription), never an identifier."""
    return {"verdict": verdict.verdict, "codes": sorted({m["code"] for m in verdict.missing}),
            "at": (now or datetime.now(timezone.utc)).isoformat()}


def read_contract(doc) -> dict:
    """The verdict as published, or ValueError: exactly its three fields, armed without a code,
    passive with at least one, codes only, an ISO time with its zone."""
    if not isinstance(doc, dict) or set(doc) != {"verdict", "codes", "at"}:
        raise ValueError("not Orodruin's verdict: exactly verdict, codes, at")
    codes = doc["codes"]
    if not isinstance(codes, list) or len(codes) > 20 or not all(isinstance(c, str) and _CODE.match(c) for c in codes):
        raise ValueError("its codes are not a list of codes")
    if doc["verdict"] not in (ARMED, PASSIVE) or (doc["verdict"] == ARMED) != (not codes):
        raise ValueError("armed without a code, or passive with its codes")
    try:
        at = datetime.fromisoformat(doc["at"]) if isinstance(doc["at"], str) else None
    except ValueError:
        at = None
    if at is None or at.tzinfo is None:
        raise ValueError("its time is not an ISO time with its zone")
    return doc


def publish_contract(verdict: Verdict, **kw) -> bool:
    """The verdict to the exercise channel (``orodruin/contract.json``: the same container, the
    same assignment — no right more), for the watch of H0 to pull and the console to show.
    False without a channel; a refused write raises to its caller."""
    from eregion_core import exercise_channel
    return exercise_channel.publish_doc(CONTRACT_BLOB, contract_doc(verdict), **kw)


# ── Audit — the journal precedes the call ─────────────────────────────────────────────

def audit_path() -> Path:
    return Path(os.environ.get(AUDIT_ENV) or Path("runs") / "orodruin" / "audit.jsonl")


def _append(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()
        os.fsync(f.fileno())  # on disk before the call: a crash leaves the intent


def push_offhost(run_id: str, line: str, *, created: bool, channel: str | None = None,
                 credential=None, put=None) -> None:
    """One journal line to the exercise channel, off this host (SEC5, V-29): the append blob
    ``audit/<run_id>.jsonl`` — created on the run's first line (never over an existing one),
    then appended to. Raises when the channel refuses: the caller says it."""
    import requests

    from eregion_core import exercise_channel as xc

    url = channel if channel is not None else xc.channel_url()
    if not url:
        return
    if not xc.safe_part(run_id):
        raise ValueError(f"unsafe run id: {run_id!r}")
    put = put or requests.put
    blob = f"{url}/{xc.AUDIT}/{run_id}.jsonl"
    headers = xc.auth_headers(credential, url)
    if not created:
        r = put(blob, headers={**headers, "x-ms-blob-type": "AppendBlob", "If-None-Match": "*"},
                data=b"", timeout=15)
        if not r.ok and r.status_code not in (409, 412):  # there already: append to it
            raise RuntimeError(f"HTTP {r.status_code} creating {xc.AUDIT}/{run_id}.jsonl")
    r = put(blob, headers={**headers, "Content-Type": "application/x-ndjson"},
            params={"comp": "appendblock"}, data=line.encode(), timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} appending to {xc.AUDIT}/{run_id}.jsonl")


@dataclass
class Session:
    """An armed run: each injector call goes through ``before_call``, which journals it
    and enforces the cap, before anything reaches Azure. The journal is on this host's disk
    first (fsync), then — with an exercise channel — off it (SEC5, V-29): a host lost or
    wiped keeps its trace in the channel. Off-host is best effort: a push that fails is
    journaled here and said, and the call goes on (refusing it could leave a target
    half-cleaned); it is no defence against a compromised host, which could stop pushing."""
    run_id: str
    injector: str
    max_injections: int
    path: Path = field(default_factory=audit_path)
    calls: int = 0
    offhost: Callable | None = None   # push_offhost unless a test swaps it
    _pushed: bool = False
    # DG-b: the request this run is a wire of — each line says it, and Orodruin counts the
    # request's calls against its cap (eregion_core/exercise_runner.py).
    request: str = ""

    def _journal(self, record: dict) -> None:
        if self.request:
            record = {**record, "request": self.request}
        _append(self.path, record)
        try:
            (self.offhost or push_offhost)(self.run_id, json.dumps(record) + "\n",
                                           created=self._pushed)
            self._pushed = True
        except Exception as e:
            why = f"{type(e).__name__}: {e}"[:300]
            _append(self.path, {**record, "outcome": "offhost_failed", "detail": why})
            print(f"[orodruin] journal line not pushed off the host: {why}")

    def before_call(self, action: str, target: str, detail: str = "") -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(), "run_id": self.run_id,
            "injector": self.injector, "action": action, "target": target, "detail": detail,
        }
        if self.calls >= self.max_injections:
            self._journal({**record, "outcome": "refused_cap"})
            raise CapReached(f"{self.calls} injector calls, cap {self.max_injections}")
        self._journal({**record, "outcome": "about_to_call"})
        self.calls += 1

    def declare(self, what: str, detail: str = "") -> None:
        """A fact of the run, journaled — no call, not counted against the cap. A run
        ``--without-glorfindel`` is written here (SEC5, N-04), not only in its report."""
        self._journal({
            "ts": datetime.now(timezone.utc).isoformat(), "run_id": self.run_id,
            "injector": self.injector, "action": what, "target": "", "detail": detail,
            "outcome": "declared",
        })


def arm(run_id: str, injector: str, verdict: Verdict | None = None,
        request: str = "") -> tuple[Verdict, Session | None]:
    """The gate at the start of a run: a session only when the contract holds. ``request``: the
    request this run is a wire of (DG-b), written on each line of the journal."""
    verdict = verdict or check()
    if not verdict.armed:
        return verdict, None
    return verdict, Session(run_id, injector, verdict.cap["max_injections"], request=request)


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
    """``orodruin-check`` on the host: the verdict and what is missing; exit 0 if armed. The
    verdict is published for the console (DG-b), best effort: said when it fails."""
    verdict = check()
    try:
        publish_contract(verdict)
    except Exception as e:
        print(f"  (verdict not published for the console: {type(e).__name__}: {e})"[:300])
    print(f"orodruin: {verdict.verdict}")
    for m in verdict.missing:
        print(f"  ✗ {m['code']}: {m['detail']}")
    if verdict.armed:
        print(f"  cap: {verdict.cap}")
    return 0 if verdict.armed else 1


if __name__ == "__main__":
    raise SystemExit(main())
