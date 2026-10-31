"""Azure Chaos Studio, the bench's native engine (G0) — and what Gothmog reads around it.

Experiments (classic): an experiment, declared by Celebrimbor (``infra/terraform/chaos.tf``),
acts on Chaos Studio targets enrolled on the bench's VMs, with its own identity — the VM
itself for a shutdown, the Chaos agent on it for load and disk writes (G1). Gothmog
never writes an experiment: it reads it (its targets, its duration), starts it, follows
its execution, cancels it. Workspaces, the model Microsoft is moving to, are in public
preview (09/2026): not for G0.

Everything goes by ARM REST (management.azure.com), like the contract
(``eregion_core/orodruin.py``): the one API Orodruin's closed egress lets through, and no
SDK beyond azure-identity in its image. The three writes a run may make — start, cancel,
start a stopped VM — each go through the armed session first (``Session.before_call``):
journaled on disk before the call, within the declared cap. Without a session, a write is
refused and nothing is touched.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone

ARM = "https://management.azure.com"
CHAOS_API = "2024-01-01"
COMPUTE_API = "2024-07-01"
RESOURCES_API = "2022-09-01"
# Log Analytics through ARM, not api.loganalytics.io: Orodruin's egress lets only ARM out.
LOGS_API = "2017-01-01-preview"

BENCH_RG_ENV = "EREGION_BENCH_RG"
DEFAULT_BENCH_RG = "rg-celebrimbor"
WORKSPACE_ENV = "EREGION_BENCH_WORKSPACE"
DEFAULT_WORKSPACE = "law-celebrimbor-amonsul"

TERMINAL = frozenset({"success", "succeeded", "completed", "failed", "cancelled", "canceled"})
# A VM the fault has reached: on its way down, or down.
DOWN = frozenset({"PowerState/stopping", "PowerState/stopped",
                  "PowerState/deallocating", "PowerState/deallocated"})

# A VM's Chaos Studio target: the VM itself (service-direct faults, Shutdown-1.0), or the
# Chaos agent installed on it (agent-based faults, CPU and disk pressure — G1).
_VM_TARGET = re.compile(
    r"^(?P<vm>/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute"
    r"/virtualmachines/[^/]+)/providers/microsoft\.chaos/targets/"
    r"(?:microsoft-virtualmachine|microsoft-agent)$",
    re.IGNORECASE)
_ISO_DURATION = re.compile(r"^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?$", re.IGNORECASE)


# ── What an experiment says, read from the experiment itself ──────────────────────────

def experiment_targets(experiment: dict) -> list[str]:
    """The VMs the experiment acts on. A dynamic selector (``Query``) names no fixed list —
    its targets could change after they were checked: refused."""
    vms: list[str] = []
    for sel in (experiment.get("properties") or {}).get("selectors") or []:
        if (sel.get("type") or "").lower() != "list":
            raise ValueError(f"selector {sel.get('id')!r} is {sel.get('type')!r}: "
                             "only a fixed list of targets can be checked")
        for t in sel.get("targets") or []:
            tid = t.get("id") or ""
            m = _VM_TARGET.match(tid)
            if not m:
                raise ValueError(f"target {tid!r} is not a VM's Chaos Studio target")
            vm = tid[:m.end("vm")]
            if vm.lower() not in {v.lower() for v in vms}:   # its VM and its agent: one VM
                vms.append(vm)
    if not vms:
        raise ValueError("the experiment names no target")
    return vms


def iso_seconds(value: str) -> float:
    m = _ISO_DURATION.match(str(value or "").strip())
    if not m or not any(m.groups()):
        raise ValueError(f"unreadable duration {value!r}")
    h, mi, s = m.groups()
    return int(h or 0) * 3600 + int(mi or 0) * 60 + float(s or 0)


def fault_duration_s(experiment: dict) -> float:
    """Steps run one after the other, branches side by side, a branch's actions in turn."""
    total = 0.0
    for step in (experiment.get("properties") or {}).get("steps") or []:
        total += max((sum(iso_seconds(a["duration"]) for a in b.get("actions") or []
                          if a.get("duration"))
                      for b in step.get("branches") or []), default=0.0)
    return total


def power_state(vm: dict) -> str:
    statuses = ((vm.get("properties") or {}).get("instanceView") or {}).get("statuses") or []
    return next((s["code"] for s in statuses if (s.get("code") or "").startswith("PowerState/")),
                "PowerState/unknown")


def agent_status(vm: dict) -> str:
    agent = ((vm.get("properties") or {}).get("instanceView") or {}).get("vmAgent") or {}
    return next((s.get("displayStatus") or "" for s in agent.get("statuses") or []), "")


def is_terminal(status: str) -> bool:
    return (status or "").lower() in TERMINAL


def _parse(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def latest_execution(executions: list[dict], since: datetime) -> dict | None:
    """The run's own execution: the latest one started since the run's start (clock skew
    allowed)."""
    floor = since - timedelta(minutes=2)
    started = [(at, e) for e in executions
               if (at := _parse((e.get("properties") or {}).get("startedAt"))) and at >= floor]
    return max(started, key=lambda p: p[0])[1] if started else None


def _rows(body: dict) -> list[dict]:
    tables = body.get("tables") or body.get("Tables") or []
    if not tables:
        return []
    t = tables[0]
    cols = [c.get("name") or c.get("ColumnName") for c in t.get("columns") or t.get("Columns") or []]
    return [dict(zip(cols, row)) for row in t.get("rows") or t.get("Rows") or []]


# ── The bench, as a run reads and touches it ──────────────────────────────────────────

class ChaosStudio:
    def __init__(self, session=None, *, credential=None, http=None,
                 subscription_id: str | None = None, bench_rg: str | None = None,
                 workspace: str | None = None):
        self._session = session
        self._credential = credential
        self._http = http
        self.subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID") or ""
        if not self.subscription_id:
            raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
        self.bench_rg = bench_rg or os.environ.get(BENCH_RG_ENV) or DEFAULT_BENCH_RG
        self.workspace = workspace or os.environ.get(WORKSPACE_ENV) or DEFAULT_WORKSPACE

    # transport
    def _headers(self) -> dict:
        if self._credential is None:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential()
        return {"Authorization": f"Bearer {self._credential.get_token(f'{ARM}/.default').token}"}

    def _client(self):
        if self._http is None:
            import requests
            self._http = requests
        return self._http

    def _call(self, method: str, path: str, api: str, *, params=None, body=None):
        r = getattr(self._client(), method)(
            f"{ARM}{path}", headers=self._headers(),
            params={"api-version": api, **(params or {})}, json=body, timeout=30)
        if not r.ok:
            # The error's code, not its message: the message names the subscription.
            try:
                code = (r.json().get("error") or {}).get("code") or ""
            except ValueError:
                code = ""
            what = f"{code} " if code else ""
            raise RuntimeError(f"HTTP {r.status_code} {what}on {method.upper()} "
                               f"…/{path.rsplit('/', 1)[-1]}")
        return r

    def experiment_id(self, name: str) -> str:
        return (f"/subscriptions/{self.subscription_id}/resourceGroups/{self.bench_rg}"
                f"/providers/Microsoft.Chaos/experiments/{name}")

    def workspace_id(self) -> str:
        return (f"/subscriptions/{self.subscription_id}/resourceGroups/{self.bench_rg}"
                f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace}")

    # reads
    def experiment(self, name: str) -> dict:
        return self._call("get", self.experiment_id(name), CHAOS_API).json()

    def executions(self, name: str) -> list[dict]:
        return self._call("get", f"{self.experiment_id(name)}/executions", CHAOS_API).json().get("value") or []

    def vm(self, vm_id: str) -> dict:
        return self._call("get", vm_id, COMPUTE_API, params={"$expand": "instanceView"}).json()

    def resource_group_tags(self, rg: str) -> dict:
        path = f"/subscriptions/{self.subscription_id}/resourcegroups/{rg}"
        return self._call("get", path, RESOURCES_API).json().get("tags") or {}

    def query(self, kql: str) -> list[dict]:
        r = self._call("post", f"{self.workspace_id()}/api/query", LOGS_API,
                       body={"query": kql, "timespan": "PT1H"})
        return _rows(r.json())

    # writes — the journal first
    def _before(self, action: str, target: str, detail: str = "") -> None:
        from eregion_core.orodruin import Passive
        if self._session is None:
            raise Passive(f"{action} on {target}: no armed Orodruin contract")
        self._session.before_call(action, target, detail)

    def start(self, name: str) -> None:
        self._before("chaos_start", self.experiment_id(name), name)
        self._call("post", f"{self.experiment_id(name)}/start", CHAOS_API)

    def cancel(self, name: str) -> None:
        self._before("chaos_cancel", self.experiment_id(name), name)
        self._call("post", f"{self.experiment_id(name)}/cancel", CHAOS_API)

    def start_vm(self, vm_id: str) -> None:
        self._before("start_vm", vm_id, "revert: the engine did not bring it back")
        self._call("post", f"{vm_id}/start", COMPUTE_API)
