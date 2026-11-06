"""The Stratus injector transport (R2): run the four phases of a resolved technique
(``annatar/engines/stratus.py``) through an armed Orodruin contract — every phase journaled by
``Session.before_call`` BEFORE the process starts and counted against the cap, exactly like the
VM executor (``annatar/executors/azure_vm.py``). The read-only Graph probe is journaled as a
declared read (``Session.declare``), never counted against the cap — it writes nothing.

Nothing runs without a session (passive → ``Passive``, nothing touched). In ``dry_run`` the
argv and the offline environment are shown, no process starts. The subprocess runner and the
Graph reader are injected (``run`` / ``get``), so the tests drive a FAKE Stratus binary with no
cloud call and no LLM call.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from rich.console import Console

from annatar.engines.stratus import ResolvedTechnique, airgap_env

console = Console()

GRAPH = "https://graph.microsoft.com"

# The staged layout inside the Orodruin image (annatar/stratus/README.md, make stratus-stage).
# Env overrides so the image can place them where it likes; the tests point them at a fake tree.
BINARY_ENV = "EREGION_STRATUS_BINARY"
HOME_ENV = "EREGION_STRATUS_HOME"
PLUGIN_CACHE_ENV = "EREGION_STRATUS_PLUGIN_CACHE"
TERRAFORMRC_ENV = "EREGION_STRATUS_TERRAFORMRC"

_DEFAULTS = {
    BINARY_ENV: "/opt/stratus/stratus",
    HOME_ENV: "/opt/stratus/home",
    PLUGIN_CACHE_ENV: "/opt/stratus/plugin-cache",
    TERRAFORMRC_ENV: "/opt/stratus/terraformrc",
}

# A Stratus phase can provision/destroy cloud infrastructure; give it room, but bounded.
PHASE_TIMEOUT_S = 900


@dataclass
class StagedLayout:
    binary: str
    home: str
    plugin_cache: str
    terraformrc: str


def staged_layout(env=None) -> StagedLayout:
    """Where the Orodruin image stages the pinned binary and the offline warmup assets, from the
    environment (``_DEFAULTS`` otherwise). Read by the runner (the binary, to resolve + verify
    before arming) and by this executor (the rest, for the offline environment)."""
    env = os.environ if env is None else env
    return StagedLayout(
        binary=env.get(BINARY_ENV) or _DEFAULTS[BINARY_ENV],
        home=env.get(HOME_ENV) or _DEFAULTS[HOME_ENV],
        plugin_cache=env.get(PLUGIN_CACHE_ENV) or _DEFAULTS[PLUGIN_CACHE_ENV],
        terraformrc=env.get(TERRAFORMRC_ENV) or _DEFAULTS[TERRAFORMRC_ENV],
    )


ARM = "https://management.azure.com"
_RG_API = "2021-04-01"


def _default_graph_get(path: str) -> dict:
    """A read-only GET of Microsoft Graph with this host's identity (Orodruin's, read-only in
    Graph by its contract). Not used in the tests, which inject ``get``."""
    import requests

    from azure.identity import DefaultAzureCredential
    token = DefaultAzureCredential().get_token(f"{GRAPH}/.default").token
    r = requests.get(f"{GRAPH}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} reading Microsoft Graph")
    return r.json()


def _default_arm_get(path: str, api: str) -> dict:
    """A read of Azure Resource Manager with this host's identity. Not used in the tests, which
    inject ``arm_get``."""
    import requests

    from azure.identity import DefaultAzureCredential
    token = DefaultAzureCredential().get_token(f"{ARM}/.default").token
    r = requests.get(f"{ARM}{path}", headers={"Authorization": f"Bearer {token}"},
                     params={"api-version": api}, timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} reading {path.rsplit('/', 1)[-1]}")
    return r.json()


class StratusExecutor:
    """Runs a resolved Stratus technique's phases from an armed Orodruin. One instance per run."""

    def __init__(self, resolved: ResolvedTechnique, session, *, target: str,
                 dry_run: bool = False, layout: StagedLayout | None = None,
                 run=None, get=None, arm_get=None):
        self.resolved = resolved
        self._session = session
        self.target = target          # the control-plane scope this run touches (journaled)
        self.dry_run = dry_run
        self.layout = layout or staged_layout()
        self._run = run or subprocess.run
        self._get = get or _default_graph_get
        self._arm_get = arm_get or _default_arm_get

    def resource_group_tags(self, subscription_id: str, resource_group: str) -> dict:
        """The bench group's tags, read through ARM — the control-plane enrollment guard
        (eregion_core/inscription.py). The reader (``arm_get``) is injected in the tests; a
        read that fails raises, so the run refuses before anything is provisioned."""
        path = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        body = self._arm_get(path, _RG_API)
        return (body.get("tags") if isinstance(body, dict) else {}) or {}

    def _env(self) -> dict[str, str]:
        """The process environment: the inherited one (Orodruin's Azure credentials) with the
        offline overrides layered on (annatar/engines/stratus.py::airgap_env)."""
        overrides = airgap_env(self.layout.home, plugin_cache=self.layout.plugin_cache,
                               terraformrc=self.layout.terraformrc)
        return {**os.environ, **overrides}

    def _before_call(self, phase: str, detail: str) -> None:
        """The journal precedes the call (O1) — a phase runs only from an armed contract."""
        from eregion_core.orodruin import Passive
        if self._session is None:
            raise Passive(f"stratus {phase} on {self.target}: no armed Orodruin contract")
        self._session.before_call(f"stratus:{phase}", self.target, detail)

    def run_phase(self, name: str) -> str:
        """Journal, then run one phase of the Stratus cycle (warmup/detonate/revert/cleanup).
        In dry_run nothing starts; the argv and the offline environment are shown."""
        phase = self.resolved.phase(name)
        if self.dry_run:   # nothing runs, so nothing is journaled against the contract
            console.print(f"  [yellow]DRY RUN[/yellow] stratus {name}: {' '.join(phase.argv)}")
            return ""
        self._before_call(name, phase.label)
        console.print(f"  [dim]Stratus → {name} : {self.resolved.technique_id}[/dim]")
        completed = self._run(phase.argv, env=self._env(), capture_output=True, text=True,
                              timeout=PHASE_TIMEOUT_S)
        out = (getattr(completed, "stdout", "") or "")
        err = (getattr(completed, "stderr", "") or "")
        if getattr(completed, "returncode", 0) != 0:
            raise RuntimeError(
                f"stratus {name} {self.resolved.technique_id} exited "
                f"{getattr(completed, 'returncode', '?')}: {err.strip()[-300:]}"
            )
        console.print(f"  [dim]{out.strip()[-200:]}[/dim]")
        return out

    def warmup(self) -> str:
        return self.run_phase("warmup")

    def detonate(self) -> str:
        return self.run_phase("detonate")

    def revert(self) -> str:
        return self.run_phase("revert")

    def cleanup(self) -> str:
        return self.run_phase("cleanup")

    def probe_initial_state(self, when: str) -> bool | None:
        """The read-only Graph probe (before detonate / after cleanup). ``None`` when the
        technique declares none. Journaled as a declared read (never counted against the cap);
        the request is held to a GET of a Graph read path by the adapter — this only reads."""
        probe = self.resolved.graph_probe
        if probe is None:
            return None
        method, path = probe.request()
        if method != "GET":   # the adapter guarantees GET; defend it here all the same
            raise RuntimeError(f"graph probe {probe.name!r}: {method} is not read-only")
        if self.dry_run:
            console.print(f"  [yellow]DRY RUN[/yellow] graph probe ({when}): GET {path}")
            return True
        if self._session is not None:
            self._session.declare(f"stratus:graph-probe:{when}", f"{probe.name} GET {path}")
        body = self._get(path)
        ok = probe.holds(body if isinstance(body, dict) else {})
        mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
        console.print(f"  {mark} graph probe {probe.name} ({when})")
        return ok
