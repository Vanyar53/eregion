"""Asset discovery service.

Runs in a background thread, queries monitoring backends (LAW Heartbeat,
Prometheus targets...) to populate the list of discovered assets.
Results are cached to disk and hot-reloaded by RulePoller and the API.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("glorfindel.discovery")

# Discovery (cheap LAW Heartbeat query) runs often for responsiveness — a VM
# powered on appears within this window. Posture checks (expensive RSV/NSG calls,
# one set per discovered VM) are throttled separately to interval_s, so the slow
# RSV API is not hammered every minute. See DiscoveryService._run.
_DISCOVERY_INTERVAL_S = 60.0
_DEFAULT_POSTURE_INTERVAL_S = 1800.0

_CACHE_FILE = Path.home() / ".glorfindel" / "discovered_assets.json"

# How long a VM that vanished from Heartbeat (e.g. powered off) is kept in the
# registry before eviction. Within this window it stays visible with a stale
# `last_seen` so the War Room can show it as "possibly offline" instead of
# dropping it (an auditor must not lose sight of a managed-but-off asset).
_DEFAULT_RETENTION_H = 8.0


def _retention_h() -> float:
    try:
        return float(os.environ.get("GLORFINDEL_DISCOVERY_RETENTION_H", _DEFAULT_RETENTION_H))
    except (TypeError, ValueError):
        return _DEFAULT_RETENTION_H


@dataclass
class DiscoveredAsset:
    """An asset discovered from a monitoring backend."""
    name: str               # short name (VM hostname)
    resource_id: str        # full Azure resource ID (if resolvable)
    monitoring_backend: str # backend that discovered this asset
    last_seen: str          # ISO timestamp
    source: str = "heartbeat"  # "heartbeat", "rsv", ...
    # kind/parent let the UI collapse scale-set members. A VMSS instance (e.g. an AKS
    # node) is one Heartbeat row each → N flapping cards otherwise. kind="vmss_instance"
    # + parent=<vmss resource id> = the grouping key; War Room shows 1 card per parent.
    # Defaults keep old cache files loadable (DiscoveredAsset(**item)).
    kind: str = "vm"        # "vm" | "vmss_instance"
    parent: str = ""        # grouping key — the VMSS resource id for instances
    extra: dict = field(default_factory=dict)  # backend-specific data


class AssetRegistry:
    """Thread-safe registry of discovered assets.

    Persisted to disk so discovery survives watch restarts.
    """

    def __init__(self, path: Path = _CACHE_FILE) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._assets: dict[str, DiscoveredAsset] = {}
        self._load()

    def update(self, assets: list[DiscoveredAsset]) -> None:
        with self._lock:
            for a in assets:
                self._assets[a.name] = a
            self._persist()

    def replace_for_backend(
        self,
        backend_name: str,
        assets: list[DiscoveredAsset],
        retention_h: float | None = None,
    ) -> None:
        """Refresh assets for a backend, retaining recently-seen offline VMs.

        A VM that drops out of Heartbeat (powered off) is NOT evicted immediately:
        it is kept — with its frozen `last_seen`, so the gap grows — until it has
        been gone longer than `retention_h` (default GLORFINDEL_DISCOVERY_RETENTION_H,
        8h). Only called with a real result list; a failed query keeps the whole
        cache upstream (found is None → no call), so this never confuses a query
        outage with a genuinely offline VM. Assets of other backends are untouched.
        """
        if retention_h is None:
            retention_h = _retention_h()
        now = datetime.now(timezone.utc)
        fresh_names = {a.name for a in assets}
        with self._lock:
            kept: dict[str, DiscoveredAsset] = {}
            for name, a in self._assets.items():
                if a.monitoring_backend != backend_name:
                    kept[name] = a            # other backends: leave as-is
                    continue
                if name in fresh_names:
                    continue                  # replaced by the fresh entry below
                # Vanished from this backend's Heartbeat — retain if still within window.
                try:
                    age_h = (now - datetime.fromisoformat(a.last_seen)).total_seconds() / 3600
                except (TypeError, ValueError):
                    age_h = retention_h + 1.0  # unparseable timestamp → evict
                if age_h < retention_h:
                    kept[name] = a            # keep stale (frozen last_seen)
            for a in assets:
                kept[a.name] = a              # fresh / updated entries win
            self._assets = kept
            self._persist()

    # Assets are returned sorted by name so the order is STABLE across discovery
    # refreshes. The heartbeat query has no guaranteed order, so without this the
    # registry rebuilds in a different order each cycle and the War Room cards
    # reshuffle on every auto-refresh.
    def _sorted(self) -> list[DiscoveredAsset]:
        return sorted(self._assets.values(), key=lambda a: a.name)

    def all(self) -> list[DiscoveredAsset]:
        with self._lock:
            return self._sorted()

    def for_backend(self, backend_name: str) -> list[DiscoveredAsset]:
        with self._lock:
            return [
                a for a in self._sorted()
                if a.monitoring_backend == backend_name
            ]

    def to_dicts(self) -> list[dict]:
        with self._lock:
            return [asdict(a) for a in self._sorted()]

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(a) for a in self._sorted()], indent=2)
        )

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            for item in json.loads(self._path.read_text()):
                a = DiscoveredAsset(**item)
                self._assets[a.name] = a
        except Exception:
            pass


# ── Discovery queries ─────────────────────────────────────────────────────────

_HEARTBEAT_QUERY = """
Heartbeat
| where TimeGenerated > ago(2h)
| summarize LastSeen = max(TimeGenerated) by Computer, _ResourceId, SourceComputerId
| where isnotempty(Computer)
| project Computer, ResourceId = _ResourceId, LastSeen
"""


def _normalize_last_seen(value, fallback: str) -> str:
    """Return an ISO-8601 string for the Heartbeat LastSeen value.

    Azure may return it as a datetime, an ISO string (often with a trailing 'Z'),
    or nothing. Normalised so AssetRegistry's retention can parse it with
    datetime.fromisoformat. Falls back to `fallback` (now) when absent/unparseable.
    """
    if value in (None, ""):
        return fallback
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    s = str(value).replace("Z", "+00:00")  # fromisoformat (3.11) handles Z, be safe
    try:
        datetime.fromisoformat(s)
        return s
    except ValueError:
        return fallback


def _classify_asset(resource_id: str) -> tuple[str, str]:
    """(kind, parent) for a discovered asset.

    A VMSS instance (e.g. an AKS node) has a resource_id of the form
    .../virtualMachineScaleSets/<vmss>/virtualMachines/<n>. Each instance is one
    Heartbeat row → N flapping cards otherwise. We tag it kind="vmss_instance" with
    parent=<vmss resource id> (the id truncated at /virtualMachines/) so the War Room
    can collapse all members of a scale set into one card. Standalone VMs → ("vm", "").
    """
    rid = resource_id or ""
    low = rid.lower()
    # Real-world AKS: the AMA heartbeat resolves every node's id to the AKS managed
    # cluster (Microsoft.ContainerService/managedClusters/<name>), shared by all nodes.
    # That shared id IS the grouping key → War Room collapses them into one card.
    if "/providers/microsoft.containerservice/managedclusters/" in low:
        return "aks_node", rid
    # Direct VMSS instance id (.../virtualMachineScaleSets/<vmss>/virtualMachines/<n>) —
    # seen when the heartbeat reports the instance rather than the cluster.
    marker = "/virtualmachinescalesets/"
    if marker in low and "/virtualmachines/" in low.split(marker, 1)[1]:
        # Parent = everything up to (and including) the VMSS name, before the instance.
        idx = low.index("/virtualmachines/", low.index(marker))
        return "vmss_instance", rid[:idx]
    return "vm", ""


def _discover_from_azure_monitor(
    backend_name: str,
    workspace_id: str,
) -> list[DiscoveredAsset] | None:
    """Query LAW Heartbeat to find monitored VMs.

    Returns a list (possibly empty) on success, None on query failure.
    Callers must treat None as "keep existing cache" — not as "zero assets".
    """
    from glorfindel.detectors import detector_for
    try:
        detector = detector_for("azure_monitor", workspace_id=workspace_id)
        raw = detector.run_query(_HEARTBEAT_QUERY.strip())
        assets = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for row in (raw or []):
            name = row.get("Computer") or row.get("computer", "")
            rid = row.get("ResourceId") or row.get("resource_id", "")
            if not name:
                continue
            short_name = name.split(".")[0]
            # Use the REAL last Heartbeat time (max(TimeGenerated) from the query),
            # NOT now: the ago(2h) window keeps a powered-off VM in results for 2h,
            # so writing `now` would freeze the gap at ~0 and defeat retention/OFFLINE.
            last_seen = _normalize_last_seen(
                row.get("LastSeen") or row.get("last_seen"), now_iso
            )
            kind, parent = _classify_asset(rid)
            assets.append(DiscoveredAsset(
                name=short_name,
                resource_id=rid,
                monitoring_backend=backend_name,
                last_seen=last_seen,
                source="heartbeat",
                kind=kind,
                parent=parent,
                extra={"fqdn": name},
            ))
        logger.info(
            "discovery: backend %s heartbeat → %d VM(s)", backend_name, len(assets)
        )
        return assets
    except Exception as e:
        # Query failed — caller keeps existing cache. Surface the cause: a silent
        # failure here looks identical to "no VMs", which hid real errors in the field.
        logger.warning(
            "discovery: backend %s heartbeat query failed (%s) — keeping cache",
            backend_name, e,
        )
        return None


def _discover_from_backend(backend) -> list[DiscoveredAsset] | None:
    """Dispatch discovery to the right function based on backend type.

    Returns None if the query failed (caller keeps existing cache).
    Returns [] if the backend returned no results (valid empty state).
    """
    if backend.type == "azure_monitor":
        return _discover_from_azure_monitor(backend.name, backend.workspace_id)
    # Unsupported backend — no results, not an error
    return []


# ── Discovery service ─────────────────────────────────────────────────────────

class DiscoveryService:
    """Background thread that periodically discovers assets from backends.

    Usage:
        svc = DiscoveryService(config, registry)
        svc.start()  # non-blocking
        # ... later ...
        svc.stop()
    """

    def __init__(
        self,
        config,                    # GlorfindelConfig
        registry: AssetRegistry,
        dry_run: bool = False,
        posture_checker=None,      # PostureChecker | None
    ) -> None:
        self._config = config
        self._registry = registry
        self._dry_run = dry_run
        self._posture_checker = posture_checker
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Posture cadence = interval_s of the first enabled backend (default 30min).
        # Discovery itself runs on the faster _DISCOVERY_INTERVAL_S for responsiveness.
        self._posture_interval_s = next(
            (b.discovery.interval_s for b in config.monitoring_backends
             if b.discovery.enabled),
            _DEFAULT_POSTURE_INTERVAL_S,
        )

    def start(self) -> None:
        """Start the discovery thread (non-blocking)."""
        if self._dry_run:
            return
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="glorfindel-discovery",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run_once(self) -> None:
        """Run a single discovery + posture cycle synchronously (for testing)."""
        self._discover_all()
        self._run_posture()

    # ── Private ───────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Main loop: discover often (responsive), run posture on a slower throttle.

        Discovery is a cheap LAW Heartbeat query — runs every _DISCOVERY_INTERVAL_S
        so a powered-on VM shows up quickly. Posture is expensive (RSV + NSG per VM)
        — runs only every interval_s, so the slow RSV API isn't hit every minute.
        """
        self._discover_all()
        self._run_posture()
        last_posture = time.monotonic()

        while not self._stop.is_set():
            self._stop.wait(_DISCOVERY_INTERVAL_S)
            if self._stop.is_set():
                break
            self._discover_all()
            if time.monotonic() - last_posture >= self._posture_interval_s:
                self._run_posture()
                last_posture = time.monotonic()

    def _discover_all(self) -> None:
        for backend in self._config.monitoring_backends:
            if not backend.discovery.enabled:
                continue
            found = _discover_from_backend(backend)
            if found is None:
                # Query failed — keep existing cache, do not evict
                continue
            self._registry.replace_for_backend(backend.name, found)

    def _run_posture(self) -> None:
        """Run posture checks (RSV/NSG per discovered VM) — best-effort."""
        if self._posture_checker is not None:
            assets = self._registry.all()
            logger.info("posture: checking %d discovered asset(s)", len(assets))
            try:
                self._posture_checker.check_and_escalate(assets)
            except Exception as e:
                logger.warning("posture: check failed (%s)", e)


# ── Singleton helpers ─────────────────────────────────────────────────────────

_registry: AssetRegistry | None = None
_service: DiscoveryService | None = None


def get_registry() -> AssetRegistry:
    global _registry
    if _registry is None:
        _registry = AssetRegistry()
    return _registry


def start_discovery(
    config, dry_run: bool = False, posture_checker=None
) -> DiscoveryService:
    """Create and start the discovery service. Returns the service instance."""
    global _service, _registry
    _registry = AssetRegistry()
    svc = DiscoveryService(
        config, _registry, dry_run=dry_run, posture_checker=posture_checker
    )
    svc.start()
    _service = svc
    return svc
