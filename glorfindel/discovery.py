"""Asset discovery service.

Runs in a background thread, queries monitoring backends (LAW Heartbeat,
Prometheus targets...) to populate the list of discovered assets.
Results are cached to disk and hot-reloaded by RulePoller and the API.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_CACHE_FILE = Path.home() / ".glorfindel" / "discovered_assets.json"


@dataclass
class DiscoveredAsset:
    """An asset discovered from a monitoring backend."""
    name: str                   # short name (VM hostname)
    resource_id: str            # full Azure resource ID (if resolvable)
    monitoring_backend: str     # backend that discovered this asset
    last_seen: str              # ISO timestamp
    source: str = "heartbeat"   # "heartbeat", "rsv", ...
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

    def all(self) -> list[DiscoveredAsset]:
        with self._lock:
            return list(self._assets.values())

    def for_backend(self, backend_name: str) -> list[DiscoveredAsset]:
        with self._lock:
            return [a for a in self._assets.values() if a.monitoring_backend == backend_name]

    def to_dicts(self) -> list[dict]:
        with self._lock:
            return [asdict(a) for a in self._assets.values()]

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps([asdict(a) for a in self._assets.values()], indent=2)
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


def _discover_from_azure_monitor(
    backend_name: str,
    workspace_id: str,
) -> list[DiscoveredAsset]:
    """Query LAW Heartbeat to find monitored VMs."""
    from glorfindel.detectors import detector_for
    now = time.time()
    try:
        detector = detector_for("azure_monitor", workspace_id=workspace_id)
        result = detector.poll_alert(
            query=_HEARTBEAT_QUERY.strip(),
            since=now - 7200,
            timeout_s=30,
            interval_s=5,
            verbose=False,
        )
        if result is None:
            return []
        # poll_alert returns first matching row — we need all rows
        # Use the underlying detector to run a full query
        raw = detector.run_query(_HEARTBEAT_QUERY.strip())
        assets = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for row in (raw or []):
            name = row.get("Computer") or row.get("computer", "")
            rid  = row.get("ResourceId") or row.get("resource_id", "")
            if not name:
                continue
            # Normalize VM name (remove FQDN suffix if any)
            short_name = name.split(".")[0]
            assets.append(DiscoveredAsset(
                name=short_name,
                resource_id=rid,
                monitoring_backend=backend_name,
                last_seen=now_iso,
                source="heartbeat",
                extra={"fqdn": name},
            ))
        return assets
    except Exception:
        return []


def _discover_from_backend(backend) -> list[DiscoveredAsset]:
    """Dispatch discovery to the right function based on backend type."""
    if backend.type == "azure_monitor":
        return _discover_from_azure_monitor(backend.name, backend.workspace_id)
    # Future: prometheus, splunk, cloudwatch...
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
        config,                     # GlorfindelConfig
        registry: AssetRegistry,
        dry_run: bool = False,
    ) -> None:
        self._config  = config
        self._registry = registry
        self._dry_run  = dry_run
        self._stop     = threading.Event()
        self._thread: threading.Thread | None = None

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
        """Run a single discovery cycle synchronously (for testing)."""
        self._discover_all()

    # ── Private ───────────────────────────────────────────────────────────────

    def _run(self) -> None:
        """Main discovery loop."""
        # Immediate first discovery at startup
        self._discover_all()

        # Then run on each backend's configured interval
        while not self._stop.is_set():
            # Sleep in small increments so stop() is responsive
            self._stop.wait(60)
            if self._stop.is_set():
                break
            self._discover_all()

    def _discover_all(self) -> None:
        for backend in self._config.monitoring_backends:
            if not backend.discovery.enabled:
                continue
            found = _discover_from_backend(backend)
            if found:
                self._registry.update(found)


# ── Singleton helpers ─────────────────────────────────────────────────────────

_registry: AssetRegistry | None = None
_service: DiscoveryService | None = None


def get_registry() -> AssetRegistry:
    global _registry
    if _registry is None:
        _registry = AssetRegistry()
    return _registry


def start_discovery(config, dry_run: bool = False) -> DiscoveryService:
    """Create and start the discovery service. Returns the service instance."""
    global _service, _registry
    _registry = AssetRegistry()
    svc = DiscoveryService(config, _registry, dry_run=dry_run)
    svc.start()
    _service = svc
    return svc
