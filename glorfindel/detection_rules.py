from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from glorfindel.detectors import detector_for  # noqa: E402  (after optional deps)

_STATUS_FILE = Path.home() / ".glorfindel" / "rule_status.json"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class MonitoringBackend:
    """A monitoring engine (LAW workspace, Prometheus endpoint, ...)."""
    name: str
    type: str                  # "azure_monitor", "prometheus", "splunk", ...
    workspace_id: str = ""     # LAW workspace GUID or Prometheus endpoint URL
    endpoint: str = ""         # generic endpoint for non-Azure backends


@dataclass
class Asset:
    """A monitored infrastructure asset (VM, backup vault, storage, ...)."""
    name: str
    type: str                              # "azure_vm", "azure_backup_vault", ...
    resource_id: str = ""                  # full Azure resource ID (VMs, storage)
    monitoring_backends: list[str] = field(default_factory=list)
    # Fields specific to azure_backup_vault
    vault_name: str = ""                   # vault short name (rsv-annatar)
    resource_group: str = ""               # resource group of the vault


@dataclass
class DetectionRule:
    """A detection rule — query + metadata.

    workspace_id and resource_id are resolved at load time (from explicit
    assets) or at runtime (from discovered assets when auto_apply=True).
    """
    name: str
    source: str                # "azure_monitor" | "prometheus" | ...
    workspace_id: str          # resolved from MonitoringBackend
    query: str
    ttp: str
    resource_id: str           # resolved from Asset (empty if auto_apply)
    interval_s: float = 30.0
    enabled: bool = True
    description: str = ""
    # references
    asset_name: str = ""
    monitoring_backend_name: str = ""
    # auto_apply: True when no explicit assets — applies to all discovered
    # assets for the monitoring_backend (filtered by GlorfindelConfig.exceptions)
    auto_apply: bool = False


@dataclass
class DetectionConfig:
    """Full detection configuration parsed from detection_rules.yaml."""
    backends: list[MonitoringBackend]
    assets: list[Asset]
    rules: list[DetectionRule]

    def backend(self, name: str) -> MonitoringBackend | None:
        return next((b for b in self.backends if b.name == name), None)

    def asset(self, name: str) -> Asset | None:
        return next((a for a in self.assets if a.name == name), None)

    def asset_for_resource(self, resource_id: str) -> Asset | None:
        return next((a for a in self.assets if a.resource_id == resource_id), None)


# ── Loading ────────────────────────────────────────────────────────────────────

def load_config(path: str | Path, glorfindel_cfg=None) -> DetectionConfig:
    """Load detection configuration from YAML.

    glorfindel_cfg (GlorfindelConfig | None): when provided, monitoring backend
    workspace_id and endpoint are resolved from it — detection_rules.yaml only
    needs backend names, not connection details (single source of truth).

    Supports two formats:
    - New (recommended): assets + rules sections, backends from glorfindel_cfg.
    - Legacy: rules with workspace_id and resource_id inline.
      Backward-compatible so existing configs and tests continue to work.
    """
    import os
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    p = Path(path)
    if not p.exists():
        return DetectionConfig(backends=[], assets=[], rules=[])
    raw = os.path.expandvars(p.read_text())
    data = yaml.safe_load(raw)
    if not data or not isinstance(data, dict):
        return DetectionConfig(backends=[], assets=[], rules=[])

    # ── Build backend lookup ──────────────────────────────────────────────────
    # glorfindel_cfg is the source of truth for connection details (workspace_id,
    # endpoint). YAML monitoring_backends (if present) supplement for legacy configs.
    backend_by_name: dict[str, MonitoringBackend] = {}
    if glorfindel_cfg:
        for b in glorfindel_cfg.monitoring_backends:
            backend_by_name[b.name] = MonitoringBackend(
                name=b.name,
                type=b.type,
                workspace_id=b.workspace_id,
                endpoint=b.endpoint,
            )
    for b in data.get("monitoring_backends", []):
        if b["name"] not in backend_by_name:
            backend_by_name[b["name"]] = MonitoringBackend(
                name=b["name"],
                type=b.get("type", "azure_monitor"),
                workspace_id=b.get("workspace_id", ""),
                endpoint=b.get("endpoint", ""),
            )
    backends = list(backend_by_name.values())

    # ── Parse assets ──────────────────────────────────────────────────────────
    assets: list[Asset] = []
    for a in data.get("assets", []):
        assets.append(Asset(
            name=a["name"],
            type=a.get("type", "azure_vm"),
            resource_id=a.get("resource_id", ""),
            monitoring_backends=a.get("monitoring_backends", []),
            vault_name=a.get("vault_name", ""),
            resource_group=a.get("resource_group", ""),
        ))

    asset_by_name = {a.name: a for a in assets}

    # ── Parse rules ───────────────────────────────────────────────────────────
    rules: list[DetectionRule] = []
    for item in data.get("rules", []):
        if not item.get("enabled", True):
            continue

        rule_assets  = item.get("assets", [])
        rule_backends = item.get("monitoring_backends", [])

        # Detect auto-apply: no explicit assets → apply to all discovered assets
        auto_apply = not rule_assets or rule_assets == ["auto"]

        # Resolve the primary backend
        if rule_backends:
            primary_backend_name = rule_backends[0]
        elif item.get("monitoring_backend"):
            primary_backend_name = item["monitoring_backend"]
        else:
            primary_backend_name = ""

        primary_backend = backend_by_name.get(primary_backend_name)

        if not auto_apply and (backends or assets):
            # Explicit assets: resolve workspace_id and resource_id from graph
            primary_asset_name = rule_assets[0] if rule_assets else ""
            primary_asset = asset_by_name.get(primary_asset_name)
            resource_id = primary_asset.resource_id if primary_asset else item.get("resource_id", "")
            if not primary_backend_name and primary_asset and primary_asset.monitoring_backends:
                primary_backend_name = primary_asset.monitoring_backends[0]
                primary_backend = backend_by_name.get(primary_backend_name)
            workspace_id = (
                primary_backend.workspace_id if primary_backend
                else item.get("workspace_id", "")
            )
            source = primary_backend.type if primary_backend else item.get("source", "azure_monitor")
        elif not auto_apply:
            # Legacy inline format
            workspace_id = item.get("workspace_id", "")
            resource_id  = item.get("resource_id", "")
            source       = item.get("source", "azure_monitor")
            primary_asset_name = ""
        else:
            # Auto-apply: workspace_id from backend, resource_id filled at runtime
            workspace_id = primary_backend.workspace_id if primary_backend else item.get("workspace_id", "")
            source       = primary_backend.type if primary_backend else item.get("source", "azure_monitor")
            resource_id  = ""
            primary_asset_name = ""

        rules.append(DetectionRule(
            name=item["name"],
            source=source,
            workspace_id=workspace_id,
            query=item["query"],
            ttp=item.get("ttp", ""),
            resource_id=resource_id,
            interval_s=float(item.get("interval_s", 30)),
            enabled=True,
            description=item.get("description", ""),
            asset_name=primary_asset_name,
            monitoring_backend_name=primary_backend_name,
            auto_apply=auto_apply,
        ))

    return DetectionConfig(backends=backends, assets=assets, rules=rules)


def load_rules(path: str | Path, glorfindel_cfg=None) -> list[DetectionRule]:
    """Return only the rules from a detection config file. Backward-compatible."""
    return load_config(path, glorfindel_cfg=glorfindel_cfg).rules


# ── Status persistence ────────────────────────────────────────────────────────

def _load_status() -> dict:
    try:
        return json.loads(_STATUS_FILE.read_text()) if _STATUS_FILE.exists() else {}
    except Exception:
        return {}


def _save_status(status: dict) -> None:
    _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATUS_FILE.write_text(json.dumps(status, indent=2))


# ── RulePoller ────────────────────────────────────────────────────────────────

class RulePoller:
    """Polls detection rules continuously and dispatches detection signals."""

    def __init__(
        self,
        rules: list[DetectionRule],
        dispatch: Callable[[dict], None],
        dry_run: bool = False,
    ) -> None:
        self._rules = rules
        self._dispatch = dispatch
        self._dry_run = dry_run
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._status: dict = _load_status()
        self._lock = threading.Lock()
        # Dedup: key = f"{rule.name}@{resource_id}", value = last dispatched row TimeGenerated
        self._last_dispatch_row: dict[str, str] = {}

    def expand_for_discovered(
        self,
        registry,              # AssetRegistry
        glorfindel_cfg=None,   # GlorfindelConfig | None
    ) -> None:
        """Expand auto_apply rules against currently discovered assets.

        Starts new poll threads for each (rule, asset) pair not yet running.
        Safe to call multiple times — skips already-running combinations.
        """
        from glorfindel.discovery import AssetRegistry as _Reg
        running_keys = {t.name for t in self._threads if t.is_alive()}

        for rule in self._rules:
            if not rule.auto_apply:
                continue
            discovered = registry.for_backend(rule.monitoring_backend_name)
            for asset in discovered:
                if glorfindel_cfg and glorfindel_cfg.is_excluded(asset.name, rule.name):
                    continue
                key = f"rule-{rule.name}@{asset.name}"
                if key in running_keys:
                    continue
                # Materialise a concrete rule for this asset
                concrete = DetectionRule(
                    name=rule.name,
                    source=rule.source,
                    workspace_id=rule.workspace_id,
                    query=rule.query,
                    ttp=rule.ttp,
                    resource_id=asset.resource_id,
                    interval_s=rule.interval_s,
                    enabled=True,
                    description=rule.description,
                    asset_name=asset.name,
                    monitoring_backend_name=rule.monitoring_backend_name,
                    auto_apply=False,
                )
                t = threading.Thread(
                    target=self._poll_rule,
                    args=(concrete, registry),
                    daemon=True,
                    name=key,
                )
                self._threads.append(t)
                t.start()

    def start(self) -> None:
        for rule in self._rules:
            if rule.auto_apply:
                continue  # expanded later via expand_for_discovered()
            t = threading.Thread(
                target=self._poll_rule,
                args=(rule,),
                daemon=True,
                name=f"rule-{rule.name}",
            )
            self._threads.append(t)
            t.start()

    def stop(self) -> None:
        self._stop.set()

    def status_snapshot(self) -> list[dict]:
        with self._lock:
            out = []
            for rule in self._rules:
                s = self._status.get(rule.name, {})
                out.append({
                    "name": rule.name,
                    "ttp": rule.ttp,
                    "source": rule.source,
                    "workspace_id": rule.workspace_id,
                    "resource_id": rule.resource_id,
                    "asset_name": rule.asset_name,
                    "monitoring_backend_name": rule.monitoring_backend_name,
                    "interval_s": rule.interval_s,
                    "description": rule.description,
                    "last_poll": s.get("last_poll", ""),
                    "last_match": s.get("last_match", ""),
                    "last_error": s.get("last_error", ""),
                    "match_count": s.get("match_count", 0),
                })
            return out

    def _poll_rule(self, rule: DetectionRule, registry=None) -> None:
        while not self._stop.is_set():
            # Self-evict: stop polling if this asset was removed from registry
            if registry is not None and rule.asset_name:
                if not any(a.name == rule.asset_name for a in registry.for_backend(rule.monitoring_backend_name)):
                    return
            now_iso = datetime.now(timezone.utc).isoformat()
            try:
                detector = detector_for(rule.source, workspace_id=rule.workspace_id)
                since = time.time() - rule.interval_s * 2
                result = detector.poll_alert(
                    query=rule.query,
                    since=since,
                    timeout_s=rule.interval_s * 0.8,
                    interval_s=min(rule.interval_s * 0.8, 10.0),
                    verbose=False,
                )
                with self._lock:
                    self._status.setdefault(rule.name, {})
                    self._status[rule.name]["last_poll"] = now_iso
                    self._status[rule.name].pop("last_error", None)
                    if result is not None:
                        _elapsed, row = result
                        self._status[rule.name]["last_match"] = now_iso
                        self._status[rule.name]["match_count"] = (
                            self._status[rule.name].get("match_count", 0) + 1
                        )
                    _save_status(self._status)

                if result is not None:
                    _elapsed, row = result

                    # Deduplication: KQL queries use ago(5m) windows, so the same
                    # event row reappears across multiple poll cycles. Skip dispatch
                    # if TimeGenerated is identical to the last dispatched row for
                    # this (rule, resource_id) pair.
                    dedup_key = f"{rule.name}@{rule.resource_id}"
                    row_ts = str(row.get("TimeGenerated", ""))
                    with self._lock:
                        last_ts = self._last_dispatch_row.get(dedup_key, "")
                    if row_ts and row_ts == last_ts:
                        self._stop.wait(rule.interval_s)
                        continue

                    with self._lock:
                        self._last_dispatch_row[dedup_key] = row_ts

                    # Synthetic run_id so store_cycle writes a debug JSONL
                    # and War Room can display the decision (isolate_vm, block…).
                    # Format: watch-{rule}-{ts} to distinguish from Annatar runs.
                    ts_compact = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    watch_run_id = f"watch-{rule.name}-{ts_compact}"
                    signal = {
                        "signal_id": f"rule-{rule.name}-{uuid.uuid4().hex[:8]}",
                        "event": "detection",
                        "ttp": rule.ttp,
                        "severity": "high",
                        "resource_id": rule.resource_id,
                        "resource_type": "vm",
                        "provider": "azure",
                        "timestamp": now_iso,
                        "context": {
                            "workspace_id": rule.workspace_id,
                            "rule_name": rule.name,
                            "asset_name": rule.asset_name,
                            "run_id": watch_run_id,
                        },
                        "raw_signal": {
                            "detection_source": rule.source,
                            "first_result_row": row,
                        },
                    }
                    if not self._dry_run:
                        self._dispatch(signal)

            except Exception as exc:
                with self._lock:
                    self._status.setdefault(rule.name, {})
                    self._status[rule.name]["last_poll"] = now_iso
                    self._status[rule.name]["last_error"] = str(exc)
                    _save_status(self._status)

            self._stop.wait(rule.interval_s)
