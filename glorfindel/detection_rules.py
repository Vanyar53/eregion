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
    """A monitored infrastructure asset (VM, Storage account, ...)."""
    name: str
    type: str                              # "azure_vm", "azure_storage", ...
    resource_id: str = ""                  # full Azure resource ID
    monitoring_backends: list[str] = field(default_factory=list)  # backend names


@dataclass
class DetectionRule:
    """A detection rule — query + metadata.

    workspace_id and resource_id are resolved at load time from the
    referenced asset and monitoring backend. Rules never hardcode them.
    """
    name: str
    source: str                # "azure_monitor" | "prometheus" | ...
    workspace_id: str          # resolved from MonitoringBackend
    query: str
    ttp: str
    resource_id: str           # resolved from Asset
    interval_s: float = 30.0
    enabled: bool = True
    description: str = ""
    # references (set at load time, empty for old-format rules)
    asset_name: str = ""
    monitoring_backend_name: str = ""


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

def load_config(path: str | Path) -> DetectionConfig:
    """Load detection configuration from YAML.

    Supports two formats:
    - New (recommended): monitoring_backends + assets + rules sections.
      workspace_id and resource_id are resolved from the asset/backend graph.
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

    # ── Parse backends ────────────────────────────────────────────────────────
    backends: list[MonitoringBackend] = []
    for b in data.get("monitoring_backends", []):
        backends.append(MonitoringBackend(
            name=b["name"],
            type=b.get("type", "azure_monitor"),
            workspace_id=b.get("workspace_id", ""),
            endpoint=b.get("endpoint", ""),
        ))

    # ── Parse assets ──────────────────────────────────────────────────────────
    assets: list[Asset] = []
    for a in data.get("assets", []):
        assets.append(Asset(
            name=a["name"],
            type=a.get("type", "azure_vm"),
            resource_id=a.get("resource_id", ""),
            monitoring_backends=a.get("monitoring_backends", []),
        ))

    backend_by_name = {b.name: b for b in backends}
    asset_by_name   = {a.name: a  for a in assets}

    # ── Parse rules ───────────────────────────────────────────────────────────
    rules: list[DetectionRule] = []
    for item in data.get("rules", []):
        if not item.get("enabled", True):
            continue

        rule_assets = item.get("assets", [])
        rule_backends = item.get("monitoring_backends", [])

        # New format: resolve workspace_id and resource_id from references
        if rule_assets or rule_backends or backends or assets:
            # Resolve the primary asset
            primary_asset_name = rule_assets[0] if rule_assets else ""
            primary_asset = asset_by_name.get(primary_asset_name)
            resource_id = primary_asset.resource_id if primary_asset else item.get("resource_id", "")

            # Resolve the primary backend (from rule override or from asset)
            if rule_backends:
                primary_backend_name = rule_backends[0]
            elif primary_asset and primary_asset.monitoring_backends:
                primary_backend_name = primary_asset.monitoring_backends[0]
            else:
                primary_backend_name = ""
            primary_backend = backend_by_name.get(primary_backend_name)
            workspace_id = (
                primary_backend.workspace_id if primary_backend
                else item.get("workspace_id", "")
            )
            source = (
                primary_backend.type if primary_backend
                else item.get("source", "azure_monitor")
            )
        else:
            # Legacy format: workspace_id and resource_id are inline
            workspace_id = item.get("workspace_id", "")
            resource_id  = item.get("resource_id", "")
            source       = item.get("source", "azure_monitor")
            primary_asset_name   = ""
            primary_backend_name = ""

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
        ))

    return DetectionConfig(backends=backends, assets=assets, rules=rules)


def load_rules(path: str | Path) -> list[DetectionRule]:
    """Return only the rules from a detection config file. Backward-compatible."""
    return load_config(path).rules


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

    def start(self) -> None:
        for rule in self._rules:
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

    def _poll_rule(self, rule: DetectionRule) -> None:
        while not self._stop.is_set():
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
