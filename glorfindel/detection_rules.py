from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from glorfindel.detectors import detector_for  # noqa: E402  (after optional deps)

_STATUS_FILE = Path.home() / ".glorfindel" / "rule_status.json"


@dataclass
class DetectionRule:
    name: str
    source: str                    # "azure_monitor"
    workspace_id: str
    query: str
    ttp: str
    resource_id: str               # full Azure resource ID
    interval_s: float = 30.0      # how often to poll (seconds)
    enabled: bool = True
    description: str = ""


def load_rules(path: str | Path) -> list[DetectionRule]:
    """Load detection rules from a YAML file.

    Values using ${VAR} syntax are expanded from environment variables
    so workspace_id and resource_id can be set via .envrc without editing
    the YAML directly.
    """
    import os
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(os.path.expandvars(p.read_text()))
    if not data or not isinstance(data, dict):
        return []
    rules = []
    for item in data.get("rules", []):
        if not item.get("enabled", True):
            continue
        rules.append(DetectionRule(
            name=item["name"],
            source=item.get("source", "azure_monitor"),
            workspace_id=item["workspace_id"],
            query=item["query"],
            ttp=item.get("ttp", ""),
            resource_id=item["resource_id"],
            interval_s=float(item.get("interval_s", 30)),
            enabled=True,
            description=item.get("description", ""),
        ))
    return rules


def _load_status() -> dict:
    try:
        return json.loads(_STATUS_FILE.read_text()) if _STATUS_FILE.exists() else {}
    except Exception:
        return {}


def _save_status(status: dict) -> None:
    _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATUS_FILE.write_text(json.dumps(status, indent=2))


class RulePoller:
    """Polls detection rules continuously and dispatches detection signals.

    Each rule runs on its own timer. When a rule matches, a synthetic
    detection signal is dispatched via the provided callback so the
    agent can decide and act.
    """

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
