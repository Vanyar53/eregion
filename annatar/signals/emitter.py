from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from annatar.signals.schema import Signal, severity_for_ttp

_PROVIDER_MAP: dict[str, str] = {
    "azure": "azure",
    "aws": "aws",
    "gcp": "gcp",
}

_RESOURCE_TYPE_MAP: dict[str, str] = {
    "vm": "vm",
    "storage": "storage",
    "network": "network",
}


def _provider(target: dict) -> str:
    resource_type = target.get("type", "")
    for prefix, provider in _PROVIDER_MAP.items():
        if resource_type.startswith(prefix + "_") or resource_type == prefix:
            return provider
    return "unknown"


def _resource_type(target: dict) -> str:
    resource_type = target.get("type", "")
    for suffix, rtype in _RESOURCE_TYPE_MAP.items():
        if resource_type.endswith("_" + suffix) or resource_type == suffix:
            return rtype
    return "unknown"


class SignalEmitter:
    def __init__(
        self,
        run_id: str,
        scenario_name: str,
        scenario_mitre: str,
        target: dict,
        resource_id: str,
        runs_dir: str | Path = "runs",
    ):
        self.run_id = run_id
        self.scenario_name = scenario_name
        self.scenario_mitre = scenario_mitre
        self.target = target
        self.resource_id = resource_id
        self._output = Path(runs_dir) / f"{run_id}_signals.jsonl"

    def emit(
        self,
        event: str,
        raw_signal: dict | None = None,
        metrics: dict | None = None,
    ) -> Signal:
        signal = Signal(
            signal_id=f"{self.run_id}_{event}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            provider=_provider(self.target),
            resource_id=self.resource_id,
            resource_type=_resource_type(self.target),
            ttp=self.scenario_mitre,
            severity=severity_for_ttp(self.scenario_mitre),
            event=event,
            raw_signal=raw_signal or {},
            context={
                "run_id": self.run_id,
                "scenario": self.scenario_name,
                **(metrics or {}),
            },
        )
        self._output.parent.mkdir(parents=True, exist_ok=True)
        with open(self._output, "a") as f:
            f.write(json.dumps(asdict(signal)) + "\n")
        return signal
