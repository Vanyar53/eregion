"""Gothmog's signals — ``fault_started``, ``fault_ended``, ``steady_state_restored``,
``revert_failed`` — in the shape of the injectors' signal (``eregion_core/signals.py``), but in a file
Glorfindel's watch does not read: ``runs/gothmog/<run_id>_signals.jsonl``.

The watch sends every event of ``runs/*_signals.jsonl`` but ``attack_started`` straight to
its decision graph (``glorfindel/cli.py``, ``_dispatch``): a ``fault_started`` there would
start a decision cycle on the declaration itself, on any host where the watch shares
``runs/``. Glorfindel learns of a fault by its exercise window (``kind: fault``) and by its
own telemetry — what a real outage would give it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

SIGNALS_SUBDIR = "gothmog"


class SignalEmitter:
    def __init__(self, run_id: str, fault_id: str, targets: list[str],
                 runs_dir: str | Path = "runs"):
        self.run_id = run_id
        self.fault_id = fault_id
        self.targets = list(targets)
        self.path = Path(runs_dir) / SIGNALS_SUBDIR / f"{run_id}_signals.jsonl"

    def emit(self, event: str, raw_signal: dict | None = None, metrics: dict | None = None) -> dict:
        signal = {
            "signal_id": f"{self.run_id}_{event}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "provider": "azure",
            "resource_id": self.targets[0] if len(self.targets) == 1 else "",
            "resource_type": "vm",
            "ttp": "",
            "severity": "info",
            "event": event,
            "raw_signal": raw_signal or {},
            "context": {"run_id": self.run_id, "fault": self.fault_id,
                        "targets": self.targets, **(metrics or {})},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(signal) + "\n")
        return signal
