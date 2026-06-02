"""Persistent incident registry — groups signals by resource_id within a TTL window."""
from __future__ import annotations

import json
import os
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Incident:
    incident_id: str
    resource_id: str
    ttps: list
    started_at: str          # ISO8601
    last_signal_at: str      # ISO8601
    actions_taken: list      # [{action, timestamp, outcome_status}]
    signals_count: int
    state: str               # "active" | "resolved"


class IncidentRegistry:
    """Incident state grouped by resource_id, persisted to JSONL, TTL-bounded.

    Same resource_id within the TTL window = same incident.
    Past TTL or resolved = new incident on next signal.

    Thread-safe: multiple worker threads can call record_action concurrently.
    TTL controlled by GLORFINDEL_INCIDENT_TTL_S env var (default 300s).
    """

    _DEFAULT_TTL_S = 300
    _DEFAULT_PATH = Path.home() / ".glorfindel" / "incidents.jsonl"

    def __init__(
        self,
        path: Path | str | None = None,
        ttl_s: int | None = None,
    ):
        self._path = Path(path) if path else self._DEFAULT_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ttl_s = ttl_s or int(
            os.environ.get("GLORFINDEL_INCIDENT_TTL_S") or self._DEFAULT_TTL_S
        )
        self._lock = threading.Lock()

    def get_or_create(self, resource_id: str, ttp: str = "") -> Incident:
        """Return the active incident for resource_id, or open a new one."""
        with self._lock:
            active = self._find_active(resource_id)
            if active is not None:
                if ttp and ttp not in active.ttps:
                    active.ttps.append(ttp)
                active.signals_count += 1
                active.last_signal_at = _now_iso()
                self._rewrite_row(active)
                return active

            inc = Incident(
                incident_id=str(uuid.uuid4())[:8],
                resource_id=resource_id,
                ttps=[ttp] if ttp else [],
                started_at=_now_iso(),
                last_signal_at=_now_iso(),
                actions_taken=[],
                signals_count=1,
                state="active",
            )
            self._append(inc)
            return inc

    def record_action(
        self,
        incident_id: str,
        action: str,
        outcome_status: str,
        investigative_context: dict | None = None,
    ) -> None:
        """Append an action record to the incident.

        investigative_context: the raw_signal.investigative_context dict from the
        cycle that triggered this action — stored so subsequent LLM cycles can see
        what was investigated before the action was taken.
        """
        with self._lock:
            rows = self._load_all()
            for inc in rows:
                if inc.incident_id == incident_id:
                    entry: dict = {
                        "action": action,
                        "timestamp": _now_iso(),
                        "outcome_status": outcome_status,
                    }
                    if investigative_context:
                        entry["investigative_context"] = investigative_context
                    inc.actions_taken.append(entry)
                    break
            self._write_all(rows)

    def resolve(self, incident_id: str) -> None:
        """Mark an incident as resolved (will not be returned by get_or_create)."""
        with self._lock:
            rows = self._load_all()
            for inc in rows:
                if inc.incident_id == incident_id:
                    inc.state = "resolved"
                    break
            self._write_all(rows)

    def get_active(self, resource_id: str) -> Incident | None:
        """Return the active incident for resource_id if one exists within TTL."""
        with self._lock:
            return self._find_active(resource_id)

    # ── Private ────────────────────────────────────────────────────────────────

    def _find_active(self, resource_id: str) -> Incident | None:
        now = datetime.now(timezone.utc)
        for inc in reversed(self._load_all()):
            if inc.resource_id != resource_id or inc.state != "active":
                continue
            age_s = (now - datetime.fromisoformat(inc.last_signal_at)).total_seconds()
            if age_s <= self._ttl_s:
                return inc
        return None

    def _load_all(self) -> list[Incident]:
        if not self._path.exists():
            return []
        rows: list[Incident] = []
        for line in self._path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(Incident(**json.loads(line)))
                except Exception:
                    pass
        return rows

    def _append(self, inc: Incident) -> None:
        with open(self._path, "a") as f:
            f.write(json.dumps(asdict(inc), default=str) + "\n")

    def _rewrite_row(self, updated: Incident) -> None:
        rows = self._load_all()
        for i, inc in enumerate(rows):
            if inc.incident_id == updated.incident_id:
                rows[i] = updated
                break
        self._write_all(rows)

    def _write_all(self, rows: list[Incident]) -> None:
        with open(self._path, "w") as f:
            for inc in rows:
                f.write(json.dumps(asdict(inc), default=str) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
