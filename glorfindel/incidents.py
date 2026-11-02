"""Persistent incident registry — groups signals by resource_id within a TTL window."""
from __future__ import annotations

import contextlib
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

    Several writers: the worker threads of one watch, and other processes — the watch and
    `glorfindel respond` each hold a registry on the same file. Each read-modify-write holds
    a thread lock and an flock on `<file>.lock`, and the file is rewritten whole (temporary
    file + os.replace, owner-only): no incident lost between two writers, no reader ever sees
    half a file (SEC13, V-10 — as the escalations store, SEC3).
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

    @contextlib.contextmanager
    def _locked(self):
        """This registry's threads, then every process writing the same file."""
        from glorfindel.response.locks import _file_lock
        with self._lock, _file_lock(self._path.with_name(self._path.name + ".lock")):
            yield

    def get_or_create(self, resource_id: str, ttp: str = "") -> Incident:
        """Return the active incident for resource_id, or open a new one."""
        with self._locked():
            rows = self._load_all()
            active = self._find_active(resource_id, rows)
            if active is not None:
                if ttp and ttp not in active.ttps:
                    active.ttps.append(ttp)
                active.signals_count += 1
                active.last_signal_at = _now_iso()
                self._write_all(rows)
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
            self._write_all(rows + [inc])
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
        with self._locked():
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
        with self._locked():
            rows = self._load_all()
            for inc in rows:
                if inc.incident_id == incident_id:
                    inc.state = "resolved"
                    break
            self._write_all(rows)

    def get_active(self, resource_id: str) -> Incident | None:
        """Return the active incident for resource_id if one exists within TTL. A read: the
        file is only ever replaced whole, so no lock is needed to read a whole one."""
        with self._lock:
            return self._find_active(resource_id, self._load_all())

    # ── Private ────────────────────────────────────────────────────────────────

    def _find_active(self, resource_id: str, rows: list[Incident]) -> Incident | None:
        now = datetime.now(timezone.utc)
        for inc in reversed(rows):
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

    def _write_all(self, rows: list[Incident]) -> None:
        """The whole registry, through a temporary file: owner-only (0600), never half-written."""
        from glorfindel.response.state import _atomic_write_text
        _atomic_write_text(self._path, "".join(json.dumps(asdict(inc), default=str) + "\n" for inc in rows))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
