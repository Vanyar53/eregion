"""Exercise windows (B2): an injector says when, and against what, it exercises; Glorfindel
reads from them the source of a cycle — ``exercise`` or ``real``.

An injector (Annatar today, Gothmog with G0) opens a window before it touches its target
and closes it when its run ends. A cycle is an ``exercise`` when its VM is one of a
window's targets and its time falls inside the window — from its start to its end, plus a
grace for the detection lag (the RulePoller sees a technique minutes after it ran). The
source goes to the memory and to the escalation card: the observation report leaves the
exercises out, and a card never merges an exercise with a real detection. The model does
not see it yet — showing it changes what it reasons on (end-to-end run with Jonathan).

The label never lowers a guard, and a window only marks what it names, for a bounded
time: a window carries an expiry, so an injector that dies leaves a window that lapses,
never an open-ended one — a real incident a day later is never taken for an exercise.

Files: one JSON per run under ``runs/exercises/`` (or ``EREGION_EXERCISES_DIR``), where
the injector and the watch share ``runs/``. A watch on another host (H0) gets them through
the exercise channel (``eregion_core/exercise_channel.py``, O1): the injector publishes
each window it writes, the watch pulls them before it reads.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

# A run that outlives this was not closed (the injector died): its window lapses.
MAX_DURATION_S = 2 * 3600
# Detections arrive after the technique: the RulePoller's period plus Log Analytics
# ingestion (84 s to 3 min 30 measured on the bench, 05–07/10), with margin.
GRACE_AFTER_S = 15 * 60

EXERCISE, REAL, UNKNOWN = "exercise", "real", "unknown"


def exercises_dir() -> Path:
    return Path(os.environ.get("EREGION_EXERCISES_DIR") or Path("runs") / "exercises")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _write(path: Path, window: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(window, indent=2), encoding="utf-8")
    tmp.replace(path)  # atomic: the watch never reads half a window


def _publish(window: dict) -> None:
    """Carry the window to a watch on another host, when a channel is configured. A failure
    is reported, never raised: the run goes on, its cycles fall toward ``real``."""
    from eregion_core import exercise_channel
    try:
        exercise_channel.publish(window)
    except Exception as e:
        print(f"[exercise-channel] window {window.get('run_id')} not published: {e}")


def open_window(run_id: str, *, injector: str, kind: str, experiment: str,
                targets: list[str], max_duration_s: float = MAX_DURATION_S,
                now: datetime | None = None, directory: Path | None = None) -> dict:
    """Declare that ``run_id`` exercises ``targets`` from now, for at most ``max_duration_s``."""
    start = now or _now()
    window = {
        "run_id": run_id,
        "injector": injector,
        "kind": kind,
        "experiment": experiment,
        "targets": [t.lower() for t in targets if t],
        "start": start.isoformat(),
        "end": None,
        "expires": (start + timedelta(seconds=max_duration_s)).isoformat(),
    }
    _write((directory or exercises_dir()) / f"{run_id}.json", window)
    _publish(window)
    return window


def close_window(run_id: str, *, now: datetime | None = None,
                 directory: Path | None = None) -> dict | None:
    """The run is over: its window ends now (detections still count during the grace)."""
    path = (directory or exercises_dir()) / f"{run_id}.json"
    try:
        window = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    window["end"] = (now or _now()).isoformat()
    _write(path, window)
    _publish(window)
    return window


def load_windows(directory: Path | None = None) -> list[dict]:
    """Every readable window; a malformed file is skipped, never fatal. The default
    directory is refreshed from the exercise channel first, when one is configured."""
    if directory is None:
        from eregion_core import exercise_channel
        exercise_channel.pull_if_due(exercises_dir())
    d = directory or exercises_dir()
    if not d.is_dir():
        return []
    out = []
    for path in sorted(d.glob("*.json")):
        try:
            w = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(w, dict) and w.get("run_id") and w.get("start"):
            out.append(w)
    return out


def live(window: dict, when: datetime) -> bool:
    """The window is open at ``when``, or closed but still in its grace."""
    start, expires = _parse(window.get("start")), _parse(window.get("expires"))
    if start is None or expires is None:
        return False
    end = _parse(window.get("end")) or expires
    # A window closed late still lapses at its expiry.
    last = min(end, expires) + timedelta(seconds=GRACE_AFTER_S)
    return start <= when <= last


def _covers(window: dict, resource_id: str, when: datetime) -> bool:
    return resource_id.lower() in (window.get("targets") or []) and live(window, when)


def covering_runs(resource_id: str, when, windows: list[dict]) -> list[str]:
    """The run_id of every window that covers this VM at ``when`` — all of them, where
    ``source_of`` stops at the first."""
    at = _parse(when)
    if not resource_id or at is None:
        return []
    return [w["run_id"] for w in windows if _covers(w, resource_id, at)]


def source_of(resource_id: str, when=None, *, run_id: str = "",
              windows: list[dict] | None = None) -> tuple[str, str]:
    """(``exercise``, its run_id) when a window covers this VM at ``when``; else (``real``, "").

    A signal carrying the run_id of a declared window (Annatar's own attack_started) is an
    exercise whatever its time. Without a resource or a readable time: (``unknown``, "").
    """
    ws = load_windows() if windows is None else windows
    if run_id and any(w.get("run_id") == run_id for w in ws):
        return EXERCISE, run_id
    at = _parse(when) if when is not None else _now()
    if not resource_id or at is None:
        return UNKNOWN, ""
    for w in ws:
        if _covers(w, resource_id, at):
            return EXERCISE, w["run_id"]
    return REAL, ""
