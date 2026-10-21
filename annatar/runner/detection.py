"""Which of Glorfindel's detection records count for an Annatar run, and how late (#157).

Pure functions on records — the lines of the ``runs/*_debug.jsonl`` files the watch writes
(the run's own file, from the poll of its ``attack_started``, and the RulePoller's
``watch-*`` files). The return channel (#159) will bring the same records from storage and
reuse :func:`detection_latency` as is.

A record counts for a run when it is a ``detection`` of the run's technique, on the run's
resource, seen **at or after** the attack. The resource is compared without case: Annatar
emits ARM's casing (``resourceGroups``, ``Microsoft.Compute``), Log Analytics writes its
``_ResourceId`` in lower case — compared as is, every RulePoller detection was a miss
(measured on the bench, 20/10). A detection seen before the attack is an earlier one on the
same VM and technique, never this run's; one whose time is unknown cannot be shown to come
after, so it does not count either. The campaign report (IA0, #167) bounds it from above
too — no later than the end of the run's exercise window, grace included
(:func:`first_detection`'s ``until``).

The latency starts at the run's ``attack_time`` (Annatar's T0, carried by
``attack_started``'s ``raw_signal``), never at the signal's own timestamp: on the atomic
path ``attack_started`` leaves about a minute after the command (after the effect proof).
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path


def _number(value) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def same_resource(a, b) -> bool:
    """Two Azure resource ids name the same resource (ARM ids are case-insensitive)."""
    a, b = str(a or "").strip().lower(), str(b or "").strip().lower()
    return bool(a) and a == b


def detection_time(signal: dict) -> float | None:
    """When Glorfindel saw the detection, as an epoch; ``None`` when the record does not say.

    The watch's poll of an ``attack_started`` keeps Annatar's signal — its ``timestamp`` is
    the ``attack_started`` emission, not the detection — and adds
    ``raw_signal.detection_time_s``, measured from ``raw_signal.attack_time``. A RulePoller
    detection is stamped (``timestamp``, ISO, UTC) when its poll saw the row.
    """
    raw = signal.get("raw_signal") or {}
    if isinstance(raw, dict):
        elapsed, start = raw.get("detection_time_s"), raw.get("attack_time")
        if _number(elapsed) and _number(start):
            return float(start) + float(elapsed)
    stamp = signal.get("timestamp")
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        seen = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if seen.tzinfo is None:  # Glorfindel stamps in UTC
        seen = seen.replace(tzinfo=timezone.utc)
    return seen.timestamp()


def detection_latency(records, ttp: str, resource_id: str, attack_time: float,
                      until: float | None = None) -> float | None:
    """Seconds from the attack to the earliest detection that counts for the run, else ``None``.

    ``0.0`` is a real latency (a detection in the same second), not a miss: test the result
    against ``None``. ``until``: see :func:`first_detection` (none by default, as before).
    """
    rec = first_detection(records, ttp, resource_id, attack_time, until)
    return None if rec is None else round(detection_time(rec["signal"]) - attack_time, 1)


def first_detection(records, ttp: str, resource_id: str, attack_time: float,
                    until: float | None = None) -> dict | None:
    """The earliest record that counts for the run (the rule above), else ``None``.

    ``until`` (an epoch) bounds it from above: a detection seen after it is not this run's.
    The campaign report (IA0, #167) passes the end of the run's exercise window plus its
    grace (``eregion_core.exercise.last_moment``): a later detection on the same VM and
    technique is a later exercise's, or a real incident's. ``None``: no upper bound — what
    the run's own wait has always done (#157).
    """
    best, best_seen = None, None
    for rec in records:
        signal = rec.get("signal") if isinstance(rec, dict) else None
        if not isinstance(signal, dict) or signal.get("event") != "detection":
            continue
        if signal.get("ttp") != ttp or not same_resource(signal.get("resource_id"), resource_id):
            continue
        seen = detection_time(signal)
        if seen is None or seen < attack_time:  # before the attack, or unknown: not this run's
            continue
        if until is not None and seen > until:  # after the window and its grace: not this run's
            continue
        if best_seen is None or seen < best_seen:
            best, best_seen = rec, seen
    return best


def has_timeout(records) -> bool:
    """The watch gave up on the run (``detection_timeout`` in its own file)."""
    return any(isinstance(rec, dict) and isinstance(rec.get("signal"), dict)
               and rec["signal"].get("event") == "detection_timeout" for rec in records)


def read_records(path: Path) -> list[dict]:
    """The JSON lines of a debug file; unreadable lines are skipped, a missing file is ``[]``."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            records.append(rec)
    return records
