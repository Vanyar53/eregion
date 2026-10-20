"""The return channel (#159): what the hosted watch (Glorfindel, H0) tells a run launched
from Orodruin — its heartbeat, and its detections of the VMs that run exercises.

The exercise channel (eregion_core/exercise_channel.py) the other way round: a blob
container reached by managed identity only, where the watch's identity writes and
Orodruin's reads — the contract refuses Orodruin any write on it, so an injector never
writes what the watch says (eregion_core/orodruin.py). ``EREGION_WATCH_CHANNEL`` is the
container's URL (``https://<account>.blob.core.windows.net/watch``); unset or empty,
nothing is published or read, and a run sees only the local watch files, as before.

Two kinds of blob:

- ``heartbeat.json`` — ``at`` (when written), ``since`` (when the watch started) and
  ``windows`` (the run_id of every exercise window open or in grace that the watch knows).
  Written only once every detection noted so far is delivered: a heartbeat vouches for
  what came before it.
- ``detections/<run_id>/<signal_id>.json`` — one per (window, detection), only for a VM
  the watch attributed the detection to and that a window covers at the detection's time.
  Never the rest of the fleet.

Every failure falls toward ``unknown``, never ``detected`` nor ``missed``: a run concludes
to a miss only on a heartbeat written after its wait, by a watch up since before the
attack, that knows the run's window (``miss_unprovable``).
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from eregion_core.exercise import (GRACE_AFTER_S, MAX_DURATION_S, covering_runs, live,
                                   load_windows)
from eregion_core.exercise_channel import auth_headers

CHANNEL_ENV = "EREGION_WATCH_CHANNEL"
HEARTBEAT = "heartbeat.json"
DETECTIONS = "detections"
TICK_S = 5.0
HEARTBEAT_EVERY_S = 60.0
# The local heartbeat's own test (annatar/runner/engine.py): older than this, no watch.
FRESH_S = 90.0
# A detection waits for its window as long as a window could still cover it.
KEEP_S = MAX_DURATION_S + GRACE_AFTER_S
# A blob name part: a run_id or a signal_id, never a path.
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def channel_url() -> str:
    return (os.environ.get(CHANNEL_ENV) or "").strip().rstrip("/")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _when(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── The watch's side ───────────────────────────────────────────────────────────────

class Publisher:
    """``note`` each detection as the RulePoller dispatches it (memory only, never fails);
    ``tick`` delivers what a window covers, then beats once nothing is left to deliver.
    A detection seen before its window is delivered when the window arrives."""

    def __init__(self, channel: str, *, credential=None, put=None, windows=None,
                 now: datetime | None = None):
        self.channel = channel
        self._credential = credential
        self._put = put
        self._windows = windows or load_windows
        self.since = (now or _now()).isoformat()
        self._lock = threading.Lock()
        self._noted: list[dict] = []
        self._sent: set[tuple[str, str]] = set()
        self._last_beat: datetime | None = None
        self.last_error = ""

    def note(self, signal: dict) -> None:
        try:
            self._note(signal)
        except Exception as e:  # never into the RulePoller
            # A detection lost is a restart of what the watch can vouch for: no run
            # attacked before now can conclude to a miss.
            self.since = _now().isoformat()
            self._report(f"detection not noted: {e}")

    def _note(self, signal: dict) -> None:
        ctx = signal.get("context") or {}
        # An unattributed row is anchored on an arbitrary VM: it names none.
        if signal.get("event") != "detection" or ctx.get("attribution") != "asset":
            return
        record = {
            "event": "detection",
            "signal_id": re.sub(r"[^A-Za-z0-9_.-]", "_", str(signal.get("signal_id") or "")),
            "ttp": signal.get("ttp", ""),
            "resource_id": signal.get("resource_id", ""),
            "detected_at": signal.get("timestamp", ""),
            "rule": ctx.get("rule_name", ""),
            "watch_run_id": ctx.get("run_id", ""),
        }
        if not _SAFE.match(record["signal_id"]):
            return
        with self._lock:
            self._noted.append(record)

    def tick(self, now: datetime | None = None) -> None:
        now = now or _now()
        windows = [w for w in self._windows() if _SAFE.match(str(w.get("run_id", "")))]
        with self._lock:
            self._noted = [r for r in self._noted
                           if (at := _when(r["detected_at"])) is not None
                           and (now - at).total_seconds() <= KEEP_S]
            noted = list(self._noted)
        kept = {r["signal_id"] for r in noted}
        self._sent = {s for s in self._sent if s[1] in kept}

        waiting = 0
        for r in noted:
            for run in covering_runs(r["resource_id"], r["detected_at"], windows):
                if (run, r["signal_id"]) in self._sent:
                    continue
                try:
                    self._write(f"{DETECTIONS}/{run}/{r['signal_id']}.json",
                                {**r, "exercise_run": run})
                    self._sent.add((run, r["signal_id"]))
                except Exception as e:
                    waiting += 1
                    self._report(f"detection {r['signal_id']} for {run} not delivered: {e}")
        if waiting:
            return  # no heartbeat while a detection waits: it would vouch for a miss
        if self._last_beat and (now - self._last_beat).total_seconds() < HEARTBEAT_EVERY_S:
            return
        self._write(HEARTBEAT, {
            "at": now.isoformat(),
            "since": self.since,
            "windows": sorted(w["run_id"] for w in windows if live(w, now)),
        })
        self._last_beat = now
        self._report("")

    def _write(self, name: str, body: dict) -> None:
        import requests

        headers = {**auth_headers(self._credential), "x-ms-blob-type": "BlockBlob",
                   "Content-Type": "application/json"}
        r = (self._put or requests.put)(f"{self.channel}/{name}", headers=headers,
                                        data=json.dumps(body, indent=2).encode(), timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} writing {name}")

    def _report(self, error: str) -> None:
        """Say when the channel breaks and when it heals — not every tick."""
        if error != self.last_error:
            print(f"[watch-channel] {error or 'delivering again'} "
                  f"at {datetime.now():%H:%M:%S}")
        self.last_error = error


def start(*, interval: float = TICK_S) -> Publisher | None:
    """The watch's publisher on its own thread, or None without a channel. A failure
    never reaches the watch: the run that waits on it falls toward ``unknown``."""
    url = channel_url()
    if not url:
        return None
    publisher = Publisher(url)

    def loop() -> None:
        while True:
            try:
                publisher.tick()
            except Exception as e:
                publisher._report(f"heartbeat not written: {e}")
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True, name="watch-channel").start()
    return publisher


# ── The run's side (Orodruin) ──────────────────────────────────────────────────────

def _get(url: str, get, credential, **kw):
    import requests

    r = (get or requests.get)(url, headers=auth_headers(credential), timeout=15, **kw)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} reading the watch channel")
    return r


def read_heartbeat(*, channel: str | None = None, credential=None, get=None) -> dict:
    """The watch's last heartbeat. Raises when the channel is unset or unreadable."""
    url = channel if channel is not None else channel_url()
    if not url:
        raise RuntimeError(f"{CHANNEL_ENV} is not set")
    body = json.loads(_get(f"{url}/{HEARTBEAT}", get, credential).content)
    if not isinstance(body, dict):
        raise RuntimeError("heartbeat is not an object")
    return body


def read_detections(run_id: str, *, channel: str | None = None, credential=None,
                    get=None) -> list[dict]:
    """Every detection the watch delivered for this run's window. Raises when the channel
    is unset or a listed detection cannot be read — a detection unread is never a miss."""
    url = channel if channel is not None else channel_url()
    if not url:
        raise RuntimeError(f"{CHANNEL_ENV} is not set")
    if not _SAFE.match(run_id):
        raise ValueError(f"unsafe run_id: {run_id!r}")
    prefix = f"{DETECTIONS}/{run_id}/"
    names, marker = [], ""
    while True:
        params = {"restype": "container", "comp": "list", "prefix": prefix}
        if marker:
            params["marker"] = marker
        root = ET.fromstring(_get(url, get, credential, params=params).content)
        names += [b.findtext("Name") or "" for b in root.iter("Blob")]
        marker = root.findtext("NextMarker") or ""
        if not marker:
            break
    out = []
    for name in names:
        leaf = name[len(prefix):]
        if not name.startswith(prefix) or not leaf.endswith(".json") \
                or not _SAFE.match(leaf[:-5]):
            continue
        record = json.loads(_get(f"{url}/{name}", get, credential).content)
        if isinstance(record, dict):
            out.append(record)
    return out


def alive(heartbeat: dict, now: datetime | None = None) -> bool:
    """A watch is running behind the channel: its heartbeat is recent."""
    at = _when(heartbeat.get("at"))
    return at is not None and ((now or _now()) - at).total_seconds() < FRESH_S


def miss_unprovable(heartbeat: dict, *, run_id: str, attack_time, until) -> str:
    """Why this heartbeat cannot prove a miss — "" when it can. A miss needs a heartbeat
    written after the wait (every detection noted before it was delivered), by a watch up
    since before the attack (nothing lost to a restart), that knows the run's window
    (else its detections were never published)."""
    at, since = _when(heartbeat.get("at")), _when(heartbeat.get("since"))
    attack, end = _when(attack_time), _when(until)
    if at is None or since is None or attack is None or end is None:
        return "heartbeat or times unreadable"
    if at < end:
        return "no heartbeat since the end of the wait"
    if since > attack:
        return "the watch restarted after the attack"
    if run_id not in (heartbeat.get("windows") or []):
        return "the watch does not know the run's window"
    return ""
