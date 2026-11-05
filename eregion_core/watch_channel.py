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

Both signed by the watch's key (eregion_core/watch_key.py), each under its own domain: the
heartbeat since SEC19, each detection since SEC21 (#530) — its run, its signal, what was seen and
when. A run believes a detection only when the key it pins signed it, for this run and under this
signal's name (``vouched_detections``); any other is never counted for « seen », and said.

Every failure falls toward ``unknown``, never ``detected`` nor ``missed``: a run concludes
to a miss only on a heartbeat written after its wait, by a watch up since before the
attack, that knows the run's window (``miss_unprovable``).

**The local channel of verdicts (SEC18, #455).** A watch with no storage channel — on a
workstation, beside its injectors — writes the same two kinds of document in a directory of its
own, ``runs/verdicts/`` (``LocalVerdicts``), the one directory of the blue the red mounts, read-only.
A verdict, never the reasoning: ``verdicts/detections/<run_id>/<n>.json`` holds exactly
``VERDICT_FIELDS`` (the run, its technique, ``detected``, when, the rule's id, the delay from the
run's window, the window's own target) and ``verdicts/heartbeat.json`` exactly ``BEAT_FIELDS``;
anything else is refused at the write (``verdict_refusal``, ``beat_refusal``) and at the read. A
run reads it as an input it does not trust, through the common reader (SEC16), only when no
storage channel is set (``source``): the storage channel keeps the priority; with neither, the
detection is ``unknown``. A verdict of another run than the one read, or of another shape, is
ignored, and said.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from eregion_core.exercise import (GRACE_AFTER_S, MAX_DURATION_S, covering_runs, live,
                                   load_windows)
from eregion_core.exercise_channel import MAX_BLOB_BYTES, MAX_BLOBS, MAX_LISTING_BYTES, \
    auth_headers, fetch

CHANNEL_ENV = "EREGION_WATCH_CHANNEL"
HEARTBEAT = "heartbeat.json"
DETECTIONS = "detections"
TICK_S = 5.0
HEARTBEAT_EVERY_S = 60.0
# A heartbeat older than this is no watch — the channel's and the local file's alike
# (eregion_core/watch_gate.py, V1).
FRESH_S = 90.0
# A heartbeat dated a little after now is the clocks of two hosts (H0, Orodruin) drifting
# apart; one dated further ahead is never fresh — else it would stay fresh for ever.
CLOCK_SKEW_S = 10.0
# A detection waits for its window as long as a window could still cover it.
KEEP_S = MAX_DURATION_S + GRACE_AFTER_S
# After its wait, a run waits this long for a heartbeat that covers it (one missed beat).
SETTLE_S = 2 * HEARTBEAT_EVERY_S + 2 * TICK_S
STALE = "no heartbeat since the end of the wait"
# A blob name part: a run_id or a signal_id, never a path.
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def channel_url() -> str:
    return (os.environ.get(CHANNEL_ENV) or "").strip().rstrip("/")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _when(value) -> datetime | None:
    """A datetime, an ISO string, or an epoch (Annatar's ``attack_time``)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, timezone.utc)
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

    SIGNS = True     # SEC19: its heartbeat signed for the injectors' gate

    def __init__(self, channel: str, *, credential=None, put=None, windows=None,
                 now: datetime | None = None, signer=None):
        self.channel = channel
        self._credential = credential
        self._put = put
        self._signer = signer
        self._unsigned = ""
        self._unsigned_detection = ""
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
                                self._signed_detection({**r, "exercise_run": run}))
                    self._sent.add((run, r["signal_id"]))
                except Exception as e:
                    waiting += 1
                    self._report(f"detection {r['signal_id']} for {run} not delivered: {e}")
        if waiting:
            return  # no heartbeat while a detection waits: it would vouch for a miss
        if self._last_beat and (now - self._last_beat).total_seconds() < HEARTBEAT_EVERY_S:
            return
        from eregion_core.watch_gate import perimeter  # watch_gate reads this module

        self._write(HEARTBEAT, self._signed({
            "at": now.isoformat(),
            "since": self.since,
            "windows": sorted(w["run_id"] for w in windows if live(w, now)),
            # SEC5 (N-03): the subscription this watch reads, as a digest — what binds this
            # heartbeat to the targets of a run (eregion_core/watch_gate.py).
            "perimeter": perimeter(),
        }, now))
        self._last_beat = now
        self._report("")

    def _signed(self, body: dict, now: datetime) -> dict:
        """SEC19 (N-03): the heartbeat signed by the watch's key — every field, ``since`` and
        ``windows`` too. Without a key it goes unsigned (the injectors refuse it), said once."""
        if not self.SIGNS:
            return body
        from eregion_core import watch_key
        signer, why = (self._signer, "") if self._signer is not None else watch_key.shared()
        if signer is None:
            if why != self._unsigned:
                print(f"[watch-channel] heartbeat not signed ({why}): the injectors refuse it (SEC19)")
            self._unsigned = why
            return body
        self._unsigned = ""
        return watch_key.sign_beat(body, signer, now)

    def _signed_detection(self, body: dict) -> dict:
        """SEC21 (#530): a detection signed by the watch's key, under its own domain — its run, its
        signal, what was seen and when. Without a key it goes unsigned (the injectors never count
        it), said once."""
        if self.SIGNS is False:      # the local channel of verdicts: its exact fields (SEC18)
            return body
        from eregion_core import watch_key
        signer, why = (self._signer, "") if self._signer is not None else watch_key.shared()
        if signer is None:
            if why != self._unsigned_detection:
                print(f"[watch-channel] detection not signed ({why}): the injectors never count it (SEC21)")
            self._unsigned_detection = why
            return body
        self._unsigned_detection = ""
        return watch_key.sign_detection(body, signer)

    def _write(self, name: str, body: dict) -> None:
        import requests

        headers = {**auth_headers(self._credential, self.channel), "x-ms-blob-type": "BlockBlob",
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

def _get(url: str, get, credential, *, params=None, limit: int = MAX_BLOB_BYTES) -> bytes:
    """A blob or a listing page of the return channel, read within its bound (SEC5, V-21);
    the token goes to an Azure Storage endpoint only (N-15)."""
    r, body = fetch(get, url, auth_headers(credential, url), limit=limit, params=params,
                    what="the watch channel")
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} reading the watch channel")
    return body


def read_heartbeat(*, channel: str | None = None, credential=None, get=None) -> dict:
    """The watch's last heartbeat. Raises when the channel is unset or unreadable. Without a
    storage channel, the local one's (SEC18, ``local_heartbeat``) when there is one."""
    url = channel if channel is not None else channel_url()
    if not url and channel is None and source() == LOCAL:
        return local_heartbeat()
    if not url:
        raise RuntimeError(f"{CHANNEL_ENV} is not set")
    body = json.loads(_get(f"{url}/{HEARTBEAT}", get, credential))
    if not isinstance(body, dict):
        raise RuntimeError("heartbeat is not an object")
    return body


def read_detections(run_id: str, *, channel: str | None = None, credential=None,
                    get=None) -> list[dict]:
    """Every detection the watch delivered for this run's window, as written — signed or not,
    never verified (the console judges each one as the run does, CON-S: ``read_named`` and
    ``watch_key.detection_refusal``). Raises when the channel is unset or a listed detection cannot be read
    — a detection unread is never a miss. Without a storage channel, the local one's (SEC18,
    ``local_detections``) when there is one. A run counts only ``vouched_detections`` (SEC21)."""
    url = channel if channel is not None else channel_url()
    if not url and channel is None and source() == LOCAL:
        return local_detections(run_id)
    return [record for _, record in read_named(run_id, channel=url, credential=credential, get=get)
            if isinstance(record, dict)]


def read_named(run_id: str, *, channel: str | None = None, credential=None,
               get=None) -> list[tuple[str, object]]:
    """The storage channel's detections of this run, each with the name of its blob — the signal
    it is filed under, ``detections/<run_id>/<signal>.json`` —, as read: what ``vouched_detections``
    checks. Raises when the channel is unset or a listed detection cannot be read."""
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
        root = ET.fromstring(_get(url, get, credential, params=params, limit=MAX_LISTING_BYTES))
        names += [b.findtext("Name") or "" for b in root.iter("Blob")]
        if len(names) > MAX_BLOBS:  # V-21: never a miss on a listing cut short — unknown
            raise RuntimeError(f"more than {MAX_BLOBS} detections listed for {run_id}")
        marker = root.findtext("NextMarker") or ""
        if not marker:
            break
    out = []
    for name in names:
        leaf = name[len(prefix):]
        if not name.startswith(prefix) or not leaf.endswith(".json") \
                or not _SAFE.match(leaf[:-5]):
            continue
        out.append((leaf[:-5], json.loads(_get(f"{url}/{name}", get, credential))))
    return out


# What a run keeps of the refusals to say them: enough to say them, never a flood (a writer of
# the channel may file up to MAX_BLOBS of them, and rotate them) — the rest counted only.
MAX_REFUSED = 20


def vouched_detections(run_id: str, *, channel: str | None = None, credential=None,
                       get=None) -> tuple[list[dict], list[str], int]:
    """SEC21 (#530): (the detections a run may count, the refusals to say — MAX_REFUSED at most —,
    how many were refused in all). On the storage
    channel, only those the key this injector pins (``EREGION_WATCH_KEY``, never a key read in
    the channel) signed under ``DOMAIN_DETECTION``, for this run, under their own signal's name;
    each other — unsigned (a watch older than this lot), another key, another domain, a field
    changed, copied from another run or another signal, or no key pinned — is refused and said,
    never counted for « seen ». Without a storage channel, the local channel's verdicts as before
    (SEC18: the watch's own directory, the red's view read-only), nothing refused. Raises as
    ``read_named`` does."""
    from eregion_core import watch_key
    url = channel if channel is not None else channel_url()
    if not url and channel is None and source() == LOCAL:
        return local_detections(run_id), [], 0
    named = read_named(run_id, channel=url, credential=credential, get=get)
    key, no_key = watch_key.pinned()
    kept, refused, total = [], [], 0
    for leaf, record in named:
        why = no_key if key is None else watch_key.detection_refusal(
            record, key, run_id=run_id, signal_id=leaf)
        if not why:
            kept.append(record)
            continue
        total += 1
        if len(refused) < MAX_REFUSED:
            refused.append(f"{DETECTIONS}/{run_id}/{leaf}.json: {why}"[:400])
    return kept, refused, total


def as_records(detections: list[dict]) -> list[dict]:
    """The channel's detections in the shape of a watch debug line, for the run's own test
    (annatar/runner/detection.py, ``detection_latency``)."""
    return [{"signal": {"event": d.get("event"), "ttp": d.get("ttp"),
                        "resource_id": d.get("resource_id"), "timestamp": d.get("detected_at")}}
            for d in detections if isinstance(d, dict)]


def alive(heartbeat: dict, now: datetime | None = None) -> bool:
    """A watch is running behind the channel: its heartbeat is recent."""
    return recent(_when(heartbeat.get("at")), now)


def recent(at: datetime | None, now: datetime | None = None) -> bool:
    """A heartbeat written at ``at`` is fresh: younger than FRESH_S, and not dated more than
    CLOCK_SKEW_S after ``now`` (V1)."""
    if at is None:
        return False
    age = ((now or _now()) - at).total_seconds()
    return -CLOCK_SKEW_S <= age < FRESH_S


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
        return STALE
    if since > attack:
        return "the watch restarted after the attack"
    if run_id not in (heartbeat.get("windows") or []):
        return "the watch does not know the run's window"
    return ""


# ── The local channel of verdicts (SEC18) ─────────────────────────────────────────────

STORAGE, LOCAL = "storage", "local"
# Exactly what a verdict holds — the run, its technique, the verdict, when, the rule's id, the delay
# from the run's window, the window's own target —, never the watch's reasoning, a log line, a
# decision, a card, a name or an address the run did not give.
VERDICT_FIELDS = ("run_id", "technique", "verdict", "detected_at", "rule", "latency_s", "target")
VERDICTS = ("detected", "missed")
BEAT_FIELDS = ("at", "since", "windows", "perimeter")
_TECHNIQUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_RULE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_HEX = re.compile(r"^[0-9a-f]{0,64}$")
_said_local: dict[str, str] = {}


def local_dir() -> Path:
    """``runs/verdicts`` — the watch's local channel, the red's one read-only view of the blue."""
    from eregion_core import runs_layout
    return runs_layout.dir_of(runs_layout.VERDICTS)


def source() -> str:
    """Where a run learns of its detection: ``storage`` (a channel set: it keeps the priority),
    ``local`` (none, and the local channel's heartbeat is there), else ""."""
    if channel_url():
        return STORAGE
    return LOCAL if os.path.lexists(local_dir() / HEARTBEAT) else ""


def _iso_ok(value) -> bool:
    return isinstance(value, str) and len(value) <= 40 and _when(value) is not None


def verdict_refusal(doc) -> str:
    """Why this is no verdict of the local channel — "" when it is: exactly ``VERDICT_FIELDS``,
    each of its shape."""
    if not isinstance(doc, dict):
        return "not an object"
    if set(doc) != set(VERDICT_FIELDS):
        extra, missing = sorted(set(doc) - set(VERDICT_FIELDS)), sorted(set(VERDICT_FIELDS) - set(doc))
        return f"fields: {', '.join(extra)} not admitted" if extra else f"fields missing: {', '.join(missing)}"
    if not isinstance(doc["run_id"], str) or not _SAFE.match(doc["run_id"]):
        return "run_id: a plain name"
    if not isinstance(doc["technique"], str) or not _TECHNIQUE.match(doc["technique"]):
        return "technique: a plain id"
    if doc["verdict"] not in VERDICTS:
        return "verdict: detected or missed"
    if doc["verdict"] == "detected" and not _iso_ok(doc["detected_at"]):
        return "detected_at: a time"
    if doc["verdict"] == "missed" and doc["detected_at"] is not None:
        return "detected_at: none for a miss"
    if not isinstance(doc["rule"], str) or not _RULE.match(doc["rule"]):
        return "rule: a plain id"
    lat = doc["latency_s"]
    if lat is not None and (isinstance(lat, bool) or not isinstance(lat, (int, float))
                            or not math.isfinite(lat) or not 0 <= lat < 86400):
        return "latency_s: seconds, or none"
    if not isinstance(doc["target"], str) or not doc["target"].startswith("/subscriptions/") \
            or len(doc["target"]) > 512:
        return "target: a resource id"
    return ""


def beat_refusal(doc) -> str:
    """Why this is no heartbeat of the local channel — "" when it is: exactly ``BEAT_FIELDS``."""
    if not isinstance(doc, dict):
        return "not an object"
    if set(doc) != set(BEAT_FIELDS):
        return f"fields: {', '.join(sorted(set(doc) ^ set(BEAT_FIELDS)))} not admitted"
    if not _iso_ok(doc["at"]) or not _iso_ok(doc["since"]):
        return "at, since: times"
    w = doc["windows"]
    if not isinstance(w, list) or len(w) > MAX_BLOBS or not all(isinstance(x, str) and _SAFE.match(x) for x in w):
        return "windows: plain run ids"
    if not isinstance(doc["perimeter"], str) or not _HEX.match(doc["perimeter"]):
        return "perimeter: a digest"
    return ""


def write_local(directory: Path, name: str, doc: dict) -> None:
    """Write one document of the local channel, held as SEC16 writes (``write_file``: at once,
    never through a link) — refused (ValueError) when it is not exactly a verdict or a
    heartbeat."""
    from eregion_core import runs_layout
    from eregion_core.channel_reader import write_file
    why = beat_refusal(doc) if name == HEARTBEAT else verdict_refusal(doc)
    if why:
        raise ValueError(f"local channel: {name} refused — {why}")
    path = Path(directory) / name
    # Its parents made without ever following a link (SEC18): a link in the way refuses.
    why = runs_layout.parents_hold(Path(directory), path)
    if why:
        raise ValueError(f"local channel: {name} refused — {why}")
    write_file(path, json.dumps(doc, sort_keys=True))


def _say_local(path, why: str) -> None:
    key = str(path)
    if _said_local.get(key) != why:
        _said_local[key] = why
        print(f"[watch-channel] {path}: {why} — ignored (SEC18)")


def local_heartbeat(directory: Path | None = None) -> dict:
    """The local channel's heartbeat, read as an input not trusted (SEC16: a regular file,
    bounded, never through a link). Raises when it is absent, unreadable or refused."""
    from eregion_core.channel_reader import read_json
    path = Path(directory or local_dir()) / HEARTBEAT
    doc = read_json(path)
    why = beat_refusal(doc)
    if why:
        _say_local(path, why)
        raise RuntimeError(f"local heartbeat refused: {why}")
    return doc


def local_detections(run_id: str, directory: Path | None = None) -> list[dict]:
    """The local channel's verdicts of this run, in the return channel's shape (``as_records``
    reads it): ``detected`` only — a miss is concluded from the heartbeat, as on the storage
    channel. A file of another shape, or naming another run, is ignored and said; more than
    MAX_BLOBS raises (never a miss on a listing cut short)."""
    from eregion_core.channel_reader import read_json
    if not _SAFE.match(run_id):
        raise ValueError(f"unsafe run_id: {run_id!r}")
    d = Path(directory or local_dir()) / DETECTIONS / run_id
    try:
        with os.scandir(d) as it:
            names = sorted(e.name for e in it if e.name.endswith(".json") and not e.name.startswith("."))
    except FileNotFoundError:
        return []
    if len(names) > MAX_BLOBS:
        raise RuntimeError(f"more than {MAX_BLOBS} verdicts for {run_id}")
    out = []
    for name in names:
        path = d / name
        try:
            doc = read_json(path)
        except (OSError, ValueError) as e:
            _say_local(path, f"unreadable ({e})")
            continue
        why = verdict_refusal(doc) or ("a verdict of another run" if doc["run_id"] != run_id else "")
        if why:
            _say_local(path, why)
            continue
        if doc["verdict"] == "detected":
            out.append({"event": "detection", "ttp": doc["technique"], "resource_id": doc["target"],
                        "detected_at": doc["detected_at"], "rule": doc["rule"]})
    return out


class LocalVerdicts(Publisher):
    """The watch's local channel (SEC18): the Publisher's rule — a detection delivered for each
    window that covers its VM, a heartbeat only once nothing waits — written as verdicts in
    ``directory``, its fields exactly ``VERDICT_FIELDS``. Also the poll of a run's own
    ``attack_started`` (``note_poll``): on a workstation, the first way the watch detects a run."""

    # Its heartbeat holds exactly BEAT_FIELDS: no signature — the gate never reads it (it reads the
    # storage channel's, or the injectors' copy, both signed: SEC19).
    SIGNS = False

    def __init__(self, directory: Path, **kw):
        # Its windows read without the pull: the local channel exists only without a storage one.
        kw.setdefault("windows", lambda: load_windows(pull=False))
        super().__init__(str(directory), **kw)
        self.directory = Path(directory)
        source_windows = self._windows
        self._starts: dict[str, str] = {}

        def windows():
            found = source_windows()
            self._starts = {str(w.get("run_id")): w.get("start") for w in found if isinstance(w, dict)}
            return found
        self._windows = windows

    def note_poll(self, signal: dict) -> None:
        """A run's ``attack_started`` resolved into a detection by its rule (the poll path):
        noted as the RulePoller's are, its time the attack's plus its detection's delay —
        never one the watch could not tie to the VM (``unattributed``). Never raises."""
        try:
            ctx = signal.get("context") or {}
            raw = signal.get("raw_signal") or {}
            if signal.get("event") != "detection" or ctx.get("attribution") == "unattributed":
                return
            at, after = raw.get("attack_time"), raw.get("detection_time_s")
            if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (at, after)):
                return
            seen = datetime.fromtimestamp(at + after, timezone.utc).isoformat()
            self.note({**signal, "timestamp": seen,
                       "context": {**ctx, "attribution": "asset", "rule_name": ctx.get("rule_name") or "poll"}})
        except Exception as e:  # never into the watch's cycle
            self._report(f"detection not noted: {e}")

    def _write(self, name: str, body: dict) -> None:
        if name == HEARTBEAT:
            write_local(self.directory, name, {k: body.get(k) for k in BEAT_FIELDS})
            return
        run = str(body.get("exercise_run") or "")
        start, seen = _when(self._starts.get(run)), _when(body.get("detected_at"))
        latency = round((seen - start).total_seconds(), 1) if start and seen and seen >= start else None
        doc = {"run_id": run, "technique": str(body.get("ttp") or ""), "verdict": "detected",
               "detected_at": str(body.get("detected_at") or ""), "rule": str(body.get("rule") or "poll"),
               "latency_s": latency, "target": str(body.get("resource_id") or "").lower()}
        # The file's name says nothing of the watch's own signal: a digest of it.
        leaf = hashlib.sha256(str(body.get("signal_id") or "").encode()).hexdigest()[:16]
        write_local(self.directory, f"{DETECTIONS}/{run}/{leaf}.json", doc)


def start_local(directory: Path | None = None, *, interval: float = TICK_S) -> LocalVerdicts | None:
    """The local channel on its own thread — only without a storage channel, which keeps the
    priority; None with one. A failure never reaches the watch."""
    if channel_url():
        return None
    directory = Path(directory or local_dir())
    if not os.path.lexists(directory) and os.path.isdir(directory.parent) \
            and not os.path.islink(directory.parent):
        directory.mkdir()   # its own directory, under a runs/ that is there — never a runs/ made
    publisher = LocalVerdicts(directory)
    publisher.stopped = threading.Event()   # set: the thread ends (the tests)

    def loop() -> None:
        while not publisher.stopped.is_set():
            try:
                publisher.tick()
            except Exception as e:
                publisher._report(f"local verdicts not written: {e}")
            publisher.stopped.wait(interval)

    threading.Thread(target=loop, daemon=True, name="watch-verdicts").start()
    return publisher
