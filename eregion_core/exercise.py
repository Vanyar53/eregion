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

A window is read, never taken on its word (H-1): whoever can write a file here, or a blob
in the channel, could otherwise pass a real attack off as an exercise. A window is refused
when it lasts longer than MAX_DURATION_S, starts more than FUTURE_SKEW_S after it was
declared, or takes the RulePoller's run name (``window_refusal``); it marks a VM only if
that VM is enrolled — its tags and its resource group's, read by the watch
(``set_enrollment_check``, eregion_core/inscription.py) — so the VM carrying a real load,
never enrolled, is never in an exercise; the run_id shortcut needs the VM among the
window's targets; a window is purged PURGE_AFTER_S after its last moment (emptied, its
tombstone keeps the channel from bringing it back). An exercise card stays in front of the
operator, flagged (glorfindel/escalations.py, ``to_judge``).

SEC5 (V-20): a window's dates are bounded by what the reader knows, not by what it declares.
A window pulled from the channel carries when its blob was created (``channel_created``, the
listing's word, eregion_core/exercise_channel.py): it may not start more than FUTURE_SKEW_S
before that — a window written now and dated 110 minutes back is refused (its file's mtime,
the pull, already bounds it the other way).
SEC14 (V-20): a window written on the watch's host itself (no channel) is bounded the same way,
by what the watch saw (``observe``): the first time the watch reads it, it writes down when, in
its own state (``seen_path()``, ``~/.glorfindel/exercise_seen.json`` — never in ``runs/``, which an
injector writes; the injectors' containers mount none of it, SEC3). The window may not start
more than FUTURE_SKEW_S before that moment, and once seen it may come again only closed — every
field as it was, ``end`` from null to a date not before its start —, as the channel does
(``exercise_channel.rewrite_refusal``). The watch reads its windows every minute
(glorfindel/cli.py's housekeeping), so an injector's window is seen within a minute of being
written; a run never starts without a live watch (V1). A registry that cannot be read believes
no window: its cycles fall toward ``real``. A window is « pulled from the channel » only when
that record says so — the pull writes it down there with its blob's creation
(``note_pulled``); a ``channel_created`` the file carries alone is the word of whoever wrote the
file, and the window is then local. A watch stopped more than FUTURE_SKEW_S during a local run
sees its window late: refused, its cycles count as real — the safe side.
MAX_DURATION_S still caps how long it lasts. And on a VM in zone ``production`` (its tags,
read by the watch), a window marks nothing unless it declares a technique that is not
destructive (``kind: technique``, ``destructive: false``): the production rule of O0 — a
destructive technique or a fault never runs there, so a window that says one did is a lie.

Files: one JSON per run under its injector's own directory, ``runs/annatar/exercises/`` or
``runs/gothmog/exercises/`` (SEC18, eregion_core/runs_layout.py; or ``EREGION_EXERCISES_DIR``),
which the watch mounts read-only. A watch on another host (H0) gets them through the exercise
channel (``eregion_core/exercise_channel.py``, O1): the injector publishes each window it writes,
the watch pulls them into its own directory (``runs/glorfindel/exercises/``) before it reads. The
watch reads the three (``windows_dirs``), and purges only in its own.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from eregion_core import runs_layout

# A run that outlives this was not closed (the injector died): its window lapses. A window
# declared longer is refused (H-1).
MAX_DURATION_S = 2 * 3600
# Detections arrive after the technique: the RulePoller's period plus Log Analytics
# ingestion (84 s to 3 min 30 measured on the bench, 05–07/10), with margin.
GRACE_AFTER_S = 15 * 60
# A window starts when its injector writes it: one that starts later than this after it was
# written (or after now) is refused — clock skew between two hosts, nothing more (H-1).
FUTURE_SKEW_S = 5 * 60
# A window is purged once its last moment is this old: the hosted report reads the windows
# of a campaign up to MAX_WAIT_S after it ends (analysis/hosted_report.py), and a campaign of
# many runs ends hours after its first window; a week leaves the margin (H-1).
PURGE_AFTER_S = 7 * 24 * 3600
# The RulePoller names its synthetic runs ``watch-<rule>-<ts>``: a window of that name would
# make a detection an exercise by its run_id (H-1).
_WATCH_RUN_PREFIX = "watch-"
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# When the blob of a window pulled from the channel was created (exercise_channel.CREATED).
CHANNEL_CREATED = "channel_created"
# SEC14 (V-20): when the watch first saw each window written on its own host, in its own state.
SEEN_ENV = "EREGION_EXERCISE_SEEN"
# What a window may change once seen: its closure (as exercise_channel._KEPT_AS_PULLED).
_CLOSURE = {"end", "closed_by", CHANNEL_CREATED}
_seen_lock = threading.Lock()

EXERCISE, REAL, UNKNOWN = "exercise", "real", "unknown"


def exercises_dir(runs_dir: Path | None = None) -> Path:
    """``EREGION_EXERCISES_DIR``, else ``<runs_dir>/exercises`` — ``runs_dir`` a writer's own
    directory (SEC18: ``runs/annatar``, ``runs/gothmog``; ``runs/glorfindel`` for the windows the
    watch pulls, its default). The campaign report passes its own (analysis/campaign_report.py)."""
    return Path(os.environ.get("EREGION_EXERCISES_DIR")
                or Path(runs_dir if runs_dir is not None else runs_layout.dir_of(runs_layout.GLORFINDEL))
                / "exercises")


def windows_dirs(root=None) -> list[Path]:
    """Where the windows of this host are (SEC18): each injector's own, then the watch's (pulled
    from the channel) — or ``EREGION_EXERCISES_DIR`` alone. ``root``: ``runs`` by default."""
    if os.environ.get("EREGION_EXERCISES_DIR"):
        return [exercises_dir()]
    return [exercises_dir(runs_layout.dir_of(w, root))
            for w in (*runs_layout.INJECTORS, runs_layout.GLORFINDEL)]


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
    """Written at once, never through a link (SEC16, SEC18: ``channel_reader.write_file``) — the
    watch never reads half a window."""
    from eregion_core.channel_reader import write_file
    path.parent.mkdir(parents=True, exist_ok=True)
    write_file(path, json.dumps(window, indent=2))


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
                now: datetime | None = None, directory: Path | None = None,
                destructive: bool | None = None, request: str = "") -> dict:
    """Declare that ``run_id`` exercises ``targets`` from now, for at most ``max_duration_s``.
    ``destructive``: what the catalog says of the experiment (SEC5, V-20) — unknown is
    destructive, and marks nothing in production. ``request``: the id of the Dagorlad request
    this run is a wire of (DG-b) — what links the wire to its run; nothing of what the request
    expects."""
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
        "destructive": destructive is not False,
    }
    if request:
        window["request"] = request
    _write((directory or exercises_dir(runs_layout.dir_of(injector))) / f"{run_id}.json", window)
    _publish(window)
    return window


def close_window(run_id: str, *, injector: str = "", now: datetime | None = None,
                 directory: Path | None = None) -> dict | None:
    """The run is over: its window ends now (detections still count during the grace). In its
    injector's own directory (SEC18), as ``open_window`` wrote it."""
    path = (directory or exercises_dir(runs_layout.dir_of(injector))) / f"{run_id}.json"
    try:
        window = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    window["end"] = (now or _now()).isoformat()
    _write(path, window)
    _publish(window)
    return window


def window_refusal(window, now: datetime | None = None,
                   declared_at: datetime | None = None) -> str:
    """Why this window is not believed — "" when it is (H-1). Its run_id must be a plain name
    and not the RulePoller's (``watch-…``); its targets a list of resource ids; its start and
    expiry readable, the expiry after the start and at most MAX_DURATION_S later; its end,
    when set, readable and not before its start. With ``now`` or ``declared_at`` (when it
    was written: its file's mtime), it must not start more than FUTURE_SKEW_S after the
    earlier of the two — a window written today for tomorrow is refused for good. Pulled from
    the channel, it must start within FUTURE_SKEW_S of when its blob was created
    (``channel_created``, SEC5 V-20): a window written now and dated back is refused too."""
    if not isinstance(window, dict):
        return "not a JSON object"
    rid = str(window.get("run_id") or "")
    if not _SAFE_RUN_ID.match(rid) or ".." in rid:
        return "its run_id is not a plain name"
    if rid.lower().startswith(_WATCH_RUN_PREFIX):
        return "its run_id takes the RulePoller's name (watch-…)"
    targets = window.get("targets")
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        return "its targets are not a list of resource ids"
    start, expires = _parse(window.get("start")), _parse(window.get("expires"))
    if start is None or expires is None:
        return "its start or its expiry is unreadable"
    lasts = (expires - start).total_seconds()
    if not 0 < lasts <= MAX_DURATION_S:
        return f"it lasts {lasts:.0f} s, outside (0, {MAX_DURATION_S}] s (MAX_DURATION_S)"
    if window.get("end") is not None:
        end = _parse(window.get("end"))
        if end is None or end < start:
            return "its end is unreadable or before its start"
    if CHANNEL_CREATED in window:
        created = _parse(window.get(CHANNEL_CREATED))
        if created is None:
            return "the time its blob was created is unreadable"
        if start < created - timedelta(seconds=FUTURE_SKEW_S):
            return (f"it starts {(created - start).total_seconds():.0f} s before the blob that "
                    f"carries it was created (more than FUTURE_SKEW_S, {FUTURE_SKEW_S} s): "
                    "antedated")
    refs = [t for t in (now, declared_at) if t is not None]
    if refs and start > min(refs) + timedelta(seconds=FUTURE_SKEW_S):
        return (f"it starts {(start - min(refs)).total_seconds():.0f} s after it was declared "
                f"(more than FUTURE_SKEW_S, {FUTURE_SKEW_S} s)")
    return ""


# What load_windows said of a refused file, by path: said again only when it changes.
_refused: dict[str, str] = {}


def seen_path() -> Path:
    """The watch's record of when it first saw each local window (SEC14, V-20):
    ``EREGION_EXERCISE_SEEN``, else ``~/.glorfindel/exercise_seen.json`` — the watch's own state."""
    return Path(os.environ.get(SEEN_ENV) or Path.home() / ".glorfindel" / "exercise_seen.json")


def _fields(window: dict) -> str:
    """What a window says, its closure aside: once seen, it never changes."""
    kept = {k: v for k, v in window.items() if k not in _CLOSURE}
    return hashlib.sha256(json.dumps(kept, sort_keys=True, default=str).encode()).hexdigest()


def seen_refusal(window: dict, entry: dict) -> str:
    """Why a local window is not believed against what the watch saw of it first — "" when it
    is (SEC14, V-20): it starts no more than FUTURE_SKEW_S before the watch first saw it, and it
    came again only closed."""
    seen, start = _parse(entry.get("seen")), _parse(window.get("start"))
    if seen is None or start is None:
        return "when the watch first saw it is unreadable"
    if start < seen - timedelta(seconds=FUTURE_SKEW_S):
        return (f"it starts {(seen - start).total_seconds():.0f} s before the watch first saw it "
                f"(more than FUTURE_SKEW_S, {FUTURE_SKEW_S} s): antedated")
    if _fields(window) != entry.get("fields"):
        return "rewritten after the watch first saw it (only its closure may come)"
    if entry.get("end") is not None and window.get("end") != entry.get("end"):
        return "its end withdrawn or moved after the watch saw it closed"
    return ""


def _update_seen(registry: Path, change) -> None:
    """Read the watch's record, let ``change(seen) -> bool`` edit it, write it back if changed —
    under an exclusive ``flock`` (the watch, ``glorfindel respond``, the console's process may
    each read windows) and through a temporary file of its own (``mkstemp``), then replaced:
    never half written, never two writers at once. Raises OSError or ValueError when it cannot
    be read or written."""
    import fcntl
    import tempfile

    registry.parent.mkdir(parents=True, exist_ok=True)
    with _seen_lock, open(registry.with_name(registry.name + ".lock"), "a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        seen = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else {}
        if not isinstance(seen, dict):
            raise ValueError("not a JSON object")
        if not change(seen):
            return
        fd, tmp = tempfile.mkstemp(prefix=f".{registry.name}.", dir=registry.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(seen, f, indent=1)
            os.replace(tmp, registry)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


def note_pulled(registry: Path | None, window: dict) -> None:
    """The exercise channel's pull wrote this window (eregion_core/exercise_channel.py): the watch
    writes down, in its own state, that it came from the channel, when its blob was created and
    what it said — the window's own ``channel_created`` is believed only if this says the same
    (SEC14, V-20). A window the channel brings again replaces the entry (its closure, checked by
    ``rewrite_refusal`` before). Never raises: a failure leaves the window to the local bound."""
    if registry is None or not isinstance(window, dict) or not window.get("run_id"):
        return

    def change(seen: dict) -> bool:
        seen[str(window["run_id"])] = {"seen": str(window.get(CHANNEL_CREATED) or ""), "channel": True,
                                       "fields": _fields(window), "end": window.get("end")}
        return True
    try:
        _update_seen(registry, change)
    except (OSError, ValueError) as e:
        print(f"[exercise] window {window.get('run_id')}: its pull not written down ({e})")


def noted_pulled(registry: Path) -> set[str]:
    """The run_ids the pull wrote down as pulled from the channel (``note_pulled``) — empty when
    the record cannot be read: every copy is then pulled again, within the pull's bounds."""
    try:
        seen = json.loads(registry.read_text(encoding="utf-8")) if registry.exists() else {}
    except (OSError, ValueError):
        return set()
    if not isinstance(seen, dict):
        return set()
    return {rid for rid, v in seen.items() if isinstance(v, dict) and v.get("channel")}


def _observe(windows: list[tuple[Path, dict]], now: datetime, registry: Path) -> dict[str, str]:
    """Write down the windows seen for the first time, and the closure of those seen open;
    return why each is not believed, by path (SEC14, V-20). A window counts as pulled from the
    channel only when the watch's own record says so (``note_pulled``) — its ``channel_created``
    field is the file's word, written by whoever writes the file —, and is then bounded by the
    blob's creation; any other is local, bounded by when the watch first saw it. Either way, once
    written down, it may come again only closed. A registry that cannot be read or written
    believes none of them."""
    if not windows:
        return {}
    out: dict[str, str] = {}

    def change(seen: dict) -> bool:
        changed = False
        for path, w in windows:
            rid = str(w.get("run_id"))
            entry = seen.get(rid)
            if not isinstance(entry, dict):
                entry = seen[rid] = {"seen": now.isoformat(), "fields": _fields(w), "end": w.get("end")}
                changed = True
            if entry.get("channel") and w.get(CHANNEL_CREATED) != entry.get("seen"):
                out[str(path)] = "its channel_created is not what the pull wrote down"
                continue
            why = seen_refusal(w, entry)
            if why:
                out[str(path)] = why
            elif entry.get("end") is None and w.get("end") is not None:
                entry["end"] = w["end"]          # its closure, the one change it may bring
                changed = True
        # Forget what was seen long ago: the window is purged by then (PURGE_AFTER_S).
        horizon = now - timedelta(seconds=PURGE_AFTER_S + MAX_DURATION_S + GRACE_AFTER_S)
        for rid in [k for k, v in seen.items() if not isinstance(v, dict)
                    or (_parse(v.get("seen")) or now) < horizon]:
            del seen[rid]
            changed = True
        return changed
    try:
        _update_seen(registry, change)
    except (OSError, ValueError) as e:
        return {str(p): f"the watch's record of the windows it saw cannot be read or written ({e})"
                for p, _ in windows}
    return out


def observe(now: datetime | None = None) -> list[dict]:
    """The watch reads its windows (every minute, glorfindel/cli.py): the local ones are written
    down the first time they are seen (SEC14, V-20)."""
    return load_windows(now=now)


def load_windows(directory: Path | None = None, *, now: datetime | None = None,
                 seen: Path | None = None) -> list[dict]:
    """Every window believed (``window_refusal``, declared at its file's mtime); a
    malformed or refused file is skipped — said once, never fatal — and a window whose last
    moment is PURGE_AFTER_S old is purged (``_purge``). The default directory is refreshed
    from the exercise channel first, when one is configured. A local window (not pulled from
    the channel) is also held against what the watch saw of it (``seen``: the watch's record;
    ``seen_path()`` for the default directory — SEC14, V-20). By default, every directory of
    windows of this host (``windows_dirs``, SEC18): the injectors', read-only, and the watch's
    own, where the pull writes — the only one where a window is purged."""
    if directory is None:
        from eregion_core import exercise_channel
        exercise_channel.pull_if_due(exercises_dir())
        seen = seen if seen is not None else seen_path()
    own = directory or exercises_dir()
    dirs = [d for d in ([directory] if directory is not None else windows_dirs()) if d.is_dir()]
    if not dirs:
        return []
    now = now or _now()
    read: list[tuple[Path, dict, datetime]] = []
    for path in sorted(p for d in dirs for p in d.glob("*.json")):
        try:
            w = json.loads(path.read_text(encoding="utf-8"))
            declared = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except (OSError, ValueError):
            continue
        if isinstance(w, dict) and w.get("purged_at"):
            continue                     # purged already: its tombstone (``_purge``)
        read.append((path, w, declared))
    unseen = {}
    if seen is not None:
        unseen = _observe([(p, w) for p, w, _ in read if isinstance(w, dict) and not window_refusal(w)],
                          now, seen)
    out = []
    for path, w, declared in read:
        why = window_refusal(w, now, declared) or unseen.get(str(path), "")
        if why:
            if _refused.get(str(path)) != why:
                _refused[str(path)] = why
                print(f"[exercise] window {path.name} refused: {why}")
            continue
        last = last_moment(w)
        if last is not None and last < now - timedelta(seconds=PURGE_AFTER_S):
            if path.parent == own:   # SEC18: an injector's directory is read-only here
                _purge(path, w)
            continue
        out.append(w)
    return out


def _purge(path: Path, window: dict) -> None:
    """Empty a window whose last moment is PURGE_AFTER_S old: what remains is its run_id and
    when it was purged, under its file's own mtime — so the channel's copy, not newer, is
    never pulled again (eregion_core/exercise_channel.py ``pull``). Never raises."""
    try:
        st = path.stat()
        _write(path, {"run_id": window.get("run_id"), "purged_at": _now().isoformat()})
        os.utime(path, (st.st_atime, st.st_mtime))
    except OSError:
        pass


def live(window: dict, when: datetime) -> bool:
    """The window is open at ``when``, or closed but still in its grace."""
    start, last = _parse(window.get("start")), last_moment(window)
    if start is None or last is None:
        return False
    return start <= when <= last


def last_moment(window: dict) -> datetime | None:
    """The last moment a detection still counts for the window — the upper bound of
    ``live``: its end (never closed: its expiry; the earlier of the two) plus the grace.
    ``None`` when its start or expiry is unreadable: nothing can be said to fall inside it.
    The campaign report bounds a run's decisions with it (analysis/campaign_report.py,
    #167)."""
    start, expires = _parse(window.get("start")), _parse(window.get("expires"))
    if start is None or expires is None:
        return None
    end = _parse(window.get("end")) or expires
    # A window closed late still lapses at its expiry.
    last = min(end, expires) + timedelta(seconds=GRACE_AFTER_S)
    return last


# Is this VM enrolled? Set by the watch at startup (glorfindel/cli.py: the VM's tags and its
# resource group's, read through Azure — eregion_core/inscription.py ``TagEnrollment``).
# Unset, nothing is enrolled: no window marks anything, every cycle is labelled real (H-1).
_enrollment_check = None


def set_enrollment_check(check) -> None:
    """``check(resource_id) -> bool``: whether a VM is enrolled, read by the reader itself —
    never from the window, which only names its targets."""
    global _enrollment_check
    _enrollment_check = check


def is_enrolled(resource_id: str) -> bool:
    """False without a check, or when the check fails: a window then marks nothing."""
    check = _enrollment_check
    if check is None or not resource_id:
        return False
    try:
        return bool(check(resource_id))
    except Exception:
        return False


def _targets(window: dict, resource_id: str) -> bool:
    """The VM is one of the window's targets, and the window is believed (H-1)."""
    return (resource_id.lower() in (window.get("targets") or [])
            and not window_refusal(window))


def _zone_reader(enrolled):
    """``zone(resource_id)`` of the check in use, or None when it reads no zone."""
    zone = getattr(enrolled, "zone", None)
    if zone is None and enrolled is is_enrolled:
        zone = getattr(_enrollment_check, "zone", None)
    return zone


def zone_allows(window: dict, resource_id: str, enrolled=None) -> bool:
    """A window marks a VM in zone ``production`` only if it declares a technique that is not
    destructive (SEC5, V-20) — the production rule of O0. The zone is the reader's, from the
    VM's tags (eregion_core/inscription.py ``TagEnrollment.zone``); a check that reads none
    leaves the rule to the injector's own (O0)."""
    zone = _zone_reader(enrolled or is_enrolled)
    if zone is None:
        return True
    try:
        z = zone(resource_id)
    except Exception:
        return False
    if z != "production":
        return True
    return window.get("kind") == "technique" and window.get("destructive") is False


def _covers(window: dict, resource_id: str, when: datetime, enrolled) -> bool:
    return (_targets(window, resource_id) and live(window, when) and enrolled(resource_id)
            and zone_allows(window, resource_id, enrolled))


def covering_runs(resource_id: str, when, windows: list[dict], *, enrolled=None) -> list[str]:
    """The run_id of every window that covers this VM at ``when`` — all of them, where
    ``source_of`` stops at the first. ``enrolled`` defaults to ``is_enrolled``."""
    at = _parse(when)
    if not resource_id or at is None:
        return []
    enrolled = enrolled or is_enrolled
    return [w["run_id"] for w in windows if _covers(w, resource_id, at, enrolled)]


def source_of(resource_id: str, when=None, *, run_id: str = "",
              windows: list[dict] | None = None, enrolled=None) -> tuple[str, str]:
    """(``exercise``, its run_id) when a window covers this VM at ``when``; else (``real``, "").

    A signal carrying the run_id of a declared window (Annatar's own signals) is an exercise
    whatever its time — if its VM is one of that window's targets, and enrolled (H-1).
    Without a resource or a readable time: (``unknown``, ""). ``enrolled`` defaults to
    ``is_enrolled``.
    """
    ws = load_windows() if windows is None else windows
    enrolled = enrolled or is_enrolled
    if run_id and resource_id and any(
            w.get("run_id") == run_id and _targets(w, resource_id)
            and zone_allows(w, resource_id, enrolled) for w in ws) \
            and enrolled(resource_id):
        return EXERCISE, run_id
    at = _parse(when) if when is not None else _now()
    if not resource_id or at is None:
        return UNKNOWN, ""
    for w in ws:
        if _covers(w, resource_id, at, enrolled):
            return EXERCISE, w["run_id"]
    return REAL, ""
