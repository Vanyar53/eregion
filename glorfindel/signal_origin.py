"""Where a signal comes from, and what the defender takes from there (SEC3, #274).

`runs/` is written by the injectors (Annatar, Gothmog) as well as by Glorfindel: whoever can
write there can write any line. The watch takes from `runs/*_signals.jsonl` only what an
injector emits (the inventory of annatar/runner/engine.py; Gothmog writes `runs/gothmog/`,
which the watch does not read), each for what it is:

  attack_started    "look": the watch runs ITS detection rule for the line's technique. From
                    the line come the VM it names (`resource_id`), the technique (`ttp`) and
                    the moment (`attack_time`, where the rule's search starts); from the
                    monitoring, the detection itself — the row the rule finds, which the
                    cycle then pins to the line's VM. Not checked here, yet: that the row
                    names that VM, and a bound on `attack_time` (SEC4);
  detection_missed  a rule proposal: a card, never an action.

and, of each, only the fields the injector writes (`_FIELDS`): a line cannot hand the
defender a query of its own, an IP to block or an attribution. Anything else —
`recovery_complete`, `detection`, `detection_timeout`, an unknown event (`attack_adapted`
too, no longer emitted since SEC3), a run id that is not a plain name — is refused: logged,
counted (~/.glorfindel/channel_refusals.json), never decided.

`recovery_complete` lifts an isolation without a human. Only Glorfindel's own path emits it:
`glorfindel restore --wait` builds it and answers it in its own process; written for later,
it goes to ~/.glorfindel/recovery_signals/, a directory no injector mounts (docker-compose.yml).
The release precondition (agent.py) lets it lift an isolation only when it was vouched for
here: built by this process, or read by `glorfindel respond` from that directory. A
location, not a signature: a key the injectors don't have would live in ~/.glorfindel too —
the same boundary, plus a key to keep.
"""
from __future__ import annotations

import logging
import re
import threading
from pathlib import Path

log = logging.getLogger(__name__)

RECOVERY_SIGNALS_DIR = Path.home() / ".glorfindel" / "recovery_signals"
# The refused lines, counted by the watch (`refuse`).
REFUSALS_FILE = Path.home() / ".glorfindel" / "channel_refusals.json"

# What the watch does with each event an injector emits.
CHANNEL_EVENTS = {"attack_started": "poll", "detection_missed": "propose"}

# The fields an injector writes in each (annatar/runner/engine.py): the rest is dropped.
_FIELDS = {
    "attack_started": {
        "raw_signal": ("attack_time", "detection_timeout_s", "detection_max_s"),
        "context": ("run_id", "scenario"),
    },
    "detection_missed": {
        "raw_signal": ("failed_query", "detection_source", "detection_hints"),
        "context": ("run_id", "scenario", "workspace_id", "detection_timeout_s", "failed_query"),
    },
}
_TOP = ("signal_id", "timestamp", "provider", "resource_id", "resource_type", "ttp", "severity", "event")
# A run id names files (runs/<run_id>_debug.jsonl): a plain name, never a path.
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

_LOCK = threading.Lock()
_REFUSED: dict[str, int] = {}
_VOUCHED: set[str] = set()


class Admission:
    """What the watch makes of one line of runs/: `signal` (cleaned) and `what` (poll,
    propose) when admitted; `refused` (why) otherwise. `dropped`: the fields taken off."""

    def __init__(self, signal: dict | None, what: str = "", refused: str = "", dropped=()):
        self.signal, self.what, self.refused, self.dropped = signal, what, refused, list(dropped)


def admit(data: dict) -> Admission:
    """The line as the watch may take it from runs/, or why it is refused. Never raises."""
    event = str((data or {}).get("event") or "")
    if event not in CHANNEL_EVENTS:
        why = ("n'est accepté que de `glorfindel restore`, jamais du canal runs/"
               if event == "recovery_complete" else
               "n'est pas un signal d'injecteur (attack_started, detection_missed)")
        return Admission(None, refused=f"« {event[:60] or '?'} » {why}")
    fields = _FIELDS[event]
    clean = {k: data.get(k, "") for k in _TOP}
    dropped = [k for k in data if k not in _TOP and k not in fields]
    for part in ("raw_signal", "context"):
        given = data.get(part) if isinstance(data.get(part), dict) else {}
        clean[part] = {k: given[k] for k in fields[part] if k in given}
        dropped += [f"{part}.{k}" for k in given if k not in fields[part]]
    run_id = clean["context"].get("run_id")
    if run_id not in (None, "") and not (isinstance(run_id, str) and _RUN_ID.fullmatch(run_id)
                                         and ".." not in run_id):
        return Admission(None, refused=f"identifiant de run invalide ({str(run_id)[:40]!r})")
    if not isinstance(clean["resource_id"], str):
        return Admission(None, refused="resource_id n'est pas une chaîne")
    return Admission(clean, CHANNEL_EVENTS[event], dropped=dropped)


def refuse(data: dict, why: str, source: str = "") -> None:
    """Say a refused line: the log, and the counter (in memory, and in REFUSALS_FILE for
    whoever reads this host: by event, the last one's file, time and reason). Never raises."""
    import json
    from datetime import datetime, timezone

    event = str((data or {}).get("event") or "?")[:60]
    log.warning("signal refused on the runs/ channel (%s): %s — %s", source or "?", event, why)
    with _LOCK:
        _REFUSED[event] = _REFUSED.get(event, 0) + 1
        try:
            try:
                kept = json.loads(REFUSALS_FILE.read_text())
            except (OSError, ValueError):
                kept = {}
            counts = kept.get("counts") if isinstance(kept, dict) and isinstance(kept.get("counts"), dict) else {}
            counts[event] = int(counts.get(event) or 0) + 1
            from glorfindel.response.state import _atomic_write_text
            _atomic_write_text(REFUSALS_FILE, json.dumps({"counts": counts, "last": {
                "at": datetime.now(timezone.utc).isoformat(), "event": event,
                "source": source[:120], "why": why[:300]}}, sort_keys=True))
        except Exception as exc:             # said in the log already: never stops the watch
            log.warning("refused signal not counted on disk (%s)", exc)


def refused_counts() -> dict[str, int]:
    """The lines refused by this process, by event."""
    with _LOCK:
        return dict(_REFUSED)


def vouch(signal: dict) -> dict:
    """A recovery_complete built by Glorfindel's own path in this process."""
    with _LOCK:
        _VOUCHED.add(str(signal.get("signal_id") or ""))
    return signal


def vouched(signal: dict) -> bool:
    sid = str((signal or {}).get("signal_id") or "")
    with _LOCK:
        return bool(sid) and sid in _VOUCHED


def in_recovery_dir(path) -> bool:
    """`path` is a file of RECOVERY_SIGNALS_DIR (links resolved): written by the defender only."""
    try:
        return Path(path).resolve().parent == RECOVERY_SIGNALS_DIR.resolve()
    except OSError:
        return False


def write_recovery_signal(signal: dict) -> Path:
    """Keep a recovery_complete for a later `glorfindel respond`, where only the defender
    writes: RECOVERY_SIGNALS_DIR, the directory 0700, the file 0600, written whole."""
    import json

    from glorfindel.response.state import _atomic_write_text
    out = RECOVERY_SIGNALS_DIR / f"{signal['context']['run_id']}_signals.jsonl"
    _atomic_write_text(out, json.dumps(signal) + "\n")
    return out
