"""IA0 on H0 (#167): the report of a campaign launched from Orodruin writes itself where the
watch runs.

Orodruin has neither the analysis dependencies, nor the model's key, nor the watch's files:
at the end of ``annatar campaign run`` it publishes the campaign to the exercise channel —
its manifest and its runs' reports, nothing else (eregion_core/exercise_channel.py). H0 has
all the rest. ``glorfindel watch`` starts this on a thread of its own, only when
``EREGION_EXERCISE_CHANNEL`` is set: every PULL_EVERY_S it pulls the published campaigns
into ``runs/campaigns/<id>/`` and writes ``report.md`` for each one that is ``done`` and has
none — once. The decisions come from the watch's ``watch-*_debug.jsonl``
(analysis/campaign_report.py, the rule of #157). The index ``campaign_runs`` stays on the
VM's disk (``~/.eregion/analysis``, mounted into the container).

A report costs a call to the analysis model (seconds, minutes): on its own thread it never
delays a cycle, and every failure (the channel, the index, the model, the files) is caught
and noted — the watch never stops for a report. A report that fails is noted beside the
manifest (``report.error``, with its attempts) and in the thread's memory, and tried again
at the next pulls, at most MAX_ATTEMPTS times in all, then given up and said so — never an
endless series of calls to the model, even when ``report.error`` cannot be written or read.
A campaign is due only once its manifest and the report of each executed run are here, and
not at a pull that failed for it (eregion_core/exercise_channel.py ``pull_campaigns``) — and
only a campaign pulled from the channel (its ``.pulled`` marker), never one of a local run
on the same runs directory. An ``aborted`` campaign gets no report of its own
(``make campaign-report``).

A report written once must hold the decisions: an executed run, detected or of unknown
detection, whose decision is not in the watch's files yet keeps its campaign waiting — until
the end of the run's window, grace included (the decision follows the detection, which the
return channel may have carried first); without a readable window, until DECISION_WAIT_S
after the end of the campaign; then DECISION_LAG_S more, the time the cycle takes to write
the decision of a detection seen at the last moment — some 25 min after the campaign's end.
Without an attack time or a resource, no wait: nothing could be attached. Past that, the report is
written, and says for each such run why its decision is unknown
(analysis/campaign_report.py ``decision_unknown``) — an unknown, never « Glorfindel did not
act ». A pull of the windows that fails puts the reports off to the next pull.
The report is visible in the watch's log (``make glorfindel-host-logs``) and on the VM
(``make glorfindel-host-campaign-report CAMPAIGN=<id>``).

The same pass pulls the report of each run launched alone from Orodruin (``annatar run``,
``gothmog run``, #193) into ``runs/<run_id>.json``, where the console of the atelier reads
its verdict (eregion_console/api.py): read against its shape first (H-1,
analysis/campaign_schema.py), never over a report of a run of this host
(eregion_core/exercise_channel.py ``pull_runs``). Why one was not pulled is said once.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from analysis import campaign_schema
from eregion_core import exercise_channel
from eregion_core.exercise import GRACE_AFTER_S, MAX_DURATION_S

MAX_ATTEMPTS = 3
# Without a readable window or an attack time, how long after the end of its campaign a
# detected run's decision is waited for — the window's own grace.
DECISION_WAIT_S = GRACE_AFTER_S
# The window bounds when the detection was seen, not when its decision is written: the cycle
# that follows (investigation, the model's decision and its retries, the action and its
# check) writes its record later. Waited for after either deadline.
DECISION_LAG_S = 10 * 60
# No wait outlasts this, counted from when the manifest came here: a window never closed
# lapses at its expiry (2 h) plus its grace, and its last decision is written DECISION_LAG_S
# later — a clock or a date gone wrong on the other host never holds a report back longer.
MAX_WAIT_S = MAX_DURATION_S + GRACE_AFTER_S + DECISION_LAG_S
REPORT = "report.md"
ERROR = "report.error"
LOCK = ".report.lock"

# The failures this process counted, by campaign directory: ``report.error`` may be neither
# writable (a full disk, a read-only mount) nor readable — the attempts still end.
_failures: dict[str, int] = {}
_failures_lock = threading.Lock()
# What the thread last said of a campaign, by sort of message (a run id refused, the wait
# for the decisions): said again only when it changes.
_said: dict[tuple[str, str], str] = {}


def _say(message: str) -> None:
    print(f"[campaign-report] {message}", flush=True)


def _key(cdir: Path) -> str:
    return str(Path(cdir).absolute())


def attempts(cdir: Path) -> int:
    """How many times the report of this campaign has failed already: the larger of what
    ``report.error`` says and what this process counted."""
    try:
        noted = int(json.loads((cdir / ERROR).read_text(encoding="utf-8")).get("attempts") or 0)
    except (OSError, ValueError, TypeError, AttributeError):
        noted = 0
    with _failures_lock:
        return max(noted, _failures.get(_key(cdir), 0))


def _say_once(cdir: Path, sort: str, message: str, say=_say, *, key: str | None = None) -> None:
    """Say ``message`` unless the last one said in this slot had the same ``key`` (the message
    itself by default)."""
    k = (_key(cdir), sort)
    key = message if key is None else key
    if _said.get(k) != key:
        _said[k] = key
        say(message)


def _error_key(e: BaseException) -> str:
    """What stays the same in a failure that lasts: its type and its HTTP status — never its
    text, which may change at every call (a timed-out connection names its object ``at
    0x…``, Azure a request id or a time): compared whole, it was said again every 30 s
    (review 5)."""
    status = None
    for attr in ("status_code", "status", "code"):
        v = getattr(e, attr, None)
        if isinstance(v, int) and not isinstance(v, bool):
            status = v
            break
    response = getattr(e, "response", None)
    if status is None and isinstance(getattr(response, "status_code", None), int):
        status = response.status_code
    if status is None and (m := re.search(r"\bHTTP (\d{3})\b", str(e))):
        status = int(m.group(1))
    return f"{type(e).__module__}.{type(e).__qualname__}" + (f" {status}" if status else "")


def _runs_awaited(manifest: dict, say=None) -> list[str]:
    """The run ids whose report must be here before the campaign's report is written: those
    of its executed scenarios — an executed run always writes its report
    (annatar/runner/engine.py). A scenario in error may carry a run id and no report:
    waiting for it would leave the campaign without a report forever. A run id that is not
    a plain name (the manifest comes from another host) never names a file: not awaited,
    said, and left out of the report's facts (analysis/campaign_report.py)."""
    out = []
    for s in manifest.get("scenarios") or []:
        if not (isinstance(s, dict) and s.get("run_id") and s.get("status") == "executed"):
            continue
        rid = str(s["run_id"])
        if exercise_channel.safe_part(rid):
            out.append(rid)
        elif say:
            say(f"scenario {str(s.get('seq'))[:8]}: run id refused (not a plain name), left out")
    return out


def ready(campaigns_root: Path, *, failed=frozenset(), say=_say) -> list[Path]:
    """The campaigns whose report may be written, decisions aside: pulled from the channel
    (``.pulled``), a manifest of the accepted shape (H-1, analysis/campaign_schema.py) and
    ``done``, no ``report.md``, attempts left, the report of each executed run here
    (``runs/<run_id>.json``), and not in ``failed`` (its pull failed just now: the next
    pull). An unreadable manifest is skipped (it may be half-pulled: the next pull)."""
    root = Path(campaigns_root)
    if not root.is_dir():
        return []
    out = []
    for cdir in sorted(p for p in root.iterdir() if p.is_dir()):
        if (cdir.name in failed or not (cdir / exercise_channel.PULLED).exists()
                or (cdir / REPORT).exists() or attempts(cdir) >= MAX_ATTEMPTS):
            continue
        try:
            manifest = json.loads((cdir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # H-1: the manifest was written on another host — read against its shape first.
        refused = campaign_schema.manifest_refusal(manifest)
        if refused:
            _say_once(cdir, "manifest", f"{cdir.name}: manifest refused ({refused}) — no report", say)
            continue
        if manifest.get("state") != "done":
            continue
        if campaign_schema.without_glorfindel(manifest):  # V1: no report, by choice
            _say_once(cdir, "without", f"{cdir.name}: {campaign_schema.NO_CAMPAIGN_REPORT}", say)
            continue
        awaited = _runs_awaited(manifest,
                                lambda m, c=cdir: _say_once(c, "run_id", f"{c.name}: {m}", say))
        if all((cdir / "runs" / f"{rid}.json").is_file() for rid in awaited):
            out.append(cdir)
    return out


def _parse(value) -> float | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def _arrival(cdir: Path) -> float:
    """When the manifest came here (its local copy's mtime)."""
    try:
        return (cdir / "manifest.json").stat().st_mtime
    except OSError:
        return time.time()


def campaign_end(cdir: Path) -> float:
    """When the campaign ended: the latest of its scenarios' ``finished_at`` and its
    manifest's ``updated_at`` (written at ``done``), never later than when its manifest came
    here (which follows the end) — and that, without a readable date."""
    try:
        manifest = json.loads((cdir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    manifest = manifest if isinstance(manifest, dict) else {}
    stamps = [_parse(s.get("finished_at")) for s in manifest.get("scenarios") or []
              if isinstance(s, dict)] + [_parse(manifest.get("updated_at"))]
    stamps = [t for t in stamps if t is not None]
    arrival = _arrival(cdir)
    return min(max(stamps), arrival) if stamps else arrival


def waits_for_decisions(cdir: Path, runs_dir: Path, *, now: float | None = None,
                        say=_say) -> bool:
    """True while an executed run of the campaign, detected or of unknown detection, has no
    decision in the watch's files and may still get one: until the end of its window, grace
    included — or, without a readable window, until DECISION_WAIT_S after the end of the
    campaign — then DECISION_LAG_S more, for the cycle to write its decision. Without an
    attack time or a resource, no wait: the run's report and the manifest are whole once the
    campaign is ready, and nothing is then ever attached (analysis/campaign_report.py
    ``run_decision``) — whereas a window may still come, and a decision still be written.
    Said once, with until when; past that, the report says why the decision is unknown. No
    wait outlasts MAX_WAIT_S after the manifest came here."""
    from analysis import campaign_report as cr

    never_attached = {cr.NO_ATTACK_TIME, cr.NO_RESOURCE}
    now = time.time() if now is None else now
    late = campaign_end(cdir) + DECISION_WAIT_S
    cap = _arrival(cdir) + MAX_WAIT_S
    waiting, given_up = [], []
    for rid, why, until in cr.undecided_runs(cdir, runs_dir, warn=lambda m: None):
        if set(why.split(", ")) & never_attached:  # the files are whole: no wait changes it
            given_up.append((rid, why, now))
            continue
        seen_by = until.timestamp() if why == cr.NONE_IN_WINDOW and until is not None else late
        deadline = min(seen_by + DECISION_LAG_S, cap)
        (waiting if now <= deadline else given_up).append((rid, why, deadline))
    if waiting:
        last = max(d for _, _, d in waiting)
        runs = ", ".join(f"{rid} ({why})" for rid, why, _ in waiting)
        _say_once(cdir, "decisions", f"{cdir.name}: waiting for Glorfindel's decision on {runs} — "
                                     f"until {datetime.fromtimestamp(last, timezone.utc):%H:%M:%S} "
                                     f"UTC at the latest", say)
        return True
    if given_up:
        runs = ", ".join(f"{rid} ({why})" for rid, why, _ in given_up)
        _say_once(cdir, "decisions", f"{cdir.name}: no decision found for {runs} — the report "
                                     f"says it is unknown", say)
    return False


def due(campaigns_root: Path, *, failed=frozenset(), runs_dir: Path | None = None,
        now: float | None = None, say=_say) -> list[Path]:
    """The campaigns whose report is to be written now: ``ready``, and no detected run of
    theirs still waiting for its decision (``waits_for_decisions``). The windows must have
    been pulled first (``tick``)."""
    root = Path(campaigns_root)
    runs = Path(runs_dir) if runs_dir is not None else root.parent
    return [cdir for cdir in ready(root, failed=failed, say=say)
            if not waits_for_decisions(cdir, runs, now=now, say=say)]


def _note_failure(cdir: Path, error: Exception) -> int:
    n = attempts(cdir) + 1
    with _failures_lock:
        _failures[_key(cdir)] = n
    try:
        (cdir / ERROR).write_text(json.dumps({
            "attempts": n, "error": f"{type(error).__name__}: {str(error)[:300]}",
            "at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
    except OSError:
        pass  # not noted on disk: the thread's own count still ends the attempts
    return n


def write_report(cdir: Path, *, model: str | None = None, llm=None,
                 index_path: Path | None = None, say=_say) -> str:
    """Write ``cdir/report.md`` once: ``written``, ``exists`` (already there), ``without`` (no
    report, by choice — V1: a campaign run --without-glorfindel), ``busy``
    (another pass holds the campaign) or ``failed: …``. Never raises."""
    cdir = Path(cdir)
    try:
        fd = os.open(cdir / LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError as e:  # no model called, so no attempt counted: said once while it lasts
        _say_once(cdir, "lock", f"{cdir.name}: report not written, its lock cannot be opened "
                                f"({type(e).__name__}: {e}) — tried again at the next pull",
                  say, key=_error_key(e))
        return f"failed: {e}"
    _said.pop((_key(cdir), "lock"), None)   # opened: a later failure is said again
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return "busy"
        if (cdir / REPORT).exists():  # written by a pass that held the lock before us
            return "exists"
        try:
            from analysis import campaign_report as cr
            if why := cr.no_report(cdir):   # V1: no report by choice — no attempt counted
                _say_once(cdir, "without", f"{cdir.name}: {why}", say)
                return "without"
            # strict: an answer without the tool's call is a failed attempt, never an
            # empty report written for good.
            report = cr.build(cdir, model=model, llm=llm, index_path=index_path, strict=True)
            tmp = cdir / (REPORT + ".tmp")
            tmp.write_text(cr.render(report), encoding="utf-8")
            tmp.replace(cdir / REPORT)
        except Exception as e:  # the model, the index, the files: noted, tried again later
            n = _note_failure(cdir, e)
            if n >= MAX_ATTEMPTS:
                say(f"{cdir.name}: given up after {n} attempts ({type(e).__name__}: {str(e)[:160]})"
                    f" — by hand: make campaign-report CAMPAIGN={cdir.name}")
            else:
                say(f"{cdir.name}: attempt {n}/{MAX_ATTEMPTS} failed ({type(e).__name__}: "
                    f"{str(e)[:160]}) — tried again at the next pull")
            return f"failed: {e}"
        try:
            (cdir / ERROR).unlink(missing_ok=True)
        except OSError:  # an error left behind: the report is written, its presence wins (ready)
            pass
        unknown = sum(1 for f in report.facts if f.decision_unknown)
        say(f"{cdir / REPORT} — {len(report.kept)} claim(s) kept, "
            f"{len(report.rejected)} rejected by the check"
            + (f", {unknown} decision(s) unknown" if unknown else ""))
        return "written"
    finally:
        os.close(fd)


def pull_runs(runs_dir: Path, *, channel: str | None = None, credential=None, get=None,
              say=_say) -> int:
    """The reports of the runs launched alone (#193), pulled into ``runs_dir`` once they
    have the shape H0 accepts (``run_report_refusal``, H-1). How many were written. A run
    not pulled is said once with why, the listing that fails too. Never raises."""
    runs_dir = Path(runs_dir)
    try:
        written, skipped = exercise_channel.pull_runs(
            runs_dir, refusal=campaign_schema.run_report_refusal,
            channel=channel, credential=credential, get=get)
    except Exception as e:  # the next pass tries again; the campaigns do not wait for it
        _say_once(runs_dir, "runs", f"run reports not pulled: {e}", say, key=_error_key(e))
        return 0
    _said.pop((_key(runs_dir), "runs"), None)
    for rid, why in sorted(skipped.items()):
        _say_once(runs_dir / f"{rid}.json", "run", f"run report {rid} not pulled: {why}", say)
    here = Path(_key(runs_dir))
    for k in [k for k in _said if k[1] == "run" and Path(k[0]).parent == here
              and Path(k[0]).stem not in skipped]:
        del _said[k]                     # pulled this time: a later refusal is said again
    return written


def pull_orodruin(runs_dir: Path, *, channel: str | None = None, credential=None, get=None,
                  say=_say) -> int:
    """Orodruin's verdict and the status of each request (DG-b), pulled into ``runs/orodruin/``
    once they have their shape — for the console, never read by the decision. Never raises."""
    where = Path(runs_dir) / exercise_channel.ORODRUIN
    try:
        written, skipped = exercise_channel.pull_orodruin(where, channel=channel,
                                                          credential=credential, get=get)
    except Exception as e:
        _say_once(where, "orodruin", f"Orodruin's verdict and statuses not pulled: {e}", say,
                  key=_error_key(e))
        return 0
    _said.pop((_key(where), "orodruin"), None)
    for name, why in sorted(skipped.items()):
        _say_once(where / name, "orodruin", f"{name} not pulled: {why}", say)
    return written


def tick(runs_dir: Path, *, channel: str | None = None, credential=None, get=None,
         model: str | None = None, llm=None, index_path: Path | None = None,
         now: float | None = None, say=_say) -> dict[str, str]:
    """One pass: pull the reports of the runs launched alone (``pull_runs``), pull the
    published campaigns, pull the windows once more (the last one closed just before its
    campaign ended), then write the report of each campaign due. What happened, by
    campaign: ``written``, ``waiting`` (a decision may still come, or the windows were not
    pulled), or ``write_report``'s answer. Never raises."""
    from analysis.campaign_report import windows_dir

    runs_dir = Path(runs_dir)
    root = runs_dir / exercise_channel.CAMPAIGNS
    kw = {"channel": channel, "credential": credential, "get": get}
    pull_runs(runs_dir, say=say, **kw)
    # A failure is said once while it lasts (every 30 s, it would fill the watch's log), and
    # again if it comes back after a pull that went through.
    try:
        _, failed = exercise_channel.pull_campaigns(root, **kw)
    except Exception as e:  # the listing failed: nothing is due at this pull — the next one
        _say_once(root, "pull", f"pull failed: {e}", say, key=_error_key(e))
        return {}
    _said.pop((_key(root), "pull"), None)
    # DG-b: Orodruin's verdict and the requests' statuses, once the channel answered — a listing
    # that fails is said once, above.
    pull_orodruin(runs_dir, say=say, **kw)
    for cid in sorted(failed):
        _say_once(root / cid, "pull", f"{cid}: not all pulled — its report waits for the next pull", say)
    here = Path(_key(root))
    for k in [k for k in _said if k[1] == "pull" and Path(k[0]).parent == here
              and Path(k[0]).name not in failed]:
        del _said[k]                     # pulled whole this time: a later failure is said again
    candidates = ready(root, failed=failed, say=say)
    if not candidates:
        return {}
    try:
        exercise_channel.pull_now(windows_dir(runs_dir), **kw)
    except Exception as e:  # without its windows, a report would miss decisions: next pull
        _say_once(root, "windows", f"windows not pulled ({e}) — {len(candidates)} report(s) wait "
                                   f"for the next pull", say, key=_error_key(e))
        return {cdir.name: "waiting" for cdir in candidates}
    _said.pop((_key(root), "windows"), None)
    out = {}
    for cdir in candidates:
        try:
            waiting = waits_for_decisions(cdir, runs_dir, now=now, say=say)
        except Exception as e:  # never a wait without end: the report's own attempts count
            say(f"{cdir.name}: decisions not read ({type(e).__name__}: {e})")
            waiting = False
        if waiting:
            out[cdir.name] = "waiting"
        else:
            out[cdir.name] = write_report(cdir, model=model, llm=llm, index_path=index_path,
                                          say=say)
    return out


def run(runs_dir: Path, *, interval: float = exercise_channel.PULL_EVERY_S,
        ticks: int | None = None, sleep=time.sleep, step=None) -> None:
    """The thread's loop: ``tick`` every ``interval``, whatever a tick raises."""
    step = step or tick
    n = 0
    while ticks is None or n < ticks:
        try:
            step(runs_dir)
        except Exception as e:  # a report never stops the thread, nor the watch
            _say(f"pass failed: {type(e).__name__}: {e}")
        n += 1
        sleep(interval)


def start(runs_dir: Path, *, interval: float = exercise_channel.PULL_EVERY_S):
    """The thread, or ``None`` without an exercise channel (a campaign run beside the watch
    writes its own report: annatar/cli.py)."""
    if not exercise_channel.channel_url():
        return None
    thread = threading.Thread(target=run, args=(Path(runs_dir),), kwargs={"interval": interval},
                              daemon=True, name="campaign-report")
    thread.start()
    return thread
