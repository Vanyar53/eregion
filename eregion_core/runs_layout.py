"""SEC18 (N-05, #455): ``runs/`` — one directory per writer, written by it alone, mounted read-only
by those who read it (docs/fichiers-cles.md, « runs/ — qui écrit, qui lit, qui monte »).

- ``runs/glorfindel/`` — the watch, and what runs in its container: its cycles
  (``*_debug.jsonl``), what it pulls from the exercise channel on H0 (``campaigns/``,
  ``<run_id>.json`` and ``.pulled-runs/``, ``exercises/``, ``orodruin/``), and what the analysis
  writes of a campaign (``campaigns/<id>/report.md``, ``report.error``, ``triage.*``,
  ``replay.json``) — wherever the campaign itself was written;
- ``runs/console/`` — the console and Glorfindel's CLI: ``manual_actions.jsonl``; the console's
  requests of the action queue (``queue/``, FS1b);
- ``runs/bot/`` — the bot (FS1b): its requests of the action queue (``queue/``), signed by its
  key — a writer of its own, so the directory says the writer, and the key must be its; and, since
  FS1c, its gestures (``manual_actions.jsonl``, the CLI it runs — ``EREGION_RUNS_WRITER=bot``): the
  bot no longer mounts ``runs/console``, nor can it replace or drown the console's requests;
- ``runs/glorfindel/queue/`` — the watch's receipts of those requests and its status, signed;
- ``runs/annatar/`` — Annatar: ``*_signals.jsonl``, ``<run_id>.json``, ``exercises/``,
  ``campaigns/``;
- ``runs/gothmog/`` — Gothmog: ``*_signals.jsonl``, ``<run_id>.json``, ``exercises/``;
- ``runs/orodruin/`` — the injectors on Orodruin's host and its runner: ``audit.jsonl``,
  ``requests/`` (the statuses, the registry, the lock of « one run at a time »);
- ``runs/verdicts/`` — the watch's local channel of verdicts (``eregion_core/watch_channel.py``,
  ``LocalVerdicts``): ``heartbeat.json``, ``detections/<run_id>/`` — a run's verdict, never the
  reasoning; the one directory of the blue the red mounts, read-only. Not on Orodruin, where the
  storage channel carries them.

A reader looks for a file only in the directory of the writer that writes it: a signal is read from
``annatar/`` only, a cycle from ``glorfindel/`` only, an operator's gesture from ``console/`` only.
What is anywhere else is never read, and ``survey`` says it — a file of the former layout (flat in
``runs/``), or one of another writer in a writer's directory (an injector's signal in the
console's): the same file written where it does not belong is refused, said once (``say_strays``).
A report's own word is held against its directory (``report_refusal``): an injector's directory
holds that injector's runs only.

The former layout is moved, once, by ``migrate`` (``python -m eregion_core.runs_layout migrate``),
run on the host before the services start — no service mounts the whole of ``runs/``: each file
goes to its writer's directory when that writer is told without ambiguity (its name, or what it
says of itself, or a marker of the pull beside it); any other is left where it is, never read, and
said with the gesture to make. Nothing is ever deleted: a file is renamed, an emptied directory of
the former layout removed. Run again, it moves nothing more.

Standard library only: the migration runs on H0's host Python, outside any image.
"""
from __future__ import annotations

import fnmatch
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path("runs")
GLORFINDEL, CONSOLE, ANNATAR, GOTHMOG, ORODRUIN = "glorfindel", "console", "annatar", "gothmog", "orodruin"
VERDICTS = "verdicts"   # written by the watch, read-only to the red (SEC18)
BOT = "bot"             # FS1b: the bot's requests of the action queue — a writer of its own
WRITERS = (GLORFINDEL, CONSOLE, ANNATAR, GOTHMOG, ORODRUIN, VERDICTS, BOT)
# FS1c: the directories of an operator's hand — the console's (and the CLI's), the bot's: each
# writes its own manual_actions.jsonl, and the feed, the indicators and the containment read both.
HANDS = (CONSOLE, BOT)
# Which hand writes a gesture: the bot sets it for the CLI it runs; unset, or anything else, the
# console's (the console, the operator's CLI).
WRITER_ENV = "EREGION_RUNS_WRITER"
# What Orodruin's host holds: no watch there — its verdicts come by the storage channel.
ORODRUIN_HOST = (ANNATAR, GOTHMOG, ORODRUIN)
INJECTORS = (ANNATAR, GOTHMOG)

# What a writer's directory may hold at its top: the patterns of its files, the names of its
# subdirectories. A name starting with a dot is a write in progress (channel_reader.write_file)
# or a marker of the pull, never read as a run's file: not surveyed.
_FILES = {
    GLORFINDEL: ("*_debug.jsonl", "*.json"),
    CONSOLE: ("manual_actions.jsonl",),
    ANNATAR: ("*_signals.jsonl", "*.json"),
    GOTHMOG: ("*_signals.jsonl", "*.json"),
    ORODRUIN: ("audit.jsonl",),
    VERDICTS: ("heartbeat.json",),
    BOT: ("manual_actions.jsonl",),
}
# FS1b: ``queue/`` — a service's requests of the action queue (console, bot), the watch's receipts
# and its status (glorfindel).
_DIRS = {
    GLORFINDEL: ("campaigns", "exercises", "orodruin", "queue"),
    CONSOLE: ("queue",),
    ANNATAR: ("campaigns", "exercises"),
    GOTHMOG: ("exercises",),
    ORODRUIN: ("requests",),
    VERDICTS: ("detections",),
    BOT: ("queue",),
}
# The analysis' files of a campaign: in the watch's directory, whoever wrote the campaign.
ANALYSIS_FILES = ("report.md", "report.error", ".report.lock", "triage.md", "triage.json",
                  ".triage.lock", "replay.json")
# Markers of the exercise channel's pull (eregion_core/exercise_channel.py PULLED, PULLED_RUNS)
# and of Orodruin's published verdict on H0 (eregion_core/orodruin.py CONTRACT_BLOB).
_PULLED, _PULLED_RUNS, _CONTRACT = ".pulled", ".pulled-runs", "contract.json"
_CHANNEL_CREATED = "channel_created"     # eregion_core/exercise.py CHANNEL_CREATED
_REPORT_BYTES = 2 * 1024 * 1024          # a report or a window read to tell its writer, bounded


def dir_of(writer: str, root=None) -> Path:
    """``<root>/<writer>`` (``runs/<writer>`` from the working directory by default)."""
    if writer not in WRITERS:
        raise ValueError(f"no writer of runs/ is called {writer!r}")
    return Path(ROOT if root is None else root) / writer


def hand(environ=None) -> str:
    """FS1c: the hand whose directory a gesture is noted in — ``bot`` when ``EREGION_RUNS_WRITER``
    says so (the CLI the bot runs), else ``console``."""
    return BOT if (os.environ if environ is None else environ).get(WRITER_ENV, "") == BOT else CONSOLE


def beside(directory, writer: str) -> Path:
    """The directory of ``writer`` next to a writer's ``directory`` (``runs/annatar`` →
    ``runs/glorfindel``): where a campaign's reader finds the watch's cycles, the operator's
    gestures. ``directory`` itself when it is that writer's."""
    directory = Path(directory)
    if writer not in WRITERS:
        raise ValueError(f"no writer of runs/ is called {writer!r}")
    return directory if directory.name == writer else directory.parent / writer


def writer_of(path) -> str:
    """The writer whose directory holds ``path`` (``runs/annatar/x.json`` → ``annatar``), or ""
    when it is in none: the innermost directory named after a writer — but a campaign's id
    (``campaigns/<id>``) and the watch's copy of Orodruin's statuses (``glorfindel/orodruin``) are
    not writers' directories."""
    parts = Path(path).parts
    for i in range(len(parts) - 2, -1, -1):
        if parts[i] not in WRITERS:
            continue
        before = parts[i - 1] if i else ""
        if before == "campaigns" or (parts[i] == ORODRUIN and before == GLORFINDEL):
            continue
        return parts[i]
    return ""


def campaign_output(campaign_dir) -> Path:
    """Where the analysis writes of a campaign — ``report.md``, ``report.error``, ``triage.*``,
    ``replay.json`` —: in the watch's directory, ``<root>/glorfindel/campaigns/<id>``, whoever
    wrote the campaign (Annatar on this host, or the watch's pull on H0: then its own directory).
    A campaign in no writer's directory (a copy named by hand) keeps its analysis beside it."""
    cdir = Path(campaign_dir)
    holder = cdir.parent.parent
    if cdir.parent.name != "campaigns" or holder.name not in WRITERS or holder.name == GLORFINDEL:
        return cdir
    return holder.parent / GLORFINDEL / "campaigns" / cdir.name


# Who holds campaigns, and run reports, on a host: the watch first (pulled on H0), then the
# injectors (written on this host).
CAMPAIGN_HOLDERS = (GLORFINDEL, ANNATAR)
REPORT_HOLDERS = (GLORFINDEL, ANNATAR, GOTHMOG)


def campaign_dirs(root=None) -> list[Path]:
    """Every campaign directory of this host: ``<holder>/campaigns/<id>``, the watch's then
    Annatar's."""
    out = []
    for w in CAMPAIGN_HOLDERS:
        base = dir_of(w, root) / "campaigns"
        out += [base / e.name for e in _entries(base) if e.is_dir(follow_symlinks=False)]
    return out


def find_campaign(campaign_id: str, root=None) -> Path | None:
    """The directory of campaign ``campaign_id`` on this host (the watch's copy first), or None."""
    for w in CAMPAIGN_HOLDERS:
        cdir = dir_of(w, root) / "campaigns" / campaign_id
        if (cdir / "manifest.json").is_file():
            return cdir
    return None


def run_reports(root=None) -> dict[str, Path]:
    """Where each run's report is on this host, by run id: a run's own report
    (``<holder>/<run_id>.json``) over the copy published with its campaign
    (``<holder>/campaigns/<id>/runs/<run_id>.json``)."""
    found: dict[str, Path] = {}
    for w in CAMPAIGN_HOLDERS:
        found.update({p.stem: p for p in sorted((dir_of(w, root) / "campaigns").glob("*/runs/*.json"))})
    for w in REPORT_HOLDERS:
        found.update({p.stem: p for p in sorted(dir_of(w, root).glob("*.json"))})
    return found


def belongs(writer: str, name: str, is_dir: bool) -> bool:
    """``name``, at the top of ``writer``'s directory, is of that writer."""
    if is_dir:
        return name in _DIRS[writer]
    return any(fnmatch.fnmatchcase(name, p) for p in _FILES[writer])


def _who_writes(name: str, is_dir: bool) -> list[str]:
    return [w for w in WRITERS if belongs(w, name, is_dir)]


def _not_of(writer: str, name: str, is_dir: bool) -> str:
    others = _who_writes(name, is_dir)
    where = " ou ".join(f"runs/{w}/" for w in others)
    return (f"pas un fichier de {writer} — " + (f"il ne se lit que de {where}" if others else
            "aucun écrivain ne l'écrit") + " : jamais lu (SEC18)")


def report_refusal(path, report) -> str:
    """Why a run's report is not read from where it is — "" when it is (SEC18): in an injector's
    directory, a report must say that injector (``metrics.injector``, or none: before C1, an
    attack's); the watch's directory holds the reports it pulled, of either."""
    writer = writer_of(path)
    if writer not in INJECTORS or not isinstance(report, dict):
        return ""
    m = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    said = m.get("injector") or (GOTHMOG if m.get("kind") == "fault" else ANNATAR)
    if said != writer:
        return f"un rapport de {said!s:.40} dans le répertoire de {writer} : jamais lu (SEC18)"
    # What the readers count it as (run_report.kind_of): Annatar's runs are attacks, Gothmog's faults.
    kind = m["kind"] if m.get("kind") in ("technique", "fault") else ("fault" if said == GOTHMOG else "technique")
    if kind != _KIND[writer]:
        return f"un rapport « {kind} » dans le répertoire de {writer} : jamais lu (SEC18)"
    return ""


_KIND = {ANNATAR: "technique", GOTHMOG: "fault"}


def window_refusal_of(path, window) -> str:
    """Why an exercise window is not believed from where it is — "" when it is (SEC18): in an
    injector's directory, a window must name that injector, and its kind be that injector's; the
    watch's directory holds the windows it pulled, of either."""
    writer = writer_of(path)
    if writer not in INJECTORS or not isinstance(window, dict):
        return ""
    if window.get("injector") != writer or window.get("kind") != _KIND[writer]:
        return (f"une fenêtre de {str(window.get('injector'))[:40]} ({str(window.get('kind'))[:20]}) "
                f"dans le répertoire de {writer} : jamais crue (SEC18)")
    return ""


def _entries(directory: Path) -> list[os.DirEntry]:
    try:
        with os.scandir(directory) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def survey(root=None) -> list[tuple[Path, str]]:
    """What the layout does not read, and why — never raises: an entry at the top of ``runs/`` that
    is no writer's directory (the former layout), a writer's directory that is not a directory,
    and an entry of a writer's directory that is not of its writer. Names starting with a dot are
    writes in progress or markers: not surveyed."""
    root = Path(ROOT if root is None else root)
    out: list[tuple[Path, str]] = []
    for e in _entries(root):
        if e.name.startswith("."):
            continue
        path = root / e.name
        if e.name in WRITERS:
            if not e.is_dir(follow_symlinks=False):
                out.append((path, "le répertoire d'un écrivain n'est pas un répertoire (un lien, "
                                  "un fichier) : jamais lu (SEC18)"))
                continue
            for sub in _entries(path):
                if sub.name.startswith("."):
                    continue
                is_dir = sub.is_dir(follow_symlinks=False)
                if not belongs(e.name, sub.name, is_dir):
                    out.append((path / sub.name, _not_of(e.name, sub.name, is_dir)))
            continue
        out.append((path, "ancienne disposition de runs/ (à plat) : jamais lu — "
                          "make runs-migrate, ou le déplacer à la main vers runs/<écrivain>/ (SEC18)"))
    return out


_said: dict[str, str] = {}


def say_strays(root=None, say=print) -> int:
    """``survey``, each entry said once per process (again only if why changes) — how a reader
    says what it does not read. Returns how many are said now. Never raises."""
    n = 0
    try:
        found = survey(root)
    except Exception:   # a survey never stops a reader
        return 0
    for path, why in found:
        key = os.path.abspath(path)
        if _said.get(key) == why:
            continue
        _said[key] = why
        shown = "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(path))
        say(f"{shown} : {why}")
        n += 1
    return n


# ── The migration of the former layout ────────────────────────────────────────────────────

def _read_json(path: Path):
    """A regular file's JSON, bounded, never through a link — None when it is not one."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, _REPORT_BYTES + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > _REPORT_BYTES:
        return None
    try:
        return json.loads(data)
    except ValueError:
        return None


def _report_writer(path: Path, root: Path) -> str:
    """Who wrote a run's report at the top of the former ``runs/``: the watch when its pull marked
    it (``.pulled-runs/<run_id>``), else the injector it says (none: an attack's, before C1)."""
    if (root / _PULLED_RUNS / path.stem).exists():
        return GLORFINDEL
    doc = _read_json(path)
    if not isinstance(doc, dict) or "metrics" not in doc or not isinstance(doc.get("metrics"), dict):
        return ""
    m = doc["metrics"]
    said = m.get("injector") or (GOTHMOG if m.get("kind") == "fault" else ANNATAR)
    return said if said in INJECTORS else ""


def _window_writer(path: Path) -> str:
    """Who wrote an exercise window: the watch when it was pulled from the channel (it carries
    ``channel_created``), else the injector it names."""
    doc = _read_json(path)
    if not isinstance(doc, dict):
        return ""
    if doc.get(_CHANNEL_CREATED):
        return GLORFINDEL
    return doc["injector"] if doc.get("injector") in INJECTORS else ""


def _plan(root: Path) -> tuple[list[tuple[Path, Path]], list[tuple[Path, str]]]:
    """(src → dst moves, entries left aside and why) for the former layout under ``root``."""
    moves: list[tuple[Path, Path]] = []
    left: list[tuple[Path, str]] = []
    unknown = "son écrivain ne se reconnaît pas sans ambiguïté"

    for e in _entries(root):
        path, name = root / e.name, e.name
        is_dir = e.is_dir(follow_symlinks=False)
        if e.is_symlink():
            left.append((path, "un lien, jamais suivi"))
            continue
        if name in WRITERS:
            if name == ORODRUIN and is_dir and (path / _CONTRACT).exists():
                # On H0, runs/orodruin/ was the watch's copy of what Orodruin published.
                moves.append((path, dir_of(GLORFINDEL, root) / ORODRUIN))
            elif name == GOTHMOG and is_dir:
                continue   # Gothmog's signals were there already: its directory now
            continue
        if name == _PULLED_RUNS and is_dir:
            moves.append((path, dir_of(GLORFINDEL, root) / name))
        elif name.startswith("."):
            left.append((path, "un fichier temporaire, ou d'un autre outil"))
        elif not is_dir and fnmatch.fnmatchcase(name, "*_debug.jsonl"):
            moves.append((path, dir_of(GLORFINDEL, root) / name))
        elif not is_dir and fnmatch.fnmatchcase(name, "*_signals.jsonl"):
            # Gothmog wrote its own under runs/gothmog/ already: a signal at the top is Annatar's.
            moves.append((path, dir_of(ANNATAR, root) / name))
        elif not is_dir and name == "manual_actions.jsonl":
            moves.append((path, dir_of(CONSOLE, root) / name))
        elif not is_dir and fnmatch.fnmatchcase(name, "*.json"):
            w = _report_writer(path, root)
            moves.append((path, dir_of(w, root) / name)) if w else left.append((path, unknown))
        elif is_dir and name == "exercises":
            for sub in _entries(path):
                p = path / sub.name
                w = _window_writer(p) if fnmatch.fnmatchcase(sub.name, "*.json") \
                    and not sub.is_dir(follow_symlinks=False) else ""
                moves.append((p, dir_of(w, root) / "exercises" / sub.name)) if w else left.append((p, unknown))
        elif is_dir and name == "campaigns":
            for c in _entries(path):
                cdir = path / c.name
                if not c.is_dir(follow_symlinks=False):
                    left.append((cdir, unknown))
                    continue
                if (cdir / _PULLED).exists():
                    moves.append((cdir, dir_of(GLORFINDEL, root) / "campaigns" / c.name))
                    continue
                for f in _entries(cdir):
                    w = GLORFINDEL if f.name in ANALYSIS_FILES else ANNATAR
                    moves.append((cdir / f.name, dir_of(w, root) / "campaigns" / c.name / f.name))
        else:
            left.append((path, unknown))
    return moves, left


def _real_dir(path: Path) -> bool:
    """``path`` is a directory itself — by lstat: never a link to one."""
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def pull_root(directory) -> str:
    """The directory a pull writes into, made as before (``makedirs``) when absent — refused when
    it is there and no real directory (a link): "" when it holds, else why (SEC18)."""
    directory = Path(directory)
    if os.path.lexists(directory):
        return "" if _real_dir(directory) else f"{directory} n'est pas un répertoire (un lien ?) : jamais traversé"
    try:
        os.makedirs(directory)
    except FileExistsError:
        pass
    return "" if _real_dir(directory) else f"{directory} n'est pas un répertoire (un lien ?) : jamais traversé"


def parents_hold(root: Path, dst: Path) -> str:
    """Make ``dst``'s parents under ``root``, each a real directory — "" when they are, else why:
    a link (or anything else) in the way is never created through nor crossed. ``root`` itself is
    never made: absent, nothing is written (a writer's directory is made by the deployment)."""
    root = Path(root)
    if not os.path.lexists(root):
        return f"{root} absent : rien n'est écrit (make runs-migrate le crée)"
    if not _real_dir(root):
        return f"{root} n'est pas un répertoire (un lien ?) : jamais traversé"
    d = root
    for part in dst.parent.relative_to(root).parts:
        d = d / part
        if not os.path.lexists(d):
            try:
                os.mkdir(d)
            except FileExistsError:
                pass
        if not _real_dir(d):
            return f"{d} n'est pas un répertoire (un lien ?) : jamais traversé"
    return ""


def _move(src: Path, dst: Path, left: list, root: Path) -> int:
    """Move ``src`` to ``dst``, never through a link, never over what is there: a regular file by
    a hard link then the old name removed (``os.link`` refuses an existing ``dst``: the two are
    kept, ``src`` left and said); a directory entry by entry; anything else (a link, a pipe) left
    where it is, said. Returns the entries moved."""
    try:
        st = os.lstat(src)
    except OSError as e:
        left.append((src, f"non déplacé ({e.strerror or e})"))
        return 0
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        left.append((src, "pas un fichier ordinaire (un lien, un tube) : jamais suivi"))
        return 0
    why = parents_hold(root, dst)
    if why:
        left.append((src, why))
        return 0
    if stat.S_ISDIR(st.st_mode):
        if os.path.lexists(dst) and not _real_dir(dst):
            left.append((src, f"{dst} existe et n'est pas un répertoire : les deux sont gardés"))
            return 0
        if not os.path.lexists(dst):
            os.mkdir(dst)
            os.utime(dst, (st.st_atime, st.st_mtime))
        n = sum(_move(src / e.name, dst / e.name, left, root) for e in _entries(src))
        _rmdir_empty(src)
        return n
    try:
        os.link(src, dst, follow_symlinks=False)
    except FileExistsError:
        left.append((src, f"{dst} existe déjà : les deux sont gardés, celui-ci n'est jamais lu — "
                          "les comparer, puis garder l'un"))
        return 0
    os.unlink(src)
    return 1


def _rmdir_empty(path: Path) -> None:
    try:
        path.rmdir()   # only when empty: nothing is ever deleted
    except OSError:
        pass


class Unsafe(OSError):
    """A writer's directory of runs/ that is no real directory (a link, a file): mounted, it would
    give its writer what it points to. Nothing is moved, nothing should start."""


# The known subdirectories of the blue's directories: a link there would make the watch (the pull,
# the campaign report, the local verdicts) write where it points.
BLUE_SUBDIRS = {GLORFINDEL: ("exercises", "campaigns", "orodruin"), CONSOLE: (), VERDICTS: ("detections",)}


def unsafe(root=None) -> list[Path]:
    """The writers' directories under ``root`` — and the known subdirectories of the blue's
    (``BLUE_SUBDIRS``) — that exist and are no real directory, by lstat, a link to one included
    (SEC18): what a mount, or the watch's own writes, would resolve elsewhere."""
    root = Path(ROOT if root is None else root)
    paths = [dir_of(w, root) for w in WRITERS]
    paths += [dir_of(w, root) / sub for w, subs in BLUE_SUBDIRS.items() for sub in subs]
    return [p for p in paths if os.path.lexists(p) and not _real_dir(p)]


def pending(root=None) -> bool:
    """The former layout holds something to move: an entry at the top of ``root`` that is no
    writer's directory (a dot aside, but the pull's marker), or H0's copy of Orodruin's statuses."""
    root = Path(ROOT if root is None else root)
    for e in _entries(root):
        if e.name in WRITERS:
            if e.name == ORODRUIN and (root / e.name / _CONTRACT).exists():
                return True
        elif not e.name.startswith(".") or e.name == _PULLED_RUNS:
            return True
    return False


def migrate(root=None, say=print, writers=WRITERS) -> tuple[int, list[tuple[Path, str]]]:
    """Move the former layout under ``root`` to its writers' directories, creating ``writers``'
    (on Orodruin, ``ORODRUIN_HOST`` only); returns (entries moved, entries left aside and why),
    each left said with the gesture to make. Nothing deleted; run again, nothing more moves. A
    writer's directory that is no real directory (a link) raises ``Unsafe`` before anything
    moves."""
    root = Path(ROOT if root is None else root)
    root.mkdir(parents=True, exist_ok=True)
    bad = unsafe(root)
    if bad:
        raise Unsafe(", ".join(str(b) for b in bad))
    for w in writers:
        dir_of(w, root).mkdir(exist_ok=True)
    moves, left = _plan(root)
    moved = 0
    for src, dst in moves:
        try:
            moved += _move(src, dst, left, root)
        except OSError as e:
            left.append((src, f"non déplacé ({e.strerror or e})"))
    for c in _entries(root / "campaigns"):   # the former layout's directories, once emptied
        _rmdir_empty(root / "campaigns" / c.name)
    for name in ("campaigns", "exercises"):
        _rmdir_empty(root / name)
    for w in writers:   # runs/orodruin/ moved away on H0: every writer keeps a directory
        if not os.path.lexists(dir_of(w, root)):
            dir_of(w, root).mkdir()
    for path, why in left:
        say(f"  laissé : {path} — {why} ; jamais lu. Le déplacer à la main vers runs/<écrivain>/ "
            "s'il est connu, sinon le garder à part (rien n'est effacé)")
    return moved, left


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    host = "--orodruin" in args
    args = [a for a in args if a != "--orodruin"]
    if not args or args[0] not in ("migrate", "survey", "pending"):
        print("usage: python -m eregion_core.runs_layout migrate|survey|pending [RUNS] [--orodruin]",
              file=sys.stderr)
        return 2
    root = Path(args[1]) if len(args) > 1 else ROOT
    if args[0] == "pending":   # 0: the former layout holds something to move (stop the services first)
        return 0 if pending(root) else 1
    if args[0] == "migrate":
        try:
            moved, left = migrate(root, writers=ORODRUIN_HOST if host else WRITERS)
        except Unsafe as e:
            print(f"✗ runs/ : {e} — pas un vrai répertoire (un lien ?) : rien n'est déplacé, rien ne doit "
                  "démarrer. Le retirer à la main (rm, jamais à travers lui), puis relancer (SEC18)",
                  file=sys.stderr)
            return 3
        print(f"runs/ ({root}) : {moved} déplacé(s) vers leur écrivain, {len(left)} laissé(s) (SEC18)")
        return 0
    found = survey(root)
    for path, why in found:
        print(f"{path} : {why}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
