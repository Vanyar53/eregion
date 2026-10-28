import importlib.util
import os

import pytest


def _present(package: str) -> bool:
    """D1: a component's tests also run with the other components absent
    (scripts/component_check.py) — a fixture of an absent one has nothing to redirect."""
    try:
        return importlib.util.find_spec(package) is not None
    except ModuleNotFoundError:   # made absent by the component check
        return False


GLORFINDEL = _present("glorfindel")
CONSOLE = _present("eregion_console")


@pytest.fixture(autouse=True)
def fake_anthropic_key(monkeypatch):
    """Ensure ANTHROPIC_API_KEY is set in all unit tests — actual calls are mocked.
    The operator's AZURE_SUBSCRIPTION_ID is removed: the subscription guard would
    otherwise refuse the tests' "/subscriptions/s/..." ids on a configured machine."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)


@pytest.fixture(autouse=True)
def hermetic_orodruin(tmp_path, monkeypatch):
    """Orodruin's contract (O1) without Azure or the network: its readers report a
    contract that holds — check() and the gate still run — and the audit journal goes
    to tmp. test_orodruin.py swaps in readers that fail."""
    import eregion_core.orodruin as orodruin
    monkeypatch.setattr(orodruin, "READERS", {
        "identity": lambda: [],
        "network": lambda: [],
        "cap": lambda: ([], {"max_injections": 20, "max_run_s": 3600}),
    })
    monkeypatch.setenv(orodruin.AUDIT_ENV, str(tmp_path / "orodruin-audit.jsonl"))
    # No exercise channel, no return channel (#159): nothing reaches Azure Storage.
    monkeypatch.delenv("EREGION_EXERCISE_CHANNEL", raising=False)
    monkeypatch.delenv("EREGION_WATCH_CHANNEL", raising=False)
    # IA0's index (analysis/campaign_report.py) in tmp, never ~/.eregion/analysis (#167).
    monkeypatch.setenv("EREGION_ANALYSIS_INDEX", str(tmp_path / "analysis-index"))
    # Its model's bound at the default, whatever the operator set in .envrc.
    monkeypatch.delenv("EREGION_ANALYSIS_TIMEOUT_S", raising=False)


@pytest.fixture(autouse=True)
def live_glorfindel_watch(monkeypatch):
    """V1 (#214): Annatar and Gothmog refuse to run without a live Glorfindel watch. Here the
    gate's readers see one — a heartbeat written just now, no channel — so the injectors'
    tests run as before; tests/unit/test_watch_gate.py swaps in readers that see none. The
    wait for a detection keeps reading the real local file (watch_gate.local_beat)."""
    from datetime import datetime, timezone

    import eregion_core.watch_gate as gate
    monkeypatch.setattr(gate, "READERS", {
        "channel": lambda: None,
        "local": lambda: gate.Beat(gate.LOCAL, datetime.now(timezone.utc)),
    })


@pytest.fixture(autouse=True)
def isolated_escalations_store(tmp_path, monkeypatch):
    """Redirect escalations._STORE to a temp file.

    Prevents test runs from writing pending escalations to ~/.glorfindel/,
    which the Discord bot would then pick up as real incidents.
    """
    if not GLORFINDEL:
        return
    import glorfindel.escalations as esc_module
    monkeypatch.setattr(esc_module, "_STORE", tmp_path / "escalations.jsonl")


@pytest.fixture(autouse=True)
def isolated_rule_status(tmp_path, monkeypatch):
    """Redirect rule_status.json to a temp file — avoids root-owned Docker file."""
    if not GLORFINDEL:
        return
    import glorfindel.detection_rules as dr_module
    monkeypatch.setattr(dr_module, "_STATUS_FILE", tmp_path / "rule_status.json")


@pytest.fixture(autouse=True)
def stop_rule_pollers(isolated_rule_status):
    """Stop every RulePoller a test started BEFORE the status file redirection is
    undone (this fixture's teardown runs first): a poll thread outlived its test and
    wrote the operator's real ~/.glorfindel/rule_status.json (sixth review, S5)."""
    yield
    if not GLORFINDEL:
        return
    import glorfindel.detection_rules as dr_module
    for poller in list(dr_module.RulePoller._live):
        poller.stop(join_s=2.0)


@pytest.fixture(scope="session", autouse=True)
def no_write_outside_the_sandbox():
    """Where ~/.glorfindel doesn't exist when the suite starts (CI), it must not exist
    when it ends: any write outside the sandbox fails the run. On an operator's machine
    the watch writes there too, so only the CI case can be told apart."""
    from pathlib import Path
    real = Path.home() / ".glorfindel"
    existed = real.exists()
    yield
    if not existed and real.exists():
        pytest.fail(f"the test suite wrote outside its sandbox: {sorted(p.name for p in real.iterdir())}")


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# What a test run may leave in the repository: the caches of Python, pytest and Hypothesis
# (ignored by git, or by their own .gitignore). Anything else is a test writing where it must not.
CACHES = frozenset({"__pycache__", ".pytest_cache", ".hypothesis", ".hypothesis-invariants",
                    ".ruff_cache", ".coverage"})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC
# The audit events of a write other than `open`: the positions of the paths written, then of the
# dir_fd arguments (-1 when there is none). A path relative to a dir_fd cannot be placed: skipped.
_WRITE_EVENTS = {
    "os.mkdir": ((0,), (2,)),
    "os.rmdir": ((0,), (1,)),
    "os.remove": ((0,), (1,)),              # os.unlink too
    "os.rename": ((0, 1), (2, 3)),          # os.replace, shutil.move on one file system
    "os.symlink": ((1,), (2,)),
    "os.link": ((1,), (2, 3)),
    "os.utime": ((0,), (3,)),               # Path.touch() on a file that exists
    "os.truncate": ((0,), ()),
    "shutil.rmtree": ((0,), ()),            # it then removes by dir_fd, which is not placed
    "sqlite3.connect": ((0,), ()),          # it may create the file
}
_writes_in_the_repo: list[tuple[str, str]] = []
_watching = [False]
_before: set[str] = set()
_checked = [False]


def _in_the_repo(path) -> str | None:
    """The path relative to the repository, if a test would write there (caches aside)."""
    if isinstance(path, int) or path is None:
        return None
    full = os.path.abspath(os.fsdecode(path))
    if not full.startswith(REPO + os.sep):
        return None
    rel = full[len(REPO) + 1:]
    parts = rel.split(os.sep)
    if CACHES & set(parts) or parts[0].startswith(".coverage"):
        return None
    return rel


def _written(event, args) -> list:
    """The paths an audit event writes (created, changed, renamed or removed), as given."""
    if event == "open":
        path, mode, flags = args
        writes = any(c in mode for c in "wax+") if isinstance(mode, str) else bool((flags or 0) & _WRITE_FLAGS)
        return [path] if writes else []
    if event not in _WRITE_EVENTS:
        return []
    paths, dir_fds = _WRITE_EVENTS[event]
    if any(args[i] not in (None, -1) for i in dir_fds if i < len(args)):
        return []
    if event == "sqlite3.connect":
        db = args[0]
        if isinstance(db, (str, bytes, os.PathLike)):
            db = os.fsdecode(db)
            if db.startswith("file:"):
                db = db[5:].split("?")[0]
            return [] if db in ("", ":memory:") else [db]
        return []
    return [args[i] for i in paths if i < len(args)]


def _audit(event, args):
    """HY1: the writes the test process makes inside the repository, as they happen, with the
    test that made them. Python's audit hook sees them whatever the code (open, pathlib,
    os, shutil, sqlite3), relative paths included."""
    if not _watching[0]:
        return
    for path in _written(event, args):
        rel = _in_the_repo(path)
        if rel is not None:
            _writes_in_the_repo.append((rel, os.environ.get("PYTEST_CURRENT_TEST", "outside a test").split(" (")[0]))


def _ignored_by_git(name: str) -> bool | None:
    """True/False as git sees it; None without git or outside a repository (a mutant's copy)."""
    import subprocess
    try:
        proc = subprocess.run(["git", "-C", REPO, "check-ignore", "-q", "--", name],
                              capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return {0: True, 1: False}.get(proc.returncode)


def _arm():
    import sys
    if not getattr(sys, "_eregion_repo_audit", False):   # one hook per interpreter, never removed
        sys.addaudithook(_audit)
        sys._eregion_repo_audit = True
    _before.clear()
    _before.update(os.listdir(REPO))
    _writes_in_the_repo.clear()
    _checked[0] = False
    _watching[0] = True


def _what_was_written() -> str | None:
    """Stops the watch; what the run wrote in the repository, or None."""
    _watching[0] = False
    _checked[0] = True
    new = sorted(set(os.listdir(REPO)) - _before)
    left = [n for n in new if n == "runs" or (n not in CACHES and _ignored_by_git(n) is not True)]
    found = sorted({f"{rel} ({test})" for rel, test in _writes_in_the_repo})
    if not (found or left):
        return None
    return ("the test suite wrote in the repository's folder: "
            + "; ".join(found + [f"{n} (new at the root)" for n in left]))


# Armed when this conftest is imported, before pytest imports a test module: what a module
# writes at collection is seen too.
_arm()


@pytest.fixture(scope="session", autouse=True)
def nothing_written_in_the_repository():
    """HY1: no test writes in the repository's folder. A test that called store_cycle left
    runs/run001_debug.jsonl at the root (it writes Path("runs") relative to the current
    folder); nothing said so. Two checks, from this conftest's import (collection included) to
    the end of the session, failing the run:

    - in the test process, the writes under the repository, caches aside (_audit) — this holds
      even where runs/ already exists (an operator's checkout, the watch writing there).
      Seen: a file opened for writing (open, pathlib, os.open, shutil's copies), a folder made
      or removed, a file removed, renamed or replaced (os.replace, shutil.move), a link made
      (os.symlink, os.link), its times or size changed (Path.touch on a file that exists,
      os.utime, os.truncate), shutil.rmtree, sqlite3.connect.
      NOT seen: what a C library writes once a file is open (sqlite's pages, a write through
      a file descriptor, mmap); ChromaDB 1.x's store (written by its Rust core, no audit
      event); a path given relative to a dir_fd, or as a descriptor; any
      write by a subprocess below the root.
    - at the root, whatever wrote it (a subprocess too): a runs/ that was not there before, or
      any new entry git does not ignore.

    Known limits:
    - in the main checkout, another process that creates an entry git does not ignore at the
      root while the suite runs (another session, an editor) fails the run wrongly;
    - a TMPDIR or a --basetemp inside the repository makes every tmp_path a write there;
    - os.makedirs(exist_ok=True) on a folder that exists counts as a write (Python raises the
      event before the folder is found), as does os.remove of a file that is not there;
    - only tests/unit/ is guarded (this conftest); tests/integration/ is not;
    - a repository opened through a symbolic link: paths are compared as given, not resolved,
      so a write through the link's other name is not seen.

    Where no test ran (all deselected), pytest_sessionfinish checks instead."""
    yield
    found = _what_was_written()
    if found:
        pytest.fail(found)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    if _checked[0]:
        return
    found = _what_was_written()
    if found:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(found, red=True)
        if session.exitstatus in (pytest.ExitCode.OK, pytest.ExitCode.NO_TESTS_COLLECTED):
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True)
def isolated_posture_state(tmp_path, monkeypatch):
    """Redirect posture_state.json to a temp file."""
    if not GLORFINDEL:
        return
    import glorfindel.posture as posture_module
    monkeypatch.setattr(posture_module, "_STATE_FILE", tmp_path / "posture_state.json")


@pytest.fixture(autouse=True)
def isolated_glorfindel_home(tmp_path, monkeypatch):
    """Redirect EVERY ~/.glorfindel path a test can write through to tmp_path.

    The three fixtures above covered escalations, rule status and posture only;
    `jobs._RECOVERY_DIR` was missed and test_jobs wrote a real
    ~/.glorfindel/recovery/vm.json on the developer's machine (found 2026-09 — the
    War Room and the LLM prompt read that directory). One fixture for all the others,
    so "0 écriture dans ~/.glorfindel" holds by construction.
    """
    if not GLORFINDEL:
        return
    home = tmp_path / "glorfindel-home"
    import glorfindel.actions as actions
    import glorfindel.jobs as jobs
    import glorfindel.proposed_rules as proposed_rules
    import glorfindel.discovery as discovery
    import glorfindel.readiness as readiness
    from glorfindel.incidents import IncidentRegistry

    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", home / "isolation")
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", home / "blocks")
    monkeypatch.setattr(jobs, "_JOBS_DIR", home / "active_jobs")
    monkeypatch.setattr(jobs, "_RECOVERY_DIR", home / "recovery")
    monkeypatch.setattr(proposed_rules, "_STORE", home / "proposed_rules.jsonl")
    # P1: the client's layer of detection rules (approved rules land there).
    import glorfindel.detection_rules as detection_rules
    monkeypatch.setattr(detection_rules, "_CLIENT_RULES_FILE", home / "client_rules.yaml")
    monkeypatch.setattr(discovery, "_CACHE_FILE", home / "discovered_assets.json")
    monkeypatch.setattr(IncidentRegistry, "_DEFAULT_PATH", home / "incidents.jsonl")
    monkeypatch.setattr(readiness, "_STATE_FILE", home / "readiness.json")
    try:
        import eregion_console.api as api
        monkeypatch.setattr(api, "_RESTORE_TRACKING", home / "restore_in_progress.json")
    except ImportError:  # war-room extra not installed
        pass


@pytest.fixture(autouse=True)
def no_local_glorfindel_config(monkeypatch):
    """Never read the developer's real glorfindel-config.yaml.

    With a local config present, the graph tests (state dry_run=False) resolved the
    REAL Log Analytics workspace in `investigate` and ran live KQL queries — "0 appel
    Azure" held only on a machine without that file, and the suite ran ~5x slower.
    Tests that need a config build or inject one explicitly.
    """
    if not GLORFINDEL:
        return
    import glorfindel.config as config
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [])


@pytest.fixture(autouse=True)
def no_console_settings(tmp_path, monkeypatch):
    """The console's token, host names and chosen sections never come from the developer's
    shell, and the sections are read afresh in each test (they are cached a few seconds).
    There is no console without a token (SEC1): every test has one, `console_client.TOKEN`;
    the token a console draws when it has none goes to tmp, never ~/.glorfindel."""
    try:
        from .console_client import TOKEN
    except ImportError:   # this conftest copied alone, without the tests (test_repo_hermetic.py)
        TOKEN = ""
    for name in ("EREGION_CONSOLE_TOKEN", "GLORFINDEL_WARROOM_TOKEN", "EREGION_CONSOLE_HOSTS",
                 "EREGION_CONSOLE_SECTIONS"):
        monkeypatch.setenv(name, "")      # recorded, so restored even if a CLI test sets it
        monkeypatch.delenv(name)
    if TOKEN:
        monkeypatch.setenv("EREGION_CONSOLE_TOKEN", TOKEN)
    if not CONSOLE:
        return
    from eregion_console import sections
    monkeypatch.setitem(sections._cache, "key", None)
    try:
        import eregion_console.api as api
    except ImportError:  # the console's extra not installed
        return
    monkeypatch.setattr(api, "_TOKEN_FILE", tmp_path / "glorfindel-home" / "console_token")
    monkeypatch.setitem(api._local_token, "value", "")


@pytest.fixture(autouse=True)
def isolated_exercise_windows(tmp_path, monkeypatch):
    """B2: the injectors' exercise windows live under tmp, never the real runs/exercises.
    H-1: the watch reads each VM's enrollment from its tags at startup (glorfindel/cli.py);
    here every target is enrolled, and no Azure call is made — the tests of the guard pass
    their own check (tests/unit/test_exercise_guard.py)."""
    monkeypatch.setenv("EREGION_EXERCISES_DIR", str(tmp_path / "exercises"))
    from eregion_core import exercise
    monkeypatch.setattr(exercise, "_enrollment_check", lambda resource_id: True)
    monkeypatch.setattr(exercise, "_refused", {})


@pytest.fixture(autouse=True)
def isolated_bot_state(tmp_path, monkeypatch):
    """The Discord bot's stores (posted ids, threads, message ids) under tmp, never ~/.glorfindel."""
    try:
        import glorfindel.bot as bot
    except ImportError:  # discord.py not installed: no bot tests run
        return
    monkeypatch.setattr(bot, "_POSTED_STORE", tmp_path / "bot_posted.json")
    monkeypatch.setattr(bot, "_THREADS_STORE", tmp_path / "bot_threads.json")
    monkeypatch.setattr(bot, "_MESSAGES_STORE", tmp_path / "bot_messages.json")
    monkeypatch.setattr(bot, "_SYNCED_STORE", tmp_path / "bot_synced.json")
    monkeypatch.setattr(bot, "_WEEKLY_STORE", tmp_path / "bot_weekly.json")
