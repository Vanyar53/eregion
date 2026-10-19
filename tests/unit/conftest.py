import pytest


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
    # No exercise channel: windows stay local, nothing reaches Azure Storage.
    monkeypatch.delenv("EREGION_EXERCISE_CHANNEL", raising=False)


@pytest.fixture(autouse=True)
def isolated_escalations_store(tmp_path, monkeypatch):
    """Redirect escalations._STORE to a temp file.

    Prevents test runs from writing pending escalations to ~/.glorfindel/,
    which the Discord bot would then pick up as real incidents.
    """
    import glorfindel.escalations as esc_module
    monkeypatch.setattr(esc_module, "_STORE", tmp_path / "escalations.jsonl")


@pytest.fixture(autouse=True)
def isolated_rule_status(tmp_path, monkeypatch):
    """Redirect rule_status.json to a temp file — avoids root-owned Docker file."""
    import glorfindel.detection_rules as dr_module
    monkeypatch.setattr(dr_module, "_STATUS_FILE", tmp_path / "rule_status.json")


@pytest.fixture(autouse=True)
def stop_rule_pollers(isolated_rule_status):
    """Stop every RulePoller a test started BEFORE the status file redirection is
    undone (this fixture's teardown runs first): a poll thread outlived its test and
    wrote the operator's real ~/.glorfindel/rule_status.json (sixth review, S5)."""
    yield
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


@pytest.fixture(autouse=True)
def isolated_posture_state(tmp_path, monkeypatch):
    """Redirect posture_state.json to a temp file."""
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
    monkeypatch.setattr(discovery, "_CACHE_FILE", home / "discovered_assets.json")
    monkeypatch.setattr(IncidentRegistry, "_DEFAULT_PATH", home / "incidents.jsonl")
    monkeypatch.setattr(readiness, "_STATE_FILE", home / "readiness.json")
    try:
        import glorfindel.api as api
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
    import glorfindel.config as config
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [])


@pytest.fixture(autouse=True)
def isolated_exercise_windows(tmp_path, monkeypatch):
    """B2: the injectors' exercise windows live under tmp, never the real runs/exercises."""
    monkeypatch.setenv("EREGION_EXERCISES_DIR", str(tmp_path / "exercises"))


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
