import pytest


@pytest.fixture(autouse=True)
def fake_anthropic_key(monkeypatch):
    """Ensure ANTHROPIC_API_KEY is set in all unit tests — actual calls are mocked."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-fake")


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
