from __future__ import annotations

import textwrap
import time
from unittest.mock import MagicMock, patch


from glorfindel.detection_rules import (
    DetectionRule,
    RulePoller,
    _load_status,
    _save_status,
    load_rules,
    load_config,
    normalize_row,
    rulepoller_recently_matched,
)


# ── load_config (new format) ────────────────────────────────────────────────────

NEW_FORMAT_YAML = textwrap.dedent("""\
    monitoring_backends:
      - name: law-test
        type: azure_monitor
        workspace_id: ws-abc

    assets:
      - name: vm-test
        type: azure_vm
        resource_id: /subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1
        monitoring_backends: [law-test]

    rules:
      - name: test-rule
        ttp: T1486
        assets: [vm-test]
        interval_s: 30
        enabled: true
        description: Test rule new format
        query: "Perf | limit 1"
""")


def test_load_config_new_format(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    cfg = load_config(f)
    assert len(cfg.backends) == 1
    assert cfg.backends[0].name == "law-test"
    assert cfg.backends[0].workspace_id == "ws-abc"
    assert len(cfg.assets) == 1
    assert cfg.assets[0].name == "vm-test"
    assert cfg.assets[0].monitoring_backends == ["law-test"]
    assert len(cfg.rules) == 1
    r = cfg.rules[0]
    assert r.workspace_id == "ws-abc"   # resolved from backend
    assert r.resource_id == "/subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    assert r.source == "azure_monitor"  # resolved from backend type
    assert r.asset_name == "vm-test"
    assert r.monitoring_backend_name == "law-test"


def test_load_config_backend_lookup(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    cfg = load_config(f)
    assert cfg.backend("law-test") is not None
    assert cfg.backend("nonexistent") is None
    assert cfg.asset("vm-test") is not None
    assert cfg.asset_for_resource(
        "/subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    ) is not None


def test_load_config_empty_resolves_gracefully(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(textwrap.dedent("""\
        monitoring_backends: []
        assets: []
        rules: []
    """))
    cfg = load_config(f)
    assert cfg.backends == []
    assert cfg.assets == []
    assert cfg.rules == []


def test_load_rules_new_format_backward_compat(tmp_path):
    """load_rules() still works with new format."""
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    rules = load_rules(f)
    assert len(rules) == 1
    assert rules[0].workspace_id == "ws-abc"


# ── backend binding: rules bind to glorfindel-config, not a brittle name match ───

def _auto_rule_yaml(backends_block: str, rule_backend_line: str) -> str:
    return (
        "monitoring_backends:\n" + backends_block +
        "rules:\n"
        "  - name: disk-write\n"
        "    ttp: T1486\n"
        "    assets: [auto]\n"
        + rule_backend_line +
        '    query: "Perf | limit 1"\n'
    )


_ONE_BACKEND = "  - name: law-prod\n    type: azure_monitor\n    workspace_id: ws-prod\n"


def test_rule_falls_back_to_single_backend_on_name_mismatch(tmp_path, caplog):
    """Rule names a backend absent from config → binds to the single config backend,
    loudly (never an empty workspace_id in silence)."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, "    monitoring_backends: [law-annatar]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"             # bound to the config backend
    assert r.source == "azure_monitor"
    assert r.monitoring_backend_name == "law-prod"  # resolved name drives asset matching
    assert r.enabled is True
    assert any("law-annatar" in m for m in caplog.messages)  # warned, not silent


def test_rule_binds_to_single_backend_when_unnamed(tmp_path):
    """Rule with no monitoring_backends → uses the single config backend directly."""
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, ""))
    r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"
    assert r.monitoring_backend_name == "law-prod"
    assert r.enabled is True


def test_named_backend_is_honored_without_fallback(tmp_path, caplog):
    """A correctly named backend resolves to itself, no fallback warning."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, "    monitoring_backends: [law-prod]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"
    assert r.monitoring_backend_name == "law-prod"
    assert not [m for m in caplog.messages if "limit" not in m]  # no backend warning


def test_rule_disabled_when_no_backend(tmp_path, caplog):
    """No backend resolvable → empty workspace → rule DISABLED + warned (not silent)."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml("monitoring_backends: []\n",
                                 "    monitoring_backends: [law-annatar]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == ""
    assert r.enabled is False
    assert any("cannot run" in m or "no workspace_id" in m for m in caplog.messages)


def _rule(name="r", ws="ws", enabled=True):
    return DetectionRule(
        name=name, source="azure_monitor", workspace_id=ws, query="q",
        ttp="T1486", resource_id="", enabled=enabled,
    )


def test_has_recognized_indicator():
    """Curated threat indicators are recognized; a generic-fallback column or empty row
    is NOT (drives the decide deterministic guardrail)."""
    from glorfindel.detection_rules import has_recognized_indicator
    assert has_recognized_indicator({"Computer": "vm", "MaxWrite": 1e8}) is True
    assert has_recognized_indicator(
        {"Computer": "vm", "FailedAttempts": 40, "SourceIP": "1.2.3.4"}) is True
    assert has_recognized_indicator({"SyslogMessage": "sudo: USER=root"}) is True
    # generic fallback (unknown column) → NOT a recognized threat indicator
    assert has_recognized_indicator({"Activity": "anomalous login", "Computer": "vm"}) is False
    assert has_recognized_indicator({}) is False


def test_syslog_is_characterized_only_by_a_curated_pattern():
    """SyslogMessage is a log SOURCE: its mere presence no longer counts. Curated
    patterns do — USER=root and account creation (real T1136.001 rows)."""
    from glorfindel.detection_rules import has_recognized_indicator, normalize_row
    t1136 = ("new user: name=testuser-annatar, UID=2001, GID=2001, "
             "home=/home/testuser-annatar, shell=/sbin/nologin")
    assert has_recognized_indicator({"SyslogMessage": t1136}) is True
    assert has_recognized_indicator({"SyslogMessage": "sudo: USER=root ; COMMAND=/bin/sh"}) is True
    assert has_recognized_indicator({"SyslogMessage": "CRON[812]: session opened for user root"}) is False
    assert has_recognized_indicator({"SyslogMessage": "systemd[1]: Started Daily apt."}) is False
    # What the LLM sees is unchanged (normalize_row untouched → no prompt change).
    assert normalize_row({"SyslogMessage": t1136})["indicator_key"] == "syslog_event"


def test_detection_inert_true_when_nothing_can_poll():
    """No rule with a resolved workspace_id (empty config) or all disabled → inert."""
    from glorfindel.detection_rules import detection_inert
    assert detection_inert([_rule(ws=""), _rule(ws="", enabled=False)]) is True
    assert detection_inert([]) is True


def test_detection_inert_false_with_one_pollable_rule():
    from glorfindel.detection_rules import detection_inert, pollable_rules
    rules = [_rule(name="dead", ws=""), _rule(name="live", ws="ws-1")]
    assert detection_inert(rules) is False
    assert [r.name for r in pollable_rules(rules)] == ["live"]


def test_rule_disabled_when_ambiguous_backends(tmp_path, caplog):
    """Several backends of the type and none named → ambiguous → disabled + warned."""
    import logging
    two = (
        "  - name: law-a\n    type: azure_monitor\n    workspace_id: ws-a\n"
        "  - name: law-b\n    type: azure_monitor\n    workspace_id: ws-b\n"
    )
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(two, ""))  # no name → ambiguous
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.enabled is False
    assert any("disambiguate" in m for m in caplog.messages)


# ── load_rules (legacy format) ──────────────────────────────────────────────────

VALID_YAML = textwrap.dedent("""\
    rules:
      - name: test-rule
        source: azure_monitor
        workspace_id: ws-123
        query: "Perf | limit 1"
        ttp: T1486
        resource_id: /subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1
        interval_s: 30
        enabled: true
        description: Test rule
""")


def test_load_rules_valid(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(VALID_YAML)
    rules = load_rules(f)
    assert len(rules) == 1
    r = rules[0]
    assert r.name == "test-rule"
    assert r.source == "azure_monitor"
    assert r.ttp == "T1486"
    assert r.interval_s == 30.0
    assert r.enabled is True


def test_load_rules_missing_file(tmp_path):
    rules = load_rules(tmp_path / "nonexistent.yaml")
    assert rules == []


def test_load_rules_empty_file(tmp_path):
    f = tmp_path / "empty.yaml"
    f.write_text("")
    rules = load_rules(f)
    assert rules == []


def test_load_rules_disabled_skipped(tmp_path):
    yaml = textwrap.dedent("""\
        rules:
          - name: active-rule
            source: azure_monitor
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1486
            resource_id: /subscriptions/sub/rg/vm1
            enabled: true
          - name: disabled-rule
            source: azure_monitor
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1110
            resource_id: /subscriptions/sub/rg/vm1
            enabled: false
    """)
    f = tmp_path / "rules.yaml"
    f.write_text(yaml)
    rules = load_rules(f)
    assert len(rules) == 1
    assert rules[0].name == "active-rule"


def test_load_rules_defaults(tmp_path):
    yaml = textwrap.dedent("""\
        rules:
          - name: minimal
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1486
            resource_id: /subscriptions/sub/rg/vm1
    """)
    f = tmp_path / "rules.yaml"
    f.write_text(yaml)
    rules = load_rules(f)
    assert rules[0].source == "azure_monitor"
    assert rules[0].interval_s == 30.0
    assert rules[0].description == ""


# ── status persistence ───────────────────────────────────────────────────────────

# ── rulepoller_recently_matched ───────────────────────────────────────────────

def test_rulepoller_recently_matched_true(tmp_path, monkeypatch):
    """Returns True when a matching TTP had a recent match."""
    from datetime import datetime, timezone
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    now_iso = datetime.now(timezone.utc).isoformat()
    _save_status({"sudo-rule": {"last_match": now_iso, "ttp": "T1548.003"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is True


def test_rulepoller_recently_matched_expired(tmp_path, monkeypatch):
    """Returns False when the last match is older than within_s."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    old_iso = "2020-01-01T00:00:00+00:00"
    _save_status({"sudo-rule": {"last_match": old_iso, "ttp": "T1548.003"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_rulepoller_recently_matched_wrong_ttp(tmp_path, monkeypatch):
    """Returns False when TTP doesn't match."""
    from datetime import datetime, timezone
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    now_iso = datetime.now(timezone.utc).isoformat()
    _save_status({"ssh-rule": {"last_match": now_iso, "ttp": "T1110.001"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_rulepoller_recently_matched_no_status(tmp_path, monkeypatch):
    """Returns False when no status file exists."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_poller_stores_ttp_in_status(tmp_path, monkeypatch):
    """rule_status.json must include ttp after a match — required by rulepoller_recently_matched."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (
        1.0,
        {"TimeGenerated": "2026-06-01T13:00:00Z", "Computer": "vm1"},
    )
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(name="test-rule", ttp="T1548.003", interval_s=0.05)
        poller = RulePoller([rule], lambda s: None, dry_run=False)
        poller.start()
        _wait_for(lambda: _load_status().get("test-rule", {}).get("ttp"))
        poller.stop()
    status = _load_status()
    assert status.get("test-rule", {}).get("ttp") == "T1548.003"


def test_status_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "rule_status.json",
    )
    _save_status({"rule-a": {"last_poll": "2026-01-01T00:00:00+00:00", "match_count": 3}})
    loaded = _load_status()
    assert loaded["rule-a"]["match_count"] == 3


def test_load_status_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "nonexistent.json",
    )
    assert _load_status() == {}


# ── normalize_row ────────────────────────────────────────────────────────────────

def test_normalize_row_disk_write():
    row = {"Computer": "vm1", "MaxWrite": 52428800, "TimeGenerated": "2026-05-31T19:00:00Z"}
    n = normalize_row(row, ttp="T1486")
    assert n["indicator_key"] == "disk_write_rate_bps"
    assert n["indicator_value"] == 52428800
    assert n["resource"] == "vm1"


def test_normalize_row_failed_auth():
    row = {"Computer": "vm1", "SourceIP": "185.220.101.1", "FailedAttempts": "34"}
    n = normalize_row(row, ttp="T1110.001")
    assert n["indicator_key"] == "failed_auth_count"
    assert n["indicator_value"] == "34"


def test_normalize_row_privilege_escalation():
    row = {"Computer": "vm1", "SyslogMessage": "sudo[12009]: USER=root COMMAND=/bin/bash"}
    n = normalize_row(row, ttp="T1548.003")
    assert n["indicator_key"] == "privilege_escalation"
    assert "USER=root" in str(n["indicator_value"])


def test_normalize_row_syslog_generic():
    row = {"Computer": "vm1", "SyslogMessage": "sshd: Accepted password for user"}
    n = normalize_row(row)
    assert n["indicator_key"] == "syslog_event"


def test_normalize_row_blob_exfil():
    row = {"AccountName": "storageannatar", "CallerIpAddress": "1.2.3.4", "PutBlobCount": 5}
    n = normalize_row(row, ttp="T1041")
    assert n["indicator_key"] == "caller_ip"
    assert n["resource"] == "storageannatar"


def test_normalize_row_unknown_fallback():
    row = {"TimeGenerated": "2026-01-01", "_ResourceId": "/sub/rg/vm"}
    n = normalize_row(row)
    assert n["indicator_key"] == "unknown"
    assert n["indicator_value"] is None


def test_normalize_row_generic_fallback():
    row = {"TimeGenerated": "2026-01-01", "MyCustomMetric": 42}
    n = normalize_row(row)
    assert n["indicator_key"] == "mycustommetric"
    assert n["indicator_value"] == 42


def test_poller_signal_contains_normalized_signal(tmp_path, monkeypatch):
    """Dispatched signals must include raw_signal.normalized_signal."""
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )
    dispatched = []
    mock_detector = MagicMock()
    row = {"TimeGenerated": "2026-05-31T19:13:29Z", "Computer": "vm1", "MaxWrite": 60000000}
    mock_detector.poll_alert.return_value = (1.0, row)

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05, ttp="T1486")
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: dispatched)
        poller.stop()

    assert len(dispatched) >= 1
    norm = dispatched[0]["raw_signal"].get("normalized_signal", {})
    assert norm["indicator_key"] == "disk_write_rate_bps"
    assert norm["resource"] == "vm1"


# ── RulePoller ───────────────────────────────────────────────────────────────────

def _wait_for(cond, timeout: float = 5.0) -> bool:
    """Wait on a CONDITION, not a fixed duration: a 0.3s sleep failed whenever the
    poll thread hadn't run enough times yet (scheduling-dependent flake under load)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return False


def _make_rule(**kwargs) -> DetectionRule:
    base = dict(
        name="rule-x",
        source="azure_monitor",
        workspace_id="ws-1",
        query="Perf | limit 1",
        ttp="T1486",
        resource_id="/subscriptions/sub/rg/vm1",
        interval_s=0.1,
        enabled=True,
        description="",
    )
    base.update(kwargs)
    return DetectionRule(**base)


def test_poller_dispatches_on_match(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    dispatched = []

    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (5.0, {"Computer": "vm1"})

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: dispatched)
        poller.stop()

    assert len(dispatched) >= 1
    sig = dispatched[0]
    assert sig["event"] == "detection"
    assert sig["ttp"] == "T1486"
    assert sig["resource_id"] == "/subscriptions/sub/rg/vm1"
    assert sig["raw_signal"]["first_result_row"] == {"Computer": "vm1"}


def test_poller_dry_run_no_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    dispatched = []
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (2.0, {"row": "data"})

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=True)
        poller.start()
        _wait_for(lambda: mock_detector.poll_alert.call_count >= 4)
        poller.stop()

    assert dispatched == []


def test_poller_no_match_no_dispatch(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    dispatched = []
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None  # no rows

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: mock_detector.poll_alert.call_count >= 4)
        poller.stop()

    assert dispatched == []


def test_poller_records_error_status(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    mock_detector = MagicMock()
    mock_detector.poll_alert.side_effect = RuntimeError("network error")

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], lambda s: None, dry_run=False)
        poller.start()
        # Wait on the CONDITION, not a fixed sleep: a 0.3s sleep failed whenever the
        # poll thread hadn't run once yet (scheduling-dependent flake).
        deadline = time.time() + 5
        status = {}
        while time.time() < deadline:
            status = _load_status()
            if "network error" in status.get("rule-x", {}).get("last_error", ""):
                break
            time.sleep(0.02)
        poller.stop()

    assert "rule-x" in status
    assert "network error" in status["rule-x"].get("last_error", "")


def test_poller_status_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(name="snap-rule", ttp="T1041", interval_s=0.05)
        poller = RulePoller([rule], lambda s: None, dry_run=False)
        poller.start()
        _wait_for(lambda: mock_detector.poll_alert.call_count >= 1)
        poller.stop()

    snap = poller.status_snapshot()
    assert len(snap) == 1
    assert snap[0]["name"] == "snap-rule"
    assert snap[0]["ttp"] == "T1041"


def test_poller_signal_has_unique_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    dispatched = []
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (1.0, {})

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: mock_detector.poll_alert.call_count >= 4)
        poller.stop()

    ids = [s["signal_id"] for s in dispatched]
    assert len(ids) == len(set(ids)), "signal_ids must be unique"


def test_poller_multiple_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )

    dispatched = []
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (1.0, {"row": "x"})

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rules = [
            _make_rule(name="rule-a", ttp="T1486", interval_s=0.05),
            _make_rule(name="rule-b", ttp="T1041", interval_s=0.05),
        ]
        poller = RulePoller(rules, dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: {s["ttp"] for s in dispatched} >= {"T1486", "T1041"})
        poller.stop()

    ttps = {s["ttp"] for s in dispatched}
    assert "T1486" in ttps
    assert "T1041" in ttps


def test_poller_deduplicates_same_row(tmp_path, monkeypatch):
    """Same TimeGenerated row across polls must produce only one dispatch."""
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )
    dispatched = []
    mock_detector = MagicMock()
    # Return the same row (same TimeGenerated) on every poll
    same_row = {"TimeGenerated": "2026-05-31T19:13:29Z", "Computer": "vm1"}
    mock_detector.poll_alert.return_value = (1.0, same_row)

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: mock_detector.poll_alert.call_count >= 4)
        poller.stop()

    assert len(dispatched) == 1, (
        f"Same event row should only dispatch once, got {len(dispatched)}"
    )


def test_poller_dispatches_new_row_after_dedup(tmp_path, monkeypatch):
    """Different TimeGenerated rows should each produce a dispatch."""
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "status.json",
    )
    dispatched = []
    mock_detector = MagicMock()
    rows = [
        {"TimeGenerated": "2026-05-31T19:13:29Z", "Computer": "vm1"},
        {"TimeGenerated": "2026-05-31T19:14:30Z", "Computer": "vm1"},
    ]
    # Alternate between two distinct rows
    call_count = [0]
    def _poll_side_effect(**kwargs):
        idx = min(call_count[0], len(rows) - 1)
        call_count[0] += 1
        return (1.0, rows[idx])
    mock_detector.poll_alert.side_effect = _poll_side_effect

    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        rule = _make_rule(interval_s=0.05)
        poller = RulePoller([rule], dispatched.append, dry_run=False)
        poller.start()
        _wait_for(lambda: call_count[0] >= 4 and len(dispatched) >= 2)
        poller.stop()

    assert len(dispatched) == 2, (
        f"Two distinct rows should produce two dispatches, got {len(dispatched)}"
    )


# ── Run Azure du 2026-10-05 : fenêtre de requête, attribution, déduplication ──────

class _Asset:
    def __init__(self, name):
        self.name = name
        self.resource_id = f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}"


class _Registry:
    def __init__(self, *names):
        self.assets = [_Asset(n) for n in names]

    def for_backend(self, _name):
        return self.assets


def _asset_rule(name="vm1", **kw):
    return _make_rule(name="ransomware-disk-write", interval_s=0.05, asset_name=name,
                      resource_id=_Asset(name).resource_id,
                      query="Perf | where TimeGenerated > ago(10m) | summarize MaxWrite=max(CounterValue) by Computer",
                      **kw)


def _run_asset_rule(poller, rule, registry, cond):
    import threading
    t = threading.Thread(target=poller._poll_rule, args=(rule, registry), daemon=True)
    t.start()
    _wait_for(cond)
    poller.stop()
    t.join(timeout=2)


def test_query_lookback_follows_the_rules_ago():
    from glorfindel.detection_rules import _query_lookback_s
    assert _query_lookback_s("Perf | where TimeGenerated > ago(10m)") == 600
    assert _query_lookback_s("X | where TimeGenerated > ago(5m) | join (Y | where T > ago(1h))") == 3600
    assert _query_lookback_s("Perf | limit 1") == 600          # no ago(): default


def test_poller_window_covers_late_ingestion(tmp_path, monkeypatch):
    """The API timespan used to start 2*interval (60 s) back and overrode the query's
    ago(10m): rows ingested 89–109 s late (real run, 05/10) were never seen."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        poller = RulePoller([], lambda s: None, dry_run=False)
        before = time.time()
        _run_asset_rule(poller, _asset_rule(), _Registry("vm1"),
                        lambda: mock_detector.poll_alert.call_count >= 1)
    since = mock_detector.poll_alert.call_args.kwargs["since"]
    assert since <= before - 600


def test_row_attribution():
    from glorfindel.detection_rules import _row_attribution
    rid = _Asset("vm1").resource_id
    assert _row_attribution({"Computer": "vm1"}, rid, "vm1") is True
    assert _row_attribution({"Computer": "VM1.internal.cloudapp.net"}, rid, "vm1") is True
    assert _row_attribution({"Computer": "vm2"}, rid, "vm1") is False
    assert _row_attribution({"_ResourceId": rid.upper()}, rid, "vm1") is True
    assert _row_attribution({"SourceIP": "203.0.113.9", "FailedAttempts": 40}, rid, "vm1") is None


def test_asset_rule_ignores_rows_about_another_vm(tmp_path, monkeypatch):
    """The per-asset rule runs the shared, unscoped query: a ransomware row for vm2 was
    dispatched for vm1 too (and for every discovered VM)."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        poller = RulePoller([], lambda s: None, dry_run=False)
        _run_asset_rule(poller, _asset_rule("vm1"), _Registry("vm1", "vm2"),
                        lambda: mock_detector.poll_alert.call_count >= 1)
    match_row = mock_detector.poll_alert.call_args.kwargs["match_row"]
    assert match_row({"Computer": "vm1", "MaxWrite": 1.2e8})
    assert not match_row({"Computer": "vm2", "MaxWrite": 1.2e8})
    assert match_row({"SourceIP": "203.0.113.9"})              # names no VM: kept


def test_aggregated_row_dispatched_once_while_its_counts_grow(tmp_path, monkeypatch):
    """No TimeGenerated on a summarized row → the old dedup never applied; with the
    10-min window the same detection would be re-dispatched at every poll."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    dispatched = []
    values = iter(range(10**6))
    mock_detector = MagicMock()
    mock_detector.poll_alert.side_effect = (
        lambda **kw: (1.0, {"Computer": "vm1", "MaxWrite": 1.2e8 + next(values)}))
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        poller = RulePoller([], dispatched.append, dry_run=False)
        _run_asset_rule(poller, _asset_rule("vm1"), _Registry("vm1"),
                        lambda: mock_detector.poll_alert.call_count >= 4)
    assert len(dispatched) == 1


def test_dedup_survives_a_restart(tmp_path, monkeypatch):
    """A detection still inside the query window must not be dispatched (and acted on)
    again by the next watch process."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    dispatched = []
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (1.0, {"Computer": "vm1", "MaxWrite": 1.2e8})
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        first = RulePoller([], dispatched.append, dry_run=False)
        _run_asset_rule(first, _asset_rule("vm1"), _Registry("vm1"), lambda: dispatched)
        second = RulePoller([], dispatched.append, dry_run=False)
        mock_detector.poll_alert.reset_mock()
        _run_asset_rule(second, _asset_rule("vm1"), _Registry("vm1"),
                        lambda: mock_detector.poll_alert.call_count >= 3)
    assert len(dispatched) == 1


def test_unattributed_row_is_flagged_when_several_vms_are_monitored(tmp_path, monkeypatch):
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = (1.0, {"SourceIP": "203.0.113.9", "FailedAttempts": 40})
    for peers, expected in ((("vm1", "vm2"), "unattributed"), (("vm1",), "single_asset")):
        dispatched = []
        (tmp_path / "s.json").unlink(missing_ok=True)
        with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
            poller = RulePoller([], dispatched.append, dry_run=False)
            _run_asset_rule(poller, _asset_rule("vm1"), _Registry(*peers), lambda: dispatched)
        assert dispatched[0]["context"]["attribution"] == expected


def test_expansion_picks_up_a_vm_discovered_after_start(tmp_path, monkeypatch):
    """The watch expanded rules once, 10 s after start: a VM that came up later (or was
    off at start) was never polled (validation run, 2026-10-06). Expansion now runs
    every minute; it must start the new VM's thread without duplicating the others."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "s.json")
    mock_detector = MagicMock()
    mock_detector.poll_alert.return_value = None
    rule = _make_rule(name="ransomware-disk-write", interval_s=0.05, auto_apply=True,
                      monitoring_backend_name="law")
    registry = _Registry("vm1")
    with patch("glorfindel.detection_rules.detector_for", return_value=mock_detector):
        poller = RulePoller([rule], lambda s: None, dry_run=False)
        poller.expand_for_discovered(registry)
        registry.assets.append(_Asset("vm2"))
        poller.expand_for_discovered(registry)
        poller.expand_for_discovered(registry)
        names = sorted(t.name for t in poller._threads if t.is_alive())
        poller.stop()
    assert names == ["rule-ransomware-disk-write@vm1", "rule-ransomware-disk-write@vm2"]


def test_shipped_rules_do_not_truncate_before_the_vm_filter():
    """`| limit 1` ran on the server before the per-VM filter: a benign sudo on another
    VM hid the attack (third review, T7). Same check warns on LLM-authored rules."""
    from pathlib import Path
    import yaml
    from glorfindel.detection_rules import _truncates_before_vm_filter
    path = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
    for r in yaml.safe_load(path.read_text())["rules"]:
        if "auto" in (r.get("assets") or []):
            assert not _truncates_before_vm_filter(r["query"]), r["name"]
    assert _truncates_before_vm_filter("Syslog\n| where x\n| limit 1")
    assert not _truncates_before_vm_filter("Syslog\n// no | limit here\n| summarize arg_max(TimeGenerated, *) by Computer")


def test_ransomware_rule_reads_the_sampling_step_from_the_data():
    """Two samples ≤ 25 s apart never exist at Azure's default 60-s sampling: the rule
    never fired there (third review, T6). Coarse series use one sample."""
    from pathlib import Path
    import yaml
    path = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
    q = next(r["query"] for r in yaml.safe_load(path.read_text())["rules"] if r["name"] == "ransomware-disk-write")
    assert "Step = min(Gap)" in q and "not(Fine) and Rate > 25000000" in q
