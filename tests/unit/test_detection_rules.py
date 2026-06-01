from __future__ import annotations

import textwrap
import time
from unittest.mock import MagicMock, patch


from glorfindel.detection_rules import (
    DetectionRule,
    DetectionConfig,
    MonitoringBackend,
    Asset,
    RulePoller,
    _load_status,
    _save_status,
    load_rules,
    load_config,
    normalize_row,
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
        time.sleep(0.3)
        poller.stop()

    assert len(dispatched) >= 1
    norm = dispatched[0]["raw_signal"].get("normalized_signal", {})
    assert norm["indicator_key"] == "disk_write_rate_bps"
    assert norm["resource"] == "vm1"


# ── RulePoller ───────────────────────────────────────────────────────────────────

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
        time.sleep(0.3)
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
        time.sleep(0.3)
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
        time.sleep(0.3)
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
        time.sleep(0.3)
        poller.stop()

    status = _load_status()
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
        time.sleep(0.3)
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
        time.sleep(0.4)
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
        time.sleep(0.4)
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
        time.sleep(0.4)
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
        time.sleep(0.4)
        poller.stop()

    assert len(dispatched) == 2, (
        f"Two distinct rows should produce two dispatches, got {len(dispatched)}"
    )
