from __future__ import annotations

import json
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from glorfindel.detection_rules import (
    DetectionRule,
    RulePoller,
    _load_status,
    _save_status,
    load_rules,
)


# ── load_rules ──────────────────────────────────────────────────────────────────

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
