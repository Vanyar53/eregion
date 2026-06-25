"""Tests for AzureMonitorDetector error surfacing — a query FAILURE must not be
swallowed as an empty result, else an unreachable LAW (deleted / IAM revoked / wrong
GUID) looks identical to 'healthy, no detections' and blinds detection + discovery."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from azure.monitor.query import LogsQueryStatus

from glorfindel.detectors import AzureMonitorDetector


def _table(columns, rows):
    t = MagicMock()
    t.columns = columns
    t.rows = rows
    return t


def _resp(status, tables=None, partial_error=None):
    r = MagicMock()
    r.status = status
    r.tables = tables or []
    r.partial_error = partial_error
    return r


def _azure(query_result):
    """Patch the lazily-imported azure SDK so query_workspace yields query_result
    (a response, or an Exception to raise)."""
    cred = patch("azure.identity.DefaultAzureCredential")
    client = patch("azure.monitor.query.LogsQueryClient")
    return cred, client


# ── run_query ──────────────────────────────────────────────────────────────────

def test_run_query_returns_rows_on_success():
    det = AzureMonitorDetector("ws")
    table = _table(["A", "B"], [[1, 2], [3, 4]])
    cred, client = _azure(None)
    with cred, client as Client:
        Client.return_value.query_workspace.return_value = _resp(
            LogsQueryStatus.SUCCESS, [table]
        )
        assert det.run_query("Q") == [{"A": 1, "B": 2}, {"A": 3, "B": 4}]


def test_run_query_empty_success_returns_empty_list():
    """Reachable workspace, zero rows → [] (a legitimate 'no data', NOT a failure)."""
    det = AzureMonitorDetector("ws")
    cred, client = _azure(None)
    with cred, client as Client:
        Client.return_value.query_workspace.return_value = _resp(
            LogsQueryStatus.SUCCESS, []
        )
        assert det.run_query("Q") == []


def test_run_query_raises_on_non_success_status():
    det = AzureMonitorDetector("ws")
    cred, client = _azure(None)
    with cred, client as Client:
        Client.return_value.query_workspace.return_value = _resp(
            LogsQueryStatus.FAILURE, []
        )
        with pytest.raises(RuntimeError):
            det.run_query("Q")


def test_run_query_propagates_exception():
    """A deleted workspace raises at the SDK — must propagate, not become []."""
    det = AzureMonitorDetector("ws")
    cred, client = _azure(None)
    with cred, client as Client:
        Client.return_value.query_workspace.side_effect = Exception(
            "workspace not found"
        )
        with pytest.raises(Exception):
            det.run_query("Q")


# ── poll_alert ─────────────────────────────────────────────────────────────────

def _poll(det, qw_setup, time_seq):
    with patch("glorfindel.detectors.time") as T, \
         patch("azure.identity.DefaultAzureCredential"), \
         patch("azure.monitor.query.LogsQueryClient") as Client:
        T.time.side_effect = time_seq
        T.sleep.return_value = None
        qw_setup(Client.return_value.query_workspace)
        return det.poll_alert(
            "Q", since=0.0, timeout_s=10.0, interval_s=1.0, verbose=False
        )


def test_poll_alert_returns_match_row():
    det = AzureMonitorDetector("ws")
    table = _table(["TimeGenerated", "X"], [["t1", 5]])
    result = _poll(
        det,
        lambda qw: setattr(qw, "return_value", _resp(LogsQueryStatus.SUCCESS, [table])),
        [0, 0, 0, 0],
    )
    assert result is not None
    _elapsed, row = result
    assert row["X"] == 5


def test_poll_alert_returns_none_on_reachable_no_match():
    """Reachable, every poll empty → None (genuine no-match), NOT an error."""
    det = AzureMonitorDetector("ws")
    result = _poll(
        det,
        lambda qw: setattr(qw, "return_value", _resp(LogsQueryStatus.SUCCESS, [])),
        [0, 0, 100, 100],
    )
    assert result is None


def test_poll_alert_raises_when_workspace_never_reached():
    """Every attempt errors and none succeeded → unreachable → raise (so the RulePoller
    records last_error instead of clearing it and showing the LAW node green)."""
    det = AzureMonitorDetector("ws")
    with pytest.raises(RuntimeError, match="unreachable"):
        _poll(
            det,
            lambda qw: setattr(qw, "side_effect", Exception("workspace not found")),
            [0, 0, 100, 100],
        )


def test_poll_alert_raises_on_persistent_failure_status():
    """Non-SUCCESS status the whole window (never a single success) → raise. Previously
    a FAILURE status fell through and CLEARED last_error → silent blindness."""
    det = AzureMonitorDetector("ws")
    with pytest.raises(RuntimeError):
        _poll(
            det,
            lambda qw: setattr(qw, "return_value", _resp(LogsQueryStatus.FAILURE, [])),
            [0, 0, 100, 100],
        )
