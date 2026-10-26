"""Azure Monitor (Log Analytics) as a detection source: the Azure side of
DetectionConnector (moved from glorfindel/detectors.py, A1 — no SDK outside the adapter).
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from rich.console import Console

from glorfindel.providers.interface import DetectionConnector

_console = Console()


class AzureMonitorDetector(DetectionConnector):
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self._client = None
        self._client_lock = threading.Lock()

    def _logs_client(self):
        """One credential + client per detector: a DefaultAzureCredential was rebuilt
        on every query (token fetch each time) — third review, T10."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    from azure.identity import DefaultAzureCredential
                    from azure.monitor.query import LogsQueryClient
                    self._client = LogsQueryClient(DefaultAzureCredential())
        return self._client

    def poll_alert(
        self,
        query: str,
        since: float,
        timeout_s: float,
        interval_s: float = 10.0,
        verbose: bool = True,
        match_row=None,
    ) -> tuple | None:
        from azure.monitor.query import LogsQueryStatus

        client = self._logs_client()
        since_dt = datetime.fromtimestamp(since, tz=timezone.utc)

        start = time.time()
        last_error: str | None = None
        saw_success = False  # at least one query reached the workspace (even 0 rows)
        while True:
            elapsed = time.time() - start
            if elapsed >= timeout_s:
                # Never reached the workspace and the last attempt errored → the backend
                # is unreachable (deleted / IAM revoked / wrong GUID). Raise so the
                # RulePoller records last_error instead of silently treating "blind" as
                # "no match" (which left the LAW node green while detection saw nothing).
                if not saw_success and last_error is not None:
                    raise RuntimeError(f"workspace unreachable: {last_error}")
                return None
            try:
                timespan = (since_dt, datetime.now(tz=timezone.utc) + timedelta(minutes=1))
                response = client.query_workspace(
                    workspace_id=self.workspace_id, query=query, timespan=timespan
                )
                if response.status == LogsQueryStatus.SUCCESS:
                    saw_success = True
                    last_error = None  # a successful query with 0 rows is not an error
                    for table in response.tables:
                        for raw_row in table.rows:
                            row = dict(zip(table.columns, raw_row))
                            if match_row is not None and not match_row(row):
                                continue
                            if verbose:
                                _console.print(
                                    f"  [green]Alert detected[/green] after {round(elapsed)}s"
                                )
                            return round(elapsed), row
                else:
                    # PARTIAL / FAILURE — not a reachable, empty result. Remember it so a
                    # window of only-failures surfaces as an error, not a silent no-match.
                    last_error = str(
                        getattr(response, "partial_error", None) or response.status
                    )
            except Exception as e:
                last_error = str(e)  # set regardless of verbose (the poller is non-verbose)
                if verbose:
                    _console.print(f"  [dim]Poll error: {e}[/dim]")
            if verbose:
                _console.print(f"  [dim]Still polling... {round(elapsed)}s elapsed[/dim]")
            time.sleep(interval_s)

    def run_query(self, query: str, timespan=None) -> list[dict]:
        """Run a query and return ALL result rows (no polling, one-shot).

        timespan: optional (start_dt, end_dt) tuple. Defaults to the last 3h. Callers
        replaying a historical attack (campaign_replay) pass an explicit window scoped
        to the attack's T0 so old events aren't excluded by the default 3h bound.

        Raises on a query FAILURE (the workspace is unreachable — deleted, IAM revoked,
        wrong GUID — or the query errored). A successful query that simply returned no
        rows yields []. The two MUST be distinguishable: swallowing the failure as []
        made an unreachable LAW look like "no VMs / no detections", silently blinding
        discovery (it evicted assets instead of keeping its cache) and detection. Callers
        that want best-effort behaviour catch the exception explicitly.
        """
        from azure.monitor.query import LogsQueryStatus

        client = self._logs_client()
        if timespan is None:
            now = datetime.now(tz=timezone.utc)
            timespan = (now - timedelta(hours=3), now + timedelta(minutes=1))
        response = client.query_workspace(
            workspace_id=self.workspace_id, query=query, timespan=timespan
        )
        if response.status != LogsQueryStatus.SUCCESS:
            detail = getattr(response, "partial_error", None) or response.status
            raise RuntimeError(f"workspace query not successful: {detail}")
        rows = []
        for table in response.tables:
            for row in table.rows:
                rows.append(dict(zip(table.columns, row)))
        return rows
