from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone

from rich.console import Console

_console = Console()


class DetectionConnector(ABC):
    """Provider-agnostic interface for polling alert/detection sources."""

    @abstractmethod
    def poll_alert(
        self,
        query: str,
        since: float,
        timeout_s: float,
        interval_s: float = 10.0,
    ) -> tuple[float, dict] | None:
        """Poll until the query returns results or timeout expires.

        since: Unix timestamp — only match events after this time.
        Returns (elapsed_seconds, first_result_row_as_dict) or None on timeout.
        """
        ...

    def run_query(self, query: str) -> list[dict]:
        """Run a query and return ALL result rows (not just the first).

        Used for discovery queries (e.g. Heartbeat). Default implementation
        returns an empty list — backends that support it override this.
        """
        return []


class AzureMonitorDetector(DetectionConnector):
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id

    def poll_alert(
        self,
        query: str,
        since: float,
        timeout_s: float,
        interval_s: float = 10.0,
        verbose: bool = True,
    ) -> tuple | None:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus

        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)
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
                        if table.rows:
                            row = dict(zip(table.columns, table.rows[0]))
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

    def run_query(self, query: str) -> list[dict]:
        """Run a query and return ALL result rows (no polling, one-shot).

        Raises on a query FAILURE (the workspace is unreachable — deleted, IAM revoked,
        wrong GUID — or the query errored). A successful query that simply returned no
        rows yields []. The two MUST be distinguishable: swallowing the failure as []
        made an unreachable LAW look like "no VMs / no detections", silently blinding
        discovery (it evicted assets instead of keeping its cache) and detection. Callers
        that want best-effort behaviour catch the exception explicitly.
        """
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus

        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)
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


_DETECTORS: dict[str, type[DetectionConnector]] = {
    "azure_monitor": AzureMonitorDetector,
}


def detector_for(source: str, **kwargs) -> DetectionConnector:
    """Instantiate the right DetectionConnector for the given source name.

    kwargs are passed to the constructor (e.g. workspace_id for AzureMonitorDetector).
    Raises ValueError for unknown sources.
    """
    cls = _DETECTORS.get(source)
    if cls is None:
        raise ValueError(
            f"Unknown detection source: '{source}'. "
            f"Supported: {sorted(_DETECTORS)}"
        )
    return cls(**kwargs)
