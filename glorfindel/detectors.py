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
    ) -> float | None:
        """Poll until the query returns results or timeout expires.

        since: Unix timestamp — only match events after this time.
        Returns elapsed seconds since polling started, or None on timeout.
        """
        ...


class AzureMonitorDetector(DetectionConnector):
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id

    def poll_alert(
        self,
        query: str,
        since: float,
        timeout_s: float,
        interval_s: float = 10.0,
    ) -> float | None:
        from azure.identity import DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient, LogsQueryStatus

        credential = DefaultAzureCredential()
        client = LogsQueryClient(credential)
        since_dt = datetime.fromtimestamp(since, tz=timezone.utc)

        start = time.time()
        while True:
            elapsed = time.time() - start
            if elapsed >= timeout_s:
                return None
            try:
                timespan = (since_dt, datetime.now(tz=timezone.utc) + timedelta(minutes=1))
                response = client.query_workspace(
                    workspace_id=self.workspace_id, query=query, timespan=timespan
                )
                if response.status == LogsQueryStatus.SUCCESS:
                    for table in response.tables:
                        if table.rows:
                            _console.print(f"  [green]Alert detected[/green] after {round(elapsed)}s")
                            return round(elapsed)
            except Exception as e:
                _console.print(f"  [dim]Poll error: {e}[/dim]")
            _console.print(f"  [dim]Still polling... {round(elapsed)}s elapsed[/dim]")
            time.sleep(interval_s)


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
