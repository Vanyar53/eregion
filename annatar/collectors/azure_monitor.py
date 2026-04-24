from __future__ import annotations

import time
from datetime import timedelta

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from rich.console import Console

console = Console()


class AzureMonitorCollector:
    def __init__(self, target: dict):
        self.workspace_id = target.get("log_analytics_workspace_id")
        self._credential = DefaultAzureCredential()
        self._client = LogsQueryClient(self._credential)

    def poll_alert(self, query: str, source: str, timeout_s: float, interval_s: float = 10.0) -> float | None:
        """
        Poll until the query returns results or timeout.
        Returns elapsed seconds since polling started, or None on timeout.
        """
        if source != "azure_monitor":
            raise ValueError(f"Unsupported detection source: {source}")

        start = time.time()
        while True:
            elapsed = time.time() - start
            if elapsed >= timeout_s:
                return None

            try:
                response = self._client.query_workspace(
                    workspace_id=self.workspace_id,
                    query=query,
                    timespan=timedelta(minutes=10),
                )
                if response.status == LogsQueryStatus.SUCCESS:
                    for table in response.tables:
                        if table.rows:
                            console.print(f"  [green]Alert detected[/green] after {round(elapsed)}s")
                            return elapsed
            except Exception as e:
                console.print(f"  [dim]Poll error: {e}[/dim]")

            time.sleep(interval_s)
