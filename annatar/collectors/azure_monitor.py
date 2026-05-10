from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from rich.console import Console

console = Console()


class AzureMonitorCollector:
    def __init__(self, target: dict):
        self.workspace_id = target.get("log_analytics_workspace_id")
        self._credential = DefaultAzureCredential()
        self._client = LogsQueryClient(self._credential)

    def wait_for_heartbeat(self, vm_name: str, timeout_s: float, since: float | None = None, interval_s: float = 30.0) -> float | None:
        """
        Poll LAW until the VM sends a Heartbeat after restore.
        since: Unix timestamp — only accept heartbeats after this time (avoids stale data).
        Returns elapsed seconds since call, or None on timeout.
        """
        query = (
            f"Heartbeat\n"
            f"| where Computer startswith '{vm_name}'\n"
            f"| summarize LastHeartbeat = max(TimeGenerated)"
        )
        since_dt = datetime.fromtimestamp(since, tz=timezone.utc) if since is not None else None
        start = time.time()
        console.print(f"  [dim]Waiting for Heartbeat from {vm_name}...[/dim]")
        while True:
            elapsed = time.time() - start
            if elapsed >= timeout_s:
                return None
            try:
                if since_dt is not None:
                    # Anchor the time window to the run — reject heartbeats from before T0
                    timespan = (since_dt, datetime.now(tz=timezone.utc) + timedelta(minutes=1))
                else:
                    timespan = timedelta(minutes=10)
                response = self._client.query_workspace(
                    workspace_id=self.workspace_id,
                    query=query,
                    timespan=timespan,
                )
                if response.status == LogsQueryStatus.SUCCESS:
                    for table in response.tables:
                        if table.rows and table.rows[0][0] is not None:
                            console.print(f"  [green]Heartbeat received[/green] after {round(elapsed)}s")
                            return elapsed
            except Exception as e:
                console.print(f"  [dim]Heartbeat poll error: {e}[/dim]")
            time.sleep(interval_s)

    def poll_alert(self, query: str, source: str, timeout_s: float, since: float | None = None, interval_s: float = 10.0) -> float | None:
        """
        Poll until the query returns results or timeout.
        since: Unix timestamp — only match events after this time (avoids stale LAW data).
        Returns elapsed seconds since polling started, or None on timeout.
        """
        if source != "azure_monitor":
            raise ValueError(f"Unsupported detection source: {source}")

        since_dt = datetime.fromtimestamp(since, tz=timezone.utc) if since is not None else None
        start = time.time()
        while True:
            elapsed = time.time() - start
            if elapsed >= timeout_s:
                return None

            try:
                if since_dt is not None:
                    timespan = (since_dt, datetime.now(tz=timezone.utc) + timedelta(minutes=1))
                else:
                    timespan = timedelta(minutes=10)
                response = self._client.query_workspace(
                    workspace_id=self.workspace_id,
                    query=query,
                    timespan=timespan,
                )
                if response.status == LogsQueryStatus.SUCCESS:
                    for table in response.tables:
                        if table.rows:
                            console.print(f"  [green]Alert detected[/green] after {round(elapsed)}s")
                            return elapsed
            except Exception as e:
                console.print(f"  [dim]Poll error: {e}[/dim]")

            time.sleep(interval_s)
