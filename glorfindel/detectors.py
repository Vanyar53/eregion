"""Detection sources: the interface (glorfindel.providers.interface.DetectionConnector)
and the registry `detector_for` reads. Each source lives in its provider's adapter —
Azure Monitor in glorfindel/providers/azure/monitor.py (A1, MC0).
"""
from __future__ import annotations

from glorfindel.providers.azure.monitor import AzureMonitorDetector
from glorfindel.providers.interface import DetectionConnector

__all__ = ["AzureMonitorDetector", "DetectionConnector", "detector_for"]


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
