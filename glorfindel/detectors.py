"""Detection sources: the interface (glorfindel.providers.interface.DetectionConnector)
and the registry `detector_for` reads. Each source lives in its provider's adapter —
Azure Monitor in glorfindel/providers/azure/monitor.py (A1, MC0), Azure's Activity Log in
glorfindel/providers/azure/activity.py (AL1), Entra ID's audit and sign-in logs in
glorfindel/providers/azure/entra.py (C2).
"""
from __future__ import annotations

from glorfindel.providers.azure.activity import AzureActivityDetector
from glorfindel.providers.azure.entra import AzureEntraDetector
from glorfindel.providers.azure.monitor import AzureMonitorDetector
from glorfindel.providers.interface import DetectionConnector

__all__ = ["AzureActivityDetector", "AzureEntraDetector", "AzureMonitorDetector",
           "DetectionConnector", "backend_type_of", "detector_class", "detector_for",
           "is_control_plane_source", "is_identity_source", "plane_of"]


_DETECTORS: dict[str, type[DetectionConnector]] = {
    "azure_monitor": AzureMonitorDetector,
    "azure_activity": AzureActivityDetector,
    "azure_entra": AzureEntraDetector,
}


def detector_class(source: str) -> type[DetectionConnector] | None:
    return _DETECTORS.get(source or "")


def is_control_plane_source(source: str) -> bool:
    """True for a source that reads what is done to the cloud's resources (AL1)."""
    cls = detector_class(source)
    return cls is not None and cls.plane == "control"


def is_identity_source(source: str) -> bool:
    """True for a source that reads what is done to identities: Entra ID's logs (C2)."""
    cls = detector_class(source)
    return cls is not None and cls.plane == "identity"


def plane_of(source: str) -> str:
    """`data`, `control` (AL1) or `identity` (C2); an unknown source: `data`."""
    cls = detector_class(source)
    return cls.plane if cls is not None else "data"


def backend_type_of(source: str) -> str:
    """The monitoring backend type a source reads: an AzureActivity rule reads the
    azure_monitor workspace of glorfindel-config.yaml. An unknown source: itself."""
    cls = detector_class(source)
    return (getattr(cls, "backend_type", "") if cls else "") or source


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
