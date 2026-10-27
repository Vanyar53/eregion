"""Providers (MC0): the interface Glorfindel asks a cloud for, and one adapter per cloud.

Azure is the only adapter that runs (glorfindel/providers/azure/); the AWS adapter
(glorfindel/providers/aws/, MC1) is written against a simulated world and runs on no
account before MC2. A provider's SDK is imported in its adapter only:
tests/unit/test_provider_boundary.py fails otherwise (it runs in CI).
"""
from glorfindel.providers.interface import (
    Capability,
    CloudConnector,
    ProviderCapabilities,
    capabilities_of,
)

__all__ = ["Capability", "CloudConnector", "ProviderCapabilities", "capabilities_of"]
