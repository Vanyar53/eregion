"""The process's Azure identity, as azure-identity reads it from the environment (#205, BL1c).

One rule for every entry point that reaches Azure with ``DefaultAzureCredential`` on a host
without a service principal — the ``glorfindel`` command (the watch, the bot), ``eregion
console``, and the analysis commands launched by ``docker exec`` in H0's container
(``python -m analysis.containment``, ``make glorfindel-host-containment``). Here, in the shared
core, so that each one calls it without importing another component (D1).
"""
from __future__ import annotations

import os

SERVICE_PRINCIPAL_VARS = ("AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID")


def drop_empty_service_principal_env(environ=os.environ) -> list[str]:
    """Unset AZURE_CLIENT_ID/SECRET/TENANT_ID when they are empty; returns the names dropped.

    azure-identity's EnvironmentCredential takes an empty variable for a set one (`is not
    None`): docker compose passes `${AZURE_CLIENT_ID:-}` as "" when the host has no service
    principal, and DefaultAzureCredential then fails on ClientSecretCredential("") instead
    of reaching the VM's managed identity. Measured on the hosted Glorfindel (H0), 16/10.
    """
    dropped = [k for k in SERVICE_PRINCIPAL_VARS if k in environ and not environ[k].strip()]
    for k in dropped:
        del environ[k]
    return dropped
