"""The Azure SDK's warm-up, and the helpers that read its errors and enums (moved from
actions.py, A1).
"""
from __future__ import annotations

import importlib
import threading


_warmed_up = False
_warmup_lock = threading.Lock()


def warm_up_azure_sdk() -> None:
    """Import the Azure SDK once, single-threaded, before any worker threads run.

    The codebase imports azure.* lazily inside methods. When several threads first-import
    azure.core concurrently (audit's 3 parallel checks, or the watch's discovery + poll
    threads), CPython's import system can deadlock (`_ModuleLock` on azure.core.exceptions)
    or expose a half-initialised module ("cannot import name 'Pipeline'"). Doing every
    azure import here, on the calling (main) thread, makes all later in-method imports
    instant cache hits — no concurrent first-import. Idempotent + best-effort.

    Call at watch startup AND at the top of audit.run (before the ThreadPoolExecutor) so
    both the watch process and the War Room API process are covered.

    Each module is imported on its own: one missing optional package (e.g. the
    recovery-services SDK) no longer cancels the warm-up of the modules that ARE
    installed — which is what removes the deadlock window for them.
    """
    global _warmed_up
    if _warmed_up:
        return
    with _warmup_lock:
        if _warmed_up:
            return
        for module in _WARM_UP_MODULES:
            try:
                importlib.import_module(module)
            except Exception:
                # Not installed / partial env — real errors surface at actual use.
                pass
        _warmed_up = True


_WARM_UP_MODULES = (
    "azure.core.pipeline",        # the module that races
    "azure.core.exceptions",
    "azure.identity",
    "azure.mgmt.network",
    "azure.mgmt.network.models",
    "azure.mgmt.compute",
    "azure.mgmt.recoveryservicesbackup",
    "azure.monitor.query",
)


def _is_not_found(exc: BaseException) -> bool:
    """True when an Azure call failed only because the resource doesn't exist."""
    if getattr(exc, "status_code", None) == 404:
        return True
    try:
        from azure.core.exceptions import ResourceNotFoundError
        if isinstance(exc, ResourceNotFoundError):
            return True
    except ImportError:
        pass
    # No substring guess: "…was not found" also describes a REFERENCED resource that is
    # missing (re-attaching a deleted customer NSG), which is a failure, not "already
    # gone". The SDK raises ResourceNotFoundError / status 404 for the target itself.
    return False


def _enum_text(value) -> str:
    """Lowercase text of an SDK field that may be a plain string or an enum.

    azure-mgmt-network 33 (the Docker image) returns enums: str(SecurityRuleAccess.ALLOW)
    is 'SecurityRuleAccess.ALLOW', so `str(access).lower() != "allow"` skipped EVERY rule
    — the precedence check saw no allow at all in the deployed product, while 30.x (the
    host venv, the tests) returns plain strings (validation run, 2026-10-06)."""
    return str(getattr(value, "value", value) or "").lower()


def _backup_item_names(vm_rg: str, vm_name: str) -> tuple[str, str]:
    """Canonical (container, item) names of an IaaS-VM backup item.

    CASE MATTERS: `recovery_points.list` is case-SENSITIVE on the type prefix
    (`IaasVMContainer;` / `VM;`) while `protected_items.get` is not. Lowercase prefixes
    made protected_items.get succeed but recovery_points.list return EMPTY — a false
    "first backup pending" in posture (commit 8bda989), and "No recovery points" in
    restore, which still built them in lowercase. One builder for every caller.
    """
    return (
        f"IaasVMContainer;iaasvmcontainerv2;{vm_rg};{vm_name}",
        f"VM;iaasvmcontainerv2;{vm_rg};{vm_name}",
    )


def _is_iam_error(err: str) -> bool:
    """Return True if the error is an Azure authorization/permission failure."""
    markers = ("AuthorizationFailed", "Forbidden", "403", "does not have authorization")
    return any(m in err for m in markers)
