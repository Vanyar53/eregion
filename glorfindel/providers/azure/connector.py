"""AzureConnector: the Azure implementation of CloudConnector, assembled from one mixin
per concern, and the two guards every write goes through — the subscription guard
(third review, T1) and the VM lock (moved from actions.py, A1).
"""
from __future__ import annotations

import os
import threading

from glorfindel.providers.azure.backup import BackupMixin
from glorfindel.providers.azure.blocks import BlockMixin
from glorfindel.providers.azure.capabilities import CAPABILITIES as AZURE_CAPABILITIES
from glorfindel.providers.azure.isolation import IsolationMixin
from glorfindel.providers.azure.network import NetworkMixin
from glorfindel.providers.azure.quarantine import QuarantineMixin
from glorfindel.providers.azure.readers import ReadersMixin
from glorfindel.providers.azure.release import ReleaseMixin
from glorfindel.providers.azure.restore import RestoreMixin
from glorfindel.providers.azure.sweep import SweepMixin
from glorfindel.providers.azure.unblock import UnblockMixin
from glorfindel.providers.azure.verify import VerifyMixin
from glorfindel.providers.interface import CloudConnector
from glorfindel.response.ids import _subscription_of
from glorfindel.response.locks import _vm_lock
from glorfindel.response.policy import WrongSubscriptionError


class AzureConnector(
    NetworkMixin,
    QuarantineMixin,
    IsolationMixin,
    ReleaseMixin,
    VerifyMixin,
    BlockMixin,
    UnblockMixin,
    BackupMixin,
    RestoreMixin,
    SweepMixin,
    ReadersMixin,
    CloudConnector,
):
    """Azure implementation of CloudConnector.

    Mutating actions act on the resource_id they are given. Scope control lives
    upstream, not in a tag allowlist: the per-asset autonomy mode (human_only by
    default) decides whether an action runs at all, and GLORFINDEL_READ_ONLY blocks
    every write (_guard_write). A defender limited to resources tagged as test targets
    would not defend production; the inscription (`eregion-target`, its zone) gates
    the injectors only (eregion_core/inscription.py).
    """

    ISOLATION_RULE_NAME = "glorfindel-isolation-deny-all"
    ISOLATION_PRIORITY = 100
    CAPABILITIES = AZURE_CAPABILITIES      # MC0: what this adapter can do, read by the readiness check

    def __init__(self, dry_run: bool = False, read_only: bool | None = None):
        self.dry_run = dry_run
        # read_only: when the SP only has Reader/Log Analytics Reader, write actions
        # cannot run. human_only mode never calls them, so detection-only deployments
        # work on read-only credentials. Declared via GLORFINDEL_READ_ONLY=1 (the
        # operator knows the SP's role; auto-detection isn't reliable without a write).
        if read_only is None:
            # Any value but a clear "off" keeps it read-only (G2): a typo never turns the
            # writes on.
            from glorfindel.config import read_only_requested
            read_only = read_only_requested()
        self.read_only = read_only
        self._credential = None
        self._subscription_id = None
        self._network = None
        self._compute = None
        self._clients_lock = threading.Lock()

    def permission_mode(self) -> str:
        """Return the effective permission regime: 'read_only' or 'read_write'."""
        return "read_only" if self.read_only else "read_write"

    def _guard_write(self, action: str) -> None:
        """Block a mutating action when running on read-only credentials.

        Raised lazily, only when an action is actually attempted — never at init,
        so detection-only (human_only) deployments start cleanly on Reader creds.
        """
        if self.read_only:
            raise PermissionError(
                f"Action '{action}' impossible : credentials lecture seule "
                "(GLORFINDEL_READ_ONLY). Glorfindel détecte et recommande mais ne peut "
                "pas agir. Utilisez un SP avec droits d'écriture pour exécuter les actions."
            )

    def _ensure_clients(self) -> None:
        # Double-checked locking: the lazy SDK import + client creation must be
        # thread-safe. audit.run() and the watch poll threads can call this
        # concurrently; without the lock, simultaneous first-calls trigger parallel
        # imports of azure.core and one thread sees a half-initialised module
        # (ImportError: cannot import name 'Pipeline'). _network is assigned LAST so
        # the lock-free fast path only passes when both clients are fully built.
        if self._network is not None:
            return
        with self._clients_lock:
            if self._network is not None:
                return
            import os
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.compute import ComputeManagementClient

            sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID")
            if not sub_id:
                raise RuntimeError("AZURE_SUBSCRIPTION_ID is not set")
            credential = DefaultAzureCredential()
            compute = ComputeManagementClient(credential, sub_id)
            network = NetworkManagementClient(credential, sub_id)
            self._credential = credential
            self._subscription_id = sub_id
            self._compute = compute
            self._network = network  # assign last — gate for the fast path


def _same_subscription(method):
    """Refuse to act on (or vouch for) a VM of another subscription (third review, T1).

    The resource ids are reduced to (resource group, name) and every client runs in
    AZURE_SUBSCRIPTION_ID. With a Log Analytics workspace shared by several
    subscriptions, a VM discovered in subscription B was isolated in subscription A —
    on the homonymous VM if one exists. Until clients exist per subscription, the
    action is refused, and the cycle escalates it as action_failed."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if not self.dry_run:
            rid = kwargs.get("resource_id") or next(
                (a for a in args if isinstance(a, str) and a.lower().startswith("/subscriptions/")), "")
            # The subscription the clients run in — read without building them, so the
            # read-only guard and its clear message still come first.
            target = _subscription_of(rid)
            mine = self._subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
            if target and mine and target.lower() != mine.lower():
                raise WrongSubscriptionError(
                    f"{rid.rsplit('/', 1)[-1]} est dans l'abonnement {target}, Glorfindel agit dans "
                    f"{mine} : action refusée (elle viserait une autre VM, ou aucune). "
                    "Agir depuis une instance configurée pour cet abonnement.")
        return method(self, *args, **kwargs)
    return wrapper


def _one_writer(method):
    """Hold the VM's lock for the whole write (see _vm_lock)."""
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        rid = kwargs.get("resource_id") or next(
            (a for a in args if isinstance(a, str) and a.lower().startswith("/subscriptions/")), "")
        if self.dry_run or not rid:
            return method(self, *args, **kwargs)
        with _vm_lock(rid.rstrip("/").rsplit("/", 1)[-1]):
            return method(self, *args, **kwargs)
    return wrapper


def _orphan_writer(method):
    """remove_orphan_rule (SEC3, N-07) through the same two guards as the other writes: the
    subscription of the NSG it writes, then the lock of every VM the rule cuts, held for
    the whole write — sorted, as the sweep takes them (re-entrant: the sweep's pass
    already holds them). It was safe through its one caller only."""
    import contextlib
    import functools

    @functools.wraps(method)
    def wrapper(self, orphan, *args, **kwargs):
        if self.dry_run or not isinstance(orphan, dict):
            return method(self, orphan, *args, **kwargs)
        nsg_id = str(orphan.get("nsg_id") or "")
        target = _subscription_of(nsg_id)
        mine = self._subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        if target and mine and target.lower() != mine.lower():
            raise WrongSubscriptionError(
                f"{nsg_id.rstrip('/').rsplit('/', 1)[-1]} est dans l'abonnement {target}, Glorfindel "
                f"agit dans {mine} : retrait refusé.")
        victims = sorted({(h.get("vm_id") or h.get("nic_id") or "").rstrip("/").rsplit("/", 1)[-1]
                          for h in orphan.get("cut") or [] if isinstance(h, dict)} - {""})
        with contextlib.ExitStack() as stack:
            for vm in victims:
                stack.enter_context(_vm_lock(vm))
            return method(self, orphan, *args, **kwargs)
    return wrapper


AzureConnector.remove_orphan_rule = _orphan_writer(AzureConnector.remove_orphan_rule)
for _name in ("isolate_vm", "release_isolation", "block_suspicious_ip", "unblock_ip", "sweep_vm_rules"):
    setattr(AzureConnector, _name, _one_writer(getattr(AzureConnector, _name)))
for _name in ("isolate_vm", "release_isolation", "verify_isolation", "verify_release",
              "block_suspicious_ip", "unblock_ip", "verify_block_ip", "snapshot",
              "restore_from_backup", "drain_connections", "sweep_vm_rules", "check_permissions"):
    if hasattr(AzureConnector, _name):
        setattr(AzureConnector, _name, _same_subscription(getattr(AzureConnector, _name)))
