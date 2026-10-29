"""The provider interface (MC0): what Glorfindel asks of a cloud, and what each cloud
declares it can do.

A provider is one adapter (`glorfindel/providers/<name>/`), the only place its SDK is
imported (`tests/unit/test_provider_boundary.py`). It implements `CloudConnector` and
declares its capabilities: each one names the response actions it serves and the
rights it needs. The readiness check reads that declaration — which rights a VM's
isolation, blocks and session cut need — instead of knowing a cloud's permission names.
Azure is the only adapter today (`glorfindel/providers/azure/`).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    """One thing a provider can do for Glorfindel, in the common vocabulary
    (docs/architecture.md): `name` is stable (the readiness check reads it), `actions`
    the response actions it serves, `rights` what the identity must hold — read without
    writing anything (`check_permissions`). Empty `rights`: not checked by the readiness."""

    name: str
    actions: tuple[str, ...]
    rights: frozenset[str] = frozenset()
    note: str = ""


@dataclass(frozen=True)
class ProviderCapabilities:
    """Everything one provider declares."""

    provider: str
    capabilities: tuple[Capability, ...]

    def get(self, name: str) -> Capability | None:
        return next((c for c in self.capabilities if c.name == name), None)

    def rights(self, name: str) -> frozenset[str]:
        """The rights a capability needs; none if the provider doesn't declare it."""
        cap = self.get(name)
        return cap.rights if cap else frozenset()

    def available(self, name: str, missing_rights) -> bool:
        """Declared, and none of its rights is among `missing_rights`."""
        cap = self.get(name)
        return cap is not None and not (set(missing_rights) & cap.rights)


# The common names (docs/architecture.md, « Le vocabulaire commun »).
NETWORK_QUARANTINE = "network_quarantine"    # isolate by a quarantine group of the provider's
NETWORK_RULES = "network_rules"              # isolate by rules, block an address
SESSION_DRAIN = "session_drain"              # cut the sessions an isolation leaves open
RESTORE_POINT = "restore_point"              # snapshot, restore


def capabilities_of(connector=None) -> ProviderCapabilities:
    """What the connector's provider declares: on the instance when it carries a
    declaration, else on its class — `__class__`, which a `MagicMock(spec=AzureConnector)`
    reports as AzureConnector. A connector that is no CloudConnector (a plain test double,
    or none at all: the audit) reads as the only adapter, Azure; a CloudConnector that
    declares nothing is a programming error."""
    declared = getattr(connector, "CAPABILITIES", None)
    if not isinstance(declared, ProviderCapabilities):
        declared = getattr(getattr(connector, "__class__", type(connector)), "CAPABILITIES", None)
    if isinstance(declared, ProviderCapabilities):
        return declared
    if isinstance(connector, CloudConnector):
        raise TypeError(f"{type(connector).__name__} declares no capabilities (CAPABILITIES)")
    from glorfindel.providers.azure.capabilities import CAPABILITIES
    return CAPABILITIES


class DetectionConnector(ABC):
    """Provider-agnostic interface for polling alert/detection sources.

    `plane`: "data" (what runs in a workload: Perf, Syslog, storage logs), "control"
    (what is done TO the cloud's resources: Azure's Activity Log — AL1) or "identity" (what
    is done to identities: Entra ID's audit and sign-in logs — C2). A control-plane or an
    identity detection never leads to an autonomous action (`decide` builds its decision
    without the model: an escalation, no action).
    `backend_type`: the monitoring backend type it reads ("" — its own source name).
    `min_lookback_s`: the shortest window a rule on it may look back (ingestion latency);
    a shorter one is said at load."""

    plane = "data"
    backend_type = ""
    min_lookback_s = 0.0

    @abstractmethod
    def poll_alert(
        self,
        query: str,
        since: float,
        timeout_s: float,
        interval_s: float = 10.0,
        match_row=None,
    ) -> tuple[float, dict] | None:
        """Poll until the query returns results or timeout expires.

        since: Unix timestamp — only match events after this time.
        match_row: optional predicate; only a row it accepts counts as a match (the
        first accepted row is returned). None = the first row of the result.
        Returns (elapsed_seconds, first_result_row_as_dict) or None on timeout.
        """
        ...

    def run_query(self, query: str, timespan=None) -> list[dict]:
        """Run a query and return ALL result rows (not just the first).

        Used for discovery queries (e.g. Heartbeat) and campaign replay. timespan is
        an optional (start_dt, end_dt) window. Default implementation returns an empty
        list — backends that support it override this.
        """
        return []


class CloudConnector(ABC):
    """Provider-agnostic interface. Azure now, AWS/GCP later.

    Each implementation sets `CAPABILITIES` (see capabilities_of)."""

    CAPABILITIES: ProviderCapabilities | None = None

    @abstractmethod
    def isolate_vm(self, resource_id: str) -> dict:
        """Block all inbound/outbound traffic on the VM's NIC. Fully reversible."""
        ...

    @abstractmethod
    def release_isolation(self, resource_id: str) -> dict:
        """Remove the isolation NSG rule applied by isolate_vm."""
        ...

    @abstractmethod
    def block_suspicious_ip(
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
        threat_port: int | None = None,
    ) -> dict:
        """Add deny rule for this IP. scope="vm" (this VM only) | "subnet" (all VMs).
        replace=True (with scope="subnet"): promote — apply the subnet rule, then drop
        the now-redundant VM-scoped rule (create-then-delete → no protection gap)."""
        ...

    @abstractmethod
    def snapshot(
        self, resource_id: str, vault: str = "", wait: bool = True,
        vault_rg: str = "",
    ) -> str:
        """Take an on-demand RSV backup snapshot.

        wait=True: blocks until job completes (~5-20 min). Use for CLI setup workflow.
        wait=False: fire-and-forget — returns job_id immediately. The agent always uses
        it: a blocking snapshot holds the VM's (serialized) signal queue for the whole
        backup — 4h25 on an initial full backup in a real run.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        ...

    @abstractmethod
    def verify_isolation(self, resource_id: str) -> dict:
        """Confirm that isolation rules are active on EVERY NIC of the VM."""
        ...

    def verify_release(self, resource_id: str) -> dict:
        """Confirm that NO isolation rule remains on any NIC of the VM.

        Not `not verify_isolation()`: that is False as soon as ONE NIC is uncovered, so
        its negation would call a VM released while another NIC is still cut off.
        Default for connectors that don't implement it: no claim (verified=None).
        """
        return {"verified": None, "method": "not_implemented"}

    @abstractmethod
    def verify_snapshot(self, snap_id: str) -> dict:
        """Confirm that a snapshot was actually created."""
        ...

    @abstractmethod
    def restore_from_backup(
        self,
        resource_id: str,
        vault: str = "",
        before_attack_time: str | None = None,
        wait: bool = True,
        staging_storage: str = "",
        vault_rg: str = "",
    ) -> dict:
        """Trigger an Azure Backup OriginalLocation restore. Human-approved action.

        before_attack_time: ISO8601 timestamp — selects the most recent recovery point
        that predates the attack, avoiding restoration of a post-attack backup. Required
        (SEC4c): without it the restore is refused, never the newest point.
        wait=False: returns after triggering the restore job, without polling.
          VM stays deallocated; caller must start it and emit recovery_complete manually.
        vault_rg: the vault's resource group (central vault ≠ VM RG); empty → VM's RG.
        """
        ...

    @abstractmethod
    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        """Confirm that the deny rule for this IP is active on the NSG."""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove the deny rules created by block_suspicious_ip for this IP."""
        ...

    @abstractmethod
    def restore_job_status(self, vault: str, vault_rg: str, job_name: str) -> str:
        """The provider's status of a restore job ("InProgress", "Completed", "Failed",
        "Cancelled"…), read in the vault's group. The job tracker (glorfindel/jobs.py)
        reconciles its records with it."""
        ...
