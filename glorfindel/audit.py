from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

AuditStatus = Literal["ok", "warn", "fail", "skip"]


@dataclass
class AuditCheck:
    action: str       # remediation action this check covers
    name: str         # what was checked
    status: AuditStatus
    message: str
    fix: str = ""     # actionable CLI command to resolve the gap
    # Structured extras so the War Room doesn't have to parse `message`.
    # NSG check → {"nsg": "rg/name", "nsg_scope": "nic"|"subnet"}.
    # Backup check → {"points": int, "protected": bool} (when available).
    data: dict = field(default_factory=dict)


@dataclass
class AuditResult:
    resource_id: str
    timestamp: str
    checks: list[AuditCheck] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not any(c.status == "fail" for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "timestamp": self.timestamp,
            "ready": self.ready,
            "checks": [
                {
                    "action": c.action,
                    "name": c.name,
                    "status": c.status,
                    "message": c.message,
                    "fix": c.fix,
                    "data": c.data,
                }
                for c in self.checks
            ],
        }


def run(
    resource_id: str,
    connector,
    vault: str = "rsv-annatar",
) -> AuditResult:
    """Check that Glorfindel can execute all remediation actions on this resource.

    Covers: NSG (isolate_vm, block_suspicious_ip), Azure Backup (restore_from_backup),
    and Compute (snapshot). Detects both IAM gaps and missing infrastructure.
    """
    result = AuditResult(
        resource_id=resource_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    if getattr(connector, "dry_run", False):
        result.checks = [
            AuditCheck("all", "dry-run", "skip",
                       "Audit skipped in dry-run — no Azure API calls made")
        ]
        return result

    # Read-only credentials: remediation actions cannot execute by design. The
    # checks below still run — they confirm READ access (needed for detection) —
    # but write capability is not verifiable without performing a write.
    # `is True` (not truthy): MagicMock connectors in tests have an auto-truthy
    # read_only attribute — only a real bool True should trigger this branch.
    if getattr(connector, "read_only", False) is True:
        result.checks.append(AuditCheck(
            action="all",
            name="Credentials",
            status="warn",
            message=(
                "Read-only credentials (GLORFINDEL_READ_ONLY) — Glorfindel detects "
                "and recommends but cannot execute remediation. Checks below confirm "
                "READ access only; write capability is not verifiable."
            ),
            fix="Use a service principal with write roles to enable autonomous actions.",
        ))

    # Run the three Azure checks concurrently. The RSV backup check
    # (recovery_points.list) is the slow leg (several seconds); running it in
    # parallel with the fast NSG/Compute checks means the whole result returns at
    # the speed of the slowest single check instead of their sum. Order is
    # preserved (NSG, backup, compute) — futures are read in submission order.
    from concurrent.futures import ThreadPoolExecutor

    # Import the Azure SDK once, on THIS thread, before spawning the 3 parallel
    # checks — otherwise their concurrent first-import of azure.core deadlocks the
    # import system (_ModuleLock) / yields a half-init module. No-op after the first
    # call. Covers the War Room API process too (it calls audit.run via to_thread).
    from glorfindel.actions import warm_up_azure_sdk
    warm_up_azure_sdk()

    jobs = [
        (_check_nsg, (resource_id, connector)),
        (_check_backup, (resource_id, connector, vault)),
        (_check_compute, (resource_id, connector)),
    ]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(fn, *args) for fn, args in jobs]
        result.checks.extend(f.result() for f in futures)
    return result


# ── Per-action checks ──────────────────────────────────────────────────────────

def _check_nsg(resource_id: str, connector) -> AuditCheck:
    rg = _rg(resource_id)
    res = connector.check_nsg_access(resource_id)

    if res.get("ok"):
        nsg = res.get("nsg", "")
        rules = res.get("rules", "?")
        return AuditCheck(
            action="isolate_vm, block_suspicious_ip",
            name="NSG access",
            status="ok",
            message=f"NSG {nsg} readable ({rules} rules)",
            data={"nsg": nsg, "nsg_scope": res.get("scope", "")},
        )

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="isolate_vm, block_suspicious_ip",
            name="NSG access",
            status="fail",
            message=f"IAM: no permission on NSG — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Network Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{rg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("isolate_vm, block_suspicious_ip", "NSG access", err)
    return AuditCheck(
        action="isolate_vm, block_suspicious_ip",
        name="NSG access",
        status="fail",
        message=f"NSG not found or VM has no NSG — {err}",
        fix=f"Attach an NSG to the VM's NIC in resource group {rg}",
    )


def _check_backup(resource_id: str, connector, vault: str) -> AuditCheck:
    rg = _rg(resource_id)
    vm = resource_id.split("/")[-1]
    res = connector.check_backup_points(resource_id, vault)

    if res.get("dry_run"):
        return AuditCheck("restore_from_backup", "Backup vault", "skip", "Skipped in dry-run")

    if res.get("ok"):
        points = res.get("points", 0)
        age_h = res.get("latest_age_h", 0)
        status: AuditStatus = "ok" if age_h < 48 else "warn"
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status=status,
            message=f"Vault '{vault}': {points} point(s), latest {age_h}h ago",
            fix=(
                "" if status == "ok" else
                f"az backup protection backup-now -g {rg} -v {vault} "
                f"-c {vm} -i {vm} --backup-management-type AzureIaasVM"
            ),
            data={"protected": True, "points": points, "latest_age_h": age_h},
        )

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status="fail",
            message=f"IAM: no access to vault '{vault}' — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Backup Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{rg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("restore_from_backup", "Backup vault", err)
    if res.get("protected"):
        # Protected but no recovery point yet — restore not yet possible, but the VM
        # IS linked. Warn (not fail), and the fix is to trigger the first backup.
        return AuditCheck(
            action="restore_from_backup",
            name="Backup vault",
            status="warn",
            message=f"{vm} protected in '{vault}' but no recovery point yet (first backup pending)",
            fix=(
                f"az backup protection backup-now -g {rg} -v {vault} "
                f"-c {vm} -i {vm} --backup-management-type AzureIaasVM"
            ),
            data={"protected": True, "points": 0},
        )
    return AuditCheck(
        action="restore_from_backup",
        name="Backup vault",
        status="fail",
        message=f"Backup not configured for {vm} in '{vault}' — {err}",
        fix=(
            f"az backup protection enable-for-vm -g {rg} -v {vault} "
            f"--vm {vm} --policy-name DefaultPolicy"
        ),
        data={"protected": False, "points": 0},
    )


def _check_compute(resource_id: str, connector) -> AuditCheck:
    rg = _rg(resource_id)
    vm = resource_id.split("/")[-1]
    res = connector.check_compute_access(resource_id)

    if res.get("dry_run"):
        return AuditCheck("snapshot", "Compute access", "skip", "Skipped in dry-run")

    if res.get("ok"):
        disks = res.get("disks", [])
        return AuditCheck(
            action="snapshot",
            name="Compute access",
            status="ok",
            message=f"VM {vm}: {len(disks)} disk(s) — {', '.join(disks[:2])}",
        )

    err = res.get("error", "")[:120]
    if res.get("iam"):
        return AuditCheck(
            action="snapshot",
            name="Compute access",
            status="fail",
            message=f"IAM: no access to VM {vm} — {err}",
            fix=(
                f"az role assignment create --assignee $AZURE_CLIENT_ID "
                f"--role 'Virtual Machine Contributor' "
                f"--scope /subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/{rg}"
            ),
        )
    if _is_transient_error(err):
        return _transient_check("snapshot", "Compute access", err)
    return AuditCheck(
        action="snapshot",
        name="Compute access",
        status="fail",
        message=f"VM {vm} not found in {rg} — {err}",
        fix=f"Verify the VM exists: az vm show -g {rg} -n {vm}",
    )


def _is_transient_error(err: str) -> bool:
    """True for an SDK/transport error (not a real IAM or config gap).

    A transient error must NOT be reported as "no NSG / not configured / not found"
    — that sends the operator chasing a phantom infra fix. Covers the lazy-import
    race and common transport failures.
    """
    markers = (
        "cannot import name", "_modulelock", "partially initialized",
        "connectionerror", "connection aborted", "timeout", "timed out",
        "temporarily unavailable", "service unavailable",
    )
    e = err.lower()
    return any(m in e for m in markers)


def _transient_check(action: str, name: str, err: str) -> AuditCheck:
    return AuditCheck(
        action=action,
        name=name,
        status="warn",
        message=f"Could not verify (transient SDK/transport error) — {err}",
        fix="Retry; if it persists, check the Azure SDK install and connectivity.",
    )


def _rg(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except StopIteration:
        return "?"
