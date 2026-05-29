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

    result.checks.append(_check_nsg(resource_id, connector))
    result.checks.append(_check_backup(resource_id, connector, vault))
    result.checks.append(_check_compute(resource_id, connector))
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
    return AuditCheck(
        action="restore_from_backup",
        name="Backup vault",
        status="fail",
        message=f"Backup not configured for {vm} in '{vault}' — {err}",
        fix=(
            f"az backup protection enable-for-vm -g {rg} -v {vault} "
            f"--vm {vm} --policy-name DefaultPolicy"
        ),
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
    return AuditCheck(
        action="snapshot",
        name="Compute access",
        status="fail",
        message=f"VM {vm} not found in {rg} — {err}",
        fix=f"Verify the VM exists: az vm show -g {rg} -n {vm}",
    )


def _rg(resource_id: str) -> str:
    parts = resource_id.split("/")
    try:
        idx = next(i for i, p in enumerate(parts) if p.lower() == "resourcegroups")
        return parts[idx + 1]
    except StopIteration:
        return "?"
