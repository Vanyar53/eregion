"""Which actions Glorfindel runs alone, the errors an action raises, and the verdicts
and checks shared by the agent, the CLI and the War Room (moved from actions.py, A1).
"""
from __future__ import annotations

from rich.console import Console


# Actions Glorfindel peut exécuter seul (réversibles)
AUTONOMOUS_ACTIONS = {
    "isolate_vm",
    "release_isolation",  # inverse of isolate_vm — safe to reverse autonomously
    # revoke_temp_access: removed 2026-10-06 — announced to the model, never implemented
    # (it ended as a no_op "executed", then notified). Proposed → escalated as unknown.
    "snapshot",           # forensic snapshot of current (compromised) state
    "block_suspicious_ip",
}

# Actions nécessitant validation humaine (destructives ou à impact large)
HUMAN_APPROVAL_REQUIRED = {
    "delete_resource",
    "modify_network_rule",
    "escalate_permissions",
    "wipe_storage",
    "restore_from_backup",  # replaces disk content — irreversible without another backup
}


class PartialActionError(RuntimeError):
    """An NSG action landed on some NICs, then failed on the next one.

    The rules already in place are KEPT (partial containment beats none) and recorded
    in state, so release / unblock / reset can remove them later. Before this, a failure
    on NIC n left the rules of NICs 1..n-1 on Azure with no state at all: invisible to
    `glorfindel list`, and out of reach of `reset`.

    Carries the original error's status_code so execute_action still tells an IAM gap
    (403 → write_blocked) from any other failure (action_failed).
    """

    def __init__(self, message: str, *, cause: BaseException, covered: list[str], failed_nic: str):
        super().__init__(message)
        self.cause = cause
        self.status_code = getattr(cause, "status_code", None)
        self.covered = covered
        self.failed_nic = failed_nic


# An Azure error names the lock (ScopeLocked) or the policy at the END of its first
# line: cut at 200 characters, the operator lost what to remove (real run, 2026-10-05).
_ERR_MAX = 600


def isolation_verdict(verification: dict, outcome: dict) -> dict:
    """verify_isolation's result, downgraded when the drain left sessions open.

    The rules only stop NEW connections (measured 2026-10-05): rules in place with an
    attacker's session still open is not a contained VM. Shared by the agent's
    verify_action and the War Room's approve route."""
    drain = (outcome or {}).get("drain") or {}
    if verification.get("verified") is True and drain.get("status") == "unsupported":
        return {
            **verification, "verified": False, "drain": drain,
            "error": ("sessions déjà ouvertes non coupées (" + (drain.get("note") or "OS non pris en charge")
                      + ") : un attaquant connecté garde la main — les couper à la main"),
        }
    if verification.get("verified") is True and drain.get("status") in ("failed", "partial"):
        return {
            **verification, "verified": False,
            "error": (
                f"règles posées, mais les sessions déjà ouvertes n'ont pas été coupées "
                f"({drain.get('error', drain.get('status'))}) — un attaquant connecté "
                "garde la main. Couper à la main : az vm run-command invoke "
                "--command-id RunShellScript --scripts 'ss -K state established'"
            ),
        }
    return verification


def _first_line(exc: BaseException) -> str:
    """First line of an exception message (Azure SDK errors repeat it on later lines)."""
    text = str(exc).strip()
    return text.splitlines()[0].strip() if text else type(exc).__name__


def single_host_ip(ip: str) -> str:
    """The address itself when `ip` is ONE host address, else ValueError. An approval
    passed `ip=*&scope=subnet` straight to a subnet-wide deny (fourth review, Q4)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        raise ValueError(f"adresse IP invalide : {ip!r} (une seule adresse attendue, pas de plage ni de tag)")
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast or addr.is_link_local:
        raise ValueError(f"adresse IP refusée : {ip} (non routable ou réservée)")
    return str(addr)


def platform_open_nics(placements) -> list[str]:
    """The NICs (short names) an isolation holds by rules only — no quarantine placement:
    Azure's DNS and IMDS stay reachable from them (Q15, measured). The War Room, `list` and
    the autonomous isolation's notification say it (sixth review, S7): it was in the
    outcome, and shown nowhere."""
    held = {str(p.get("nic_id", "")).rstrip("/").lower()
            for p in placements or [] if p.get("kind") == "quarantine"}
    out: list[str] = []
    for p in placements or []:
        nic = str(p.get("nic_id", "")).rstrip("/")
        short = nic.rsplit("/", 1)[-1]
        if nic and nic.lower() not in held and short not in out:
            out.append(short)
    return out


class WrongSubscriptionError(RuntimeError):
    """The target lives in another subscription than the one Glorfindel acts in."""


_console = Console()
