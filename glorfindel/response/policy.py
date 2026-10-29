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


# Addresses Glorfindel never blocks, whatever the rule or the model says (SEC2): Azure's
# platform (DNS and the host agent at 168.63.129.16, IMDS at 169.254.169.254), the private
# ranges (RFC 1918, the shared space of carrier NAT, IPv6's unique local) and the loopback.
# A private address is never blocked: lateral movement is answered by isolating the source
# VM. glorfindel-config.yaml's `never_block` adds the deployment's own (a scanner, a
# monitoring probe, the office).
NEVER_BLOCK_SHIPPED = (
    "168.63.129.16/32", "169.254.169.254/32",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
    "127.0.0.0/8", "::1/128",
)


class ProtectedAddressError(ValueError):
    """The address is on the never-block list: no block, ever — a human looks."""


def never_block_networks() -> list[str]:
    """The shipped list, then glorfindel-config.yaml's `never_block`. An unreadable config
    raises: not knowing the list is no reason to block (fail closed)."""
    from glorfindel.config import load_glorfindel_config
    return list(NEVER_BLOCK_SHIPPED) + list(load_glorfindel_config().never_block)


def protected_by(ip: str, networks: list[str] | None = None) -> str:
    """The never-block entry that holds `ip` ("" when none). `networks`: the list, when
    the caller already has it (default: `never_block_networks()`)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    # An IPv4 address written as IPv6 (::ffff:a.b.c.d) is that IPv4 address.
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    for net in never_block_networks() if networks is None else networks:
        try:
            if addr in ipaddress.ip_network(net, strict=False):
                return net
        except ValueError:
            continue
    return ""


def blockable_ip(ip: str) -> str:
    """`single_host_ip`, and never an address of the never-block list (SEC2): every block
    goes through here — the agent's, an approval's, a reassertion's, on every provider."""
    addr = single_host_ip(ip)
    try:
        held = protected_by(addr)
    except Exception as exc:
        raise ProtectedAddressError(
            f"blocage de {addr} refusé : liste never_block illisible "
            f"(glorfindel-config.yaml : {_first_line(exc)})") from exc
    if held:
        raise ProtectedAddressError(
            f"blocage de {addr} refusé : adresse protégée ({held}, liste never_block) — "
            "Glorfindel ne la bloque jamais ; à examiner par un humain")
    return addr


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


def original_unknown_nics(placements) -> list[str]:
    """The NICs (short names) in our quarantine whose original NSG nothing recorded — not
    the state, and so not our tag either (Q7; or isolated beside a state that couldn't be
    read, SEC4b): their release, autonomous or not, stops until the operator sets the tag.
    Said at the isolation, not first at the release (SEC4b, second review)."""
    out: list[str] = []
    for p in placements or []:
        short = str(p.get("nic_id", "")).rstrip("/").rsplit("/", 1)[-1]
        if p.get("kind") == "quarantine" and "original_nsg_id" not in p and short and short not in out:
            out.append(short)
    return out


class WrongSubscriptionError(RuntimeError):
    """The target lives in another subscription than the one Glorfindel acts in."""


_console = Console()
