"""orodruin-kill (O1): revoke Orodruin's identity, then deallocate its VM.

Run from the operator's own `az login` — the identity cannot, and must not be able to,
drop its own rights. Revoking a managed identity = deleting its role assignments, every
one of them, at every scope. The order is eregion_core.orodruin.kill's: revoke first,
so a running injector loses its rights even if the stop drags; a failed revocation
still stops the VM and exits non-zero.

    python infra/orodruin/kill.py <principal_id> <vm_id> [--dry-run]

RBAC removal is not instantaneous (the control plane caches): the delay before the
first refusal is measured on the bench, not assumed.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eregion_core.orodruin import kill  # noqa: E402


def az(args: list[str]) -> str:
    return subprocess.run(["az", *args], check=True, capture_output=True, text=True).stdout


def steps(principal_id: str, vm_id: str, run=az, dry_run: bool = False, say=print):
    """The two steps of the kill, as callables, in the order kill() runs them."""
    def call(args: list[str]) -> str:
        say(("[dry-run] az " if dry_run else "az ") + " ".join(args))
        return "[]" if dry_run else run(args)

    def revoke() -> None:
        # Filtered on principalId by JMESPath: no Graph lookup, nothing missed by scope.
        ids = json.loads(call(["role", "assignment", "list", "--all",
                               "--query", f"[?principalId=='{principal_id}'].id", "-o", "json"]))
        if not ids:
            say("no role assignment left for this identity")
            return
        call(["role", "assignment", "delete", "--ids", *ids])

    def stop() -> None:
        call(["vm", "deallocate", "--ids", vm_id, "--no-wait"])

    return revoke, stop


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--dry-run"]
    if len(args) != 2 or not all(args):
        print(__doc__)
        return 2
    revoke, stop = steps(*args, dry_run="--dry-run" in argv)
    failures = kill(revoke, stop)
    for f in failures:
        print(f"!! {f}", file=sys.stderr)
    if failures:
        print("!! kill INCOMPLETE — check the identity's role assignments by hand", file=sys.stderr)
        return 1
    print("identity revoked, VM deallocating")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
