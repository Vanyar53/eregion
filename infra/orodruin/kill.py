"""orodruin-kill (O1, M-1): stop what Orodruin does, from the operator's own `az login`.

The identity cannot, and must not be able to, drop its own rights. Four steps, in the
order eregion_core.orodruin.kill runs them:

  revoke  delete every role assignment of the identity, at every scope, on the CONTRACT's
          subscription (and the VM's own, when it differs) — never the CLI's current one:
          in the wrong context the listing comes back empty and proves nothing. "Nothing
          left" is said only from a listing of that subscription, read again after the
          deletion.
  cancel  cancel every chaos experiment still running on the bench: it acts with its own
          identity, so revoking Orodruin's does not stop it.
  stop    deallocate the VM, without waiting.
  close   close the exercise windows still open in the channel (B2), so the hosted watch
          stops labelling what their targets do as an exercise. The operator writes them
          (`channel_operator`, main.tf): Orodruin's identity has just been revoked.

Then what is still in flight, which no step stops: a Run Command already sent runs to its
end on its VM, and the atomic's cleanup may be left to replay; a cancelled fault may leave
its VM down; a closed window still labels its targets during its grace.

A failed step does not stop the next ones, and is reported: exit 1, never a kill that
claims success. RBAC removal is not instantaneous (the control plane caches): the first
refusal came under 3 s on the bench (19/10, a single measure — not a bound).

    python infra/orodruin/kill.py <principal_id> <vm_id> --subscription <id>
        [--bench-rg rg-celebrimbor] [--channel <url>] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eregion_core import exercise, exercise_channel  # noqa: E402
from eregion_core.orodruin import DEFAULT_BENCH_RG, kill  # noqa: E402
from gothmog.engines.chaos_studio import ARM, CHAOS_API, experiment_targets, is_terminal  # noqa: E402

_SUBSCRIPTION = re.compile(r"^/subscriptions/([^/]+)/", re.IGNORECASE)


def az(args: list[str]) -> str:
    r = subprocess.run(["az", *args], capture_output=True, text=True)
    if r.returncode:
        last = (r.stderr.strip().splitlines() or ["no message"])[-1]
        raise RuntimeError(f"az {' '.join(args[:3])} … exit {r.returncode}: {last}")
    return r.stdout


def subscriptions(subscription: str, vm_id: str) -> list[str]:
    """The contract's subscription, then the VM's own if it differs — never the CLI's."""
    m = _SUBSCRIPTION.match(vm_id or "")
    found = [s for s in ((subscription or "").strip().strip('"'), m.group(1) if m else "") if s]
    return list({s.lower(): s for s in found}.values())


def redact(text: str, subs: list[str]) -> str:
    """Printed lines and errors never name the subscription (as the Makefile, M124)."""
    for s in subs:
        text = re.sub(re.escape(s), "<subscription>", text, flags=re.IGNORECASE)
    return text


def _cli_credential():
    # The operator's own `az login` — not DefaultAzureCredential, which would take a
    # service principal from the environment first (.envrc).
    from azure.identity import AzureCliCredential
    return AzureCliCredential()


def _lapsed(window: dict, at: datetime) -> bool:
    try:
        expires = datetime.fromisoformat(str(window.get("expires")).replace("Z", "+00:00"))
    except ValueError:
        return False  # unreadable: closed anyway
    return (expires if expires.tzinfo else expires.replace(tzinfo=timezone.utc)) <= at


def _names(ids) -> str:
    return ", ".join(i.rstrip("/").rsplit("/", 1)[-1] for i in ids) or "no target"


def _in_flight(window: dict, at: datetime, said_down: set[str] = frozenset()) -> list[str]:
    """What a closed window says may still run: the injector's own leftovers — a VM the
    cancel step already said may stay down is not said twice."""
    names = [i.rstrip("/").rsplit("/", 1)[-1] for i in window.get("targets") or []]
    run_id, targets = window["run_id"], ", ".join(names) or "no target"
    grace = (at + timedelta(seconds=exercise.GRACE_AFTER_S)).strftime("%H:%M UTC")
    out = [f"{run_id} ({window.get('injector')}, {window.get('experiment')}): detections on "
           f"{targets} are still labelled exercise until {grace} (the window's grace)"]
    if window.get("injector") == "annatar":
        out.append(f"{run_id}: a Run Command already sent runs to its end on {targets} — the "
                   "revocation does not stop it; the atomic's cleanup may not have run: "
                   "`annatar run <scenario> --dry-run` prints it, to replay by hand "
                   "(az vm run-command invoke)")
    elif window.get("injector") == "gothmog" and not set(names) <= said_down:
        out.append(f"{run_id}: the fault may leave {targets} down — `az vm start` it if the "
                   "cancelled experiment did not bring it back")
    return out


def steps(principal_id: str, vm_id: str, *, subscription: str = "",
          bench_rg: str = DEFAULT_BENCH_RG, channel: str = "", run=None, credential=None,
          get=None, put=None, dry_run: bool = False, say=print,
          inflight: list[str] | None = None, now: datetime | None = None):
    """The four steps of the kill, as callables, in the order kill() runs them. What they
    see still running and cannot stop is appended to ``inflight``."""
    run = run or az
    inflight = [] if inflight is None else inflight
    said_down: set[str] = set()  # the VMs the cancel step said a fault may leave down
    subs = subscriptions(subscription, vm_id)

    def call(args: list[str]) -> str:
        say(redact(("[dry-run] az " if dry_run else "az ") + " ".join(args), subs))
        return "[]" if dry_run else run(args)

    def listed(sub: str) -> list[str]:
        # Filtered on principalId by JMESPath: no Graph lookup, nothing missed by scope.
        return json.loads(call(["role", "assignment", "list", "--all", "--subscription", sub,
                                "--query", f"[?principalId=='{principal_id}'].id", "-o", "json"]))

    def revoke() -> None:
        if not subs:
            raise RuntimeError("no subscription to check (the contract's is unknown): nothing proven")
        found = 0
        for sub in subs:
            ids = listed(sub)
            found += len(ids)
            if ids:
                call(["role", "assignment", "delete", "--subscription", sub, "--ids", *ids])
        if dry_run:
            return
        # Read again: "nothing left" comes from a listing of these subscriptions, never assumed.
        left = [i for sub in subs for i in listed(sub)]
        if left:
            raise RuntimeError(f"{len(left)} role assignment(s) still listed after the deletion")
        if not found:
            # Nothing was there: true only if the principal is the VM's own identity.
            own = call(["vm", "show", "--ids", vm_id, "--query", "identity.principalId",
                        "-o", "tsv"]).strip()
            if own.lower() != principal_id.lower():
                raise RuntimeError(f"nothing listed for {principal_id}, which is not the VM's "
                                   f"identity ({own or 'none'}): nothing proven")
        say("no role assignment left for this identity on the contract's subscription")

    def pages(url: str) -> list[dict]:
        out: list[dict] = []
        while url:
            body = json.loads(call(["rest", "--method", "get", "--url", url, "-o", "json"]) or "{}")
            out += body.get("value") or []
            url = body.get("nextLink") or ""
        return out

    def running(experiment_id: str) -> list[dict]:
        return [e for e in pages(f"{ARM}{experiment_id}/executions?api-version={CHAOS_API}")
                if not is_terminal((e.get("properties") or {}).get("status"))]

    def cancel() -> None:
        if not subs:
            raise RuntimeError("no subscription to check: the bench's experiments were not read")
        url = (f"{ARM}/subscriptions/{subs[0]}/resourceGroups/{bench_rg}"
               f"/providers/Microsoft.Chaos/experiments?api-version={CHAOS_API}")
        if dry_run:
            call(["rest", "--method", "get", "--url", url])
            return
        cancelled = 0
        for experiment in pages(url):
            eid, name = experiment["id"], experiment.get("name") or "?"
            if not running(eid):
                continue
            call(["rest", "--method", "post", "--url", f"{ARM}{eid}/cancel?api-version={CHAOS_API}"])
            cancelled += 1
            try:
                targets = experiment_targets(experiment)
            except ValueError:
                targets = []
            said_down.update(t.rstrip("/").rsplit("/", 1)[-1] for t in targets)
            inflight.append(f"chaos {name}: cancelled — the fault may leave "
                            f"{_names(targets) if targets else 'its targets'} down; "
                            "`az vm start` it if the cancel did not bring it back")
            for e in running(eid):
                status = (e.get("properties") or {}).get("status")
                # Measured on the bench (26/10): Running right after the cancel, Cancelled
                # about 50 s later, the VM restarted by Chaos Studio itself.
                inflight.append(f"chaos {name}: execution still {status} right after the "
                                "cancel (it usually ends within a minute)")
        if not cancelled:
            say("no chaos experiment running on the bench")

    def stop() -> None:
        call(["vm", "deallocate", "--ids", vm_id, "--no-wait"])
        if not dry_run:
            inflight.append("the VM is deallocating (not awaited)")

    def close() -> None:
        if not channel:
            raise RuntimeError("no exercise channel given: its open windows were not checked")
        if dry_run:
            say(f"[dry-run] close the open windows of {channel}")
            return
        cred = credential or _cli_credential()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                exercise_channel.pull(Path(tmp), channel=channel, credential=cred, get=get)
                windows = exercise.load_windows(Path(tmp))
        except Exception as e:
            raise RuntimeError(
                f"{e} — the operator writes the windows (channel_operator: make orodruin-lock "
                f"YES=1); a window still open lapses at its expiry, at most "
                f"{exercise.MAX_DURATION_S // 3600} h after it opened, plus "
                f"{exercise.GRACE_AFTER_S // 60} min") from e
        at = now or datetime.now(timezone.utc)
        open_ = [w for w in windows if not w.get("end") and not _lapsed(w, at)]
        if not open_:
            say("no exercise window open in the channel")
        still_open = []
        for w in open_:
            closed = {**w, "end": at.isoformat(), "closed_by": "orodruin-kill"}
            try:
                exercise_channel.publish(closed, channel=channel, credential=cred, put=put)
            except Exception as e:
                still_open.append(f"{w['run_id']} ({e})")
                continue
            say(f"window {w['run_id']} closed ({w.get('injector')}: {w.get('experiment')})")
            inflight.extend(_in_flight(closed, at, said_down))
        if still_open:
            raise RuntimeError("windows still open: " + ", ".join(still_open))

    return revoke, cancel, stop, close


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="kill.py", description=__doc__.splitlines()[0])
    ap.add_argument("principal_id")
    ap.add_argument("vm_id")
    ap.add_argument("--subscription", default="", help="the contract's (AZURE_SUBSCRIPTION_ID)")
    ap.add_argument("--bench-rg", default=DEFAULT_BENCH_RG)
    ap.add_argument("--channel", default="", help="EREGION_EXERCISE_CHANNEL")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not (args.principal_id and args.vm_id):
        print(__doc__)
        return 2
    subs = subscriptions(args.subscription, args.vm_id)
    inflight: list[str] = []
    failures = kill(*steps(args.principal_id, args.vm_id, subscription=args.subscription,
                           bench_rg=args.bench_rg, channel=args.channel,
                           dry_run=args.dry_run, inflight=inflight))
    if inflight:
        print("still in flight — no step of the kill stops these:")
        for line in inflight:
            print(f"  - {line}")
    for f in failures:
        print(f"!! {redact(f, subs)}", file=sys.stderr)
    if failures:
        print("!! kill INCOMPLETE — check by hand what failed above (the identity's role "
              "assignments, the bench's experiments, the channel's windows)", file=sys.stderr)
        return 1
    print("[dry-run] nothing done" if args.dry_run else
          "identity revoked, experiments cancelled, VM deallocating, windows closed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
