"""Orodruin judges a request and runs it (DG-b, docs/design/console.md §7, phase b).

    python -m eregion_core.exercise_runner /app/requests/<id>.json

On Orodruin, in the injectors' image, where ``make orodruin-exercise`` copied the request and,
beside it, the names the operator typed (``<id>.typed.json``). The console advised; Orodruin
decides, on what it reads now, with its own identity:

    1  read     the request by its one reader (``exercise_request.read``), the names typed apart
    2  contract ``orodruin.check()``: armed, or the request is refused (``passive``, its codes)
    3  judge    every wire with the console's codes (``exercise_plan.plan``): the bench's
                perimeter, the enrollment and the zone read now (O0) — the production rule —, a
                live watch (V1), a fault's engine aiming at its VM (``gothmog targets``, read
                without Orodruin), Orodruin's declared cap; then the name typed for each wire
                that asks for one, compared to the name Orodruin reads of its target
                (``typed_name``). One wire refused: the request is refused whole, nothing runs
    4  run      the wires one after the other, in their rank. Before each one: the cap left to
                the request (its calls journaled since it started, its time), the watch again,
                the target's enrollment and zone again, the name again; a VM whose fault did not
                verify its return takes no other wire (a fault and a technique never overlap on
                a VM); a VM isolated by Glorfindel waits for its release up to
                ``WAIT_ISOLATION_S``, then its wire is skipped and said — an injector never
                undoes what Glorfindel did. Each wire is its injector's own run, a process of
                its own (D1: ``annatar wire`` / ``gothmog run``), its cap the request's
                remainder, the request's id written in its exercise window
    5  status   at each step: judged, refused (its codes), running, finished — per wire its rank,
                its state, its code and its runs; never its experiment nor its target
                (``Status.to_dict``). Kept here and, with a channel, published for the console

Every reader is a parameter: the tests run it on fakes, no Azure, no injector.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from eregion_core import exercise_request as xr
from eregion_core import held, orodruin, watch_gate
from eregion_core.exercise import exercises_dir
from eregion_core.exercise_plan import Target, judge, load_catalog, plan
from eregion_core.inscription import Scope, TagEnrollment, rg_from_id, subscription_from_id

# How long a wire waits for its VM's release when Glorfindel isolated it, before it is skipped.
WAIT_ISOLATION_S = 20 * 60
POLL_S = 30.0
# Request-level codes, besides the wires' (exercise_plan.REFUSALS).
REQUEST_REFUSALS = ("unreadable", "passive", "refused_wires", "busy")
# Why a wire did not run, once the request was judged.
SKIPS = ("over_cap", "no_watch", "isolated", "not_returned", "refused_now", "launch_failed")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class WireStatus:
    rank: int
    state: str = "queued"          # queued, refused, skipped, running, done, failed
    code: str = ""
    runs: list[str] = field(default_factory=list)
    result: str = ""


@dataclass
class Status:
    """What Orodruin says of a request — its rank, state, code and runs per wire, never what the
    wire was (the windows say that, as today): blind to the red side's plan."""
    request: str
    state: str = "judging"          # judging, refused, judged, running, finished
    at: str = ""
    codes: list[str] = field(default_factory=list)
    wires: list[WireStatus] = field(default_factory=list)

    def wire(self, rank: int) -> WireStatus:
        return next(w for w in self.wires if w.rank == rank)

    def to_dict(self) -> dict:
        return {"request": self.request, "state": self.state, "at": self.at,
                "codes": list(self.codes),
                "wires": [{"rank": w.rank, "state": w.state, "code": w.code, "runs": list(w.runs),
                           "result": w.result} for w in self.wires]}


# ── The readers on Orodruin (its identity; Reader on the bench's group) ─────────────────

_reader: TagEnrollment | None = None


def _arm_get(path: str, api: str) -> dict:
    """A read of ARM with Orodruin's identity — the inscription's reader (O0), no SDK here."""
    global _reader
    if _reader is None:
        _reader = TagEnrollment()
    return _reader.arm_get(path, api)


def read_target(resource_id: str) -> tuple[Target, str]:
    """The VM now: its tags and its group's, and its name as Azure writes it."""
    sub, rg = subscription_from_id(resource_id), rg_from_id(resource_id)
    group = _arm_get(f"/subscriptions/{sub}/resourceGroups/{rg}", "2021-04-01")
    vm = _arm_get(resource_id, "2024-07-01")
    return Target(resource_id, group.get("tags") or {}, vm.get("tags") or {}), str(vm.get("name") or "")


def isolated(resource_id: str) -> str:
    """Why the VM is held by Glorfindel now — an isolation or a quarantine rule on a security group
    of one of its NICs or their subnets, wherever it lives (eregion_core/held.py, the rule Annatar's
    preflight reads too) — or "". Unreadable: said, held (a wire never runs on a VM it cannot tell
    is free)."""
    return held.holding(resource_id, _arm_get)


def fault_targets() -> dict[str, list[str] | None]:
    """The VMs each fault's experiment aims at, as Gothmog reads them without Orodruin (``gothmog
    targets --json``, its own process: D1). Unreadable: {} — every fault's engine unknown, its
    preflight decides."""
    try:
        out = subprocess.run(["gothmog", "targets", "--json"], capture_output=True, text=True,
                             timeout=60, check=True).stdout
        data = json.loads(out)
    except Exception:
        return {}
    return {str(k): [str(n) for n in v] if isinstance(v, list) else None for k, v in data.items()}


def publish_status(status: "Status") -> bool:
    """The status to the exercise channel, for the console (no channel: kept here only)."""
    from eregion_core import exercise_channel
    return exercise_channel.publish_doc(f"{exercise_channel.ORODRUIN}/requests/{status.request}.json",
                                        status.to_dict())


def launch(argv: list[str], env: dict) -> int:
    """A wire: its injector's own run, its own process, the operator's terminal for its output."""
    return subprocess.run(argv, env={**os.environ, **env}, check=False).returncode


def argv_for(experiment, wire: xr.Wire, request_id: str, typed: str = "") -> list[str]:
    """The injector's command for a wire: Annatar for a technique, Gothmog for a fault."""
    if experiment.kind == "fault":
        return ["gothmog", "run", experiment.id, "--yes", "--request", request_id,
                "--target", wire.target] + (["--typed-name", typed] if typed else [])
    return ["annatar", "wire", experiment.id, wire.target, "--request", request_id] + (
        ["--typed-name", typed] if typed else [])


class Busy(RuntimeError):
    """Another request (or this one, launched again) runs on this Orodruin."""


@contextlib.contextmanager
def request_lock(runs_dir: Path | str):
    """One request at a time on this Orodruin (DG-b review, point 5): an exclusive ``flock`` on
    ``runs/orodruin/requests/.lock``, never waited for — two requests side by side would overlap
    on a VM and double Orodruin's cap. Held while the request runs; the kernel lets it go with the
    process, a crash included."""
    path = Path(runs_dir) / "orodruin" / "requests" / ".lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy("another request runs on this Orodruin: one at a time — wait for its end, "
                       "or stop it (make orodruin-kill)") from None
        yield
    finally:
        os.close(fd)


# ── The runner ────────────────────────────────────────────────────────────────────────

class Runner:
    def __init__(self, *, check: Callable = None, watch: Callable = None,
                 read_target: Callable = read_target, fault_targets: Callable = fault_targets,
                 isolated: Callable = isolated, launch: Callable = launch,
                 publish: Callable | None = publish_status,
                 publish_contract: Callable | None = orodruin.publish_contract,
                 catalog: dict | None = None,
                 runs_dir: Path | str = "runs", scope: Scope | None = None, now=_now,
                 sleep=time.sleep, wait_isolation_s: float = WAIT_ISOLATION_S,
                 poll_s: float = POLL_S, say=print):
        self.check = check or orodruin.check
        self.watch = watch or watch_gate.refusal
        self.read_target, self.fault_targets = read_target, fault_targets
        self.isolated, self.launch = isolated, launch
        self.publish = publish or (lambda status: None)
        self.publish_contract = publish_contract or (lambda verdict: None)
        self.catalog = catalog
        self.runs_dir = Path(runs_dir)
        self.scope = scope or Scope.for_bench()
        self.now, self.sleep, self.say = now, sleep, say
        self.wait_isolation_s, self.poll_s = wait_isolation_s, poll_s

    # The status, kept on this host and published at each step.
    def _emit(self, status: Status) -> None:
        status.at = self.now().isoformat()
        path = self.runs_dir / "orodruin" / "requests" / f"{status.request}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(status.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(path)
        try:
            self.publish(status)
        except Exception as e:  # the run goes on: the operator sees it in the terminal
            self.say(f"[request] status not published: {e}")

    def _read(self, wires) -> tuple[dict[str, Target], dict[str, str]]:
        """Each distinct target, read now: its tags and its name — or absent (not enrolled)."""
        targets, names = {}, {}
        for rid in {w.target.lower(): w.target for w in wires}.values():
            try:
                t, name = self.read_target(rid)
            except Exception as e:
                self.say(f"[request] {rid.rsplit('/', 1)[-1]}: unreadable ({e}) — not enrolled")
                continue
            targets[rid.lower()], names[rid.lower()] = t, name
        return targets, names

    def _typed_refusal(self, wire, typed: dict[int, str], names: dict[str, str]) -> str:
        """Why the name typed does not hold — "" when it does. Compared to the name Orodruin read."""
        got, want = typed.get(wire.rank, ""), names.get(wire.target.lower(), "")
        if not got:
            return "no name typed for a wire that asks for one (destructive, or not declared harmless)"
        if not want or got != want:
            return f"the name typed is not the target's ({want or 'unread'})"
        return ""

    def _calls_used(self, request_id: str, since: datetime) -> int:
        """The request's injector calls journaled since it started — the journal precedes each
        call (O1), so this is never fewer than the calls made."""
        n = 0
        try:
            with open(orodruin.audit_path(), encoding="utf-8") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("request") == request_id and rec.get("outcome") == "about_to_call" \
                            and str(rec.get("ts") or "") >= since.isoformat():
                        n += 1
        except FileNotFoundError:
            pass
        return n

    def _windows(self, request_id: str) -> dict[str, dict]:
        out = {}
        for p in sorted(exercises_dir(self.runs_dir).glob("*.json")):
            try:
                w = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(w, dict) and w.get("request") == request_id and w.get("run_id"):
                out[str(w["run_id"])] = w
        return out

    def _report(self, run_id: str) -> dict:
        try:
            return json.loads((self.runs_dir / f"{run_id}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def judge(self, req: xr.Request, typed: dict[int, str]):
        """Steps 2–3: the contract, then every wire. Returns the status, the verdicts, the cap,
        the names read, the fault targets."""
        status = Status(req.id, wires=[WireStatus(w.rank) for w in req.wires])
        verdict = self.check()
        try:
            self.publish_contract(verdict)
        except Exception as e:  # the console says « unknown here »; the judgment goes on
            self.say(f"[request] Orodruin's verdict not published: {e}")
        if not verdict.armed:
            status.state = "refused"
            status.codes = ["passive"] + [m["code"] for m in verdict.missing]
            for w in status.wires:
                w.state, w.code = "refused", "passive"
            return status, [], {}, {}, {}
        cap = verdict.cap
        targets, names = self._read(req.wires)
        faults = self.fault_targets()
        catalog = self.catalog if self.catalog is not None else load_catalog()
        verdicts = plan([(w.experiment, w.target) for w in req.wires], targets, catalog=catalog,
                        watch_refusal=self.watch(), fault_targets=faults, scope=self.scope,
                        max_injections=cap.get("max_injections", 0), max_run_s=cap.get("max_run_s", 0))
        for w, v in zip(req.wires, verdicts):
            if not v.code and any(x["code"] == "typed_name" for x in v.warnings):
                why = self._typed_refusal(w, typed, names)
                if why:
                    v.refuse("typed_name", why)
            ws = status.wire(w.rank)
            if v.code:
                ws.state, ws.code = "refused", v.code
        refused = [v for v in verdicts if v.code]
        status.state = "refused" if refused else "judged"
        status.codes = ["refused_wires"] if refused else []
        return status, verdicts, cap, names, faults

    def run(self, req: xr.Request, typed: dict[int, str]) -> Status:
        try:
            with request_lock(self.runs_dir):
                return self._run(req, typed)
        except Busy as e:
            # Nothing judged, nothing published: the status of the request that runs stays its own.
            self.say(f"Request {req.id} refused — busy: {e}")
            return Status(req.id, state="refused", codes=["busy"],
                          wires=[WireStatus(w.rank, "refused", "busy") for w in req.wires])

    def _run(self, req: xr.Request, typed: dict[int, str]) -> Status:
        start = self.now()
        status, verdicts, cap, names, faults = self.judge(req, typed)
        for w, v in zip(req.wires, verdicts):
            if v.code:
                self.say(f"  ✗ wire {w.rank} refused — {v.code}: {v.reason}")
        if status.state == "refused":
            self.say(f"Request {req.id} refused: {', '.join(status.codes)} — nothing runs.")
            self._emit(status)
            return status
        self._emit(status)
        status.state = "running"
        catalog = self.catalog if self.catalog is not None else load_catalog()
        not_returned: set[str] = set()
        for i, w in enumerate(req.wires):
            ws = status.wire(w.rank)
            e = catalog[w.experiment]

            def left() -> tuple[int, int]:
                return (int(cap["max_run_s"] - (self.now() - start).total_seconds()),
                        cap["max_injections"] - self._calls_used(req.id, start))

            def stop_rest(code: str, why: str) -> None:
                for rest in req.wires[i:]:
                    status.wire(rest.rank).state, status.wire(rest.rank).code = "skipped", code
                self.say(f"  ✗ {why} — wires {w.rank}– skipped")

            over = (f"Orodruin's cap reached ({cap['max_injections']} calls, "
                    f"{cap['max_run_s'] // 60} min for the request)")
            left_s, left_calls = left()
            if left_s <= 0 or left_calls <= 0:
                stop_rest("over_cap", over)
                break
            # First the wait (a VM without its return, a VM held by Glorfindel), then everything
            # read again: the watch, the target, its zone and its name are those of the moment the
            # wire leaves, never of before a wait of minutes (DG-b review, point 6).
            why = self._wait(w, not_returned, left_s)
            if not why:
                left_s, left_calls = left()
                if left_s <= 0 or left_calls <= 0:
                    stop_rest("over_cap", over)
                    break
                lost = self.watch()
                if lost:
                    stop_rest("no_watch", f"no live Glorfindel watch: {lost}")
                    break
                why = self._recheck(w, typed, faults)
            if why:
                ws.state, ws.code = ("refused" if why[0] in ("refused_now", "typed_name") else "skipped"), why[0]
                self.say(f"  ✗ wire {w.rank} {ws.state} — {why[0]}: {why[1]}")
                self._emit(status)
                continue
            ws.state = "running"
            self._emit(status)
            before = set(self._windows(req.id))
            env = {orodruin.MAX_INJECTIONS_ENV: str(left_calls), orodruin.MAX_RUN_S_ENV: str(max(left_s, 1))}
            self.say(f"→ wire {w.rank}: {e.kind} {e.id} on {w.target_name}")
            try:
                code = self.launch(argv_for(e, w, req.id, typed.get(w.rank, "")), env)
            except Exception as ex:
                # DG-b review, point 7: an injector that could not even start — whether it touched
                # its target is unknown. The wire fails, the status says it, the rest does not run.
                ws.state, ws.code = "failed", "launch_failed"
                ws.runs = sorted(k for k in self._windows(req.id) if k not in before)
                for rest in req.wires[i + 1:]:
                    status.wire(rest.rank).state, status.wire(rest.rank).code = "skipped", "launch_failed"
                self.say(f"  ✗ wire {w.rank} failed to launch ({type(ex).__name__}: {ex}) — "
                         f"wires {w.rank + 1}– not run")
                break
            windows = {k: v for k, v in self._windows(req.id).items() if k not in before}
            ws.runs = sorted(windows)
            reports = [self._report(r) for r in ws.runs]
            ws.result = ",".join(str(r.get("result") or "") for r in reports if r) or ("" if code == 0 else "error")
            ws.state = "done" if code == 0 else "failed"
            if e.kind == "fault":
                returned = bool(reports) and all((r.get("checks") or {}).get("revert_verified") == "PASS"
                                                 for r in reports)
                if not returned:
                    aimed = {t.lower() for win in windows.values() for t in win.get("targets") or []}
                    not_returned |= aimed or {w.target.lower()}
            self._emit(status)
        status.state = "finished"
        self._emit(status)
        done = sum(1 for x in status.wires if x.state == "done")
        self.say(f"Request {req.id} finished: {done}/{len(status.wires)} wire(s) run.")
        return status

    def _recheck(self, w, typed, faults) -> tuple[str, str] | None:
        """At each injection (O0), right before it: the target read again and judged again, its
        name again. None: the wire may run."""
        try:
            target, name = self.read_target(w.target)
        except Exception as ex:
            return "refused_now", f"its target unreadable now: {ex}"
        v = judge(w.experiment, w.target, target, catalog=self.catalog if self.catalog is not None
                  else load_catalog(), watch_refusal="", fault_targets=faults, scope=self.scope)
        if v.code:
            return "refused_now", f"{v.code}: {v.reason}"
        if any(x["code"] == "typed_name" for x in v.warnings):
            why = self._typed_refusal(w, typed, {w.target.lower(): name})
            if why:
                return "typed_name", why
        return None

    def _wait(self, w, not_returned, left_s) -> tuple[str, str] | None:
        """A VM whose fault did not come back takes no wire; a VM held by Glorfindel is waited for,
        within the request's time left. None: the VM is free now."""
        if w.target.lower() in not_returned:
            return "not_returned", (f"a fault on {w.target_name} did not verify its return: no other "
                                    "wire runs on it")
        waited, held = 0.0, self.isolated(w.target)
        limit = min(self.wait_isolation_s, max(left_s, 0))
        while held and waited < limit:
            self.say(f"  … wire {w.rank}: {w.target_name} held ({held}) — waiting for its release")
            self.sleep(self.poll_s)
            waited += self.poll_s
            held = self.isolated(w.target)
        if held:
            return "isolated", (f"{w.target_name} still held after {waited / 60:.0f} min ({held}): "
                                "skipped — an injector never undoes what Glorfindel did")
        return None


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m eregion_core.exercise_runner <requests/<id>.json>", file=sys.stderr)
        return 2
    path = Path(args[0])
    try:
        req = xr.load(path)
        typed = xr.load_typed(path.with_name(f"{path.stem}.typed.json"), req)
    except xr.RequestRefused as e:
        print(f"✗ request refused — unreadable: {e}. Nothing runs.", file=sys.stderr)
        return 1
    if req.id != path.stem:
        # DG-b review: the file names the request carried; its content is that one, or nothing runs.
        print(f"✗ request refused — {path.name} holds {xr.shown(req.id)}. Nothing runs.", file=sys.stderr)
        return 1
    status = Runner().run(req, typed)
    return 0 if status.state == "finished" and all(w.state == "done" for w in status.wires) else 1


if __name__ == "__main__":
    raise SystemExit(main())
