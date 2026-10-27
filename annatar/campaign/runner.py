"""Sequential, budgeted campaign executor — the blind-loop driver.

Runs a ratified campaign's scenarios one at a time, with a detection window and an
NSG reset between each (clean attribution vs IncidentRegistry; kill-chain logic;
detection latency). Honours the load-bearing guardrails at EXECUTION time (a
hand-edited manifest cannot bypass them):

  - re-check scope per scenario (allowlist Celebrimbor);
  - destructive scenario only runs if budget.allow_destructive;
  - stop at budget.max_scenarios; honour an externally-set kill_switch.

Annatar announces NOTHING to Glorfindel — it just runs and records detected/missed
into the manifest (read post-hoc by the blue replay engine).
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Callable

from rich.console import Console

from annatar.campaign.manifest import CampaignManifest
from annatar.runner.engine import Engine, RunOutcome
from eregion_core import watch_gate

console = Console()


class CampaignRefused(ValueError):
    """A campaign that does not start (V1): no live Glorfindel watch, or a resume with another
    --without-glorfindel than the one it started with. Its manifest is left as it was."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_reset(resource_id: str) -> str:
    """Reset NSG state (isolation + IP blocks) between scenarios.

    Returns what happened, recorded in the manifest: ``"reset"``, ``"skipped: …"`` or
    ``"failed: exit <rc>"`` (a non-zero exit did not reset). ``glorfindel reset`` is not in
    the Orodruin image (and outside the ``injector`` role). There, the ``glorfindel`` launcher
    IS on PATH — ``pip install -e ".[annatar]"`` installs every ``[project.scripts]`` entry —
    but the ``glorfindel`` package is not copied (annatar/Dockerfile), so the launcher would
    exit 1 on ``ModuleNotFoundError``. The guard therefore tests the PACKAGE first
    (``find_spec``), then the launcher: when either is missing, the reset is SKIPPED — quietly
    (no loud failure), without shelling out or writing anything — and the manifest says so.
    On H0 nothing isolates (human_only, read-only), so there is nothing to reset anyway.
    """
    if find_spec("glorfindel") is None:
        return "skipped: glorfindel absent (package not installed — reset is not in the Orodruin image)"
    if shutil.which("glorfindel") is None:
        return "skipped: glorfindel absent (no launcher on PATH)"
    proc = subprocess.run(
        ["glorfindel", "reset", resource_id, "--yes"],
        check=False,
        capture_output=True,
        timeout=120,
    )
    # A reset that exits non-zero did not reset: say so, never "reset".
    if proc.returncode != 0:
        return f"failed: exit {proc.returncode}"
    return "reset"


class CampaignRunner:
    def __init__(
        self,
        campaign_dir: str | Path,
        *,
        dry_run: bool = False,
        reset_fn: Callable[[str], str | None] | None = None,
        engine_factory: Callable[[], Engine] | None = None,
        without_glorfindel: bool = False,
    ):
        self.campaign_dir = Path(campaign_dir)
        self.dry_run = dry_run
        self.reset_fn = reset_fn or _default_reset
        # V1 (#214): each run checks the watch itself; --without-glorfindel reaches each one.
        self.without_glorfindel = without_glorfindel
        self.engine_factory = engine_factory or (
            lambda: Engine(skip_preflight=False, without_glorfindel=without_glorfindel))

    def run(self) -> CampaignManifest:
        m = CampaignManifest.load(self.campaign_dir)
        scope = m.scope
        budget = m.budget

        # A dry-run is a no-op preview — allowed in any state, mutates nothing.
        if self.dry_run:
            self._preview(m)
            return m

        if m.state not in ("ratified", "running"):
            if m.state in ("done", "aborted"):
                hint = "re-plan to run again (terminal state)"
            else:
                hint = "ratify it with --yes before running"
            raise ValueError(
                f"campaign {m.campaign_id} is '{m.state}' — {hint}"
            )

        # V1 (#214): a campaign is resumed the way it started — with Glorfindel, or without it:
        # its runs would otherwise mix measured and unmeasured detections.
        if m.state == "running" and m.without_glorfindel != self.without_glorfindel:
            said = "without" if m.without_glorfindel else "with"
            raise CampaignRefused(
                f"campaign {m.campaign_id} started {said} Glorfindel — resume it the same way "
                f"({'with' if m.without_glorfindel else 'without'} {watch_gate.FLAG})")
        # No live Glorfindel watch, no campaign — refused before its first run, its state left
        # as it was (ratified: it can run once the watch is up).
        if not self.without_glorfindel:
            no_watch = watch_gate.refusal()
            if no_watch:
                raise CampaignRefused(
                    f"campaign {m.campaign_id} refused — no live Glorfindel watch: {no_watch}")

        m.without_glorfindel = self.without_glorfindel
        m.set_state("running")
        m.save(self.campaign_dir)

        # Multi-scenario advisory: an autonomous blue response (isolate_vm) mid-chain
        # persists and can break every downstream scenario (AMA/egress cut → no
        # telemetry, no attack traffic). Recommend running the chain with Glorfindel
        # in human_only so it detects+decides without executing. See 2026-07-30 e2e
        # finding (Fix A). Not enforced here — cross-container, operator's call.
        pending = sum(1 for s in m.scenarios if s.status == "pending")
        if pending > 1:
            console.print(
                "[yellow]⚠ Multi-scenario campaign: run Glorfindel in "
                "[bold]human_only[/bold] to avoid an autonomous isolation "
                "persisting across scenarios and breaking the chain "
                "(egress/telemetry cut).[/yellow]"
            )

        executed = sum(1 for s in m.scenarios if s.status == "executed")
        aborted = False

        for entry in m.scenarios:
            if entry.status != "pending":
                continue  # resume: skip already-processed scenarios

            # kill switch — re-read from disk so an operator can stop mid-campaign
            if self._kill_switch_set():
                m.kill_switch = True
                aborted = True
                break

            # budget ceiling
            if executed >= budget.max_scenarios:
                entry.status = "skipped"
                entry.error = "budget: max_scenarios reached"
                m.save(self.campaign_dir)
                continue

            # scope re-check (defence against a hand-edited manifest)
            guard = scope.check(entry.target_resource_id)
            if not guard.allowed:
                entry.status = "error"
                entry.error = f"out of scope: {guard.reason}"
                m.save(self.campaign_dir)
                continue

            # destructive policy
            if entry.destructive and not budget.allow_destructive:
                entry.status = "skipped"
                entry.error = "destructive but budget.allow_destructive is false"
                m.save(self.campaign_dir)
                continue

            self._execute(entry, m)
            if entry.status == "executed":
                executed += 1
            elif (entry.error or "").startswith("glorfindel:"):
                # The watch died mid-campaign: every next run would be refused too.
                aborted = True
                break

            # NSG reset between scenarios (clean attribution for the next one). What happened
            # is recorded on the entry — including a quiet skip when glorfindel is absent.
            if budget.reset_nsg_between:
                try:
                    status = self.reset_fn(entry.target_resource_id)
                except Exception as e:  # reset failure must not abort the campaign
                    status = f"failed: {e}"
                    console.print(f"[yellow]NSG reset failed: {e}[/yellow]")
                if isinstance(status, str):
                    entry.reset = status
                    m.save(self.campaign_dir)

        m.set_state("aborted" if aborted else "done")
        m.save(self.campaign_dir)
        return m

    # ── internals ────────────────────────────────────────────────────────────
    def _execute(self, entry, m: CampaignManifest) -> None:
        path = self.campaign_dir / entry.scenario_file
        entry.status = "running"
        entry.started_at = _utcnow()
        m.save(self.campaign_dir)

        console.print(
            f"[cyan]==>[/cyan] [{entry.seq}] {entry.ttp} ({entry.tactic}) — {path.name}"
        )
        try:
            outcome: RunOutcome | None = self.engine_factory().run(
                str(path), skip_confirm=True
            )
        except Exception as e:  # unexpected engine failure → error, continue campaign
            entry.status = "error"
            entry.error = f"engine raised: {e}"
            entry.finished_at = _utcnow()
            m.save(self.campaign_dir)
            return

        entry.finished_at = _utcnow()
        if outcome is None or outcome.error:
            entry.status = "error"
            entry.error = (outcome.error if outcome else "run produced no outcome")
            entry.run_id = outcome.run_id if outcome else None
        else:
            entry.status = "executed"
            entry.run_id = outcome.run_id
            entry.detection = outcome.detection
            entry.detection_latency_s = outcome.detection_latency_s
        m.save(self.campaign_dir)

    def _kill_switch_set(self) -> bool:
        try:
            return CampaignManifest.load(self.campaign_dir).kill_switch
        except Exception:
            return False

    def _preview(self, m: CampaignManifest) -> None:
        console.print(f"[yellow]DRY RUN — campaign {m.campaign_id}[/yellow]")
        for e in m.scenarios:
            console.print(
                f"  [{e.seq}] {e.ttp} ({e.tactic}) → {e.scenario_file} "
                f"[dim]target={e.target_resource_id}[/dim]"
            )
        console.print(
            f"[dim]budget: max_scenarios={m.budget.max_scenarios}, "
            f"allow_destructive={m.budget.allow_destructive}[/dim]"
        )

