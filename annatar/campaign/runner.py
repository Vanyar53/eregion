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

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from rich.console import Console

from annatar.campaign.manifest import CampaignManifest
from annatar.campaign.scope import Scope
from annatar.runner.engine import Engine, RunOutcome

console = Console()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_reset(resource_id: str) -> None:
    """Reset NSG state (isolation + IP blocks) between scenarios."""
    subprocess.run(
        ["glorfindel", "reset", resource_id, "--yes"],
        check=False,
        capture_output=True,
        timeout=120,
    )


class CampaignRunner:
    def __init__(
        self,
        campaign_dir: str | Path,
        *,
        dry_run: bool = False,
        reset_fn: Callable[[str], None] | None = None,
        engine_factory: Callable[[], Engine] | None = None,
    ):
        self.campaign_dir = Path(campaign_dir)
        self.dry_run = dry_run
        self.reset_fn = reset_fn or _default_reset
        self.engine_factory = engine_factory or (lambda: Engine(skip_preflight=False))

    def run(self) -> CampaignManifest:
        m = CampaignManifest.load(self.campaign_dir)
        scope = Scope(**_scope_dict(m))
        budget = m.budget

        # A dry-run is a no-op preview — allowed in any state, mutates nothing.
        if self.dry_run:
            self._preview(m)
            return m

        if m.state not in ("ratified", "running"):
            raise ValueError(
                f"campaign {m.campaign_id} is '{m.state}' — ratify it before running"
            )

        m.set_state("running")
        m.save(self.campaign_dir)

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

            # NSG reset between scenarios (clean attribution for the next one)
            if budget.reset_nsg_between:
                try:
                    self.reset_fn(entry.target_resource_id)
                except Exception as e:  # reset failure must not abort the campaign
                    console.print(f"[yellow]NSG reset failed: {e}[/yellow]")

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


def _scope_dict(m: CampaignManifest) -> dict:
    s = m.scope
    return {
        "sandbox": s.sandbox,
        "subscription_id": s.subscription_id,
        "allowed_resource_groups": list(s.allowed_resource_groups),
        "allowed_resource_ids": list(s.allowed_resource_ids),
    }
