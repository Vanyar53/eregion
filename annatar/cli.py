import os

import click
from rich.console import Console

console = Console()


class _AnnatarCli(click.Group):
    """Render operational failures as a clean one-liner, not a raw traceback.

    Missing creds, an azure-mgmt import mismatch, a campaign in a terminal state —
    these are operator conditions, not bugs. Dumping a 20-line stack helps no one.
    Print the cause + a targeted hint and exit non-zero. ANNATAR_DEBUG=1 restores
    the full traceback for real debugging. Mirrors glorfindel's _GlorfindelCli.
    """

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (click.ClickException, click.exceptions.Abort, SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:  # noqa: BLE001 — deliberate CLI boundary
            if os.environ.get("ANNATAR_DEBUG"):
                raise
            console.print(f"[red]✗ {type(e).__name__}: {e}[/red]")
            msg = str(e)
            if "AZURE_SUBSCRIPTION_ID" in msg or "credential" in msg.lower():
                console.print(
                    "[dim]  → environnement non chargé : `direnv allow` ou "
                    "`source .envrc` avant de relancer.[/dim]"
                )
            console.print("[dim]  (ANNATAR_DEBUG=1 pour la stack complète)[/dim]")
            ctx.exit(1)


@click.group(cls=_AnnatarCli)
@click.version_option()
def cli():
    """Annatar — simulate attacks, measure real RTO/RPO."""


@cli.command()
@click.argument("scenario")
@click.option(
    "--dry-run", is_flag=True, help="Show what would happen without executing."
)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option(
    "--skip-preflight",
    is_flag=True,
    help="Skip VM state checks (power + isolation).",
)
def run(scenario: str, dry_run: bool, yes: bool, skip_preflight: bool):
    """Run a chaos scenario (path or scenario name).

    SCENARIO can be a file path or the scenario name from 'annatar list'.

    Examples:
        annatar run azure-ransomware-vm
        annatar run annatar/scenarios/azure/ransomware-vm.yaml
    """
    import os
    from annatar.runner.engine import Engine
    from annatar.runner.parser import find_scenario_by_name

    path = scenario
    if not os.path.exists(path):
        resolved = find_scenario_by_name(scenario)
        if resolved:
            path = resolved
        else:
            console.print(
                f"[red]Scenario not found:[/red] '{scenario}'\n"
                "  Pass a file path or a scenario name from 'annatar list'."
            )
            raise SystemExit(1)

    engine = Engine(dry_run=dry_run, skip_preflight=skip_preflight)
    engine.run(path, skip_confirm=yes)


@cli.command(name="list")
def list_scenarios():
    """List available scenarios."""
    from annatar.runner.parser import list_available
    list_available()


@cli.command()
@click.argument("scenario", required=False)
@click.option(
    "--all", "validate_all", is_flag=True, help="Validate all available scenarios."
)
def validate(scenario: str | None, validate_all: bool):
    """Validate one scenario YAML or all available scenarios.

    Examples:
        annatar validate annatar/scenarios/azure/ransomware-vm.yaml
        annatar validate azure-ransomware-vm
        annatar validate --all
    """
    import glob
    import os
    from annatar.runner.parser import (
        ScenarioParser,
        scenarios_root,
        find_scenario_by_name,
    )

    parser = ScenarioParser()

    if validate_all or not scenario:
        root = scenarios_root()
        files = sorted(glob.glob(str(root / "**" / "*.yaml"), recursive=True))
        if not files:
            console.print("[yellow]No scenarios found.[/yellow]")
            return
        project_root = root.parent.parent
        failed = 0
        for f in files:
            result = parser.validate(f)
            rel = os.path.relpath(f, project_root)
            if result.valid:
                console.print(f"[green]OK[/green]   {rel}")
            else:
                failed += 1
                console.print(f"[red]FAIL[/red] {rel}")
                for err in result.errors:
                    console.print(f"     [dim]{err}[/dim]")
        summary = f"{len(files)} scenario(s)"
        if failed:
            console.print(f"\n[red]{failed} failed[/red] / {summary}")
        else:
            console.print(f"\n[green]All {summary} valid[/green]")
        return

    # Single scenario — resolve by name if needed
    path = scenario
    if not __import__("os").path.exists(path):
        resolved = find_scenario_by_name(scenario)
        if resolved:
            path = resolved
        else:
            console.print(f"[red]Not found:[/red] '{scenario}'")
            raise SystemExit(1)

    result = parser.validate(path)
    if result.valid:
        console.print(f"[green]OK[/green] {path} is valid")
    else:
        for err in result.errors:
            console.print(f"[red]FAIL[/red] {err}")


@cli.command()
@click.argument("run_id")
def report(run_id: str):
    """Display or export a run report."""
    from annatar.runner.report import RunReport
    RunReport.display(run_id)


@cli.command()
@click.option(
    "--yes", is_flag=True, help="Pass -auto-approve to terraform apply."
)
@click.argument("scenario", type=click.Path(exists=True), required=False)
def init(yes: bool, scenario: str | None):
    """Provision Azure test environment.

    Optionally pass a SCENARIO path to also prepare the VM disk in one step:

        annatar init --yes scenarios/azure/ransomware-vm.yaml
    """
    from annatar.runner.initializer import InitRunner
    InitRunner().run(auto_approve=yes, scenario_path=scenario)


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
def clean(scenario: str):
    """Reset the VM disk to a clean state before re-running a scenario.

    After this, run 'glorfindel snapshot <resource_id> --yes' to capture
    a clean recovery point.
    """
    from annatar.runner.initializer import InitRunner
    InitRunner().clean(scenario)


# ── Generative campaigns ─────────────────────────────────────────────────────
@cli.group()
def campaign():
    """Plan, run and inspect generative attack campaigns (kill-chains)."""


@campaign.command(name="plan")
@click.option("--target", required=True, help="Target resource_id (must be in the Celebrimbor sandbox).")
@click.option("--objective", default="", help="One-line campaign intent (steers the LLM planner).")
@click.option("--max-scenarios", default=5, show_default=True, help="Budget ceiling.")
@click.option("--allow-destructive", is_flag=True, help="Permit destructive (testdata-only) techniques.")
@click.option("--llm/--no-llm", "use_llm", default=False, help="Use the LLM planner (default: deterministic).")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_plan(target, objective, max_scenarios, allow_destructive, use_llm, runs_dir):
    """Plan a kill-chain and materialize its scenarios (state: planned)."""
    from annatar.campaign.catalog import load_catalog
    from annatar.campaign.manifest import (
        Budget,
        CampaignManifest,
        ScenarioEntry,
        Scope,
        campaign_dir,
        new_campaign_id,
    )
    from annatar.campaign.planner import plan_campaign
    from annatar.campaign.scope import Scope as GuardScope
    from annatar.campaign.scope import _rg_from_id
    from annatar.campaign.synthesizer import synthesize

    rg = _rg_from_id(target)
    sub = _subscription_from_id(target)
    guard = GuardScope(
        subscription_id=sub,
        allowed_resource_groups=[rg] if rg else [],
        allowed_resource_ids=[target],
    )
    res = guard.check(target, rg)
    if not res.allowed:
        console.print(f"[red]Target rejected:[/red] {res.reason}")
        raise SystemExit(1)

    catalog = load_catalog()
    plan = plan_campaign(objective=objective, max_scenarios=max_scenarios, use_llm=use_llm)

    cid = new_campaign_id()
    cdir = campaign_dir(cid, runs_dir=runs_dir)
    scen_dir = cdir / "scenarios"

    entries: list[ScenarioEntry] = []
    for i, tech in enumerate(plan.techniques, 1):
        entry = catalog.get(tech.ttp)
        if not entry:
            continue
        s = synthesize(
            entry=entry, target_resource_id=target, scope=guard,
            out_dir=scen_dir, seq=i, allow_destructive=allow_destructive,
        )
        if not s.ok:
            console.print(f"[yellow]skip {tech.ttp}: {s.reason}[/yellow]")
            continue
        entries.append(
            ScenarioEntry(
                seq=i, ttp=tech.ttp, tactic=tech.tactic, name=tech.name,
                scenario_file=f"scenarios/{s.path.name}",
                target_resource_id=target,
                destructive=bool(entry.get("destructive")),
                safe_target=entry.get("safe_target", "") or "",
            )
        )

    if not entries:
        console.print("[red]No scenario could be synthesized — nothing planned.[/red]")
        raise SystemExit(1)

    manifest = CampaignManifest(
        campaign_id=cid,
        objective=objective or plan.objective,
        scope=Scope(
            subscription_id=sub,
            allowed_resource_groups=[rg] if rg else [],
            allowed_resource_ids=[target],
        ),
        budget=Budget(max_scenarios=max_scenarios, allow_destructive=allow_destructive),
        scenarios=entries,
    )
    manifest.save(cdir)
    console.print(f"[green]Planned campaign {cid}[/green] — {len(entries)} scenario(s):")
    for e in entries:
        console.print(f"  [{e.seq}] {e.tactic:22} {e.ttp}  {e.scenario_file}")
    console.print(
        f"\n[dim]Review {cdir}/manifest.json, then:[/dim] "
        f"annatar campaign run {cid} --yes"
    )


@campaign.command(name="run")
@click.argument("campaign_id")
@click.option("--yes", is_flag=True, help="Ratify the budget/scope and execute.")
@click.option("--dry-run", is_flag=True, help="Preview the sequence without executing.")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_run(campaign_id, yes, dry_run, runs_dir):
    """Execute a planned campaign sequentially within its budget/scope."""
    from annatar.campaign.manifest import CampaignManifest, campaign_dir
    from annatar.campaign.runner import CampaignRunner

    cdir = campaign_dir(campaign_id, runs_dir=runs_dir)
    if not (cdir / "manifest.json").exists():
        console.print(f"[red]Campaign not found:[/red] {campaign_id}")
        raise SystemExit(1)

    m = CampaignManifest.load(cdir)
    if m.state == "planned":
        if not (yes or dry_run):
            console.print(
                "[yellow]Campaign is 'planned' — ratify budget/scope with --yes "
                "(or preview with --dry-run).[/yellow]"
            )
            raise SystemExit(1)
        if yes and not dry_run:
            m.set_state("ratified")
            m.save(cdir)

    result = CampaignRunner(cdir, dry_run=dry_run).run()
    if not dry_run:
        r = result.results
        console.print(
            f"\n[bold]Campaign {result.campaign_id} → {result.state}[/bold]  "
            f"executed={r['executed']} detected={r['detected']} "
            f"missed={r['missed']} skipped={r['skipped']} errors={r['errors']}"
        )


@campaign.command(name="list")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_list(runs_dir):
    """List campaigns and their state."""
    from annatar.campaign.manifest import CampaignManifest, campaigns_root

    root = campaigns_root(runs_dir)
    if not root.exists():
        console.print("[dim]No campaigns yet.[/dim]")
        return
    for d in sorted(root.iterdir()):
        if not (d / "manifest.json").exists():
            continue
        m = CampaignManifest.load(d)
        r = m.results
        console.print(
            f"{m.campaign_id}  [{m.state}]  {len(m.scenarios)} scenario(s)  "
            f"detected={r['detected']}/{r['executed']}"
        )


@campaign.command(name="show")
@click.argument("campaign_id")
@click.option("--runs-dir", default="runs", help="Where campaigns are stored.")
def campaign_show(campaign_id, runs_dir):
    """Show a campaign manifest summary."""
    from annatar.campaign.manifest import CampaignManifest, campaign_dir

    cdir = campaign_dir(campaign_id, runs_dir=runs_dir)
    if not (cdir / "manifest.json").exists():
        console.print(f"[red]Campaign not found:[/red] {campaign_id}")
        raise SystemExit(1)
    m = CampaignManifest.load(cdir)
    console.print(f"[bold]{m.campaign_id}[/bold]  state={m.state}  objective={m.objective!r}")
    console.print(f"scope: {m.scope.allowed_resource_ids}")
    for e in m.scenarios:
        det = e.detection or "-"
        console.print(
            f"  [{e.seq}] {e.ttp:12} {e.status:9} detection={det:9} "
            f"run_id={e.run_id or '-'}"
        )


def _subscription_from_id(resource_id: str) -> str:
    parts = resource_id.split("/")
    for i, p in enumerate(parts):
        if p.lower() == "subscriptions" and i + 1 < len(parts):
            return parts[i + 1]
    return ""
