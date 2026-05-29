import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def cli():
    """Annatar — simulate attacks, measure real RTO/RPO."""


@cli.command()
@click.argument("scenario")
@click.option("--dry-run", is_flag=True, help="Show what would happen without executing.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--skip-preflight", is_flag=True, help="Skip VM state checks (power + isolation).")
def run(scenario: str, dry_run: bool, yes: bool, skip_preflight: bool):
    """Run a chaos scenario (path or scenario name).

    SCENARIO can be a file path or the scenario name as shown by 'annatar list'.

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
@click.option("--all", "validate_all", is_flag=True, help="Validate all available scenarios.")
def validate(scenario: str | None, validate_all: bool):
    """Validate one scenario YAML or all available scenarios.

    Examples:
        annatar validate annatar/scenarios/azure/ransomware-vm.yaml
        annatar validate azure-ransomware-vm
        annatar validate --all
    """
    import glob
    import os
    from annatar.runner.parser import ScenarioParser, scenarios_root, find_scenario_by_name

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
@click.option("--yes", is_flag=True, help="Pass -auto-approve to terraform apply.")
@click.argument("scenario", type=click.Path(exists=True), required=False)
def init(yes: bool, scenario: str | None):
    """Provision Azure test environment.

    Optionally pass a SCENARIO path to also prepare the VM and create the
    first clean backup in one step:

        annatar init --yes scenarios/azure/ransomware-vm.yaml
    """
    from annatar.runner.initializer import InitRunner
    InitRunner().run(auto_approve=yes, scenario_path=scenario)


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
def snapshot(scenario: str):
    """Clean the VM disk and take a fresh backup — use before re-running a scenario."""
    from annatar.runner.initializer import InitRunner
    InitRunner().snapshot(scenario)
