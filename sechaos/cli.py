import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def cli():
    """SecurityChaos — simulate attacks, measure real RTO/RPO."""


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Show what would happen without executing.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def run(scenario: str, dry_run: bool, yes: bool):
    """Run a chaos scenario."""
    from sechaos.runner.engine import Engine
    engine = Engine(dry_run=dry_run)
    engine.run(scenario, skip_confirm=yes)


@cli.command(name="list")
def list_scenarios():
    """List available scenarios."""
    from sechaos.runner.parser import list_available
    list_available()


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
def validate(scenario: str):
    """Validate a scenario YAML without running it."""
    from sechaos.runner.parser import ScenarioParser
    parser = ScenarioParser()
    result = parser.validate(scenario)
    if result.valid:
        console.print(f"[green]✓[/green] {scenario} is valid")
    else:
        for err in result.errors:
            console.print(f"[red]✗[/red] {err}")


@cli.command()
@click.argument("run_id")
def report(run_id: str):
    """Display or export a run report."""
    from sechaos.runner.report import Report
    Report.display(run_id)


@cli.command()
def init():
    """Initialize Azure test environment via Terraform."""
    console.print("[yellow]→[/yellow] Initializing Azure test environment...")
    console.print("  Run: cd infra/terraform && terraform init && terraform apply")
