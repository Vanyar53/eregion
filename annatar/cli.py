import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def cli():
    """Annatar — simulate attacks, measure real RTO/RPO."""


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Show what would happen without executing.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def run(scenario: str, dry_run: bool, yes: bool):
    """Run a chaos scenario."""
    from annatar.runner.engine import Engine
    engine = Engine(dry_run=dry_run)
    engine.run(scenario, skip_confirm=yes)


@cli.command(name="list")
def list_scenarios():
    """List available scenarios."""
    from annatar.runner.parser import list_available
    list_available()


@cli.command()
@click.argument("scenario", type=click.Path(exists=True))
def validate(scenario: str):
    """Validate a scenario YAML without running it."""
    from annatar.runner.parser import ScenarioParser
    parser = ScenarioParser()
    result = parser.validate(scenario)
    if result.valid:
        console.print(f"[green]OK[/green] {scenario} is valid")
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
