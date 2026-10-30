import os

import click
from rich.console import Console

console = Console()


class _GothmogCli(click.Group):
    """Operational failures as a clean one-liner, not a traceback (mirrors Annatar's).
    GOTHMOG_DEBUG=1 restores the full traceback."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (click.ClickException, click.exceptions.Abort, click.exceptions.Exit,
                SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:  # noqa: BLE001 — deliberate CLI boundary
            if os.environ.get("GOTHMOG_DEBUG"):
                raise
            console.print(f"[red]✗ {type(e).__name__}: {e}[/red]")
            console.print("[dim]  (GOTHMOG_DEBUG=1 pour la stack complète)[/dim]")
            ctx.exit(1)


@click.group(cls=_GothmogCli)
def cli():
    """Gothmog — declared faults on the bench, run from an armed Orodruin."""


_WITHOUT_HELP = ("Development run: no live Glorfindel watch required. The report says "
                 "Glorfindel's reaction was not measured, by choice.")


@cli.command()
@click.argument("fault")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@click.option("--dry-run", is_flag=True, help="Show the declared fault; read and write nothing on Azure.")
@click.option("--without-glorfindel", is_flag=True, help=_WITHOUT_HELP)
@click.option("--request", default="", help="A wire of a Dagorlad request (its id): written in the window.")
@click.option("--target", default="", help="With --request: the VM of the wire, one the fault declares.")
def run(fault: str, yes: bool, dry_run: bool, without_glorfindel: bool, request: str, target: str):
    """Run a fault (a path, or a name in gothmog/experiments/).

        gothmog run vm-shutdown --yes
    """
    if request:
        from eregion_core.exercise_request import valid_id
        if not valid_id(request) or without_glorfindel:
            raise click.UsageError("--request takes a request id (r-…), never with --without-glorfindel")
    from gothmog.runner.engine import Engine, load_fault

    if dry_run:
        doc = load_fault(fault)
        console.print("[yellow]DRY RUN — nothing read or written on Azure[/yellow]\n")
        console.print(f"  Fault   : {doc['name']} ({doc.get('id')})")
        console.print(f"  Engine  : {doc['engine']} / {doc['engine_ref']}")
        console.print(f"  Targets : {', '.join(doc['targets']['names'])}")
        for p in doc["steady_state"]["probes"]:
            console.print(f"  Probe   : {p['name']} — expect {p['expect']}")
        for r in doc.get("revert") or []:
            console.print(f"  Revert  : {r['name']}")
        return
    wire = {"request": request, "target": target} if request else {}
    outcome = Engine().run(fault, skip_confirm=yes, without_glorfindel=without_glorfindel, **wire)
    raise SystemExit(0 if outcome.result == "PASS" else 1)


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="As JSON: {fault id: [VM names]}.")
def targets(as_json: bool):
    """The VMs each declared fault's experiment aims at — read from gothmog/experiments/, without
    Orodruin nor Azure (Dagorlad's no_engine)."""
    import json

    from gothmog.runner.engine import declared_targets

    found = declared_targets()
    if as_json:
        click.echo(json.dumps(found))
        return
    for fid, names in found.items():
        console.print(f"  {fid}: {', '.join(names)}")


@cli.command()
@click.argument("fault")
@click.option("--without-glorfindel", is_flag=True, help=_WITHOUT_HELP)
def preflight(fault: str, without_glorfindel: bool):
    """Glorfindel's watch, the contract, targets and steady state, from where the run would
    start — nothing written."""
    from gothmog.runner.engine import Engine

    outcome = Engine().preflight(fault, without_glorfindel=without_glorfindel)
    raise SystemExit(0 if outcome.result == "OK" else 1)


@cli.command()
@click.argument("run_id")
def report(run_id: str):
    """Show a run's report (runs/<run_id>.json)."""
    from gothmog.runner.report import RunReport

    raise SystemExit(0 if RunReport.display(run_id) else 1)
