from __future__ import annotations

import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
def cli():
    """Glorfindel — detect, respond, restore."""


@cli.command()
@click.argument("signals_file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Reason and decide without executing actions.")
@click.option("--model", default="claude-sonnet-4-6", show_default=True)
@click.option("--memory-path", default=None, help="Override default ChromaDB path.")
def respond(signals_file: str, dry_run: bool, model: str, memory_path: str | None):
    """Process all signals in a JSONL file and respond to each."""
    from glorfindel.agent import GlorfindelAgent
    from glorfindel.signals import load_signals

    signals = load_signals(signals_file)
    if not signals:
        console.print("[yellow]No signals found in file.[/yellow]")
        return

    agent = GlorfindelAgent(dry_run=dry_run, model=model, memory_path=memory_path)

    for sig in signals:
        console.rule(f"[bold cyan]Signal — {sig.signal_id}[/bold cyan]")
        console.print(f"  TTP      : {sig.ttp}  |  Severity: [red]{sig.severity}[/red]")
        console.print(f"  Event    : {sig.event}  |  Resource: {sig.resource_type}")
        console.print(f"  Provider : {sig.provider}\n")

        state = agent.respond(sig.__dict__ if hasattr(sig, '__dict__') else dict(sig))

        _render_decision(state, dry_run)
        console.print()


@cli.command()
@click.argument("resource_id")
@click.option("--dry-run", is_flag=True, help="Show what would be done without executing.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def release(resource_id: str, dry_run: bool, yes: bool):
    """Release an isolation applied by Glorfindel on a VM."""
    from glorfindel.actions import AzureConnector

    connector = AzureConnector(dry_run=dry_run)

    console.rule("[bold yellow]Glorfindel — Release Isolation[/bold yellow]")
    console.print(f"  Resource : {resource_id}")
    console.print(f"  Dry-run  : {dry_run}\n")

    if not dry_run:
        verification = connector.verify_isolation(resource_id)
        if not verification.get("verified"):
            console.print("[yellow]No active isolation found on this resource — nothing to release.[/yellow]")
            return

    if not dry_run and not yes:
        if not click.confirm("Release isolation on this VM?", default=False):
            console.print("Aborted.")
            return

    result = connector.release_isolation(resource_id)

    if dry_run:
        console.print("[yellow]DRY RUN — no changes made.[/yellow]")
    else:
        console.print(f"[green]✓ Isolation released.[/green]  ({result})")


@cli.command()
@click.option("--memory-path", default=None)
def memory_stats(memory_path: str | None):
    """Show how many cycles are stored in memory."""
    from glorfindel.memory import CycleMemory
    m = CycleMemory(path=memory_path)
    console.print(f"Cycles in memory: [cyan]{m.count()}[/cyan]")


def _render_decision(state: dict, dry_run: bool) -> None:
    action = state.get("action", "?")
    escalated = state.get("escalate", False)
    confidence = state.get("confidence", 0.0)
    outcome = state.get("outcome") or {}

    verified = outcome.get("verified")
    status_color = "yellow" if escalated else "green"
    status_label = "ESCALATED — awaiting human approval" if escalated else (
        "DRY RUN" if dry_run else "EXECUTED"
    )

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="dim", width=18)
    table.add_column()
    table.add_row("Decision", f"[bold]{action}[/bold]")
    table.add_row("Confidence", f"{confidence:.0%}")
    table.add_row("Status", f"[{status_color}]{status_label}[/{status_color}]")
    if verified is not None and not escalated:
        verified_label = "[green]✓ action confirmed[/green]" if verified else "[red]✗ action failed — check manually[/red]"
        table.add_row("Verification", verified_label)
    table.add_row("Explanation", state.get("explanation", ""))
    if escalated:
        table.add_row("Escalation reason", state.get("escalation_reason", ""))
    console.print(table)

    console.print(Panel(
        state.get("reasoning", ""),
        title="[dim]Reasoning[/dim]",
        border_style="dim",
        padding=(0, 1),
    ))
