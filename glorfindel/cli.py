from __future__ import annotations

import json
import time
from pathlib import Path

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
@click.argument("runs_dir", type=click.Path(exists=True), default="runs")
@click.option("--dry-run", is_flag=True)
@click.option("--model", default="claude-sonnet-4-6", show_default=True)
@click.option("--memory-path", default=None)
@click.option("--interval", default=2, show_default=True, help="Poll interval in seconds.")
def watch(runs_dir: str, dry_run: bool, model: str, memory_path: str | None, interval: int):
    """Watch a runs/ directory and respond to signals as they arrive.

    Start this before (or during) an Annatar run to get real-time responses.
    Existing signal files are tracked from their current end — only new signals
    are processed.
    """
    from annatar.signals.schema import Signal
    from glorfindel.agent import GlorfindelAgent

    agent = GlorfindelAgent(dry_run=dry_run, model=model, memory_path=memory_path)

    # path → byte offset of last read position
    tracked: dict[Path, int] = {}

    # Files that existed at startup — skip their past content
    existing_at_start = {p for p in Path(runs_dir).glob("*_signals.jsonl")}
    for path in existing_at_start:
        tracked[path] = path.stat().st_size
        console.print(f"[dim]Skipping existing {path.name}[/dim]")

    def _poll() -> None:
        for path in sorted(Path(runs_dir).glob("*_signals.jsonl")):
            if path not in tracked:
                tracked[path] = 0  # new file — read from beginning
                console.print(f"[dim]New run: {path.name}[/dim]")

        for path in list(tracked):
            with open(path) as f:
                f.seek(tracked[path])
                for raw in f:
                    raw = raw.strip()
                    if not raw:
                        continue
                    data = json.loads(raw)
                    sig = Signal(**data)
                    console.rule(f"[bold cyan]Signal — {sig.signal_id}[/bold cyan]")
                    console.print(f"  TTP      : {sig.ttp}  |  Severity: [red]{sig.severity}[/red]")
                    console.print(f"  Event    : {sig.event}  |  Resource: {sig.resource_type}\n")
                    state = agent.respond(data)
                    _render_decision(state, dry_run)
                    console.print()
                tracked[path] = f.tell()

    console.print(f"[bold]Glorfindel watching[/bold] [dim]{runs_dir}/[/dim]  (Ctrl+C to stop)\n")
    try:
        while True:
            _poll()
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Watch stopped.[/dim]")


@cli.command()
@click.argument("resource_id")
@click.option("--vault", default="rsv-annatar", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--keep-isolated", is_flag=True, envvar="GLORFINDEL_KEEP_ISOLATED",
              help="Skip recovery_complete signal — VM stays isolated after restore. "
                   "Also honoured via GLORFINDEL_KEEP_ISOLATED=1.")
@click.option("--model", default="claude-sonnet-4-6", show_default=True)
@click.option("--memory-path", default=None)
def restore(resource_id: str, vault: str, dry_run: bool, yes: bool, keep_isolated: bool, model: str, memory_path: str | None):
    """Trigger an Azure Backup restore on a VM (human approval action).

    Run this after Glorfindel escalates a restore_from_backup recommendation.
    After a successful restore, emits a recovery_complete signal and lets
    Glorfindel decide the next action (release_isolation), unless --keep-isolated.
    """
    from glorfindel.actions import AzureConnector

    connector = AzureConnector(dry_run=dry_run)

    console.rule("[bold yellow]Glorfindel — Restore from Backup[/bold yellow]")
    console.print(f"  Resource : {resource_id}")
    console.print(f"  Vault    : {vault}")
    console.print(f"  Dry-run  : {dry_run}\n")

    if not dry_run and not yes:
        if not click.confirm("Trigger Azure Backup restore on this VM?", default=False):
            console.print("Aborted.")
            return

    import time as _time
    console.print("[cyan]->[/cyan] Triggering restore...")
    t0 = _time.time()
    result = connector.restore_from_backup(resource_id, vault=vault)
    rto_s = round(_time.time() - t0)

    if dry_run:
        console.print("[yellow]DRY RUN — no changes made.[/yellow]")
        return

    restore_label = f"{rto_s // 60}min {rto_s % 60}s"
    console.print(f"[green]✓ Restore complete.[/green]  restore_time: {restore_label}  RP: {result.get('recovery_point_time')}")
    console.print(f"[dim]RTO = detection_s + isolation_s + restore_time  (human decision time excluded)[/dim]\n")

    if keep_isolated:
        console.print("[yellow]--keep-isolated: VM stays isolated. Run 'glorfindel release' when ready.[/yellow]")
        return

    # Emit recovery_complete and let Glorfindel decide (release_isolation)
    sig = _build_recovery_signal(resource_id, result, rto_s)
    _write_signal(sig)
    console.rule("[bold cyan]Glorfindel — Recovery Response[/bold cyan]")
    console.print(f"  Event    : recovery_complete  |  Resource: {resource_id}\n")

    from glorfindel.agent import GlorfindelAgent
    agent = GlorfindelAgent(dry_run=dry_run, model=model, memory_path=memory_path)
    state = agent.respond(sig)
    _render_decision(state, dry_run)


@cli.command()
@click.option("--memory-path", default=None)
def memory_stats(memory_path: str | None):
    """Show how many cycles are stored in memory."""
    from glorfindel.memory import CycleMemory
    m = CycleMemory(path=memory_path)
    console.print(f"Cycles in memory: [cyan]{m.count()}[/cyan]")


def _build_recovery_signal(resource_id: str, restore_result: dict, restore_time_s: int) -> dict:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc)
    run_id = ts.strftime("%Y%m%dT%H%M%SZ")
    return {
        "signal_id": f"{run_id}_recovery_complete",
        "timestamp": ts.isoformat(),
        "provider": "azure",
        "resource_id": resource_id,
        "resource_type": "vm",
        "ttp": "",
        "severity": "low",
        "event": "recovery_complete",
        "raw_signal": {
            "recovery_point_time": restore_result.get("recovery_point_time", ""),
            "restore_time_s": restore_time_s,
        },
        "context": {"run_id": run_id},
    }


def _write_signal(signal: dict, runs_dir: str = "runs") -> Path:
    from pathlib import Path
    out = Path(runs_dir) / f"{signal['context']['run_id']}_signals.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "a") as f:
        f.write(json.dumps(signal) + "\n")
    return out


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
    if "action_s" in outcome and not escalated and not dry_run:
        detection_s = state.get("signal", {}).get("raw_signal", {}).get("detection_time_s")
        action_s = outcome["action_s"]
        timing = f"{action_s}s"
        if detection_s:
            timing = f"detect {detection_s}s + {action} {action_s}s"
        table.add_row("Timing", f"[dim]{timing}[/dim]")
    if "verified" in outcome and not escalated:
        if verified is True:
            verified_label = "[green]✓ action confirmed[/green]"
        elif verified is False:
            verified_label = "[red]✗ action failed — check manually[/red]"
        else:
            verified_label = "[yellow]⚠ verification not implemented[/yellow]"
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
