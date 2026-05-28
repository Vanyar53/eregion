from __future__ import annotations

import json
import os
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="glorfindel")
def cli():
    """Glorfindel — detect, respond, restore."""


@cli.command()
@click.argument("signals_file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True, help="Reason and decide without executing actions.")
@click.option("--model", default=lambda: os.environ.get("GLORFINDEL_LLM_MODEL", "anthropic/claude-sonnet-4-6"), show_default=True)
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
@click.argument("ip")
@click.argument("resource_id")
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
def unblock(ip: str, resource_id: str, dry_run: bool, yes: bool):
    """Remove a block rule created by Glorfindel for a suspicious IP."""
    from glorfindel.actions import AzureConnector

    connector = AzureConnector(dry_run=dry_run)

    console.rule("[bold yellow]Glorfindel — Unblock IP[/bold yellow]")
    console.print(f"  IP       : {ip}")
    console.print(f"  Resource : {resource_id}")
    console.print(f"  Dry-run  : {dry_run}\n")

    if not dry_run and not yes:
        if not click.confirm(f"Remove block rules for {ip}?", default=False):
            console.print("Aborted.")
            return

    result = connector.unblock_ip(ip, resource_id)

    if dry_run:
        console.print("[yellow]DRY RUN — no changes made.[/yellow]")
    elif result["status"] == "not_found":
        console.print(f"[yellow]No block rules found for {ip} — already removed?[/yellow]")
    else:
        console.print(f"[green]✓ Unblocked {ip}.[/green]  Deleted: {result['deleted_rules']}")


@cli.command()
@click.argument("runs_dir", type=click.Path(exists=True), default="runs")
@click.option("--dry-run", is_flag=True)
@click.option("--model", default=lambda: os.environ.get("GLORFINDEL_LLM_MODEL", "anthropic/claude-sonnet-4-6"), show_default=True)
@click.option("--memory-path", default=None)
@click.option("--interval", default=2, show_default=True, help="Poll interval in seconds.")
def watch(runs_dir: str, dry_run: bool, model: str, memory_path: str | None, interval: int):
    """Watch a runs/ directory and respond to signals as they arrive.

    Start this before (or during) an Annatar run to get real-time responses.
    Existing signal files are tracked from their current end — only new signals
    are processed.

    Signals from different resource_ids are processed in parallel.
    Signals from the same resource_id are serialized (queue per resource).
    """
    import queue as _queue
    import threading as _threading

    from annatar.signals.schema import Signal
    from glorfindel.agent import GlorfindelAgent

    agent = GlorfindelAgent(dry_run=dry_run, model=model, memory_path=memory_path)

    # path → byte offset of last read position
    tracked: dict[Path, int] = {}

    # per-resource dispatch: resource_id → Queue
    _resource_queues: dict[str, _queue.Queue] = {}
    _output_lock = _threading.Lock()

    def _get_or_start_worker(resource_id: str) -> _queue.Queue:
        """Return the resource queue, starting its worker thread if needed."""
        if resource_id not in _resource_queues:
            q: _queue.Queue = _queue.Queue()
            _resource_queues[resource_id] = q

            def _worker(q=q):
                while True:
                    item = q.get()
                    if item is None:
                        break
                    _data, _sig = item
                    try:
                        with _output_lock:
                            console.rule(f"[bold cyan]Signal — {_sig.signal_id}[/bold cyan]")
                            console.print(
                                f"  TTP      : {_sig.ttp}  |  "
                                f"Severity: [red]{_sig.severity}[/red]"
                            )
                            console.print(
                                f"  Event    : {_sig.event}  |  "
                                f"Resource: {_sig.resource_type}\n"
                            )
                        state = agent.respond(_data)
                        with _output_lock:
                            _render_decision(state, dry_run)
                            console.print()
                    except Exception as e:
                        with _output_lock:
                            console.print(
                                f"[red]Error processing {_sig.signal_id}:[/red] {e}"
                            )
                    finally:
                        q.task_done()

            vm_short = resource_id.split("/")[-1]
            t = _threading.Thread(
                target=_worker, daemon=True, name=f"glorf-{vm_short}"
            )
            t.start()
        return _resource_queues[resource_id]

    def _dispatch(data: dict, sig: Signal) -> None:
        """Route signal to its resource worker queue.

        attack_started: spawns a poll thread immediately — polling runs in parallel
        per resource, not serialized in the queue. When polling resolves, the
        resulting detection/timeout signal is enqueued for decide+execute.

        All other events go directly to the resource queue (serialized per resource).
        """
        from glorfindel.agent import resolve_attack_started

        resource_id = data.get("resource_id", "unknown")

        if data.get("event") == "attack_started":
            def _poll_and_enqueue():
                src = data.get("raw_signal", {}).get("detection_source", "azure_monitor")
                with _output_lock:
                    console.rule(f"[bold cyan]Signal — {sig.signal_id}[/bold cyan]")
                    console.print(
                        f"  TTP      : {sig.ttp}  |  Severity: [red]{sig.severity}[/red]"
                    )
                    console.print(f"  Event    : attack_started → polling {src}...\n")
                resolved = resolve_attack_started(data)
                resolved_sig = Signal(**{k: resolved.get(k, getattr(sig, k, ""))
                                         for k in sig.__dataclass_fields__})
                _get_or_start_worker(resource_id).put((resolved, resolved_sig))

            vm_short = resource_id.split("/")[-1]
            t = _threading.Thread(
                target=_poll_and_enqueue, daemon=True,
                name=f"poll-{vm_short}-{sig.signal_id[-6:]}",
            )
            t.start()
            return

        _get_or_start_worker(resource_id).put((data, sig))

    # Files that existed at startup — skip their past content
    existing_at_start = {p for p in Path(runs_dir).glob("*_signals.jsonl")}
    for path in existing_at_start:
        tracked[path] = path.stat().st_size

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
                    _dispatch(data, sig)   # non-blocking — worker thread takes over
                tracked[path] = f.tell()

    import os
    from datetime import datetime, timezone
    from glorfindel.actions import AzureConnector, active_isolations

    ttl_h = float(os.environ.get("GLORFINDEL_ISOLATION_TTL_H") or "4")
    ttl_connector = AzureConnector(dry_run=dry_run)
    _ttl_check_counter = 0

    def _check_ttl() -> None:
        now = datetime.now(timezone.utc)
        for iso in active_isolations():
            isolated_at_s = iso.get("isolated_at")
            resource_id = iso.get("resource_id", "")
            if not isolated_at_s or not resource_id:
                continue
            age_h = (now - datetime.fromisoformat(isolated_at_s)).total_seconds() / 3600
            if age_h >= ttl_h:
                vm_short = resource_id.split("/")[-1]
                console.print(
                    f"[yellow]⚠ TTL exceeded[/yellow] — {vm_short} isolated {age_h:.1f}h "
                    f"(limit {ttl_h}h). {'DRY RUN' if dry_run else 'Auto-releasing...'}"
                )
                if not dry_run:
                    ttl_connector.release_isolation(resource_id)
                    from glorfindel import escalations as _esc
                    _esc.record(
                        signal_id="ttl-auto-release",
                        resource_id=resource_id,
                        action="release_isolation",
                        escalation_type="ttl_exceeded",
                        reason=f"Isolation TTL exceeded ({age_h:.1f}h > {ttl_h}h) — auto-released by watch",
                    )
                    console.print("  [green]✓ Released.[/green]")

    _HEARTBEAT = Path.home() / ".glorfindel" / "watch_heartbeat"

    def _write_heartbeat() -> None:
        _HEARTBEAT.parent.mkdir(parents=True, exist_ok=True)
        _HEARTBEAT.write_text(datetime.now(timezone.utc).isoformat())

    console.print(f"[bold]Glorfindel watching[/bold] [dim]{runs_dir}/[/dim]  "
                  f"(TTL={ttl_h}h, Ctrl+C to stop)\n")
    _write_heartbeat()
    try:
        while True:
            _poll()
            _ttl_check_counter += 1
            if _ttl_check_counter % 30 == 0:  # check TTL every 30 polls (~1 min at 2s interval)
                _check_ttl()
                _write_heartbeat()
            time.sleep(interval)
    except KeyboardInterrupt:
        _HEARTBEAT.unlink(missing_ok=True)
        console.print("\n[dim]Watch stopped.[/dim]")


@cli.command()
@click.argument("resource_id")
@click.option("--vault", default="rsv-annatar", show_default=True)
@click.option("--dry-run", is_flag=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.option("--keep-isolated", is_flag=True, envvar="GLORFINDEL_KEEP_ISOLATED",
              help="Skip recovery_complete signal — VM stays isolated after restore. "
                   "Also honoured via GLORFINDEL_KEEP_ISOLATED=1.")
@click.option("--before", default=None, metavar="ISO8601",
              help="Select recovery point before this timestamp (ISO8601). "
                   "Prevents restoring a backup taken after the attack. "
                   "Example: 2026-05-24T13:44:00+00:00")
@click.option("--model", default=lambda: os.environ.get("GLORFINDEL_LLM_MODEL", "anthropic/claude-sonnet-4-6"), show_default=True)
@click.option("--memory-path", default=None)
def restore(resource_id: str, vault: str, dry_run: bool, yes: bool, keep_isolated: bool, before: str | None, model: str, memory_path: str | None):
    """Trigger an Azure Backup restore on a VM (human approval action).

    Run this after Glorfindel escalates a restore_from_backup recommendation.
    After a successful restore, emits a recovery_complete signal and lets
    Glorfindel decide the next action (release_isolation), unless --keep-isolated.

    Use --before <ISO8601> to ensure the recovery point predates the attack.
    Without it, Azure may restore a post-attack backup that still contains artifacts.
    """
    from glorfindel.actions import AzureConnector

    connector = AzureConnector(dry_run=dry_run)

    console.rule("[bold yellow]Glorfindel — Restore from Backup[/bold yellow]")
    console.print(f"  Resource : {resource_id}")
    console.print(f"  Vault    : {vault}")
    if before:
        console.print(f"  Before   : {before}")
    console.print(f"  Dry-run  : {dry_run}\n")

    if not dry_run and not yes:
        if not click.confirm("Trigger Azure Backup restore on this VM?", default=False):
            console.print("Aborted.")
            return

    if not before and not dry_run:
        before = _find_last_attack_time()
        if before:
            console.print(f"  [dim]Auto-detected attack time: {before} (from last attack_started signal)[/dim]")
        else:
            console.print("  [yellow]Warning: --before not set and no attack_started signal found in runs/. "
                          "May restore a post-attack backup.[/yellow]")

    import time as _time
    console.print("[cyan]->[/cyan] Triggering restore...")
    t0 = _time.time()
    result = connector.restore_from_backup(resource_id, vault=vault, before_attack_time=before)
    rto_s = round(_time.time() - t0)

    if dry_run:
        console.print("[yellow]DRY RUN — no changes made.[/yellow]")
        return

    restore_label = f"{rto_s // 60}min {rto_s % 60}s"
    console.print(f"[green]✓ Restore complete.[/green]  restore_time: {restore_label}  RP: {result.get('recovery_point_time')}")
    console.print("[dim]RTO = detection_s + isolation_s + restore_time  (human decision time excluded)[/dim]\n")

    from glorfindel import escalations as _esc
    resolved = _esc.resolve_by_resource(resource_id, "restore_from_backup")
    if resolved:
        console.print(f"[dim]✓ {resolved} pending escalation(s) resolved.[/dim]\n")

    if keep_isolated:
        console.print("[yellow]--keep-isolated: VM stays isolated. Run 'glorfindel release' when ready.[/yellow]")
        return

    # Emit recovery_complete and let Glorfindel decide (release_isolation)
    sig = _build_recovery_signal(resource_id, result, rto_s)
    out = _write_signal(sig)
    console.rule("[bold cyan]Glorfindel — Recovery Response[/bold cyan]")
    console.print(f"  Event    : recovery_complete  |  Resource: {resource_id}\n")

    try:
        from glorfindel.agent import GlorfindelAgent
        agent = GlorfindelAgent(dry_run=dry_run, model=model, memory_path=memory_path)
        state = agent.respond(sig)
        _render_decision(state, dry_run)
    except Exception as e:
        console.print(f"[red]Glorfindel agent error:[/red] {e}")
        console.print(
            f"[yellow]Signal saved to {out.name} — process manually:[/yellow]\n"
            f"  glorfindel respond {out}"
        )


def _render_escalation(e: dict) -> None:
    from datetime import datetime, timezone
    from rich.table import Table

    now = datetime.now(timezone.utc)
    ts = datetime.fromisoformat(e["timestamp"])
    age_m = int((now - ts).total_seconds() // 60)
    resource_short = e["resource_id"].split("/")[-1]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column(style="dim", width=18)
    table.add_column()
    table.add_row("ID", f"[dim]{e['id']}[/dim]")
    table.add_row("Time", f"{ts.strftime('%H:%M')} ({age_m}m ago)")
    table.add_row("Action", f"[bold yellow]{e['action']}[/bold yellow]")
    table.add_row("Resource", resource_short)
    table.add_row("Type", e["escalation_type"])
    table.add_row("Reason", e["reason"][:120] + ("…" if len(e["reason"]) > 120 else ""))
    table.add_row("Run", e["run_id"])
    console.print(table)

    _render_next_steps(e)
    console.print(f"  [dim]glorfindel ack {e['id']}[/dim]\n")



def _render_next_steps(e: dict) -> None:
    rid = e["resource_id"]
    action = e["action"]
    esc_type = e["escalation_type"]

    llm_steps = e.get("suggested_steps") or []
    if llm_steps:
        console.print("  [bold cyan]Next steps (Glorfindel):[/bold cyan]")
        for i, step in enumerate(llm_steps, 1):
            console.print(f"  [cyan]{i}.[/cyan] {step}")
        return

    # Fallback statique pour les escalades sans suggested_steps (anciennes ou dry-run)
    if esc_type == "low_confidence" and action == "snapshot":
        steps = [
            f"Check VM state: az vm show -g <rg> -n {rid.split('/')[-1]} --query powerState",
            f"If compromise confirmed: glorfindel restore {rid} --yes",
            f"If false positive: glorfindel ack {e['id']}",
        ]
    elif action == "restore_from_backup":
        steps = [
            f"glorfindel restore {rid} --yes",
            "Glorfindel releases isolation automatically after restore (~20 min)",
        ]
    elif action == "release_isolation":
        steps = [f"glorfindel release {rid} --yes"]
    elif esc_type == "proposed_action":
        steps = [
            f"Review proposed action: {action}",
            "If approved: implement manually, then glorfindel ack",
        ]
    elif esc_type == "destructive_action":
        steps = [
            f"glorfindel {action.replace('_', '-')} {rid} --yes",
            "Requires explicit human approval — review before executing",
        ]
    else:
        steps = [f"Review and act manually on: {action}"]

    console.print("  [bold cyan]Next steps:[/bold cyan]")
    for i, step in enumerate(steps, 1):
        console.print(f"  [cyan]{i}.[/cyan] {step}")


@cli.command()
@click.option("--watch", is_flag=True, help="Stay running and print new escalations as they arrive.")
def pending(watch: bool):
    """Show pending escalations waiting for human action.

    With --watch: stays running and prints new escalations in real-time.
    Use this in a dedicated terminal during an Annatar run.
    """
    import time
    from glorfindel import escalations

    items = escalations.pending()

    if not watch:
        if not items:
            console.print("[green]No pending escalations.[/green]")
            return
        console.rule(f"[bold yellow]Glorfindel — {len(items)} pending escalation(s)[/bold yellow]")
        for e in items:
            _render_escalation(e)
        return

    # Watch mode — poll every 2s, print new escalations as they arrive
    seen_ids = {e["id"] for e in items}
    if items:
        console.rule(f"[bold yellow]Glorfindel — {len(items)} existing escalation(s)[/bold yellow]")
        for e in items:
            _render_escalation(e)

    console.print("[dim]Watching for escalations... (Ctrl+C to stop)[/dim]")
    try:
        while True:
            time.sleep(2)
            for e in escalations.pending():
                if e["id"] not in seen_ids:
                    seen_ids.add(e["id"])
                    console.rule("[bold red]NEW ESCALATION[/bold red]")
                    _render_escalation(e)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@cli.command()
@click.argument("escalation_id", required=False)
@click.option("--all", "all_pending", is_flag=True, help="Acknowledge all pending escalations.")
def ack(escalation_id: str | None, all_pending: bool):
    """Acknowledge (resolve) a pending escalation.

    Use 'glorfindel pending' to list escalation IDs.
    Use --all to acknowledge everything at once.
    """
    from glorfindel import escalations

    if all_pending:
        items = escalations.pending()
        for e in items:
            escalations.resolve(e["id"])
        console.print(f"[green]✓ {len(items)} escalation(s) acknowledged.[/green]")
        return

    if not escalation_id:
        console.print("[red]Provide an escalation ID or use --all.[/red]")
        return

    escalations.resolve(escalation_id)
    console.print(f"[green]✓ Escalation {escalation_id} acknowledged.[/green]")


@cli.command("list")
def list_active():
    """List all VMs with active Glorfindel actions (isolation, blocked IPs)."""
    from datetime import datetime, timezone
    from glorfindel.actions import active_blocks, active_isolations

    now = datetime.now(timezone.utc)

    def _age(ts: str) -> str:
        if not ts:
            return ""
        age_m = int((now - datetime.fromisoformat(ts)).total_seconds() // 60)
        return f"{ts[:19].replace('T', ' ')} UTC ({age_m}m ago)"

    isolations = {i["resource_id"]: i for i in active_isolations()}
    blocks: dict[str, list] = {}
    for b in active_blocks():
        blocks.setdefault(b["resource_id"], []).append(b)

    all_ids = sorted(set(isolations) | set(blocks))
    if not all_ids:
        console.print("[green]No active actions — all VMs clean.[/green]")
        return

    console.rule(f"[bold yellow]Glorfindel — {len(all_ids)} VM(s) with active actions[/bold yellow]")
    for resource_id in all_ids:
        vm_short = resource_id.split("/")[-1]
        console.print(f"[bold]{vm_short}[/bold]")

        if resource_id in isolations:
            ts = isolations[resource_id].get("isolated_at", "")
            console.print(f"  [red]ISOLATED[/red]  {_age(ts)}")
            console.print(f"  [dim]→ glorfindel release {resource_id} --yes[/dim]",
                          soft_wrap=True)

        for b in blocks.get(resource_id, []):
            ts = b.get("blocked_at", "")
            console.print(f"  [yellow]BLOCKED[/yellow]   {b['ip']}  {_age(ts)}")
            console.print(f"  [dim]→ glorfindel unblock {b['ip']} {resource_id} --yes[/dim]",
                          soft_wrap=True)

        console.print(f"  [dim]→ glorfindel revert {resource_id} --yes  (all at once)[/dim]\n",
                      soft_wrap=True)


@cli.command()
@click.argument("resource_id")
@click.option("--yes", is_flag=True, help="Confirm revert (skip prompt)")
@click.option("--dry-run", is_flag=True)
def revert(resource_id: str, yes: bool, dry_run: bool):
    """Release isolation and unblock all IPs on a VM in one command.

    Useful between runs — resets the VM to a clean NSG state without having
    to run isolated/blocked separately.
    """
    from glorfindel.actions import active_blocks, active_isolations, AzureConnector

    isolations = [i for i in active_isolations() if i.get("resource_id") == resource_id]
    blocks = [b for b in active_blocks() if b.get("resource_id") == resource_id]

    if not isolations and not blocks:
        console.print(f"[green]Nothing to revert on {resource_id.split('/')[-1]}.[/green]")
        return

    vm_short = resource_id.split("/")[-1]
    console.rule(f"[bold yellow]Revert — {vm_short}[/bold yellow]")
    if isolations:
        console.print("  • Release isolation")
    for b in blocks:
        console.print(f"  • Unblock {b['ip']}")

    if not yes and not dry_run:
        click.confirm("\nProceed?", abort=True)

    connector = AzureConnector(dry_run=dry_run)
    if isolations:
        r = connector.release_isolation(resource_id)
        status = r.get("status", "?")
        console.print(f"  [cyan]release_isolation[/cyan] → {status}")
    for b in blocks:
        r = connector.unblock_ip(b["ip"], resource_id)
        status = r.get("status", "?")
        console.print(f"  [cyan]unblock {b['ip']}[/cyan] → {status}")

    console.print(f"\n[green]✓ Revert complete — {vm_short} is clean.[/green]")


@cli.command()
@click.option("--memory-path", default=None)
def memory_stats(memory_path: str | None):
    """Show how many cycles are stored in memory."""
    from glorfindel.memory import CycleMemory
    m = CycleMemory(path=memory_path)
    console.print(f"Cycles in memory: [cyan]{m.count()}[/cyan]")


@cli.command("check-ttl")
@click.option("--ttl", default=None, type=float, metavar="HOURS",
              help="Max isolation age in hours before auto-release. "
                   "Defaults to GLORFINDEL_ISOLATION_TTL_H env var or 4h.")
@click.option("--dry-run", is_flag=True)
def check_ttl(ttl: float | None, dry_run: bool):
    """Release isolations that have exceeded the TTL.

    Protects against false-positive isolations staying locked indefinitely.
    Default TTL: 4h (override via --ttl or GLORFINDEL_ISOLATION_TTL_H).

    Run this periodically (cron, watch loop) on any operator machine.
    """
    import os
    from datetime import datetime, timezone
    from glorfindel.actions import AzureConnector, active_isolations

    ttl_h = ttl or float(os.environ.get("GLORFINDEL_ISOLATION_TTL_H") or "4")
    connector = AzureConnector(dry_run=dry_run)
    now = datetime.now(timezone.utc)
    released = 0

    for iso in active_isolations():
        isolated_at_s = iso.get("isolated_at")
        resource_id = iso.get("resource_id", "")
        if not isolated_at_s or not resource_id:
            continue
        isolated_at = datetime.fromisoformat(isolated_at_s)
        age_h = (now - isolated_at).total_seconds() / 3600
        vm_short = resource_id.split("/")[-1]

        if age_h >= ttl_h:
            console.print(
                f"[yellow]TTL exceeded[/yellow] — {vm_short} isolated for {age_h:.1f}h "
                f"(limit {ttl_h}h). {'[dim]DRY RUN[/dim]' if dry_run else 'Releasing...'}"
            )
            if not dry_run:
                connector.release_isolation(resource_id)
                from glorfindel import escalations
                escalations.record(
                    signal_id="ttl-auto-release",
                    resource_id=resource_id,
                    action="release_isolation",
                    escalation_type="ttl_exceeded",
                    reason=f"Isolation TTL exceeded ({age_h:.1f}h > {ttl_h}h) — auto-released",
                )
                console.print("  [green]✓ Released.[/green]")
            released += 1

    if released == 0:
        console.print(f"[green]No isolations older than {ttl_h}h.[/green]")


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


def _find_last_attack_time() -> str | None:
    """Extract attack_time from the most recent attack_started signal in runs/."""
    from datetime import datetime, timezone
    candidates = sorted(Path("runs").glob("*_signals.jsonl"), reverse=True)
    for path in candidates:
        try:
            for line in reversed(path.read_text().splitlines()):
                if not line.strip():
                    continue
                sig = json.loads(line)
                if sig.get("event") == "attack_started":
                    attack_time = sig.get("raw_signal", {}).get("attack_time")
                    if attack_time:
                        dt = datetime.fromtimestamp(float(attack_time), tz=timezone.utc)
                        return dt.isoformat()
        except Exception:
            continue
    return None


def _write_signal(signal: dict, runs_dir: str = "runs") -> Path:
    from pathlib import Path
    # Recovery signals go to runs/recovery/ — watch only monitors runs/*_signals.jsonl
    out = Path(runs_dir) / "recovery" / f"{signal['context']['run_id']}_signals.jsonl"
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
    table.add_row("[dim]LLM confidence (self-reported)[/dim]", f"[dim]{confidence:.0%}[/dim]")
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


@cli.command()
def bot():
    """Start the Discord bot — watches escalations and posts interactive embeds."""
    from glorfindel.bot import run
    run()


@cli.command()
def dashboard():
    """Full-screen TUI: resources, live feed, and escalations in one view.

    Refreshes every 2s. Reads active isolations/blocks from ~/.glorfindel/
    and the most recent run from runs/. Press Ctrl+C to exit.
    """
    from glorfindel.tui import run
    run()


@cli.command("war-room")
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--port", default=7007, show_default=True)
def war_room(host: str, port: int):
    """Start the War Room web UI (cards + live feed + action buttons).

    Requires: pip install eregion[war-room]
    Then open http://localhost:7007 in a browser.
    """
    from glorfindel.api import serve
    serve(host=host, port=port)
