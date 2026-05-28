from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


def _age(ts: str, now: datetime) -> str:
    if not ts:
        return ""
    try:
        age_s = int((now - datetime.fromisoformat(ts)).total_seconds())
        if age_s < 60:
            return f"{age_s}s"
        elif age_s < 3600:
            return f"{age_s // 60}m"
        else:
            return f"{age_s // 3600}h{(age_s % 3600) // 60}m"
    except Exception:
        return ""


def _resources_renderable(now: datetime) -> Panel:
    from glorfindel.actions import active_blocks, active_isolations

    isolations = {i["resource_id"]: i for i in active_isolations()}
    blocks: dict[str, list] = {}
    for b in active_blocks():
        blocks.setdefault(b["resource_id"], []).append(b)

    all_ids = sorted(set(isolations) | set(blocks))

    if not all_ids:
        return Panel(
            Text.from_markup(
                "[green]✓ All clear[/green]\n[dim]No active actions[/dim]"
            ),
            title="[bold]RESOURCES[/bold]",
            border_style="green",
        )

    lines = Text(overflow="fold")
    for resource_id in all_ids:
        vm_short = resource_id.split("/")[-1]
        lines.append(f"  {vm_short}\n", style="bold white")

        if resource_id in isolations:
            age = _age(isolations[resource_id].get("isolated_at", ""), now)
            lines.append("  🔴 ISOLATED", style="bold red")
            lines.append(f"  {age} ago\n", style="dim")

        for b in blocks.get(resource_id, []):
            age = _age(b.get("blocked_at", ""), now)
            lines.append("  🟡 BLOCKED ", style="bold yellow")
            lines.append(f"  {b['ip']}  {age} ago\n", style="dim")

        lines.append("\n")

    return Panel(
        lines,
        title=f"[bold yellow]RESOURCES ({len(all_ids)})[/bold yellow]",
        border_style="yellow",
    )


def _escalations_renderable(now: datetime) -> Panel:
    from glorfindel import escalations as esc_module

    items = esc_module.pending()
    if not items:
        return Panel(
            Text.from_markup("[green]✓ No pending escalations[/green]"),
            title="[bold]ESCALATIONS[/bold]",
            border_style="green",
        )

    lines = Text(overflow="fold")
    for e in items[:4]:
        age = _age(e["timestamp"], now)
        vm_short = e["resource_id"].split("/")[-1]
        esc_id = e["id"][:8]
        action = e["action"]
        esc_type = e.get("escalation_type", "")

        lines.append(f"  [{esc_id}]  ", style="dim")
        lines.append(f"{action}", style="bold yellow")
        lines.append(f"  {vm_short}  {age} ago\n", style="dim")

        if action == "restore_from_backup":
            lines.append(
                f"    → glorfindel restore {vm_short} --yes\n",
                style="dim cyan",
            )
        elif esc_type == "verification_failed":
            lines.append(
                f"    → glorfindel revert {vm_short} --yes\n",
                style="dim cyan",
            )
        else:
            lines.append(
                f"    → glorfindel ack {esc_id}\n", style="dim cyan"
            )

    if len(items) > 4:
        lines.append(
            f"\n  … {len(items) - 4} more  →  glorfindel pending\n",
            style="dim",
        )

    return Panel(
        lines,
        title=f"[bold red]ESCALATIONS ({len(items)})[/bold red]",
        border_style="red",
    )


def _format_signal(s: dict) -> str:
    ts = s.get("timestamp", "")[:19].replace("T", " ")
    event = s.get("event", "unknown")
    ttp = s.get("ttp", "")
    resource = s.get("resource_id", "").split("/")[-1]
    color = {
        "attack_started": "yellow",
        "detection": "green",
        "detection_timeout": "dark_orange",
        "recovery_complete": "cyan",
        "recovery_failed": "red",
    }.get(event, "white")
    return (
        f"[dim]{ts}[/dim]  [{color}]{event:<22}[/{color}]"
        f"  [dim]{ttp:<14}  {resource}[/dim]"
    )


def _format_debug(d: dict) -> str:
    ts = d.get("timestamp", "")[:19].replace("T", " ")
    action = d.get("action", "")
    confidence = d.get("confidence", 0.0)
    escalate = d.get("escalate", False)
    verified = d.get("outcome", {}).get("verified")
    ttp = d.get("signal", {}).get("ttp", "")
    pct = f"{int(confidence * 100)}%"

    if escalate:
        icon, color, label = "🚨", "red", f"escalate → {action}"
    elif verified:
        icon, color, label = "✓", "green", action
    elif verified is False:
        icon, color, label = "✗", "red", f"{action} (verify failed)"
    else:
        icon, color, label = "⚡", "cyan", action

    return (
        f"[dim]{ts}[/dim]  [{color}]{icon} {label:<28}[/{color}]"
        f"  [dim]{ttp:<14}  {pct}[/dim]"
    )


def _load_feed(max_entries: int = 60) -> list[str]:
    runs = Path("runs")
    if not runs.exists():
        return ["[dim]No runs/ directory — start an annatar run[/dim]"]

    sig_files = sorted(
        runs.glob("*_signals.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    dbg_files = sorted(
        runs.glob("*_debug.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not sig_files and not dbg_files:
        return ["[dim]No run data yet — start an annatar run[/dim]"]

    name = sig_files[0].name if sig_files else dbg_files[0].name
    prefix = name.replace("_signals.jsonl", "").replace("_debug.jsonl", "")
    entries: list[tuple[str, str]] = []

    for path, fmt in [
        (runs / f"{prefix}_signals.jsonl", _format_signal),
        (runs / f"{prefix}_debug.jsonl", _format_debug),
    ]:
        if path.exists():
            for line in path.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    entries.append((d.get("timestamp", ""), fmt(d)))
                except Exception:
                    pass

    entries.sort(key=lambda x: x[0])
    return [text for _, text in entries[-max_entries:]]


def _feed_renderable(feed_lines: list[str], run_label: str) -> Panel:
    text = Text(overflow="fold")
    for line in feed_lines:
        text.append_text(Text.from_markup(line))
        text.append("\n")
    title = (
        f"[bold]FEED[/bold]  [dim]{run_label}[/dim]"
        if run_label
        else "[bold]FEED[/bold]"
    )
    return Panel(text, title=title, border_style="cyan")


def _current_run_label() -> str:
    runs = Path("runs")
    if not runs.exists():
        return ""
    candidates = sorted(
        runs.glob("*_signals.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        return ""
    return candidates[0].name.replace("_signals.jsonl", "")


def run() -> None:
    """Launch the Rich full-screen TUI dashboard."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),
        Layout(name="main", ratio=3),
        Layout(name="escalations", size=10),
    )
    layout["main"].split_row(
        Layout(name="resources", ratio=1, minimum_size=30),
        Layout(name="feed", ratio=3),
    )

    feed_lines: list[str] = ["[dim]Loading…[/dim]"]
    last_mtime: float = 0.0
    run_label = ""

    def _maybe_reload() -> None:
        nonlocal last_mtime, run_label
        runs = Path("runs")
        if not runs.exists():
            return
        files = (
            list(runs.glob("*_debug.jsonl"))
            + list(runs.glob("*_signals.jsonl"))
        )
        if not files:
            return
        newest = max(f.stat().st_mtime for f in files)
        if newest != last_mtime:
            last_mtime = newest
            run_label = _current_run_label()
            new = _load_feed(60)
            feed_lines.clear()
            feed_lines.extend(new or ["[dim]No events yet[/dim]"])

    _maybe_reload()
    run_label = _current_run_label()

    console = Console()

    def _header() -> Text:
        now = datetime.now(timezone.utc)
        t = Text(justify="right")
        t.append("GLORFINDEL  ", style="bold blue")
        t.append("dashboard", style="bold white")
        t.append(f"  ·  {now.strftime('%H:%M:%S')} UTC", style="dim")
        t.append("   Ctrl+C to exit", style="dim")
        return t

    with Live(layout, console=console, refresh_per_second=0.5, screen=True):
        try:
            while True:
                now = datetime.now(timezone.utc)
                _maybe_reload()
                layout["header"].update(_header())
                layout["resources"].update(_resources_renderable(now))
                layout["feed"].update(_feed_renderable(feed_lines, run_label))
                layout["escalations"].update(_escalations_renderable(now))
                time.sleep(2)
        except KeyboardInterrupt:
            pass
