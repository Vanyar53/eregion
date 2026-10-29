from __future__ import annotations

import json
import queue
import select
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


# ── Helpers ────────────────────────────────────────────────────────────────────

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


def _bin() -> str:
    c = Path(sys.executable).parent / "glorfindel"
    return str(c) if c.exists() else "glorfindel"


# ── Key reading (best-effort, requires tty) ────────────────────────────────────

_key_q: queue.Queue[str] = queue.Queue()
_stop_keys = threading.Event()


def _start_key_reader() -> bool:
    """Start background key reader. Returns True if interactive."""
    if not sys.stdin.isatty():
        return False
    try:
        import termios
        import tty
    except ImportError:
        return False

    def _reader() -> None:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not _stop_keys.is_set():
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    ch = sys.stdin.read(1)
                    if ch:
                        _key_q.put(ch)
        except Exception:
            pass
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except Exception:
                pass

    threading.Thread(target=_reader, daemon=True).start()
    return True


# ── Action execution ───────────────────────────────────────────────────────────

# The cards whose VM is an anchor the detection may not concern (AL1, C2) — the same set as the
# bot's (glorfindel/bot.py, which imports discord) and the console's; a test keeps the three
# equal. Never a command aimed at that VM from here: ack only (SEC5, V-35).
_ANCHORED_TYPES = {"control_plane_change", "identity_change", "unattributed_signal"}


def _anchored(esc: dict) -> bool:
    return esc.get("escalation_type") in _ANCHORED_TYPES


def _can_restore(esc: dict) -> bool:
    """Restore only on a restore card the console and the bot would offer it on: never on an
    anchored one (SEC5, V-35), never on a held snapshot (fourth review, Q16)."""
    return esc.get("action") == "restore_from_backup" and not _anchored(esc)


def _can_undo(esc: dict) -> bool:
    """Release, unblock, reset: on a failed verification of the card's own VM only."""
    return esc.get("escalation_type") == "verification_failed" and not _anchored(esc)


def _commands(key: str, esc: dict, before: str = "") -> list[list[str]]:
    """What a confirmed key runs, as glorfindel CLI arguments — [] when the card allows none.
    « unblock » removes the VM's IP blocks one by one (``glorfindel unblock <ip> <vm>``), never
    its isolation: it is not « reset » (SEC5, V-35). « restore » runs only with the moment the
    operator gave (`before`, SEC4c): without it, nothing."""
    rid = esc["resource_id"]
    if key == "r":
        from glorfindel import restore_plan
        return [restore_plan.restore_args(rid, before)] if _can_restore(esc) and before else []
    if not _can_undo(esc):
        return []
    if key == "x":
        return [["release", rid, "--yes"]]
    if key == "v":
        return [["reset", rid, "--yes"]]
    if key == "u":
        from glorfindel.actions import active_blocks
        ips = sorted({b["ip"] for b in active_blocks()
                      if (b.get("resource_id") or "").lower() == rid.lower() and b.get("ip")})
        return [["unblock", ip, rid, "--yes"] for ip in ips]
    return []


def _execute(pending: dict) -> None:
    """Execute a confirmed action. Restore/release/unblock/reset run in a background thread."""
    from glorfindel import escalations as esc_module

    key = pending["key"]
    esc = pending["esc"]

    if key == "a":
        esc_module.resolve(esc["id"])
        return

    commands = _commands(key, esc)
    if not commands:
        return

    def _run() -> None:
        for args in commands:
            subprocess.run([_bin(), *args], capture_output=True)

    threading.Thread(target=_run, daemon=True).start()


# ── Restore: the moment is asked (SEC4c) ───────────────────────────────────────
# The field is filled with the moment the runs/ channel gives for the VM (an exercise), else
# the card's first detection; Enter shows the recovery points before it (read only); y runs
# `glorfindel restore --before`. What the command says — a refusal too — stays on screen.

_last_restore: dict = {}


def _restore_pending(esc: dict) -> dict:
    from glorfindel import restore_plan
    plan = restore_plan.proposed_moment(esc["resource_id"], esc)
    return {"key": "r", "esc": esc, "stage": "moment", "buffer": plan.get("before", ""),
            "why": plan.get("why", ""), "error": "",
            "label": f"restore {esc['resource_id'].split('/')[-1]} from backup (~20 min)"}


def _load_points(pending: dict) -> None:
    from glorfindel import restore_plan
    try:
        pending["points"] = restore_plan.points_before(pending["esc"]["resource_id"], pending["before"])
    except Exception as exc:  # unreadable vault: said, the restore stays possible
        pending["points_error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
        pending["points"] = []


def _restore_key(pending: dict, key: str) -> dict | None:
    """One key on the restore's screen: the pending state after it, None when cancelled."""
    if key == "\x1b":
        return None
    if pending["stage"] == "moment":
        if key in ("\r", "\n"):
            from glorfindel import restore_plan
            try:
                pending["before"] = restore_plan.parse_moment(pending["buffer"])
            except ValueError as exc:
                pending["error"] = str(exc)
                return pending
            pending.update(stage="points", error="", points=None, points_error="",
                           warning=restore_plan.moment_warning(pending["esc"]["resource_id"], pending["before"]))
            threading.Thread(target=_load_points, args=(pending,), daemon=True).start()
        elif key in ("\x7f", "\b"):
            pending["buffer"] = pending["buffer"][:-1]
        elif key.isprintable() and len(pending["buffer"]) < 40:
            pending["buffer"] += key
        return pending
    if key in ("y", "Y"):
        _start_restore(pending["esc"], pending["before"])
        return None
    if key in ("n", "N", "q", "Q"):
        return None
    return pending


def _start_restore(esc: dict, before: str) -> None:
    from glorfindel import restore_plan
    vm = esc["resource_id"].split("/")[-1]
    _last_restore.clear()
    _last_restore.update(vm=vm, text=f"restore {vm} before {before}: running…", ok=None)

    def run():
        try:
            cmds = _commands("r", esc, before)
            if not cmds:
                raise ValueError("cette carte n'offre pas de restore")
            proc = subprocess.run([_bin(), *cmds[0]], capture_output=True, text=True, timeout=1800)
            ok = proc.returncode == 0
            said = restore_plan.failure_text(proc.returncode, (proc.stdout or "") + (proc.stderr or ""))
        except Exception as exc:
            ok, said = False, f"{type(exc).__name__}: {exc}"
        _last_restore.update(ok=ok, text=(f"✓ restore {vm} started: {said}" if ok
                                          else f"✗ restore {vm} refused or failed: {said}"))
    threading.Thread(target=run, daemon=True).start()


def _restore_panel(pending: dict) -> Panel:
    lines = Text(overflow="fold")
    lines.append(f"\n  ⚡ {pending['label']}\n\n", style="bold yellow")
    if pending["stage"] == "moment":
        lines.append("  Restore to the newest point from before: ", style="white")
        lines.append(pending["buffer"] + "▌\n", style="bold cyan")
        lines.append(f"  {pending['why']}\n", style="dim")
        if pending["error"]:
            lines.append(f"  ✗ {pending['error']}\n", style="red")
        lines.append("\n  [Enter] points before it   [Esc] cancel\n", style="cyan")
    else:
        lines.append(f"  Before {pending['before']}\n", style="bold cyan")
        if pending.get("warning"):
            lines.append(f"  ⚠ {pending['warning']}\n", style="yellow")
        points = pending.get("points")
        if points is None:
            lines.append("  reading the recovery points…\n", style="dim")
        elif pending.get("points_error"):
            lines.append(f"  recovery points unreadable: {pending['points_error']}\n", style="yellow")
        elif not points:
            lines.append("  no recovery point before it: the restore would be refused\n", style="red")
        for i, p in enumerate((points or [])[:6]):
            lines.append(f"  {p.get('time')}{' · vault tier' if p.get('vault_tier') else ''}"
                         f"{' · taken during the incident' if p.get('during_incident') else ''}"
                         f"{'  ← restored' if i == 0 else ''}\n", style="green" if i == 0 else "dim")
        lines.append("\n  Confirm?   [y] Yes   [n] Cancel\n", style="cyan")
    return Panel(lines, title="[bold white on red] RESTORE [/bold white on red]", border_style="red")


# ── Renderables ────────────────────────────────────────────────────────────────

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


def _escalations_renderable(
    now: datetime,
    pending: dict | None,
    interactive: bool,
) -> Panel:
    from glorfindel import escalations as esc_module

    items = esc_module.pending()
    if pending and pending.get("stage"):
        return _restore_panel(pending)
    if not items:
        last = Text(overflow="fold")
        if _last_restore:                    # what the restore said stays on screen (SEC4c)
            last.append(f"  {_last_restore.get('text', '')}\n\n",
                        style="green" if _last_restore.get("ok") else "red" if _last_restore.get("ok") is False else "dim")
        last.append("✓ No pending escalations", style="green")
        return Panel(last, title="[bold]ESCALATIONS[/bold]", border_style="green")

    lines = Text(overflow="fold")

    if pending:
        lines.append(f"\n  ⚡ {pending['label']}\n\n", style="bold yellow")
        lines.append("  Confirm?   [y] Yes   [n] Cancel\n", style="cyan")
        return Panel(
            lines,
            title="[bold white on red] CONFIRM ACTION [/bold white on red]",
            border_style="red",
        )

    if _last_restore:
        lines.append(f"  {_last_restore.get('text', '')}\n\n",
                     style="green" if _last_restore.get("ok") else ("red" if _last_restore.get("ok") is False else "dim"))

    for e in items[:4]:
        age = _age(e["timestamp"], now)
        vm_short = e["resource_id"].split("/")[-1]
        esc_id = e["id"][:8]
        action = e["action"]
        esc_type = e.get("escalation_type", "")

        lines.append(f"  [{esc_id}]  ", style="dim")
        lines.append(f"{action}", style="bold yellow")
        lines.append(f"  {vm_short}  {age} ago\n", style="dim")

        for step in (e.get("suggested_steps") or [])[:2]:
            lines.append(f"    • {step[:72]}\n", style="dim")

        if esc_type in _ANCHORED_TYPES:   # its VM is an anchor: ack only (SEC5, V-35)
            lines.append(f"    → glorfindel ack {esc_id}\n", style="dim cyan")
        elif action == "restore_from_backup":
            lines.append(
                f"    → glorfindel restore {vm_short} --yes --before "
                f"{e.get('first_seen') or e.get('timestamp') or '<ISO8601>'}  # before the attack began\n",
                style="dim cyan"
            )
        elif esc_type == "verification_failed":
            lines.append(
                f"    → glorfindel revert {vm_short} --yes\n", style="dim cyan"
            )
        else:
            lines.append(f"    → glorfindel ack {esc_id}\n", style="dim cyan")

    if len(items) > 4:
        lines.append(
            f"\n  … {len(items) - 4} more  →  glorfindel pending\n", style="dim"
        )

    if interactive:
        first = items[0]
        hints = ["[a] ack"]
        if _can_restore(first):      # the keys offered are the keys that act (SEC5, V-35)
            hints.append("[r] restore")
        if _can_undo(first):
            hints.append("[x] release   [u] unblock   [v] reset")
        lines.append("\n  " + "   ".join(hints) + "\n", style="dim cyan")

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


# ── Main ───────────────────────────────────────────────────────────────────────

def run() -> None:
    """Launch the Rich full-screen TUI dashboard."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),
        Layout(name="main", ratio=3),
        Layout(name="escalations", size=14),
    )
    layout["main"].split_row(
        Layout(name="resources", ratio=1, minimum_size=30),
        Layout(name="feed", ratio=3),
    )

    feed_lines: list[str] = ["[dim]Loading…[/dim]"]
    last_mtime: float = 0.0
    run_label = ""
    pending: dict | None = None

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

    interactive = _start_key_reader()

    console = Console()

    def _header() -> Text:
        now = datetime.now(timezone.utc)
        t = Text(justify="right")
        t.append("GLORFINDEL  ", style="bold blue")
        t.append("dashboard", style="bold white")
        t.append(f"  ·  {now.strftime('%H:%M:%S')} UTC", style="dim")
        hint = "   q:quit  a:ack  r:restore  x:release  u:unblock  v:reset" if interactive else "   Ctrl+C to exit"
        t.append(hint, style="dim")
        return t

    with Live(
        layout,
        console=console,
        refresh_per_second=4 if interactive else 0.5,
        screen=True,
    ):
        try:
            while True:
                now = datetime.now(timezone.utc)
                _maybe_reload()

                while not _key_q.empty():
                    key = _key_q.get_nowait()
                    if pending and pending.get("stage"):     # the restore asks its moment (SEC4c)
                        pending = _restore_key(pending, key)
                        continue
                    if pending:
                        if key in ("y", "Y"):
                            _execute(pending)
                            pending = None
                        elif key in ("n", "N", "q", "Q", "\x1b"):
                            pending = None
                    else:
                        from glorfindel import escalations as esc_module
                        escs = esc_module.pending()
                        if key in ("q", "Q"):
                            return
                        elif key == "a" and escs:
                            e = escs[0]
                            vm = e["resource_id"].split("/")[-1]
                            pending = {
                                "key": "a",
                                "esc": e,
                                "label": f"ack [{e['id'][:8]}] on {vm}",
                            }
                        elif key == "r" and escs:
                            e = escs[0]
                            # Only a restore card: a held snapshot never ran (fourth review, Q16),
                            # and never an anchored one (SEC5, V-35). It asks its moment (SEC4c).
                            if _can_restore(e):
                                pending = _restore_pending(e)
                        elif key == "x" and escs:
                            e = escs[0]
                            if _can_undo(e):
                                vm = e["resource_id"].split("/")[-1]
                                pending = {
                                    "key": "x",
                                    "esc": e,
                                    "label": f"release {vm} (isolation only)",
                                }
                        elif key == "u" and escs:
                            e = escs[0]
                            if _can_undo(e):
                                vm = e["resource_id"].split("/")[-1]
                                pending = {
                                    "key": "u",
                                    "esc": e,
                                    "label": f"unblock {vm} (IP blocks only)",
                                }
                        elif key == "v" and escs:
                            e = escs[0]
                            if _can_undo(e):
                                vm = e["resource_id"].split("/")[-1]
                                pending = {
                                    "key": "v",
                                    "esc": e,
                                    "label": f"reset {vm} (release + unblock all IPs)",
                                }

                layout["header"].update(_header())
                layout["resources"].update(_resources_renderable(now))
                layout["feed"].update(_feed_renderable(feed_lines, run_label))
                layout["escalations"].update(
                    _escalations_renderable(now, pending, interactive)
                )
                time.sleep(0.1 if interactive else 2)
        except KeyboardInterrupt:
            pass
        finally:
            _stop_keys.set()
