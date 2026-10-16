from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import discord
from discord import app_commands
from rich.console import Console

from glorfindel import escalations as esc_module
from glorfindel.escalations import _ACTION_LABELS, _ESCALATION_LABELS

_console = Console()
_POSTED_STORE = Path.home() / ".glorfindel" / "bot_posted.json"
_THREADS_STORE = Path.home() / ".glorfindel" / "bot_threads.json"
# escalation id → the Discord message that carries its buttons. A restarted bot gives each
# message its view back (add_view): without it, every button posted before a redeploy
# answered « interaction failed » (16/10).
_MESSAGES_STORE = Path.home() / ".glorfindel" / "bot_messages.json"
_RESTORE_DAYS = 14


def _load_posted() -> set[str]:
    if _POSTED_STORE.exists():
        return set(json.loads(_POSTED_STORE.read_text()))
    return set()


def _save_posted(ids: set[str]) -> None:
    _POSTED_STORE.parent.mkdir(parents=True, exist_ok=True)
    _POSTED_STORE.write_text(json.dumps(list(ids)))


def _load_threads() -> dict[str, int]:
    if _THREADS_STORE.exists():
        data = json.loads(_THREADS_STORE.read_text())
        return {k: int(v) for k, v in data.items()}
    return {}


def _save_threads(threads: dict[str, int]) -> None:
    _THREADS_STORE.parent.mkdir(parents=True, exist_ok=True)
    _THREADS_STORE.write_text(json.dumps(threads))


def _cli_command(esc: dict) -> str:
    """Return CLI command(s) the operator should run for this escalation."""
    action = esc["action"]
    rid = esc["resource_id"]
    esc_id = esc["id"]
    if action == "restore_from_backup":
        return (
            f"glorfindel restore {rid} --yes\n"
            f"glorfindel ack {esc_id}"
        )
    if esc["escalation_type"] == "verification_failed":
        return (
            f"glorfindel revert {rid} --yes\n"
            f"glorfindel ack {esc_id}"
        )
    if esc["escalation_type"] == "readiness_hold":
        return (
            f"# Lire les réserves, puis les accepter :\n"
            f"glorfindel activate {rid}"
        )
    # No restore on a low_confidence card: a held snapshot never ran — restoring would
    # overwrite the disk the model wanted preserved (fourth review, Q16).
    return f"glorfindel ack {esc_id}"


# What a card asks for, as a recommendation: a held decision is not a done action. The
# first real card of the pre-observation read « IP suspecte bloquée » for a block that
# human_only had held (16/10) — _ACTION_LABELS are past participles, for what ran.
_RECOMMEND_LABELS = {
    "isolate_vm": "isoler la VM",
    "release_isolation": "lever l'isolation",
    "snapshot": "prendre un snapshot forensique",
    "block_suspicious_ip": "bloquer l'IP suspecte",
    "restore_from_backup": "restaurer depuis le backup",
    "delete_resource": "supprimer la ressource",
    "wipe_storage": "effacer le stockage",
    "modify_network_rule": "modifier une règle réseau",
    "escalate_permissions": "élever des permissions",
}
_RAN = {"verification_failed"}                   # the action ran; its check failed
_ATTEMPTED = {"write_blocked", "action_failed"}  # tried, did not go through


def _embed_title(esc: dict) -> str:
    """Never a past participle for what did not run."""
    action, etype = esc.get("action", ""), esc.get("escalation_type", "")
    type_label = _ESCALATION_LABELS.get(etype, etype)
    if etype in _RAN:
        return f"🚨 {_ACTION_LABELS.get(action, action)} — {type_label}"
    rec = _RECOMMEND_LABELS.get(action)
    if etype in _ATTEMPTED:
        return f"🚨 {(rec or action or '?').capitalize()} — {type_label}"
    if not rec or not esc_module.is_decision(esc):
        return f"🚨 {_ACTION_LABELS.get(action) or type_label[:1].upper() + type_label[1:]}"
    return f"🚨 Recommandé : {rec} (non exécuté)"


def _embed_body(esc: dict) -> tuple[str, list[tuple[str, str, bool]]]:
    """The description and fields: the evidence to judge on (the model's explanation, the
    IP a block targets, the rule, the confidence), then why it did not run."""
    explanation = (esc.get("explanation") or "").strip()
    reason = (esc.get("reason") or "").strip()
    fields: list[tuple[str, str, bool]] = [
        ("Action", f"`{esc.get('action') or '—'}`", True),
        ("Ressource", f"`{(esc.get('resource_id') or '').split('/')[-1]}`", True),
    ]
    params = esc.get("action_params") or {}
    if params.get("ip"):
        target = params["ip"] + (f":{params['port']}" if params.get("port") else "")
        fields.append(("Cible", f"`{target}`", True))
    if esc.get("rule_name"):
        fields.append(("Règle", f"`{esc['rule_name']}`", True))
    if esc.get("confidence"):
        fields.append(("Confiance", f"{round(float(esc['confidence']) * 100)} %", True))
    type_label = _ESCALATION_LABELS.get(esc.get("escalation_type", ""), esc.get("escalation_type", ""))
    fields.append(("Contexte", " · ".join(filter(None, [esc.get("ttp", ""), esc.get("severity", ""), type_label])), False))
    if explanation and reason and reason != explanation:
        fields.append(("Pourquoi rien n'est exécuté", reason[:1024], False))
    if esc.get("suggested_steps"):
        steps = "\n".join(f"• {s}" for s in esc["suggested_steps"][:3])
        fields.append(("Prochaines étapes", steps[:1024], False))
    return (explanation or reason)[:2048], fields


def _load_messages() -> dict[str, int]:
    if _MESSAGES_STORE.exists():
        try:
            return {k: int(v) for k, v in json.loads(_MESSAGES_STORE.read_text()).items()}
        except (ValueError, AttributeError):
            return {}
    return {}


def _save_messages(messages: dict[str, int]) -> None:
    _MESSAGES_STORE.parent.mkdir(parents=True, exist_ok=True)
    _MESSAGES_STORE.write_text(json.dumps(messages))


def _views_to_restore(escs: list[dict], messages: dict[str, int], now=None) -> list[tuple[dict, int]]:
    """(escalation, message id) whose buttons must answer again after a restart: every card
    posted in the last _RESTORE_DAYS days — pending, or acknowledged but still to judge."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    out = []
    for e in escs:
        mid = messages.get(e.get("id", ""))
        if not mid:
            continue
        try:
            when = datetime.fromisoformat(str(e.get("first_seen") or e.get("timestamp")).replace("Z", "+00:00"))
        except ValueError:
            continue
        if now - when <= timedelta(days=_RESTORE_DAYS):
            out.append((e, mid))
    return out


def _glorfindel_bin() -> str:
    """Find the glorfindel CLI binary next to the current Python."""
    candidate = Path(sys.executable).parent / "glorfindel"
    if candidate.exists():
        return str(candidate)
    return "glorfindel"  # fall back to PATH


class _ExecuteButton(discord.ui.Button):
    """A button that runs a glorfindel CLI command and reports the result."""

    def __init__(
        self,
        esc: dict,
        label: str,
        style: discord.ButtonStyle,
        cli_args: list[str],
    ) -> None:
        super().__init__(
            label=label,
            style=style,
            custom_id=f"glorfindel_exec_{esc['id'][:8]}",
            row=1,
        )
        self.esc = esc
        self.cli_args = cli_args

    async def callback(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer()

        # Disable all buttons immediately so nobody double-clicks
        for item in self.view.children:  # type: ignore[union-attr]
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.message.edit(  # type: ignore[union-attr]
            view=self.view  # type: ignore[union-attr]
        )

        cmd_display = "glorfindel " + " ".join(self.cli_args)
        await interaction.channel.send(  # type: ignore[union-attr]
            f"⚡ **{interaction.user.display_name}** → `{cmd_display}`"
        )

        # Auto-ack before executing so the escalation closes right away
        esc_module.resolve(self.esc["id"])

        channel = interaction.channel
        asyncio.create_task(self._execute_and_report(channel))

    async def _execute_and_report(
        self, channel: discord.abc.Messageable
    ) -> None:
        try:
            loop = asyncio.get_running_loop()
            output = await loop.run_in_executor(None, self._run)
            short = output.strip()[:1800] or "(pas de sortie)"
            await channel.send(f"```\n{short}\n```")
            # Archive thread if no more pending escalations for this resource
            remaining = [
                e for e in esc_module.pending()
                if e["resource_id"] == self.esc["resource_id"]
            ]
            if not remaining and isinstance(channel, discord.Thread):
                await channel.edit(
                    archived=True, reason="All escalations acknowledged"
                )
        except Exception as exc:
            await channel.send(f"✗ Erreur lors de l'exécution : {exc}")

    def _run(self) -> str:
        import subprocess
        result = subprocess.run(
            [_glorfindel_bin()] + self.cli_args,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 min max (restore ~20 min)
        )
        return (result.stdout + result.stderr).strip()


def _make_action_button(esc: dict) -> _ExecuteButton | None:
    """Return an execute button for this escalation, or None."""
    action = esc["action"]
    esc_type = esc["escalation_type"]
    rid = esc["resource_id"]

    if action == "restore_from_backup":
        return _ExecuteButton(
            esc, "🔄 Restore",
            discord.ButtonStyle.primary,
            ["restore", rid, "--yes"],
        )
    if esc_type == "verification_failed":
        return _ExecuteButton(
            esc, "↩️ Revert",
            discord.ButtonStyle.danger,
            ["revert", rid, "--yes"],
        )
    # No Restore on a low_confidence card: a held snapshot never ran (fourth review, Q16).
    return None


_VERDICT_WORDS = {"right": "✓ Right", "wrong": "✗ Wrong", "unsure": "? Unsure"}


class _VerdictButton(discord.ui.Button):
    """The observation's verdict, from Discord (docs/observation.md): was the
    recommendation right? Independent of the ack, like in the War Room."""

    def __init__(self, esc: dict, verdict: str, style: discord.ButtonStyle) -> None:
        super().__init__(
            label=_VERDICT_WORDS[verdict],
            style=style,
            custom_id=f"glorfindel_verdict_{verdict}_{esc['id'][:8]}",
            row=2,
        )
        self.esc = esc
        self.verdict = verdict

    async def callback(self, interaction: discord.Interaction) -> None:
        try:
            esc_module.set_verdict(self.esc["id"], self.verdict, "")
        except (KeyError, ValueError) as exc:
            await interaction.response.send_message(f"✗ {exc}", ephemeral=True)
            return
        # One click: a judged card is also acknowledged (Jonathan, 16/10).
        esc_module.resolve(self.esc["id"])
        for item in self.view.children:  # type: ignore[union-attr]
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.response.edit_message(view=self.view)  # type: ignore[union-attr]
        await interaction.followup.send(
            f"{_VERDICT_WORDS[self.verdict]} — jugé par **{interaction.user.display_name}**"
        )


class EscalationView(discord.ui.View):
    def __init__(self, esc: dict):
        super().__init__(timeout=None)
        self.esc_id = esc["id"]
        self.esc = esc
        btn = _make_action_button(esc)
        if btn:
            self.add_item(btn)
        if esc_module.is_decision(esc):
            self.add_item(_VerdictButton(esc, "right", discord.ButtonStyle.success))
            self.add_item(_VerdictButton(esc, "wrong", discord.ButtonStyle.danger))
            self.add_item(_VerdictButton(esc, "unsure", discord.ButtonStyle.secondary))

    @discord.ui.button(
        label="✓ Acknowledge",
        style=discord.ButtonStyle.green,
        custom_id="glorfindel_ack",
    )
    async def ack_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        esc_module.resolve(self.esc_id)
        for item in self.children:
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.response.edit_message(view=self)
        await interaction.followup.send(
            f"✓ Acknowledged by **{interaction.user.display_name}**"
        )
        remaining = [
            e for e in esc_module.pending()
            if e["resource_id"] == self.esc["resource_id"]
        ]
        if not remaining and isinstance(interaction.channel, discord.Thread):
            await interaction.channel.edit(
                archived=True, reason="All escalations acknowledged"
            )

    @discord.ui.button(
        label="📋 Command",
        style=discord.ButtonStyle.secondary,
        custom_id="glorfindel_cmd",
    )
    async def cmd_btn(
        self, interaction: discord.Interaction, button: discord.ui.Button
    ):
        cmds = _cli_command(self.esc)
        await interaction.response.send_message(
            f"Command to run:\n```\n{cmds}\n```",
            ephemeral=True,
        )


class GlorfindelBot(discord.Client):
    def __init__(self, channel_id: int, ping_role: int | None):
        intents = discord.Intents.default()
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.channel_id = channel_id
        self.ping_role = ping_role
        self._posted: set[str] = _load_posted()
        self._threads: dict[str, int] = _load_threads()
        self._messages: dict[str, int] = _load_messages()

    async def setup_hook(self) -> None:
        @self.tree.command(
            name="pending", description="Lister les escalades en attente"
        )
        async def pending_cmd(interaction: discord.Interaction) -> None:
            escs = esc_module.pending()
            if not escs:
                await interaction.response.send_message(
                    "✓ Aucune escalade en attente.", ephemeral=True
                )
                return
            lines = []
            for e in escs[:5]:
                label = _ACTION_LABELS.get(e["action"], e["action"])
                short = e["resource_id"].split("/")[-1]
                lines.append(
                    f"• `{e['id'][:8]}` — **{label}** sur `{short}`"
                )
            if len(escs) > 5:
                lines.append(f"_... et {len(escs) - 5} autre(s)_")
            await interaction.response.send_message(
                "\n".join(lines), ephemeral=True
            )

        await self.tree.sync()
        self._restore_views()

    def _restore_views(self) -> int:
        """Give the messages posted before this start their buttons back."""
        restored = 0
        for esc, message_id in _views_to_restore(esc_module.all_escalations(), self._messages):
            try:
                self.add_view(EscalationView(esc), message_id=message_id)
                restored += 1
            except Exception as exc:  # one bad card must not stop the bot
                _console.print(f"[yellow]View not restored for {esc.get('id', '')[:8]}: {exc}[/yellow]")
        if restored:
            _console.print(f"[dim]  → {restored} message(s) given their buttons back[/dim]")
        return restored

    async def on_ready(self) -> None:
        _console.print(
            f"[green]🔵 Glorfindel bot connecté : {self.user}[/green]"
        )
        channel = self.get_channel(self.channel_id)
        if channel is None:
            _console.print(
                f"[red]✗ Channel {self.channel_id} introuvable — "
                "vérifie DISCORD_CHANNEL_ID et que le bot est bien "
                "invité dans le serveur.[/red]"
            )
        else:
            _console.print(f"[green]  → Channel : #{channel.name}[/green]")

        if self._posted:
            _console.print(
                f"[dim]  → {len(self._posted)} escalation(s) "
                "already posted (bot_posted.json)[/dim]"
            )

        self.bg_task = self.loop.create_task(self._watch_escalations())

    async def _get_or_create_thread(
        self, channel: discord.TextChannel, resource_id: str
    ) -> discord.Thread:
        last = resource_id.split("/")[-1]
        vm_name = last or resource_id.strip("/").split("/")[-1] or "unknown"
        thread_id = self._threads.get(resource_id)
        if thread_id:
            thread = self.get_channel(thread_id)
            if isinstance(thread, discord.Thread):
                try:
                    if thread.archived:
                        await thread.edit(archived=False)
                    return thread
                except discord.NotFound:
                    _console.print(
                        f"[yellow]Thread {thread_id} deleted on Discord, "
                        "creating new one[/yellow]"
                    )

        thread = await channel.create_thread(
            name=f"🔴 {vm_name}",
            type=discord.ChannelType.public_thread,
        )
        self._threads[resource_id] = thread.id
        _save_threads(self._threads)
        _console.print(
            f"[cyan]New thread created: {thread.name} "
            f"(id={thread.id})[/cyan]"
        )

        if self.ping_role:
            await thread.send(
                f"<@&{self.ping_role}> Incident opened on `{vm_name}`"
            )
        return thread

    async def _watch_escalations(self) -> None:
        channel: discord.TextChannel | None = None
        _console.print("[dim]Watch loop started[/dim]")
        while True:
            try:
                await asyncio.sleep(5)
                if channel is None:
                    channel = self.get_channel(self.channel_id)  # type: ignore
                    if channel is None:
                        _console.print(
                            f"[yellow]Watch: channel {self.channel_id} "
                            "not in cache yet[/yellow]"
                        )
                        continue
                    _console.print(
                        f"[dim]Watch: channel #{channel.name} ready[/dim]"
                    )
                pending = esc_module.pending()
                new = [e for e in pending if e["id"] not in self._posted]
                if new:
                    _console.print(
                        f"[dim]Watch: {len(new)} new escalation(s)[/dim]"
                    )
                for esc in new:
                    try:
                        await self._post_escalation(channel, esc)
                        self._posted.add(esc["id"])
                        _save_posted(self._posted)
                        _console.print(
                            f"[green]✓ Posted {esc['id'][:8]} "
                            f"({esc['action']})[/green]"
                        )
                    except Exception as e:
                        _console.print(f"[red]Bot post error: {e}[/red]")
            except Exception as e:
                _console.print(f"[red]Watch loop error: {e}[/red]")

    async def _post_escalation(
        self, channel: discord.TextChannel, esc: dict
    ) -> None:
        thread = await self._get_or_create_thread(channel, esc["resource_id"])

        color = (
            discord.Color.red()
            if esc["escalation_type"] == "destructive_action"
            else discord.Color.orange()
        )
        description, fields = _embed_body(esc)
        embed = discord.Embed(title=_embed_title(esc), description=description, color=color)
        for name, value, inline in fields:
            embed.add_field(name=name, value=value, inline=inline)
        embed.set_footer(text=f"Run: {esc['run_id']} · ID: {esc['id'][:8]}")
        view = EscalationView(esc)
        message = await thread.send(embed=embed, view=view)
        self._messages[esc["id"]] = message.id
        _save_messages(self._messages)


def run() -> None:
    token = os.environ.get("DISCORD_BOT_TOKEN", "")
    channel_id_str = os.environ.get("DISCORD_CHANNEL_ID", "")
    ping_role_str = os.environ.get("DISCORD_PING_ROLE", "")
    if not token:
        raise RuntimeError(
            "DISCORD_BOT_TOKEN is not set — create a bot at "
            "https://discord.com/developers/applications"
        )
    if not channel_id_str:
        raise RuntimeError(
            "DISCORD_CHANNEL_ID is not set — right-click the channel → "
            "Copy Channel ID (Developer Mode required)"
        )
    ping_role = int(ping_role_str) if ping_role_str else None
    bot = GlorfindelBot(channel_id=int(channel_id_str), ping_role=ping_role)
    bot.run(token, log_handler=None)
