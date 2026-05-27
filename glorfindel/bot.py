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
    if esc["escalation_type"] == "low_confidence":
        return (
            f"# Vérifier le snapshot, puis si nécessaire :\n"
            f"glorfindel restore {rid} --yes\n"
            f"glorfindel ack {esc_id}"
        )
    return f"glorfindel ack {esc_id}"


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
    if esc_type == "low_confidence":
        # Detection timeout — snapshot taken, operator may want to restore
        return _ExecuteButton(
            esc, "🔄 Restore",
            discord.ButtonStyle.secondary,
            ["restore", rid, "--yes"],
        )
    return None


class EscalationView(discord.ui.View):
    def __init__(self, esc: dict):
        super().__init__(timeout=None)
        self.esc_id = esc["id"]
        self.esc = esc
        btn = _make_action_button(esc)
        if btn:
            self.add_item(btn)

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

        # Seed existing escalations — only post new ones after startup
        for esc in esc_module.pending():
            self._posted.add(esc["id"])
        _save_posted(self._posted)
        if self._posted:
            _console.print(
                f"[dim]  → {len(self._posted)} escalade(s) "
                "existing escalation(s) ignored[/dim]"
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
                if thread.archived:
                    await thread.edit(archived=False)
                return thread

        thread = await channel.create_thread(
            name=f"🔴 {vm_name}",
            type=discord.ChannelType.public_thread,
        )
        self._threads[resource_id] = thread.id
        _save_threads(self._threads)

        if self.ping_role:
            await thread.send(
                f"<@&{self.ping_role}> Incident opened on `{vm_name}`"
            )
        return thread

    async def _watch_escalations(self) -> None:
        channel: discord.TextChannel | None = None
        while True:
            await asyncio.sleep(5)
            if channel is None:
                channel = self.get_channel(self.channel_id)  # type: ignore
                if channel is None:
                    continue
            for esc in esc_module.pending():
                if esc["id"] in self._posted:
                    continue
                self._posted.add(esc["id"])
                _save_posted(self._posted)
                try:
                    await self._post_escalation(channel, esc)
                except Exception as e:
                    _console.print(f"[red]Bot post error: {e}[/red]")

    async def _post_escalation(
        self, channel: discord.TextChannel, esc: dict
    ) -> None:
        thread = await self._get_or_create_thread(channel, esc["resource_id"])

        label = _ACTION_LABELS.get(esc["action"], esc["action"])
        type_label = _ESCALATION_LABELS.get(
            esc["escalation_type"], esc["escalation_type"]
        )
        color = (
            discord.Color.red()
            if esc["escalation_type"] == "destructive_action"
            else discord.Color.orange()
        )
        embed = discord.Embed(
            title=f"🚨 {label}",
            description=esc["reason"][:2048],
            color=color,
        )
        embed.add_field(name="Action", value=f"`{esc['action']}`", inline=True)
        embed.add_field(
            name="Ressource",
            value=f"`{esc['resource_id'].split('/')[-1]}`",
            inline=True,
        )
        parts = [esc.get("ttp", ""), esc.get("severity", ""), type_label]
        embed.add_field(
            name="Contexte",
            value=" · ".join(filter(None, parts)),
            inline=False,
        )
        if esc.get("suggested_steps"):
            steps = "\n".join(f"• {s}" for s in esc["suggested_steps"][:3])
            embed.add_field(
                name="Prochaines étapes", value=steps[:1024], inline=False
            )
        embed.set_footer(text=f"Run: {esc['run_id']} · ID: {esc['id'][:8]}")
        view = EscalationView(esc)
        await thread.send(embed=embed, view=view)


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
