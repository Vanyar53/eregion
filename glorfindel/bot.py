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
from glorfindel.chat_text import discord_code, discord_text
from glorfindel.escalations import _ACTION_LABELS, _ESCALATION_LABELS

_console = Console()
_POSTED_STORE = Path.home() / ".glorfindel" / "bot_posted.json"
_THREADS_STORE = Path.home() / ".glorfindel" / "bot_threads.json"
# escalation id → the Discord message that carries its buttons. A restarted bot gives each
# message its view back (add_view): without it, every button posted before a redeploy
# answered « interaction failed » (16/10).
_MESSAGES_STORE = Path.home() / ".glorfindel" / "bot_messages.json"
_RESTORE_DAYS = 14
# escalation id → the card state its Discord message last showed (status|verdict|count).
# The bot only posted new cards: a card acknowledged or judged in the War Room kept live
# buttons in Discord, and repeats never showed (16/10).
_SYNCED_STORE = Path.home() / ".glorfindel" / "bot_synced.json"
_SYNC_EVERY = 3  # watch-loop turns (5 s each) between two syncs of the posted messages
# The observation's week, posted in the channel every Monday from 08:00 UTC — what
# `glorfindel report --since 7d` says, without opening anything.
_WEEKLY_STORE = Path.home() / ".glorfindel" / "bot_weekly.json"
_WEEKLY_HOUR_UTC = 8


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


# Escalation types whose card is anchored on a VM the detection may not concern (AL1;
# an identity detection names no VM — C2): never a command, nor a button, aimed at that VM.
_ANCHORED_TYPES = {"control_plane_change", "identity_change", "unattributed_signal"}


def _cli_command(esc: dict) -> str:
    """Return CLI command(s) the operator should run for this escalation."""
    action = esc["action"]
    rid = esc["resource_id"]
    esc_id = esc["id"]
    if esc.get("escalation_type") in _ANCHORED_TYPES:
        return f"glorfindel ack {esc_id}"
    if action == "restore_from_backup":
        # The moment is asked (SEC4c): the card's first detection — the attack began before.
        before = esc.get("first_seen") or esc.get("timestamp") or "<ISO8601>"
        return (
            "# --before : un instant avant le début de l'attaque (ici la 1re détection de la carte)\n"
            f"glorfindel restore {rid} --yes --before {before}\n"
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
    """Never a past participle for what did not run. An action or a type Glorfindel has no
    label for (the model may name any action) is shown as written, never as Markdown."""
    action, etype = esc.get("action", ""), esc.get("escalation_type", "")
    type_label = _ESCALATION_LABELS.get(etype) or discord_text(etype)
    if etype in _RAN:
        return f"🚨 {_ACTION_LABELS.get(action) or discord_text(action)} — {type_label}"
    rec = _RECOMMEND_LABELS.get(action)
    if etype in _ATTEMPTED:
        return f"🚨 {rec.capitalize() if rec else discord_text((action or '?').capitalize())} — {type_label}"
    if not rec or not esc_module.is_decision(esc):
        return f"🚨 {_ACTION_LABELS.get(action) or type_label[:1].upper() + type_label[1:]}"
    return f"🚨 Recommandé : {rec} (non exécuté)"


def _embed_body(esc: dict) -> tuple[str, list[tuple[str, str, bool]]]:
    """The description and fields: the evidence to judge on (the model's explanation, the
    IP a block targets, the rule, the confidence), then why it did not run.

    Every text from outside — the model's, Azure's names (an Entra application's display
    name), a rule's — is escaped (SEC6, N-09: glorfindel/chat_text.py), then cut."""
    explanation = (esc.get("explanation") or "").strip()
    reason = (esc.get("reason") or "").strip()
    fields: list[tuple[str, str, bool]] = [
        ("Action", discord_code(esc.get("action") or "—"), True),
        ("Ressource", discord_code((esc.get("resource_id") or "").split("/")[-1]), True),
    ]
    params = esc.get("action_params") or {}
    if params.get("ip"):
        target = str(params["ip"]) + (f":{params['port']}" if params.get("port") else "")
        fields.append(("Cible", discord_code(target), True))
    if esc.get("rule_name"):
        fields.append(("Règle", discord_code(esc["rule_name"]), True))
    if esc.get("confidence"):
        fields.append(("Confiance", f"{round(float(esc['confidence']) * 100)} %", True))
    rec = esc.get("recurrence")
    if rec:
        verdict = f", jugée {rec['last_verdict']}" if rec.get("last_verdict") else ""
        fields.append(("Déjà vue", f"↻ même IP {rec['previous']}× en 7 jours — dernière le "
                       f"{str(rec.get('last_seen') or '')[:16].replace('T', ' ')} UTC{verdict}", False))
    type_label = _ESCALATION_LABELS.get(esc.get("escalation_type", ""), esc.get("escalation_type", ""))
    fields.append(("Contexte", discord_text(" · ".join(filter(None, [
        str(esc.get("ttp") or ""), str(esc.get("severity") or ""), type_label]))), False))
    if explanation and reason and reason != explanation:
        fields.append(("Pourquoi rien n'est exécuté", discord_text(reason)[:1024], False))
    if esc.get("suggested_steps"):
        steps = "\n".join(f"• {discord_text(s)}" for s in esc["suggested_steps"][:3])
        fields.append(("Prochaines étapes", steps[:1024], False))
    return discord_text(explanation or reason)[:2048], fields


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


def _posted_at(esc: dict):
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(esc.get("first_seen") or esc.get("timestamp")).replace("Z", "+00:00"))
    except ValueError:
        return None


def _posted_within(escs: list[dict], messages: dict[str, int], now=None) -> list[tuple[dict, int]]:
    """(escalation, message id) of every card posted in the last _RESTORE_DAYS days — what the
    sync keeps in line with its card, settled ones included (their buttons greyed)."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    out = []
    for e in escs:
        mid = messages.get(e.get("id", ""))
        when = _posted_at(e) if mid else None
        if when is not None and now - when <= timedelta(days=_RESTORE_DAYS):
            out.append((e, mid))
    return out


def _known_vms() -> set[str] | None:
    """The VMs the discovery knows (lowercase resource ids), or None when it knows none — an
    empty or unreadable registry says nothing of a VM, never that it is gone."""
    try:
        from glorfindel.discovery import AssetRegistry
        known = {a.resource_id.lower() for a in AssetRegistry().all() if a.resource_id}
    except Exception:
        return None
    return known or None


# What a button does: `act` (the card's action, its ack, its command — while it is pending) or
# `judge` (its verdict — a decision not judged yet, acknowledged or not).
_JUDGE_PREFIX = "glorfindel_verdict_"


def _button_kind(custom_id: str) -> str:
    return "judge" if str(custom_id or "").startswith(_JUDGE_PREFIX) else "act"


def _stale_reason(esc: dict | None, kind: str, now=None, known_vms: set[str] | None = None) -> str:
    """Why a button of this card no longer does anything ("" while it still waits) — V-08: a
    card settled, expired, or whose VM the discovery no longer knows has no live button."""
    from datetime import datetime, timedelta, timezone
    if not isinstance(esc, dict):
        return "carte introuvable"
    now = now or datetime.now(timezone.utc)
    when = _posted_at(esc)
    if when is None or now - when > timedelta(days=_RESTORE_DAYS):
        return f"expirée (plus de {_RESTORE_DAYS} jours)"
    rid = str(esc.get("resource_id") or "").lower()
    if (known_vms is not None and esc.get("escalation_type") not in _ANCHORED_TYPES
            and "/virtualmachines/" in rid and rid.rstrip("/") not in known_vms):
        return "sa VM n'est plus dans la découverte"
    if kind == "judge":
        if not esc_module.is_decision(esc):
            return "rien à juger"
        if esc.get("verdict"):
            return f"déjà jugée ({esc['verdict']})"
        return ""
    if esc.get("status") != "pending":
        return "acquittée"
    return ""


def _waits(esc: dict, now=None, known_vms: set[str] | None = None) -> bool:
    """The card still waits for something: its action or ack, or its verdict."""
    return not _stale_reason(esc, "act", now, known_vms) or not _stale_reason(esc, "judge", now, known_vms)


def _views_to_restore(escs: list[dict], messages: dict[str, int], now=None,
                      known_vms: set[str] | None = None) -> list[tuple[dict, int]]:
    """(escalation, message id) whose buttons must answer again after a restart: the cards
    posted in the last _RESTORE_DAYS days that still wait — pending, or a decision still to
    judge (V-08). A card acknowledged and judged, expired, or whose VM is gone is not
    re-armed: its buttons stay greyed, and a click on one answers « carte réglée »."""
    return [(e, mid) for e, mid in _posted_within(escs, messages, now) if _waits(e, now, known_vms)]


def _current(esc_id: str) -> dict | None:
    """The card as the store holds it now — never as it was when its view was built."""
    return next((e for e in esc_module.all_escalations() if e.get("id") == esc_id), None)


async def _still_waits(interaction: discord.Interaction, esc_id: str, kind: str) -> bool:
    """At the click, the card read again (V-08): a button of a card settled since its view was
    built — acknowledged or judged elsewhere, expired, its VM gone — runs nothing, and says so."""
    why = _stale_reason(_current(esc_id), kind, known_vms=_known_vms())
    if not why:
        return True
    custom_id = (getattr(interaction, "data", None) or {}).get("custom_id", "?")
    _console.print(f"[dim]Stale button on {esc_id[:8]} [{custom_id}] — {why}[/dim]")
    await interaction.response.send_message(
        f"✓ Carte réglée — {why} : ce bouton ne lance plus rien.", ephemeral=True)
    return False


def _load_synced() -> dict[str, str]:
    if _SYNCED_STORE.exists():
        try:
            return {k: str(v) for k, v in json.loads(_SYNCED_STORE.read_text()).items()}
        except (ValueError, AttributeError):
            return {}
    return {}


def _save_synced(synced: dict[str, str]) -> None:
    _SYNCED_STORE.parent.mkdir(parents=True, exist_ok=True)
    _SYNCED_STORE.write_text(json.dumps(synced))


def _card_signature(esc: dict) -> str:
    return f"{esc.get('status', '')}|{esc.get('verdict') or ''}|{int(esc.get('occurrences') or 1)}"


def _card_state_line(esc: dict) -> str:
    """What became of the card, wherever it was handled (Discord, War Room, CLI)."""
    parts = []
    if esc.get("verdict"):
        parts.append(f"jugée {esc['verdict']}")
    parts.append("acquittée" if esc.get("status") == "resolved" else "en attente")
    n = int(esc.get("occurrences") or 1)
    if n > 1:
        parts.append(f"{n}× (dernière : {str(esc.get('last_seen') or '')[11:16]} UTC)")
    return " · ".join(parts)


def _weekly_due(now, last_sent: str | None) -> bool:
    """Monday from 08:00 UTC, once per week."""
    if now.weekday() != 0 or now.hour < _WEEKLY_HOUR_UTC:
        return False
    return last_sent != now.date().isoformat()


def _weekly_summary(report: dict, to_judge: int, now) -> str:
    from datetime import timedelta
    start = (now - timedelta(days=7)).strftime("%d/%m")
    d = report.get("disruptive") or {}
    rate = "—" if d.get("false_rate") is None else f"{round(d['false_rate'] * 100)} %"
    lines = [
        f"📊 **Observation — semaine du {start} au {now.strftime('%d/%m')}**",
        f"{report.get('cards', 0)} carte(s) de décision · {report.get('judged', 0)} jugée(s) · "
        f"isoler/bloquer jugés faux : **{rate}**"
        + (f" · {report['exercises']} exercice(s) écarté(s)" if report.get("exercises") else ""),
    ]
    blocks = report.get("blocks") or {}
    if blocks.get("cards"):
        lines.append(f"🔁 blocages recommandés : {blocks['cards']} carte(s) pour {blocks['distinct_ips']} IP distincte(s)")
    rules = sorted((report.get("by_rule") or {}).items(), key=lambda kv: -sum(kv[1].values()))
    for name, b in rules[:5]:
        lines.append(f"• {discord_code(name)} : {b.get('right', 0)} right · {b.get('wrong', 0)} wrong · "
                     f"{b.get('unsure', 0)} unsure · {b.get('unjudged', 0)} non jugée(s)")
    lines.append(f"⚖️ **{to_judge} carte(s) à juger**" if to_judge else "✓ Rien à juger.")
    return "\n".join(lines)


# M-3 (#183): who may press a card's buttons. They set verdicts, acknowledge cards and run
# restores; Discord shows them to whoever reads the channel. Closed by default: with no list,
# every click is refused, said to the clicker and logged — an open default would let a
# forgotten variable hand the buttons to the whole server, and the War Room (behind its
# token) still judges every card meanwhile.
_ALLOWED_USERS_ENV = "DISCORD_ALLOWED_USERS"
_ALLOWED_ROLES_ENV = "DISCORD_ALLOWED_ROLES"


def _parse_ids(raw: str) -> tuple[frozenset[int], list[str]]:
    """Discord ids, comma- or space-separated. What is not an id (a name, a mention) is
    returned apart, never matched."""
    ids, bad = set(), []
    for part in (raw or "").replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            ids.add(int(part))
        else:
            bad.append(part)
    return frozenset(ids), bad


class ButtonPolicy:
    """The users (by id) and the roles (by id) allowed to press the buttons."""

    def __init__(self, users: frozenset[int] = frozenset(), roles: frozenset[int] = frozenset()):
        self.users = frozenset(users)
        self.roles = frozenset(roles)

    @classmethod
    def from_env(cls, environ) -> tuple["ButtonPolicy", list[str]]:
        users, bad_users = _parse_ids(environ.get(_ALLOWED_USERS_ENV, ""))
        roles, bad_roles = _parse_ids(environ.get(_ALLOWED_ROLES_ENV, ""))
        return cls(users, roles), bad_users + bad_roles

    @property
    def configured(self) -> bool:
        return bool(self.users or self.roles)

    def allows(self, user) -> bool:
        if user is None:
            return False
        if getattr(user, "id", None) in self.users:
            return True
        # A guild member carries its roles; a user outside a guild (a DM) has none.
        held = {getattr(r, "id", None) for r in (getattr(user, "roles", None) or ())}
        return bool(held & self.roles)


async def _refuse(interaction: discord.Interaction, esc_id: str, policy) -> None:
    user = interaction.user
    why = ("aucun utilisateur ni rôle autorisé (fermé par défaut)"
           if not isinstance(policy, ButtonPolicy) or not policy.configured
           else "absent des utilisateurs et rôles autorisés")
    custom_id = (getattr(interaction, "data", None) or {}).get("custom_id", "?")
    _console.print(
        f"[yellow]Button refused: user {getattr(user, 'id', '?')} "
        f"({getattr(user, 'display_name', '?')}) on {esc_id[:8]} [{custom_id}] — {why}[/yellow]"
    )
    await interaction.response.send_message(
        f"✗ Bouton refusé : {why}. Un opérateur ajoute ton id Discord à "
        f"`{_ALLOWED_USERS_ENV}` (ou un de tes rôles à `{_ALLOWED_ROLES_ENV}`).",
        ephemeral=True,
    )


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
            f"⚡ **{discord_text(interaction.user.display_name)}** → {discord_code(cmd_display)}"
        )

        channel = interaction.channel
        asyncio.create_task(_execute_and_report(self.esc, self.cli_args, channel, self._run,
                                                interaction.message, self.view))

    def _run(self) -> tuple[int, str]:
        return _run_cli(self.cli_args)


def _run_cli(cli_args: list[str]) -> tuple[int, str]:
    """(return code, output) of a glorfindel command."""
    import subprocess
    result = subprocess.run(
        [_glorfindel_bin()] + cli_args,
        capture_output=True,
        text=True,
        timeout=1800,  # 30 min max (restore ~20 min)
    )
    return result.returncode, (result.stdout + result.stderr).strip()


async def _execute_and_report(esc: dict, cli_args: list[str], channel, run, card_message=None,
                              card_view=None, on_done=None) -> None:
    """Run the command, say its output in the thread; the card is acknowledged only once it
    succeeded (SEC4c) — a refusal or a failure is said, the card stays open and its buttons
    come back."""
    try:
        loop = asyncio.get_running_loop()
        code, output = await loop.run_in_executor(None, run)
        # The CLI's output (names from Azure in it): no ``` of its own closes the block.
        short = output.strip()[:1800].replace("`", "ˋ") or "(pas de sortie)"
        await channel.send(f"```\n{short}\n```")
        if code != 0:
            await channel.send(f"✗ Refusé ou en échec (code {code}) : la carte reste ouverte.")
            if card_message is not None and card_view is not None:
                for item in card_view.children:
                    item.disabled = False  # type: ignore[attr-defined]
                await card_message.edit(view=card_view)
            return
        esc_module.resolve(esc["id"])
        # Archive thread if no more pending escalations for this resource
        remaining = [
            e for e in esc_module.pending()
            if e["resource_id"] == esc["resource_id"]
        ]
        if not remaining and isinstance(channel, discord.Thread):
            await channel.edit(
                archived=True, reason="All escalations acknowledged"
            )
    except Exception as exc:
        await channel.send(f"✗ Erreur lors de l'exécution : {discord_text(exc)} — la carte reste ouverte.")
    finally:
        if on_done is not None:
            on_done()


# The cards whose restore this bot is running (SEC4c): a second confirmation — a second form,
# a double click — is refused and says so, until the first one ends.
_RESTORING: set[str] = set()


async def _allowed(interaction: discord.Interaction, esc_id: str) -> bool:
    """The clicker is allowed by the bot's ButtonPolicy (M-3), or refused and told."""
    policy = getattr(interaction.client, "button_policy", None)
    if isinstance(policy, ButtonPolicy) and policy.allows(interaction.user):
        return True
    await _refuse(interaction, esc_id, policy)
    return False


# The field's label, by where its moment comes from (a Discord label: 45 characters at most).
_MOMENT_LABELS = {"exercise": "Point d'avant… (début de l'exercice, UTC)",
                  "card": "Point d'avant… (1re détection, UTC)",
                  "": "Point d'avant… (début de l'attaque, UTC)"}


class _RestoreButton(discord.ui.Button):
    """A restore asks for its moment (SEC4c): a form, filled with the moment the runs/ channel
    gives for this VM (an exercise), else the card's first detection."""

    def __init__(self, esc: dict) -> None:
        super().__init__(label="🔄 Restore", style=discord.ButtonStyle.primary,
                         custom_id=f"glorfindel_exec_{esc['id'][:8]}", row=1)
        self.esc = esc

    async def callback(self, interaction: discord.Interaction) -> None:
        from glorfindel import restore_plan
        # Discord wants the form within 3 s: runs/ is read off the event loop, and given up
        # past 2 s (the card's own moment then).
        rid = self.esc["resource_id"]
        loop = asyncio.get_running_loop()
        try:
            plan = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: restore_plan.proposed_moment(rid, self.esc)), timeout=2.0)
        except Exception:
            plan = restore_plan.proposed_moment(rid, self.esc, read_runs=False)
        await interaction.response.send_modal(
            _RestoreModal(self.esc, plan, interaction.message, self.view))


class _RestoreModal(discord.ui.Modal):
    def __init__(self, esc: dict, plan: dict, card_message=None, card_view=None) -> None:
        super().__init__(title="Restaurer depuis la sauvegarde", timeout=600)
        self.esc, self.plan = esc, plan
        self.card_message, self.card_view = card_message, card_view
        text = _MOMENT_LABELS.get(plan.get("source", ""), _MOMENT_LABELS[""])
        if hasattr(discord.ui, "Label"):     # discord.py ≥ 2.6 (the lock: 2.7)
            self.moment = discord.ui.TextInput(
                default=plan.get("before") or None, placeholder="2026-10-29T08:00:00+00:00",
                required=True, max_length=40)
            # Where the moment comes from, under the field (a description: 100 characters).
            self.field = discord.ui.Label(
                text=text, description=(str(plan.get("why") or "")[:100] or None),
                component=self.moment)
        else:
            self.moment = self.field = discord.ui.TextInput(
                label=text, default=plan.get("before") or None,
                placeholder="2026-10-29T08:00:00+00:00", required=True, max_length=40)
        self.add_item(self.field)

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return (await _allowed(interaction, self.esc["id"])
                and await _still_waits(interaction, self.esc["id"], "act"))

    async def on_submit(self, interaction: discord.Interaction) -> None:
        from glorfindel import restore_plan
        try:
            before = restore_plan.parse_moment(self.moment.value)
        except ValueError as exc:
            await interaction.response.send_message(f"✗ {discord_text(exc)}", ephemeral=True)
            return
        await interaction.response.defer()
        loop = asyncio.get_running_loop()
        try:
            points = await loop.run_in_executor(
                None, lambda: restore_plan.points_before(self.esc["resource_id"], before))
            unread = ""
        except Exception as exc:  # unreadable vault: said, the restore stays possible
            points, unread = [], f"{type(exc).__name__}: {exc}"
        await interaction.channel.send(  # type: ignore[union-attr]
            _points_text(self.esc, before, self.plan, points, unread),
            view=_RestoreConfirmView(self.esc, before, self.card_message, self.card_view))


def _points_text(esc: dict, before: str, plan: dict, points: list[dict], unread: str) -> str:
    """What the confirmation shows: the moment, where it came from, the points before it."""
    vm = str(esc.get("resource_id") or "?").rstrip("/").split("/")[-1]
    lines = [f"🔄 Restaurer **{discord_text(vm)}** au point le plus récent d'avant "
             f"{discord_code(before)}"]
    if plan.get("why") and plan.get("before") == before:
        lines.append(f"Moment proposé : {discord_text(plan['why'])}")
    from glorfindel.restore_plan import moment_warning
    warning = moment_warning(str(esc.get("resource_id") or ""), before)
    if warning:
        lines.append(f"⚠ {discord_text(warning)}")
    if unread:
        lines.append(f"Points de restauration illisibles : {discord_text(unread[:300])}")
    elif not points:
        lines.append("Aucun point de restauration avant ce moment : le restore sera refusé.")
    else:
        lines.append("Points avant ce moment (lecture seule) :")
        for i, p in enumerate(points[:8]):
            tier = " · niveau coffre" if p.get("vault_tier") else ""
            during = " · **pris pendant l'incident**" if p.get("during_incident") else ""
            lines.append(f"• {discord_code(str(p.get('time')))}{tier}{during}" + (" ← restauré" if i == 0 else ""))
    return "\n".join(lines)


class _RestoreConfirmView(discord.ui.View):
    """Confirm, and the restore runs with --before; the card is acknowledged once it started."""

    def __init__(self, esc: dict, before: str, card_message=None, card_view=None) -> None:
        super().__init__(timeout=900)
        self.esc, self.before = esc, before
        self.card_message, self.card_view = card_message, card_view

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return (await _allowed(interaction, self.esc["id"])
                and await _still_waits(interaction, self.esc["id"], "act"))

    @discord.ui.button(label="🔄 Confirmer le restore", style=discord.ButtonStyle.primary)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        from glorfindel import restore_plan
        esc_id = self.esc["id"]
        if esc_id in _RESTORING:
            await interaction.response.send_message(
                "✗ Un restore de cette carte est déjà en cours : attendre sa fin (son résultat est dans le fil).",
                ephemeral=True)
            return
        _RESTORING.add(esc_id)
        for item in self.children:
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.response.edit_message(view=self)
        if self.card_view is not None and self.card_message is not None:
            for item in self.card_view.children:
                item.disabled = True  # type: ignore[attr-defined]
            await self.card_message.edit(view=self.card_view)
        args = restore_plan.restore_args(self.esc["resource_id"], self.before)
        await interaction.channel.send(  # type: ignore[union-attr]
            f"⚡ **{discord_text(interaction.user.display_name)}** → {discord_code('glorfindel ' + ' '.join(args))}")
        asyncio.create_task(_execute_and_report(self.esc, args, interaction.channel,
                                                lambda: _run_cli(args), self.card_message,
                                                self.card_view, on_done=lambda: _RESTORING.discard(esc_id)))

    @discord.ui.button(label="Annuler", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        for item in self.children:
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.response.edit_message(content="Restore annulé.", view=self)


def _make_action_button(esc: dict) -> discord.ui.Button | None:
    """Return an execute button for this escalation, or None."""
    action = esc["action"]
    esc_type = esc["escalation_type"]
    rid = esc["resource_id"]

    # A control-plane change or an unattributed signal (AL1): the card's VM is an anchor,
    # chosen among the watched ones — one click on it would restore or revert a VM the
    # detection says nothing of.
    if esc_type in _ANCHORED_TYPES:
        return None
    if action == "restore_from_backup":
        return _RestoreButton(esc)
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
            await interaction.response.send_message(f"✗ {discord_text(exc)}", ephemeral=True)
            return
        # One click: a judged card is also acknowledged (Jonathan, 16/10).
        esc_module.resolve(self.esc["id"])
        for item in self.view.children:  # type: ignore[union-attr]
            item.disabled = True  # type: ignore[attr-defined]
        await interaction.response.edit_message(view=self.view)  # type: ignore[union-attr]
        await interaction.followup.send(
            f"{_VERDICT_WORDS[self.verdict]} — jugé par **{discord_text(interaction.user.display_name)}**"
        )
        remaining = [e for e in esc_module.pending() if e["resource_id"] == self.esc["resource_id"]]
        if not remaining and isinstance(interaction.channel, discord.Thread):
            await interaction.channel.edit(archived=True, reason="All escalations handled")


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

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        """Every button of the card, before its callback (M-3): the clicker must be allowed
        by the bot's ButtonPolicy. No policy, or an empty one: refused."""
        policy = getattr(interaction.client, "button_policy", None)
        if not (isinstance(policy, ButtonPolicy) and policy.allows(interaction.user)):
            await _refuse(interaction, self.esc_id, policy)
            return False
        # Then the card as it is now (V-08): a view re-armed after a restart, or built before
        # the card was settled elsewhere, runs nothing on a card that no longer waits.
        custom_id = (getattr(interaction, "data", None) or {}).get("custom_id", "")
        return await _still_waits(interaction, self.esc_id, _button_kind(custom_id))

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
            f"✓ Acknowledged by **{discord_text(interaction.user.display_name)}**"
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


def _build_embed(esc: dict) -> discord.Embed:
    color = discord.Color.red() if esc.get("escalation_type") == "destructive_action" else discord.Color.orange()
    if esc.get("status") == "resolved":
        color = discord.Color.dark_grey()
    try:
        esc = {**esc, "recurrence": esc_module.recurrence(esc)}
    except Exception:  # a label must never stop a post
        pass
    description, fields = _embed_body(esc)
    embed = discord.Embed(title=_embed_title(esc), description=description, color=color)
    for name, value, inline in fields:
        embed.add_field(name=name, value=value, inline=inline)
    embed.add_field(name="État", value=_card_state_line(esc), inline=False)
    embed.set_footer(text=f"Run: {esc.get('run_id', '')} · ID: {esc['id'][:8]}")
    return embed


def _build_view(esc: dict, known_vms: set[str] | None = None) -> EscalationView:
    """A button that no longer does anything is greyed (V-08, the rule of the click,
    `_stale_reason`): an acknowledged card's action, ack and command; a judged card's verdict;
    every button of an expired card or of a VM the discovery no longer knows."""
    view = EscalationView(esc)
    for item in view.children:
        if _stale_reason(esc, _button_kind(getattr(item, "custom_id", "")), known_vms=known_vms):
            item.disabled = True  # type: ignore[attr-defined]
    return view


class GlorfindelBot(discord.Client):
    def __init__(self, channel_id: int, ping_role: int | None,
                 button_policy: ButtonPolicy | None = None):
        intents = discord.Intents.default()
        # No mention from any text the bot posts (SEC6, N-09): only the role it is set to
        # ping, and only in that message (_get_or_create_thread).
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.tree = app_commands.CommandTree(self)
        self.channel_id = channel_id
        self.ping_role = ping_role
        self.button_policy = button_policy or ButtonPolicy()  # none given: closed
        self._posted: set[str] = _load_posted()
        self._threads: dict[str, int] = _load_threads()
        self._messages: dict[str, int] = _load_messages()
        self._synced: dict[str, str] = _load_synced()
        try:
            self._weekly_last: str | None = json.loads(_WEEKLY_STORE.read_text()).get("last")
        except (OSError, ValueError, AttributeError):
            self._weekly_last = None

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
                label = _ACTION_LABELS.get(e["action"]) or discord_text(e["action"])
                short = e["resource_id"].split("/")[-1]
                lines.append(
                    f"• {discord_code(e['id'][:8])} — **{label}** sur {discord_code(short)}"
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
        for esc, message_id in _views_to_restore(esc_module.all_escalations(), self._messages,
                                                 known_vms=_known_vms()):
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
                f"<@&{self.ping_role}> Incident opened on {discord_code(vm_name)}",
                # Every field said: the message mentions its role alone, whatever the client's
                # own allowed mentions (send merges the two).
                allowed_mentions=discord.AllowedMentions(everyone=False, users=False, replied_user=False,
                                                         roles=[discord.Object(id=self.ping_role)]),
            )
        return thread

    async def _watch_escalations(self) -> None:
        channel: discord.TextChannel | None = None
        _console.print("[dim]Watch loop started[/dim]")
        turn = 0
        while True:
            try:
                await asyncio.sleep(5)
                turn += 1
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
                await self._post_weekly(channel)
                if turn % _SYNC_EVERY == 0:
                    try:
                        await self._sync_messages()
                    except Exception as e:
                        _console.print(f"[red]Bot sync error: {e}[/red]")
            except Exception as e:
                _console.print(f"[red]Watch loop error: {e}[/red]")

    async def _post_escalation(
        self, channel: discord.TextChannel, esc: dict
    ) -> None:
        thread = await self._get_or_create_thread(channel, esc["resource_id"])

        message = await thread.send(embed=_build_embed(esc), view=_build_view(esc))
        self._messages[esc["id"]] = message.id
        _save_messages(self._messages)
        self._synced[esc["id"]] = _card_signature(esc)
        _save_synced(self._synced)

    async def _sync_messages(self) -> int:
        """Bring each posted message in line with its card: acknowledged or judged in the
        War Room → buttons off and the state said; repeats → « N× »; a VM with nothing
        left pending → its thread archived. Returns the number of messages edited."""
        edited, touched, changed = 0, set(), False
        known_vms = _known_vms()
        for esc, message_id in _posted_within(esc_module.all_escalations(), self._messages):
            sig = _card_signature(esc)
            if self._synced.get(esc["id"]) == sig:
                continue
            thread = await self._thread_of(esc.get("resource_id", ""))
            if thread is None:
                continue
            # One attempt per state change, whatever happens: a failing edit retried every
            # 15 s logged 10 800 errors in a day (19/10).
            self._synced[esc["id"]] = sig
            changed = True
            try:
                if getattr(thread, "archived", False):
                    # Discord archives an idle thread on its own; a message in it can't be
                    # edited until it is reopened (50083) — archived again below.
                    await thread.edit(archived=False, reason="Card updated")
                try:
                    await thread.get_partial_message(message_id).edit(
                        embed=_build_embed(esc), view=_build_view(esc, known_vms))
                except discord.HTTPException as exc:
                    if exc.code != 50083:
                        raise
                    # The cached thread read open, Discord had archived it without a
                    # THREAD_UPDATE (#169, 20/10): reopen it, try again once.
                    await thread.edit(archived=False, reason="Card updated")
                    await thread.get_partial_message(message_id).edit(
                        embed=_build_embed(esc), view=_build_view(esc, known_vms))
            except discord.NotFound:
                # The message is gone (deleted in Discord): forget it.
                self._messages.pop(esc["id"], None)
                _save_messages(self._messages)
                continue
            except discord.HTTPException as exc:
                _console.print(f"[yellow]Sync {esc['id'][:8]}: {exc}[/yellow]")
                continue
            finally:
                touched.add(esc.get("resource_id", ""))
            edited += 1
        if changed:
            _save_synced(self._synced)
        pending_rids = {e.get("resource_id", "") for e in esc_module.pending()}
        for rid in touched - pending_rids:
            thread = await self._thread_of(rid)
            if thread is not None and not thread.archived:
                await thread.edit(archived=True, reason="All escalations handled")
        return edited

    async def _post_weekly(self, channel) -> bool:
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        if not _weekly_due(now, self._weekly_last):
            return False
        report = esc_module.observation_report(now - timedelta(days=7))
        to_judge = len(esc_module.to_judge(now - timedelta(days=7)))
        await channel.send(_weekly_summary(report, to_judge, now))
        self._weekly_last = now.date().isoformat()
        _WEEKLY_STORE.parent.mkdir(parents=True, exist_ok=True)
        _WEEKLY_STORE.write_text(json.dumps({"last": self._weekly_last}))
        return True

    async def _thread_of(self, resource_id: str):
        tid = self._threads.get(resource_id)
        if not tid:
            return None
        thread = self.get_channel(tid)
        if thread is None:
            try:
                thread = await self.fetch_channel(tid)
            except discord.HTTPException:
                return None
        return thread if isinstance(thread, discord.Thread) else None


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
    policy, bad = ButtonPolicy.from_env(os.environ)
    for b in bad:
        _console.print(f"[yellow]⚠ « {b} » n'est pas un id Discord : ignoré "
                       f"({_ALLOWED_USERS_ENV} / {_ALLOWED_ROLES_ENV})[/yellow]")
    if policy.configured:
        _console.print(f"[dim]  → Boutons : {len(policy.users)} utilisateur(s), "
                       f"{len(policy.roles)} rôle(s) autorisé(s)[/dim]")
    else:
        _console.print(
            f"[yellow]⚠ {_ALLOWED_USERS_ENV} et {_ALLOWED_ROLES_ENV} vides : tous les boutons "
            "refusent (fermé par défaut). Les cartes se jugent dans la console (page Glorfindel, TO JUDGE).[/yellow]")
    bot = GlorfindelBot(channel_id=int(channel_id_str), ping_role=ping_role, button_policy=policy)
    bot.run(token, log_handler=None)
