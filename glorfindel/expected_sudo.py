"""The sudo the administrators are expected to run (ADM1, #284).

`sudo-privilege-escalation` (SEC2) finds every real sudo to root — most of them, on a VM
in use, its administrators'. In `human_only` each one is a card to judge; in
`non_disruptive` each one can launch a snapshot (a real backup of the vault), and the model
isolated at 93 % on this rule in production. The safety of that answer is not handed to the
model's confidence: like a rule's threshold, the expected sudo are set aside **before**
any signal exists — by the RulePoller, in code — and never in the prompt.

- `glorfindel-config.yaml`, `expected_sudo.admins`: the accounts expected per VM or pattern
  of VMs (`glorfindel.config.ExpectedSudoConfig`, read strictly: a form nobody reads refuses
  the file, and the watch does not start on it).
- A sudo line opens no card when, all at once: it is sudo's own form (`<account> : TTY=… ;
  PWD=… ; USER=root ; … COMMAND=…`, the fields separated by « ; » or by spaces, as the agent
  writes them, `TTY=` absent without a terminal), every `USER=` before the command says
  root, the account is expected on the VM the line was routed to, and the command is not
  sensitive (`SENSITIVE_SHIPPED`, plus the config's `sensitive_commands`). Anything else —
  a line read another way, another account, `sudo -u other`, a line no VM claims — stays a
  card: what cannot be read is never excluded.
- Never silent: each sudo set aside is written to `~/.glorfindel/expected_sudo.jsonl`
  (when, VM, account, command) before it is set aside — a journal that cannot be written
  excludes nothing — and counted in `rule_status.json`; `glorfindel report` and the
  console show both.
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# The technique of the rules whose rows are sudo lines: the shipped
# `sudo-privilege-escalation`, or a client's rule on the same technique.
SUDO_TTP = "T1548.003"

_JOURNAL = Path.home() / ".glorfindel" / "expected_sudo.jsonl"
# Past this size, the oldest half goes; the report says from when its count runs.
_JOURNAL_MAX_BYTES = 2 * 1024 * 1024
# What a journal line keeps of a command, and what is read of one (a log line is unbounded).
_COMMAND_KEPT = 300
_COMMAND_READ = 8192

# sudo's form, as the shipped rule's regex reads it: the account, then the fields from TTY=
# or PWD= (a failure, « 3 incorrect password attempts ; … », starts otherwise) up to the
# first COMMAND= that follows a « ; » or a space. The command is the rest — whatever a PWD
# holds before it, the real command is in that rest, since sudo writes COMMAND last.
_LINE = re.compile(r"\s*(?P<account>\S+) : (?P<fields>(?:TTY|PWD)=.*?[ ;])COMMAND=(?P<command>.*)", re.DOTALL)
_RUN_AS = re.compile(r"(?:^|[ ;])USER=([^ ;]*)")

# Commands that make a card even from an expected account: what an administrator rarely does
# under sudo and an intruder with that account would (case ignored, read in the whole command
# line, `bash -c '…'` included). Extended — never replaced — by `sensitive_commands`.
_AGENTS = (r"azuremonitoragent|azuremonitor-\S+|omsagent|mdsd|rsyslog|syslog-ng|auditd|mdatp|"
           r"walinuxagent|waagent|amazon-cloudwatch-agent|falcon-sensor|osqueryd|wazuh-agent")
SENSITIVE_SHIPPED: tuple[tuple[str, str], ...] = (
    # /etc/shadow, /etc/gshadow, `cd /etc && cat shadow`
    ("shadow", r"\bg?shadow\b"),
    # an account created, changed, deleted, its password set (root's, with a bare `passwd`)
    ("accounts", r"(?:^|[\s/;&|(`'\"])(?:useradd|adduser|usermod|userdel|deluser|passwd|chpasswd|chage|"
                 r"gpasswd|groupadd|groupmod|newusers|vipw|vigr)(?=$|[\s;&|)`'\"])"),
    # who may sudo
    ("sudoers", r"\bsudoers\b|\bvisudo\b"),
    # a setuid or setgid bit (u+s, g+s, +s, 4755, 2755), a capability
    ("setuid", r"\bchmod\b[^;&|]*?(?:[\s,][ugoa]*[+=][rwxXt]*s|\s0?[2-7][0-7]{3}\b)"),
    ("capabilities", r"\bsetcap\b"),
    # a supervision agent stopped, disabled, masked, killed, removed; the audit rules changed
    ("supervision", rf"(?=.*\b(?:stop|disable|mask|kill|pkill|killall|remove|purge|erase|uninstall)\b)"
                    rf"(?=.*\b(?:{_AGENTS})\b)"),
    ("audit", r"\bauditctl\b"),
    # the logs deleted or emptied
    ("logs", r"\b(?:rm|shred|truncate|unlink)\b[^;&|]*?/var/log\b|>\s*/var/log/|\bjournalctl\b[^;&|]*?--vacuum"),
    # an SSH key planted, PAM or the loader changed
    ("ssh_keys", r"\bauthorized_keys\b"),
    ("pam", r"/etc/pam\.d\b|\bpam_\w+\.so\b"),
    ("preload", r"\bld\.so\.preload\b"),
)
_SENSITIVE = tuple((name, re.compile(rx, re.IGNORECASE | re.DOTALL)) for name, rx in SENSITIVE_SHIPPED)


@dataclass(frozen=True)
class SudoLine:
    account: str
    run_as: tuple[str, ...]      # every USER= before the command
    command: str

    @property
    def to_root(self) -> bool:
        return bool(self.run_as) and all(u == "root" for u in self.run_as)


def parse(message) -> SudoLine | None:
    """sudo's line, read as the shipped rule reads it; None for any other form."""
    if not isinstance(message, str):
        return None
    m = _LINE.fullmatch(message)
    if m is None:
        return None
    return SudoLine(account=m["account"], run_as=tuple(_RUN_AS.findall(m["fields"])),
                    command=m["command"].strip())


def sensitive(command: str, extra=()) -> str | None:
    """What makes this command sensitive (a shipped category, or the config's text), or None."""
    text = command[:_COMMAND_READ]
    for name, rx in _SENSITIVE:
        if rx.search(text):
            return name
    low = text.lower()
    for t in extra or ():
        if t and t.lower() in low:
            return f"config: {t}"
    return None


def judge(row: dict, asset_name: str, policy) -> dict | None:
    """The journal entry of an expected sudo — or None: the row stays a card. `asset_name`:
    the VM the row was routed to (empty when none claims it)."""
    if policy is None or not getattr(policy, "admins", None) or not asset_name:
        return None
    line = parse(row.get("SyslogMessage"))
    if line is None or not line.to_root:
        return None
    if line.account not in policy.accounts_for(asset_name):
        return None
    if sensitive(line.command, policy.sensitive_commands) is not None:
        return None
    return {"asset": asset_name, "account": line.account, "command": line.command[:_COMMAND_KEPT],
            "logged_at": str(row.get("TimeGenerated") or "")}


def record(entries: list[dict], rule_name: str, now_iso: str) -> bool:
    """Write the sudo set aside to the journal, before they are set aside. False when it
    cannot be written: the caller then excludes nothing."""
    if not entries:
        return True
    try:
        _JOURNAL.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(_JOURNAL, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write("".join(json.dumps({"at": now_iso, "rule": rule_name, **e}, ensure_ascii=False) + "\n"
                            for e in entries))
    except OSError as exc:
        logger.warning("expected sudo: journal %s not written (%s) — every sudo stays a card", _JOURNAL, exc)
        return False
    _trim()
    return True


def _trim() -> None:
    """Past `_JOURNAL_MAX_BYTES`, keep the newest half (the report says from when it runs)."""
    try:
        if _JOURNAL.stat().st_size <= _JOURNAL_MAX_BYTES:
            return
        lines = _JOURNAL.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        fd, tmp = tempfile.mkstemp(dir=_JOURNAL.parent, prefix=".expected_sudo.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.writelines(lines[len(lines) // 2:])
        os.replace(tmp, _JOURNAL)
    except OSError as exc:
        logger.warning("expected sudo: journal %s not trimmed (%s)", _JOURNAL, exc)


def _when(text) -> datetime | None:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None


def summary(since: datetime | None = None, latest: int = 10) -> dict:
    """The sudo set aside since `since` (all if None): how many, per VM, per account, the
    latest ones, and from when the journal runs. A journal that cannot be read is said
    (`error`), a line that cannot be read counted (`unreadable`) — never a silent zero."""
    out: dict = {"count": 0, "by_asset": {}, "by_account": {}, "latest": [], "journal_from": None,
                 "unreadable": 0, "error": ""}
    try:
        text = _JOURNAL.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return out
    except OSError as exc:
        out["error"] = f"{_JOURNAL}: {exc}"
        return out
    kept = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        try:
            e = json.loads(raw)
            at = _when(e["at"])
            asset, account = str(e["asset"]), str(e["account"])
        except (ValueError, KeyError, TypeError):
            out["unreadable"] += 1
            continue
        if at is None or at.tzinfo is None:
            out["unreadable"] += 1
            continue
        if out["journal_from"] is None:
            out["journal_from"] = at.isoformat()
        if since is not None and at < since:
            continue
        out["count"] += 1
        out["by_asset"][asset] = out["by_asset"].get(asset, 0) + 1
        out["by_account"][account] = out["by_account"].get(account, 0) + 1
        kept.append({"at": at.isoformat(), "asset": asset, "account": account,
                     "command": str(e.get("command") or "")[:_COMMAND_KEPT]})
    out["latest"] = kept[-latest:] if latest else []
    return out
