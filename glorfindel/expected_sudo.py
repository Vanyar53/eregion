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
  writes them, `TTY=` absent without a terminal) and not ambiguous (shorter than sudo's cut,
  no line break, one COMMAND=), every `USER=` of the line says root, the account is expected
  on the VM the line was routed to, and neither the command nor the loader's variables in
  ENV= are sensitive (`SENSITIVE_SHIPPED`, plus the config's `sensitive_commands`). Anything
  else — a line read another way, another account, `sudo -u other`, a line no VM claims —
  stays a card: what cannot be read is never excluded.
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
# What a journal line keeps of a command, and what is read of one (a log line is unbounded,
# and the reading runs in the poller: bounded, whatever a local user writes with `logger`).
_COMMAND_KEPT = 300
_COMMAND_READ = 1024
# sudo cuts its syslog lines at `syslog_maxlen` (960 by default): the rest goes into a second
# line, « (command continued) », that the rule does not read. A line this long may be the
# start of a command whose sensitive part is cut off — it is never set aside.
_SUDO_LINE_CUT = 900

# sudo's form, as the shipped rule's regex reads it: the account, then the fields from TTY=
# or PWD= (a failure, « 3 incorrect password attempts ; … », starts otherwise) up to the
# COMMAND= that follows a « ; » or a space; the command is the rest. Ambiguous, so a card: a
# second COMMAND=, a USER= anywhere that is not root, a line break (`parse`) — what a PWD or
# a command can be made to write.
_LINE = re.compile(r"\s*(?P<account>\S+) : (?P<fields>(?:TTY|PWD)=.*?[ ;])COMMAND=(?P<command>.*)", re.DOTALL)
_RUN_AS = re.compile(r"(?:^|[ ;])USER=([^ ;]*)")
# The loader's variables kept by sudo in its ENV= field (`sudo LD_PRELOAD=… cmd`).
_LD_ENV = re.compile(r"\bLD_(?:PRELOAD|LIBRARY_PATH|AUDIT)=", re.IGNORECASE)

# Commands that make a card even from an expected account: what an administrator rarely does
# under sudo and an intruder with that account would (case ignored, read in the whole command
# line, `bash -c '…'` included). Extended — never replaced — by `sensitive_commands`. Each one
# linear in the command's length: a lookahead is anchored at the start (`\A`).
_AGENTS = (r"azuremonitoragent|azuremonitor-\S+|omsagent|mdsd|rsyslog|syslog-ng|auditd|mdatp|"
           r"walinuxagent|waagent|amazon-cloudwatch-agent|falcon-sensor|osqueryd|wazuh-agent")
_DISABLE = (r"\b(?:stop|disable|mask|kill|pkill|killall|remove|purge|erase|uninstall|rm|mv|unlink)\b"
            r"|\bdpkg\b[^;&|]*?\s-[a-zA-Z]*[rP]|\brpm\b[^;&|]*?\s-[a-zA-Z]*e"
            r"|\bchmod\b[^;&|]*?[\s,][ugoa]*-[rwX]*x")
SENSITIVE_SHIPPED: tuple[tuple[str, str], ...] = (
    # /etc/shadow, /etc/gshadow, `cd /etc && cat shadow`
    ("shadow", r"\bg?shadow\b"),
    # an account created, changed, deleted, its password set (root's, with a bare `passwd`)
    ("accounts", r"(?:^|[\s/;&|(`'\"])(?:useradd|adduser|usermod|userdel|deluser|passwd|chpasswd|chage|"
                 r"gpasswd|groupadd|groupmod|newusers|vipw|vigr)(?=$|[\s;&|)`'\"])"),
    # who may sudo
    ("sudoers", r"\bsudoers\b|\bvisudo\b"),
    # a setuid or setgid bit (u+s, g+s, +s, 4755, 2755) by chmod or install, a capability
    ("setuid", r"\b(?:chmod|install)\b[^;&|]*?(?:[\s,=]|-m)(?:[ugoa]*[+=][rwxXt]*s|0?[2-7][0-7]{3}\b)"),
    ("capabilities", r"\bsetcap\b"),
    # a supervision agent stopped, disabled, masked, killed, removed (dpkg -r/-P, rpm -e, rm,
    # chmod -x); the audit rules changed; the logging's configuration changed
    ("supervision", rf"\A(?=.*?(?:{_DISABLE}))(?=.*?\b(?:{_AGENTS})\b)"),
    ("audit", r"\bauditctl\b"),
    ("log_config", r"/etc/(?:rsyslog|syslog-ng|audit)\b|/etc/opt/microsoft/azuremonitoragent\b"),
    # the logs deleted or emptied
    ("logs", r"\b(?:rm|shred|truncate|unlink)\b[^;&|]*?/var/log\b|>\s*/var/log/|\bjournalctl\b[^;&|]*?--vacuum"),
    # persistence: cron, a systemd unit written or edited, a kernel module loaded
    ("cron", r"\b(?:crontab|anacrontab)\b|/etc/cron|/var/spool/cron\b"),
    ("systemd", r"/etc/systemd/system\b|/(?:usr/)?lib/systemd/system\b|\bsystemctl\b[^;&|]*?\s(?:edit|link)\b"),
    ("kernel_modules", r"\b(?:insmod|modprobe|rmmod)\b"),
    # the firewall emptied
    ("firewall", r"\bip6?tables\b[^;&|]*?\s(?:-F|--flush|-X|--delete-chain|-P)\b"
                 r"|\bnft\b[^;&|]*?\b(?:flush|delete|add|insert|replace|-f)\b|\bufw\b[^;&|]*?\b(?:disable|reset)\b"),
    # an SSH key planted, PAM or the loader changed
    ("ssh_keys", r"\bauthorized_keys2?\b"),
    ("pam", r"/etc/pam\.d\b|\bpam_\w+\.so\b"),
    ("preload", r"\bld\.so\.preload\b|\bLD_(?:PRELOAD|LIBRARY_PATH|AUDIT)="),
)
_SENSITIVE = tuple((name, re.compile(rx, re.IGNORECASE | re.DOTALL)) for name, rx in SENSITIVE_SHIPPED)


@dataclass(frozen=True)
class SudoLine:
    account: str
    run_as: tuple[str, ...]      # every USER= of the line
    command: str
    fields: str = ""             # what comes before COMMAND= (TTY, PWD, USER, ENV…)

    @property
    def to_root(self) -> bool:
        return bool(self.run_as) and all(u == "root" for u in self.run_as)


def parse(message) -> SudoLine | None:
    """sudo's line, read as the shipped rule reads it; None for any other form — and for an
    ambiguous one, that stays a card: cut by sudo, holding a line break, a second COMMAND=."""
    if not isinstance(message, str):
        return None
    if len(message) >= _SUDO_LINE_CUT:
        return None
    if "\n" in message or "\r" in message:
        return None
    if message.count("COMMAND=") != 1:
        return None
    m = _LINE.fullmatch(message)
    if m is None:
        return None
    return SudoLine(account=m["account"], run_as=tuple(_RUN_AS.findall(message)),
                    command=m["command"].strip(), fields=m["fields"])


# A root shell (Jonathan, 02/11): under sudo, whatever runs a shell gives root without sudo
# writing another line — what is done in it is never seen. Sensitive, shipped, no exception
# in ADM1: COR1 will set aside the ones whose SSH session comes from an expected origin.
# The program is read past these wrappers: after one, every word is a candidate (their
# options, their VAR=value, a duration — `env -i bash`, `nice -n 10 bash`, `timeout 5 sh`).
# Not exhaustive: a script or a program not listed (`sudo /tmp/x.py`) passes — the blind spot
# assumed until COR1 (the session's origin) and AUD1 (auditd).
_WRAPPERS = frozenset({"env", "nice", "nohup", "timeout", "stdbuf", "command",
                       "time", "ionice", "chrt", "taskset", "setsid", "flock", "chroot", "strace",
                       "ltrace", "nsenter", "unshare", "watch", "systemd-run"})
# Shells, the programs that open a session, sudo itself: `sudo -i`, `sudo -s` are written
# COMMAND=/bin/bash (the user's shell), `sudo su -` COMMAND=/usr/bin/su -.
_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox",
                     "su", "runuser", "login", "script", "sudo"})
# Terminal multiplexers: they open a shell.
_MULTIPLEXERS = frozenset({"screen", "tmux"})
# A debugger runs a shell (`gdb -ex '!sh'`, its `shell` command).
_DEBUGGERS = frozenset({"gdb", "lldb"})
_PYTHON = re.compile(r"python[\d.]*")
_SOCAT_EXEC = re.compile(r"\b(?:exec|system):", re.IGNORECASE)
# Interpreters: code given in line (or none: the interpreter reads it, a REPL is a shell).
_INLINE = (
    (re.compile(r"python[\d.]*"), re.compile(r"-[A-Za-z]*c|-")),
    (re.compile(r"perl[\d.]*"), re.compile(r"-[A-Za-z]*[eE]|-")),
    (re.compile(r"ruby[\d.]*"), re.compile(r"-[A-Za-z]*e|-")),
    (re.compile(r"node(?:js)?"), re.compile(r"-e|--eval|-p|--print|-")),
    (re.compile(r"php[\d.]*"), re.compile(r"-r|-a")),
    (re.compile(r"lua[\d.]*"), re.compile(r"-e|-i|-")),
)
# Editors and pagers that run a shell (`:!sh`, `!sh`), sudo's own `sudoedit` aside.
_SHELL_ESCAPES = frozenset({"vi", "vim", "nvim", "view", "vimdiff", "ex", "nano", "less", "more",
                            "man"})
_AWKS = frozenset({"awk", "gawk", "mawk", "nawk"})


def _name(token: str) -> str:
    """A token as a program's name: no quotes, no path, no login shell's dash; past an option's
    `=` (`env --split-string='bash -c …'`)."""
    if token.startswith("-") and "=" in token:
        token = token.split("=", 1)[1]
    return token.strip("'\"`(){};").rsplit("/", 1)[-1].lstrip("-")


def _programs(tokens: list[str]) -> range:
    """Where the program may be: the first word, or — past `env`, `nice`, `nohup`, `timeout`,
    `stdbuf`, `command` — any of the words after them (what they take is not parsed: read
    wide; the first 32, the reading bounded)."""
    i = 0
    while i < len(tokens) and _name(tokens[i]) in _WRAPPERS:
        i += 1
    return range(i, min(len(tokens), i + 32)) if i else range(min(1, len(tokens)))


def root_shell(command: str) -> bool:
    """Does this command give a root shell? (a shell, su, a nested sudo; an interpreter with code
    in line or none; find -exec, xargs to a shell, awk's system(); an editor or a pager)"""
    tokens = command[:_COMMAND_READ].split()
    if _runs_a_shell(tokens, command):
        return True
    return any(_gives_a_shell(_name(tokens[i]), tokens[i + 1:], command) for i in _programs(tokens))


def _runs_a_shell(tokens: list[str], command: str) -> bool:
    """The programs that run a command given to them: `systemd-run --shell`, socat's `exec:`,
    tar's `--checkpoint-action=exec`, `docker exec`/`run` to a shell."""
    names = [_name(t) for t in tokens[:32]]
    if "systemd-run" in names and any(t in ("--shell", "-S") for t in tokens):
        return True
    if "socat" in names and _SOCAT_EXEC.search(command):
        return True
    if "tar" in names and ("--checkpoint-action=exec" in command or "--to-command" in command):
        return True
    if ({"docker", "podman"} & set(names) and {"exec", "run"} & set(names)
            and any(n in _SHELLS for n in names[1:])):
        return True
    return False


def _gives_a_shell(prog: str, args: list[str], command: str) -> bool:
    if prog in _SHELLS:
        return True
    if prog in _MULTIPLEXERS:
        return True
    if _PYTHON.fullmatch(prog) and ("-mpty" in args or any(a == "-m" and b == "pty" for a, b in zip(args, args[1:]))):
        return True
    if prog in _DEBUGGERS:
        return True
    for name, inline in _INLINE:
        if name.fullmatch(prog) and (not args or any(inline.fullmatch(a) for a in args)):
            return True
    if prog == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args):
        return True
    if prog == "xargs" and any(_name(a) in _SHELLS for a in args):
        return True
    if prog in _AWKS and ("system(" in command or "getline" in command or "|&" in command):
        return True
    if prog in _SHELL_ESCAPES:
        return True
    return False


def sensitive(command: str, extra=()) -> str | None:
    """What makes this command sensitive (a shipped category, or the config's text), or None."""
    text = command[:_COMMAND_READ]
    for name, rx in _SENSITIVE:
        if rx.search(text):
            return name
    if root_shell(text):
        return "root_shell"
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
    if _LD_ENV.search(line.fields):
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
