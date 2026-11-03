"""What a human login does as root, read in auditd's lines (AUD1, #408).

ADM1 and COR1 judge a `sudo` to root. What is then done in a root shell is never written by
sudo: COR2 keeps it as a limit — a session older than the window, an access that writes no
session line, stays unseen. auditd sees it. The bench (`infra/terraform/auditd.tf`, off by
default) loads two rules and sends their lines to Syslog through auditd's syslog plugin
(audisp-syslog, facility local6):

  - the CIS benchmarks' rule, `-C euid!=uid -F auid!=unset -S execve -k user_emulation`: a
    program run as another user (sudo, su, a setuid binary) under the login identity (`auid`)
    that the kernel keeps through sudo and su;
  - what the CIS rule does not see: after sudo, the root shell has uid = euid = 0, so its
    commands match no `euid != uid`. `-F euid=0 -F auid>=1000 -F auid!=unset -S execve
    -k root_command` logs each one, under the same `auid`.

The shipped rule `auditd-sensitive-root-command` reads them (`glorfindel/rules/azure/
detection_rules.yaml`): one row per exec of a human login (auid ≥ 1000, not unset) as root
(euid 0), its SYSCALL and EXECVE records gathered by event (`msg=audit(<time>:<serial>)`).
Here, in the RulePoller, before any signal (`settle`), each row is read:

  - read whole, and its command line sensitive — the list of ADM1, never a copy of it
    (`expected_sudo.listed`: `SENSITIVE_SHIPPED`, plus the config's `sensitive_commands`) — a
    card, which names the login account (`LoginAccount`), its command (`AuditCommand`), why
    (`Sensitive`). An expected administrator (ADM1) is held to the list as for sudo;
  - read whole and not sensitive: no card. That is the rule, not an exemption: a root shell's
    every `ls` is no finding; its sudo was judged by `sudo-privilege-escalation`;
  - anything else is a card that says why (`AuditRead`, A0): no SYSCALL or no EXECVE record, two
    of either for one event (a line written to look like it — an intruder root on the VM can
    write a line at its own event's serial — never chooses which one is read), an argument cut
    or split, a field unreadable, a command longer than what is read.

The program is read with its arguments: `exe` (the kernel's path, which argv[0] cannot hide)
then argv. What is not an exec is not seen (a file read by a program already running, a
renamed copy of a binary); a silenced plugin is not seen either — both are written as limits
(`docs/design/correlation.md`, « Ce que ferme AUD1 »). The records' form is a hypothesis until
measured on the bench (`docs/operations.md`, « Les hypothèses d'AUD1 », A1–A13).
"""
from __future__ import annotations

import json
import re

from glorfindel import expected_sudo

# The technique of the rules whose rows are auditd's execs of a human login as root: the
# shipped `auditd-sensitive-root-command`, or a client's rule on the same technique (whose
# rows, if not of this form, stay cards: unreadable).
TTP = "T1059.004"

# The keys of the two audit rules (infra/terraform/scripts/auditd.sh).
KEYS = ("user_emulation", "root_command")
# A login uid at or above this is a human's (UID_MIN of /etc/login.defs on Ubuntu, Debian,
# RHEL: hypothesis A9). The unset auid: (uid_t)-1.
HUMAN_UID_MIN = 1000
UNSET = 4294967295

# What a row keeps of a command, and what is read of one (expected_sudo's own bound).
_COMMAND_KEPT = 300
_COMMAND_READ = 1024
# The commands a folded card names besides its own (one card per VM and poll).
FOLD_MAX = 20
# What a record may say, read bounded whatever a local user writes with `logger` (review, AUD1):
# a number of 10 ASCII digits at most (an auid is 32 bits), an argument index of 4, at most
# ARGC_MAX arguments, each record kept to RECORD_KEPT characters on the card.
ARGC_MAX = 256
RECORD_KEPT = 2000

# What the rule's window holds at its last poll (`rule_status.json`, `auditd`): a gauge, not a
# total — a row read and not sensitive is read again at the next poll, and never marked sent.
COUNTS = ("events", "sensitive", "unreadable")

_TYPE = re.compile(r"(?:^|\s)type=([A-Z_]+)\s")
_EVENT = re.compile(r"msg=audit\(([0-9]+\.[0-9]+:[0-9]+)\)")
# A record's fields: `name=value`, at a word's start. The kernel writes an untrusted string
# (comm, exe, an argument) in quotes, or in hex when it holds a space, a quote, a control
# character or a byte above 0x7e (audit_log_untrustedstring): a value never carries a space.
_VALUE = r'("[^"]*"|\S+)'


def _field(record: str, name: str) -> str | None:
    m = re.search(rf"(?:^|\s){re.escape(name)}={_VALUE}", record)
    return m.group(1) if m else None


def _untrusted(value: str | None) -> str | None:
    """A quoted value as written; a hex one decoded; `(null)`, or a value of neither form, None."""
    if value is None:
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    if re.fullmatch(r"(?:[0-9A-F]{2})+", value):
        try:
            return bytes.fromhex(value).decode("utf-8")
        except UnicodeDecodeError:
            return None
    return None


def _number(record: str, name: str) -> int | None:
    """A field's number: ASCII digits only, 10 at most — `²` is a digit to str.isdigit() and
    not to int(), and int() refuses more than 4 300 digits (review, AUD1)."""
    v = _field(record, name)
    return int(v) if v is not None and re.fullmatch(r"[0-9]{1,10}", v) else None


def _records(value) -> list[str]:
    """The records an aggregate column holds: a list (the SDK, the tests), or its JSON text
    (a dynamic column as text: hypothesis A11). Anything else holds none."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError):
            return []
    if not isinstance(value, list):
        return []
    return sorted({v for v in value if isinstance(v, str)})


def _argv(execve: str) -> list[str] | str:
    """EXECVE's argv, or why it cannot be read whole."""
    if re.search(r"(?:^|\s)a[0-9]+(?:_len=|\[)", execve):
        return "argument découpé (aN_len, aN[i]) — trop long pour un seul enregistrement"
    argc = _number(execve, "argc")
    if argc is None or argc < 1:
        return "argc illisible"
    if argc > ARGC_MAX:
        return f"argc={argc} hors borne ({ARGC_MAX} au plus)"
    found = {int(i): v for i, v in re.findall(rf"(?:^|\s)a([0-9]{{1,4}})={_VALUE}", execve)}
    if len(found) != argc or any(i not in found for i in range(argc)):
        return f"argc={argc}, {len(found)} argument(s) lu(s)"
    args = []
    for i in range(argc):
        text = _untrusted(found[i])
        if text is None:
            return f"argument a{i} illisible"
        args.append(text)
    return args


def read(row: dict) -> dict:
    """What the row says, or why it cannot be read: {"why": …} (plus what could be read)."""
    syscalls, execves = _records(row.get("Syscall")), _records(row.get("Execve"))
    out: dict = {}
    if len(syscalls) != 1:
        return {"why": "aucun enregistrement SYSCALL" if not syscalls
                else f"{len(syscalls)} enregistrements SYSCALL pour un événement"}
    syscall = syscalls[0]
    exe = _untrusted(_field(syscall, "exe"))
    auid, euid = _number(syscall, "auid"), _number(syscall, "euid")
    key = _untrusted(_field(syscall, "key"))
    name = re.search(r'AUID="([^"]*)"', syscall)
    out.update({"exe": exe or "", "auid": auid, "account": name.group(1) if name else "",
                "tty": _field(syscall, "tty") or "", "session": _field(syscall, "ses") or "",
                "key": key or ""})
    event, kind = _EVENT.search(syscall), _TYPE.search(syscall)
    if kind is None or kind.group(1) != "SYSCALL" or event is None:
        return {**out, "why": "enregistrement SYSCALL illisible"}
    if exe is None:
        return {**out, "why": "exe illisible"}
    if auid is None or euid is None or key is None:
        return {**out, "why": "auid, euid ou key illisible"}
    if key not in KEYS or not (HUMAN_UID_MIN <= auid < UNSET) or euid != 0:
        # The query keeps only a human login's exec as root: a row that says otherwise was
        # not written by this rule's records — never cleared on what it says.
        return {**out, "why": f"key={key} auid={auid} euid={euid} : pas une commande root d'un humain"}
    if len(execves) != 1:
        return {**out, "why": "aucun enregistrement EXECVE" if not execves
                else f"{len(execves)} enregistrements EXECVE pour un événement"}
    execve = execves[0]
    other, kind = _EVENT.search(execve), _TYPE.search(execve)
    if kind is None or kind.group(1) != "EXECVE" or other is None or other.group(1) != event.group(1):
        return {**out, "why": "enregistrement EXECVE d'un autre événement"}
    argv = _argv(execve)
    if isinstance(argv, str):
        return {**out, "why": argv}
    command = " ".join(argv)
    # The program by its path (argv[0] is the caller's to write: `exec -a vim useradd`), then argv.
    text = f"{exe} {command}"
    if len(text) > _COMMAND_READ or "\n" in text or "\r" in text:
        return {**out, "command": command, "why": "commande trop longue ou sur plusieurs lignes : non lue en entier"}
    return {**out, "command": command, "text": text}


def login_account(said: dict) -> str:
    """The login account a card names: its name (the enriched record) and its auid."""
    auid = said.get("auid")
    name = said.get("account") or ""
    if auid is None:
        return name or "?"
    return f"{name} (auid {auid})" if name else f"auid {auid} (nom absent de la ligne)"


def _card(row: dict, said: dict, records: list[str]) -> dict:
    """The row as its card says it. A row with no record at all (a client's rule of this
    technique, of another form) is left as it came: it is no audit row."""
    if not records:
        return dict(row)
    command = said.get("command") or said.get("exe") or ""
    # The records once read: in SyslogMessage only, each bounded — never twice in the signal.
    rest = {k: v for k, v in row.items() if k not in ("Syscall", "Execve")}
    return {**rest,
            # The rows' identity (`_row_identity`: instant and text): the event's records, sorted.
            "SyslogMessage": "\n".join(r[:RECORD_KEPT] for r in records),
            "LoginAccount": login_account(said),
            "Auid": said.get("auid"),
            "AuditCommand": command[:_COMMAND_KEPT],
            "Exe": (said.get("exe") or "")[:_COMMAND_KEPT],
            "AuditKey": said.get("key") or "",
            "Tty": said.get("tty") or "",
            "Session": said.get("session") or ""}


def settle(ttp: str, rows: list[dict], extra=()) -> tuple[list[dict], dict]:
    """(the rows that stay cards, the counts). Only for a rule of this technique: any other's
    rows pass as they came. `extra`: the config's `sensitive_commands`."""
    counts = dict.fromkeys(COUNTS, 0)
    if ttp != TTP:
        return rows, counts
    kept = []
    for row in rows:
        counts["events"] += 1
        try:
            card = _settle_row(row, extra)
        except Exception as exc:  # a line written to make the reading fail is a card, never a silence
            card = _unread(row, {}, f"lecture en erreur ({type(exc).__name__})")
        if card is None:
            continue
        counts["unreadable" if "AuditRead" in card else "sensitive"] += 1
        kept.append(card)
    return kept, counts


def _unread(row: dict, said: dict, why: str) -> dict:
    """The card of a row that cannot be read whole (A0)."""
    try:
        records = sorted(set(_records(row.get("Syscall")) + _records(row.get("Execve"))))
        card = _card(row, said, records)
    except Exception:
        card = {k: v for k, v in row.items() if k not in ("Syscall", "Execve")}
    return {**card, "AuditRead": {"status": "unreadable", "why": why[:200]}}


def _settle_row(row: dict, extra) -> dict | None:
    """One row: its card (sensitive, or unreadable), or None — read whole, not sensitive."""
    said = read(row)
    if "why" in said:
        return _unread(row, said, said["why"])
    category = expected_sudo.listed(said["text"], extra)
    if category is None:
        return None
    records = sorted(set(_records(row.get("Syscall")) + _records(row.get("Execve"))))
    return {**_card(row, said, records), "Sensitive": category}


def fold(rows: list[dict]) -> dict:
    """One card per VM and poll: the newest row, naming the others (`AuditCommands`, at most
    FOLD_MAX, the newest first; `AuditCount`, all of them) — none sent unsaid."""
    ordered = sorted(rows, key=lambda r: str(r.get("TimeGenerated") or ""), reverse=True)
    newest = ordered[0]
    if len(ordered) == 1:
        return newest
    return {**newest, "AuditCount": len(ordered), "AuditCommands": [
        {"TimeGenerated": str(r.get("TimeGenerated") or ""), "LoginAccount": r.get("LoginAccount") or "",
         "AuditCommand": r.get("AuditCommand") or "", "Sensitive": r.get("Sensitive") or "",
         **({"AuditRead": r["AuditRead"]} if r.get("AuditRead") else {})}
        for r in ordered[1:FOLD_MAX + 1]]}


def window(counts: dict, now_iso: str) -> dict:
    """The rule's window at its last poll, for `rule_status.json` (`auditd`)."""
    return {**{k: int(counts.get(k) or 0) for k in COUNTS}, "at": now_iso}
