"""The correlation: two events of one VM tied together, before the decision (COR1, #407).

A detection that ties two events is worth more than two detections apart: a sudo is read with
the SSH sessions that carry it, a brute force with the login that follows it. Like a rule's
threshold or an administrator's expected sudo (ADM1), the tie is made by the RulePoller, in
code, once a row is routed to its VM and before any signal exists — never in the prompt, never
by the model's confidence (the lesson of 28/07).

What it reads — Syslog's `auth`/`authpriv` lines of the VM, in one bounded query per VM:
  - sshd's « Accepted <method> for <account> from <address> port <n> … »: a session, and its
    origin;
  - « pam_unix(sshd:session): session opened for user <account> » with no Accepted line of the
    same process just before: a session whose origin is not written — unknown;
  - « pam_unix(<su, su-l, sudo, runuser, login, cron…>:session): session opened for user
    <account> by <other> »: the account taken by another one (or by the system) — its origin
    is not followed, unknown.
A « session closed » line is not read: any local user writes one with `logger`, and a session
said closed would clear its origin. Every session opened in the window counts as open.

Its limit (Jonathan, 02/11: a noise reducer, its limit written): any local user can write an
sshd login line from a declared origin (`logger -t sshd`). The set-aside thus holds against an
honest administrator and an intruder who does not know Eregion — no more. An intruder whose real
session is older than the window, or an access that writes no session line, can have a root
shell set aside on its own; a sensitive command is always a card. The answer is planned: an
origin confirmed outside the VM (Bastion, network flows) — COR2, #427.

What it never does: conclude without lines. A query that fails, a reading cut at its limit, a
line no VM names, no session found, the cap of queries reached — the result is unknown (A0),
and unknown is a card.

Two uses:
  1. `settle_origins` (ADM1's root shells): a root shell or code in line, by an account whose
     `origins` are declared, is set aside only if EVERY session of that account in the window
     comes from one of them; otherwise a card that says why (`SessionOrigin` on the row:
     « session depuis 203.0.113.9, origine inconnue »). A sensitive command never reaches here.
  2. `tag_compromise` (`ssh-brute-force`, T1110.001): a brute force followed by a login from the
     same address on the same VM, in the rule's window — the row marked `Correlation:
     ssh-login-after-brute-force`, a critical card, once per address and VM.

Bounded, counted, said: the queries run only for the rows that need them (a root shell pending,
a brute-force row), at most `QUERIES_PER_POLL` per rule and poll, and `rule_status.json` counts
them (`correlation`), with the unknowns.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from glorfindel import kql

logger = logging.getLogger(__name__)

# The sessions read behind a root shell: those opened in the last 7 days (Jonathan, 02/11). A
# session opened before is not seen — if none is left in the window, the result is unknown (a card).
SESSION_LOOKBACK_S = 7 * 24 * 3600
# At most this many lines per query; a reading that reaches it may miss a session: unknown.
ROWS_MAX = 1000
# At most this many correlation queries per rule and poll; beyond, unknown (a card).
QUERIES_PER_POLL = 4
# A session opened up to this long after the sudo line still counts (the lines of one host
# share its clock, at the second).
SKEW_S = 2
# A pam session of sshd paired with an Accepted line of the same process written this long before.
PAIR_S = 60

# What a pass counts, `rule_status.json` adds up (`correlation`) and the console shows.
COUNTS = ("queries", "origin", "card", "unknown", "compromised", "unchecked")

BRUTE_FORCE_TTP = "T1110.001"
COMPROMISED = "ssh-login-after-brute-force"
# The logins a compromise card carries, at most.
LOGINS_KEPT = 10
# Services whose pam session is no origin of its own: systemd's user manager opens one with
# every SSH login.
_NOT_AN_ORIGIN = frozenset({"sshd", "systemd-user"})

# A network's own addresses (RFC 1918, shared, unique-local, link-local, loopback): a session
# from one not declared is a move inside the network — possibly lateral.
_INTERNAL = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128"))

_ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<account>\S+) from (?P<ip>\S+) port \d+")
_PAM_OPEN = re.compile(r"pam_unix\((?P<service>[\w.-]+):session\): session opened for user "
                       r"(?P<account>[^\s(]+)(?:\(uid=\d+\))? by (?P<by>\S*)")

_SESSIONS = """
Syslog
| where TimeGenerated > ago({lookback}s)
| where {scope}
| where Facility in ("auth", "authpriv")
// The lines `sessions()` reads, and no more: sshd's own Accepted lines (its tag) for these
// accounts; the session lines of any service opened FOR these accounts — not sudo's own
// (`session opened for user root … by <account>`, one per sudo), not systemd's user manager:
// an active administrator's week of them filled the 1,000 lines, and every root shell a card.
| where (SyslogMessage startswith "Accepted " and ProcessName in ("sshd", "sshd-session") and ({accepted}))
    or (SyslogMessage has "session opened" and SyslogMessage !has "systemd-user" and ({opened}))
| project TimeGenerated, ProcessName, ProcessID, SyslogMessage
| order by TimeGenerated asc
| limit {limit}
"""

_LOGINS = """
Syslog
| where TimeGenerated > ago({lookback}s)
| where {scope}
| where Facility in ("auth", "authpriv")
| where ProcessName in ("sshd", "sshd-session")
| where SyslogMessage startswith "Accepted "
| project TimeGenerated, ProcessName, ProcessID, SyslogMessage
| order by TimeGenerated asc
| limit {limit}
"""


def origin(text) -> tuple[str, str]:
    """An origin of the config, read strictly: (the canonical range, "") or ("", why)."""
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=True)
    except ValueError:
        return "", ("ni une adresse ni une plage CIDR aux bits d'hôte nuls "
                    "(ex. 203.0.113.0/24, 2001:db8::/48, 198.51.100.7)")
    if net.prefixlen == 0:
        return "", "/0 : toute adresse serait une origine attendue"
    return str(net), ""


def address(text):
    """An address as read in a line, an IPv4 written in IPv6 (`::ffff:a.b.c.d`) read as itself;
    None when it is not one."""
    try:
        ip = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    return getattr(ip, "ipv4_mapped", None) or ip


def instant(value) -> datetime | None:
    """A row's TimeGenerated (a datetime from Log Analytics, or ISO text), in UTC; None if unreadable."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def scope(row: dict) -> str | None:
    """The KQL predicate that names this row's VM — its `_ResourceId` as Log Analytics wrote it,
    else its `Computer` — each value checked and written as a literal (SEC4c); None if neither."""
    for col, check in (("_ResourceId", kql.resource_id), ("Computer", kql.name)):
        try:
            return f"{col} == {kql.literal(check(row.get(col)))}"
        except kql.UnsafeValue:
            continue
    return None


# ── The sessions ──────────────────────────────────────────────────────────────────

def sessions(lines: list[dict], account: str, at: datetime) -> list[dict]:
    """The sessions that may carry `account` at `at`: each one {"via", "origin", "at", "by"} —
    via "ssh" (an Accepted line: origin its address), "ssh-pam" (sshd's pam session, no
    Accepted line: origin unknown), or a service that gave the account (su, sudo, login,
    cron…: by whom). Opened in the window, before `at` (+ SKEW_S); a closed line is not read."""
    upto = at + timedelta(seconds=SKEW_S)
    accepted: list[tuple[datetime | None, object]] = []
    out: list[dict] = []
    for row in lines:
        msg = row.get("SyslogMessage")
        if not isinstance(msg, str):
            continue
        when = instant(row.get("TimeGenerated"))
        if when is not None and when > upto:
            continue
        m = _ACCEPTED.match(msg)
        if m and m["account"] == account:
            accepted.append((when, row.get("ProcessID")))
            ip = address(m["ip"])
            out.append({"via": "ssh", "origin": str(ip) if ip else "", "at": when, "by": ""})
            continue
        p = _PAM_OPEN.search(msg)
        if not p or p["account"] != account:
            continue
        by = p["by"].split("(", 1)[0]
        if p["service"] == "sshd":
            if not _paired(when, row.get("ProcessID"), accepted):
                out.append({"via": "ssh-pam", "origin": "", "at": when, "by": ""})
        elif p["service"] not in _NOT_AN_ORIGIN and by != account:
            out.append({"via": p["service"], "origin": "", "at": when, "by": by or "le système"})
    return out


def _paired(when, pid, accepted) -> bool:
    """An Accepted line of the same account, from the same process when both say theirs, at most
    PAIR_S before (lines in time order). An unreadable time pairs with nothing."""
    if when is None:
        return False
    for at, apid in accepted:
        if at is None or not (0 <= (when - at).total_seconds() <= PAIR_S):
            continue
        if pid in (None, "") or apid in (None, "") or str(pid) == str(apid):
            return True
    return False


def verdict(found: list[dict], origins) -> tuple[bool, str, list[str]]:
    """(every session from an expected origin, why in words, the origins seen). None found,
    an origin unknown, an address outside the ranges, the account taken by another: False."""
    nets = [ipaddress.ip_network(o) for o in origins]
    if not found:
        return False, "aucune session SSH trouvée pour ce compte sur 7 jours — origine inconnue", []
    seen = sorted({s["origin"] for s in found if s["origin"]})
    for s in found:
        if s["via"] not in ("ssh", "ssh-pam"):
            return False, f"compte pris par {s['via']} depuis {s['by']} — origine non suivie", seen
        if s["via"] == "ssh-pam":
            return False, "session SSH sans ligne « Accepted » — origine inconnue", seen
        if not s["origin"]:
            return False, "session SSH d'adresse illisible — origine inconnue", seen
    bad = [o for o in seen if not any(ipaddress.ip_address(o) in n for n in nets)]
    if bad:
        private = [o for o in bad if any(ipaddress.ip_address(o) in n for n in _INTERNAL)]
        what = ", ".join(bad)
        if private:
            return False, (f"session depuis {what}, adresse du réseau hors des origines déclarées — "
                           "mouvement latéral possible"), seen
        return False, f"session depuis {what}, origine inconnue", seen
    return True, f"session{'s' if len(found) > 1 else ''} depuis {', '.join(seen)} — origine attendue", seen


# ── One pass: the queries of one rule's poll ──────────────────────────────────────

class Pass:
    """The correlation queries of one poll of one rule: bounded (`QUERIES_PER_POLL`), counted."""

    def __init__(self, run_query, now: datetime | None = None) -> None:
        self._run = run_query
        self.now = now or datetime.now(timezone.utc)
        # queries run; root shells set aside by origin, carded by origin, unknown (nothing to
        # read); brute forces marked compromised, left unchecked.
        self.counts = dict.fromkeys(COUNTS, 0)

    def query(self, template: str, lookback_s: float, **values) -> list[dict] | str:
        """The rows, or why there are none to read (the result is then unknown)."""
        if self.counts["queries"] >= QUERIES_PER_POLL:
            return f"plafond de {QUERIES_PER_POLL} requêtes de corrélation par passe atteint"
        self.counts["queries"] += 1
        text = template.format(lookback=int(lookback_s), limit=ROWS_MAX, **values)
        try:
            rows = self._run(text, timespan=(self.now - timedelta(seconds=lookback_s + 300),
                                             self.now + timedelta(minutes=1)))
        except Exception as exc:
            return f"journal illisible ({str(exc)[:160]})"
        if not isinstance(rows, list):
            return "réponse illisible"
        if len(rows) >= ROWS_MAX:
            return f"{ROWS_MAX} lignes ou plus — lecture incomplète"
        return rows


def settle(ttp: str, routed: dict, judged: dict, run_query, seen: set, identity, window_s: float,
           now: datetime | None = None) -> dict:
    """COR1, both uses, for one poll of one rule — outside the poller's lock. `judged`: ADM1's
    entries (id(row) → entry); a root shell pending (`origins`) leaves it set aside or a card,
    never pending. `seen`: the identities already dispatched. Returns the pass's counts."""
    p = Pass(run_query, now)
    try:
        settle_origins(p, routed, judged, seen, identity)
        if ttp == BRUTE_FORCE_TTP:
            tag_compromise(p, routed, seen, identity, window_s)
    except Exception as exc:
        # A fault here never stops the rule's poll, and never sets aside what it did not settle.
        pending = [k for k, e in judged.items() if "origins" in e]
        for k in pending:
            del judged[k]
        p.counts["unknown"] += len(pending)
        logger.warning("correlation failed (%s) — %d root shell(s) left as cards", exc, len(pending))
    return p.counts


def settle_origins(p: Pass, routed: dict, judged: dict, seen: set, identity) -> None:
    from glorfindel import expected_sudo
    groups: dict[str, list[tuple[dict, dict]]] = {}
    for _tgt, rows in routed.values():
        for row in rows:
            entry = judged.get(id(row))
            if not entry or "origins" not in entry:
                continue
            if identity(row) in seen:          # dispatched or set aside already: no query
                del judged[id(row)]
                continue
            where = scope(row)
            if where is None:
                _unknown(p, judged, row, "la ligne ne nomme pas sa VM — origine inconnue")
                continue
            groups.setdefault(where, []).append((row, entry))
    for where, items in groups.items():
        accounts = sorted({e["account"] for _, e in items})
        accepted = " or ".join(f"SyslogMessage has {kql.literal(f'for {a} from')}" for a in accounts)
        opened = " or ".join(f"SyslogMessage has {kql.literal(f'for user {a}')}" for a in accounts)
        lines = p.query(_SESSIONS, SESSION_LOOKBACK_S, scope=where, accepted=accepted, opened=opened)
        for row, entry in items:
            if isinstance(lines, str):
                _unknown(p, judged, row, f"sessions non lues : {lines} — origine inconnue")
                continue
            at = instant(row.get("TimeGenerated"))
            if at is None:
                _unknown(p, judged, row, "instant de la ligne illisible — origine inconnue")
                continue
            ok, why, seen_origins = verdict(sessions(lines, entry["account"], at), entry["origins"])
            if not ok:
                _unknown(p, judged, row, why, kind="card")
                continue
            judged[id(row)] = {k: v for k, v in entry.items() if k != "origins"} | {
                "via": "origin", "origin": ", ".join(seen_origins)[:expected_sudo._COMMAND_KEPT]}
            p.counts["origin"] += 1


def _unknown(p: Pass, judged: dict, row: dict, why: str, kind: str = "unknown") -> None:
    """The row stays a card, and says why (`SessionOrigin`)."""
    judged.pop(id(row), None)
    row["SessionOrigin"] = why
    p.counts[kind] += 1


def tag_compromise(p: Pass, routed: dict, seen: set, identity, window_s: float) -> None:
    """A brute-force row whose address logged in on the same VM, in the window: marked
    `Correlation` (a text, so part of the row's identity — one card per address and VM, deduped
    like the brute force) with the logins it saw. A row already carded so keeps the mark, with
    no query. A login that could not be checked is counted and said on the row (`LoginCheck`,
    not a text: the row's identity does not move) — the cycle says it to a human."""
    groups: dict[str, list[tuple[dict, object]]] = {}
    for _tgt, rows in routed.values():
        for row in rows:
            ip = address(row.get("SourceIP"))
            if ip is None or "FailedAttempts" not in row:
                continue
            if identity({**row, "Correlation": COMPROMISED}) in seen:
                row["Correlation"] = COMPROMISED
                continue
            where = scope(row)
            if where is None:
                _unchecked(p, row, "la ligne ne nomme pas sa VM")
                continue
            groups.setdefault(where, []).append((row, ip))
    for where, items in groups.items():
        lines = p.query(_LOGINS, window_s, scope=where)
        if isinstance(lines, str):
            logger.warning("correlation: logins after brute force not checked (%s)", lines)
            for row, _ip in items:
                _unchecked(p, row, lines)
            continue
        for row, ip in items:
            logins = []
            for line in lines:
                m = _ACCEPTED.match(str(line.get("SyslogMessage") or ""))
                if m and address(m["ip"]) == ip:
                    when = instant(line.get("TimeGenerated"))
                    logins.append({"account": m["account"][:64], "method": m["method"][:64],
                                   "at": when.isoformat() if when else str(line.get("TimeGenerated") or "")})
            if logins:
                row["Correlation"] = COMPROMISED
                row["SuccessfulLogins"] = logins[-LOGINS_KEPT:]
                p.counts["compromised"] += 1


def _unchecked(p: Pass, row: dict, why: str) -> None:
    row["LoginCheck"] = {"status": "unchecked", "why": why[:200]}
    p.counts["unchecked"] += 1


def add_counts(previous, counts: dict, now_iso: str) -> dict:
    """The rule's running totals in `rule_status.json` (`correlation`)."""
    prev = previous if isinstance(previous, dict) else {}
    out = {}
    for k, v in counts.items():
        try:
            out[k] = int(prev.get(k) or 0) + int(v)
        except (TypeError, ValueError):
            out[k] = int(v)
    out["last"] = now_iso
    return out
