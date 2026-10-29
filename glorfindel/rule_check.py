"""Every loaded rule run once, read-only, on its backend (H2, #266).

`glorfindel rules check` loads the rules as the watch loads them — the shipped base, the
client's layer over it, the rules approved into that layer (P1) — and says, rule by rule:

- **bound or not**: a rule that resolves no workspace, a rule applied to the discovered VMs
  of no backend (the inline form an approval wrote before P1), a static rule on no resource,
  a source no detector reads — the silent defaults P1 put into words, here an error;
- with `--live`, **its query, once**, on its backend, as the rule poller sends it (the same
  detector, the same window): `ok` (zero rows included — no row is not an error), `error`
  only for what lasts (an invalid query, a table or a column absent, a 403, a 404),
  `unproven` for what may pass (a 429, a 5xx, a 401 or a credential not available, the
  network, a partial result, anything else), `timeout`.

Read-only by construction: the detector's `run_query` and nothing else — no rule poller (it
writes `rule_status.json` and dispatches), no model, no action, nothing written. Each query
is bounded (`query_timeout_s`, in a thread of its own), and so is the whole (`total_s`): past
it, the rules left are « not run », said as timeouts. Never a retry, never a loop.

The JSON (`--json`) is what H0's CD reads before and after a switch (`infra/glorfindel-host/
cd/eregion_cd.py`): a rule in a lasting error after the switch that was ok before is a
rollback. Its errors are **reduced** — a kind, a code (`SEM0100`, `429`), a short line, no
workspace, subscription, resource path, host name, address. The full detail goes to stderr
(with `--json`: the CD's journal, private) or the terminal.

Exit code: 0 every rule ok, 1 a lasting error (a rule, or the loading itself), 3 unproven or
timeouts only.
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

SCHEMA = "eregion.rules-check/1"
OK, ERROR, TIMEOUT, UNPROVEN = "ok", "error", "timeout", "unproven"
EXIT_OK, EXIT_ERROR, EXIT_TIMEOUT = 0, 1, 3
# What lasts: an error the next query would meet again. Everything else may pass — never
# called an error (the CD would roll a release back for a throttled workspace).
DURABLE = frozenset({"backend", "syntax", "table", "access", "workspace"})

# What each kind of error is called, in the words #deploy uses.
KINDS = {
    "backend": "backend non lié",
    "syntax": "requête invalide",
    "table": "table ou colonne absente",
    "access": "accès refusé (403)",
    "workspace": "workspace introuvable (404)",
    "throttled": "limité (429)",
    "service": "service indisponible (5xx)",
    "auth": "identité indisponible",
    "network": "réseau",
    "partial": "résultat partiel",
    "timeout": "délai dépassé",
    "budget": "non lancée",
    "load": "chargement",
    "other": "erreur inconnue",
}

_MAX_ERROR = 200


@dataclass
class RuleOutcome:
    name: str
    status: str                 # ok | error | unproven | timeout
    layer: str = "base"
    source: str = ""
    kind: str = ""              # a key of KINDS, for an error or a timeout
    code: str = ""              # KQL's own (SEM0100, SYN0002), else the HTTP status, else the type
    error: str = ""             # reduced: no identifier of the infrastructure
    rows: int | None = None     # with --live, for a query that answered
    seconds: float = 0.0
    detail: str = field(default="", repr=False)   # the full text: the terminal only, never the JSON

    def public(self) -> dict:
        out = asdict(self)
        out.pop("detail")
        return out


# ── reducing an error ───────────────────────────────────────────────────────────────

_GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_ARM = re.compile(r"/subscriptions/[^\s'\"),;]*", re.IGNORECASE)
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"),;]*", re.IGNORECASE)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
# A host name: three labels at least (`vm-x.internal.example.net`), or two ending in a known
# top-level name (`example.com`). Not `LogsQueryStatus.PARTIAL`, a rule named `ssh.v2`, a file.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_FQDN = re.compile(rf"\b(?:{_LABEL}\.){{2,}}[a-z]{{2,}}\b"
                   rf"|\b{_LABEL}\.(?:com|net|org|io|internal|local|lan|corp|cloud|azure|windows)\b", re.IGNORECASE)
# A quoted word is kept when it can only be a KQL name (`'Perf'`, `'MaxWrite'`, `'_ResourceId'`):
# letters and underscores. Anything else in quotes (`'vm-prod-01'`, a resource group) goes.
_QUOTED = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_KQL_NAME = re.compile(r"[A-Za-z_]{1,64}")
_MESSAGE = re.compile(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"')


def scrub(text) -> str:
    """One line, short, without what names the infrastructure: workspace and other ids
    (GUIDs), resource paths, URLs, addresses, host names, quoted values that are not KQL
    names. Said in #deploy: what is left is the kind of error, never where."""
    s = " ".join(("" if text is None else str(text)).split())
    s = _ARM.sub("<ressource>", s)
    s = _URL.sub("<url>", s)
    s = _EMAIL.sub("<adresse>", s)
    s = _GUID.sub("<id>", s)
    s = _IPV4.sub("<ip>", s)
    s = _FQDN.sub("<hôte>", s)

    def quoted(m: re.Match) -> str:
        inner = m.group(1) if m.group(1) is not None else m.group(2)
        q = "'" if m.group(1) is not None else '"'
        return m.group(0) if _KQL_NAME.fullmatch(inner) else f"{q}…{q}"
    s = _QUOTED.sub(quoted, s)
    return s if len(s) <= _MAX_ERROR else s[: _MAX_ERROR - 1] + "…"


_KQL_CODE = re.compile(r'"code"\s*:\s*"([A-Za-z][A-Za-z0-9_.-]{1,39})"')
# What Log Analytics says of a query it cannot read (a 400's words, its inner codes).
_QUERY_MARKS = ("badargumenterror", "semanticerror", "syntaxerror", "syntax error", "could not be parsed",
                "failed to resolve")
_QUERY_CODE = re.compile(r'"(?:SEM|SYN)\d{4}"')


def status_of(exc) -> int | None:
    """The HTTP status an error carries (azure-core's HttpResponseError: `status_code`, or its
    response's) — read by attribute, never by importing the SDK (MC0)."""
    for value in (getattr(exc, "status_code", None), getattr(getattr(exc, "response", None), "status_code", None)):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def classify(exc) -> str:
    """The kind of an error. Lasting (DURABLE) only on explicit evidence: a 403, a 404, a 400
    or Log Analytics' own words for a query it cannot read. Everything else may pass."""
    status = status_of(exc)
    text = str(exc)
    low = text.lower()
    name = type(exc).__name__.lower() if isinstance(exc, BaseException) else ""
    if status == 403:
        return "access"
    if status == 404:
        return "workspace"
    if status == 429:
        return "throttled"
    if status == 401 or "credential" in name or "authentication" in name:
        return "auth"
    if status is not None and status >= 500:
        return "service"
    if isinstance(exc, (OSError, TimeoutError)) or any(k in name for k in ("servicerequest", "serviceresponse",
                                                                             "connection", "timeout")):
        return "network"
    if "not successful" in low:          # run_query: a PARTIAL (or FAILURE) status, not raised by the SDK
        return "partial"
    if status == 400 or any(k in low for k in _QUERY_MARKS) or _QUERY_CODE.search(text):
        return "table" if "failed to resolve" in low or "could not find table" in low else "syntax"
    return "other"


def code_of(exc) -> str:
    """KQL's innermost code (`SEM0100`), else the HTTP status, else the error's type."""
    codes = _KQL_CODE.findall(str(exc))
    if codes:
        return codes[-1]
    status = status_of(exc)
    if status is not None:
        return str(status)
    return type(exc).__name__ if isinstance(exc, BaseException) else ""


def reduce_error(exc) -> tuple[str, str, str, str]:
    """(kind, code, reduced line, full text). The line is the most specific message the error
    holds — Log Analytics nests it (`"message": "'where' operator: Failed to resolve…"`) —
    else its first line, scrubbed."""
    full = f"{type(exc).__name__}: {exc}" if isinstance(exc, BaseException) else str(exc)
    raw = str(exc)
    messages = [m.replace('\\"', '"').replace("\\n", " ") for m in _MESSAGE.findall(raw)]
    first = next((line.strip() for line in raw.splitlines() if line.strip()), type(exc).__name__)
    line = messages[-1] if messages else first
    return classify(exc), scrub(code_of(exc))[:40], scrub(line), full[:2000]


# ── one rule ────────────────────────────────────────────────────────────────────────

def binding_problem(rule) -> str:
    """'' when the rule can run on a backend and apply to a VM, else why not (P1's silent
    defaults: each one a rule that loads and detects nothing)."""
    from glorfindel.detectors import detector_class

    if detector_class(rule.source) is None:
        return f"source « {scrub(rule.source)} » : aucun détecteur ne la lit"
    if not rule.enabled or not rule.workspace_id:
        return "aucun workspace résolu (monitoring_backends de glorfindel-config.yaml) : la règle ne tourne pas"
    if rule.auto_apply and not rule.monitoring_backend_name:
        return "workspace en ligne sans backend : elle ne s'applique à aucune VM découverte (migrate-rules)"
    if not rule.auto_apply and not rule.resource_id:
        return "ni assets: [auto] ni ressource : elle ne s'applique à aucune VM"
    return ""


def _default_detector(rule):
    from glorfindel.detectors import detector_for
    return detector_for(rule.source, workspace_id=rule.workspace_id)


def _window(rule) -> tuple[datetime, datetime]:
    """The window the rule poller asks for (`RulePoller.poll_once`)."""
    from glorfindel.detection_rules import _INGESTION_MARGIN_S, _query_lookback_s
    now = datetime.now(timezone.utc)
    return now - timedelta(seconds=_query_lookback_s(rule.query) + _INGESTION_MARGIN_S), now + timedelta(minutes=1)


def run_once(rule, timeout_s: float, detector: Callable, clock: Callable[[], float] = time.monotonic) -> RuleOutcome:
    """The rule's query, once, in a thread of its own, waited for `timeout_s` at most. A
    query still running past it is left to finish alone (a daemon thread: the process does
    not wait for it) — never waited for again, never sent again."""
    box: dict = {}

    def work() -> None:
        try:
            box["rows"] = detector(rule).run_query(rule.query, timespan=_window(rule))
        except BaseException as exc:      # noqa: BLE001 — every failure is the rule's result
            box["exc"] = exc

    base = RuleOutcome(name=rule.name, status=OK, layer=rule.layer, source=rule.source)
    started = clock()
    t = threading.Thread(target=work, daemon=True, name=f"rules-check-{rule.name}")
    t.start()
    t.join(timeout_s)
    base.seconds = round(clock() - started, 2)
    if t.is_alive():
        base.status, base.kind = TIMEOUT, "timeout"
        base.error = f"pas de réponse en {timeout_s:g} s"
        return base
    if "exc" in box:
        base.kind, base.code, base.error, base.detail = reduce_error(box["exc"])
        base.status = ERROR if base.kind in DURABLE else UNPROVEN
        return base
    rows = box.get("rows")
    base.rows = len(rows) if isinstance(rows, list) else 0
    return base


def check_rules(rules, *, live: bool, query_timeout_s: float, total_s: float,
                detector: Callable | None = None, clock: Callable[[], float] = time.monotonic) -> list[RuleOutcome]:
    """Each rule: its binding, then (live) its query once. The whole is bounded by
    `total_s`: a rule reached past it is not run, and said."""
    make = detector or _default_detector
    cache: dict = {}

    def shared(rule):     # one detector (one credential) per source and workspace
        key = (rule.source, rule.workspace_id)
        if key not in cache:
            cache[key] = make(rule)
        return cache[key]

    deadline = clock() + total_s
    out: list[RuleOutcome] = []
    for rule in rules:
        problem = binding_problem(rule)
        if problem:
            out.append(RuleOutcome(name=rule.name, status=ERROR, layer=rule.layer, source=rule.source,
                                   kind="backend", error=problem, detail=problem))
            continue
        if not live:
            out.append(RuleOutcome(name=rule.name, status=OK, layer=rule.layer, source=rule.source))
            continue
        left = deadline - clock()
        if left <= 0:
            out.append(RuleOutcome(name=rule.name, status=TIMEOUT, layer=rule.layer, source=rule.source,
                                   kind="budget", error=f"budget total de {total_s:g} s épuisé"))
            continue
        out.append(run_once(rule, min(query_timeout_s, left), shared, clock))
    return out


def exit_code(outcomes: list[RuleOutcome], load_error: str = "") -> int:
    if load_error or any(o.status == ERROR for o in outcomes):
        return EXIT_ERROR
    if any(o.status in (TIMEOUT, UNPROVEN) for o in outcomes):
        return EXIT_TIMEOUT
    return EXIT_OK


def report(outcomes: list[RuleOutcome], *, live: bool, query_timeout_s: float, total_s: float,
           load_error: str = "") -> dict:
    counts = {s: sum(1 for o in outcomes if o.status == s) for s in (OK, ERROR, UNPROVEN, TIMEOUT)}
    return {"schema": SCHEMA, "live": live, "query_timeout_s": query_timeout_s, "total_s": total_s,
            "error": scrub(load_error) if load_error else "", "counts": counts,
            "rules": [o.public() for o in outcomes]}


# ── the command ─────────────────────────────────────────────────────────────────────

def load_rules(rules_file: str):
    """The rules as the watch loads them: glorfindel-config.yaml under A3's strict reading
    (refused: an error, as the watch refuses to start), then the base and the client's layer.
    Returns (rules, notes, load_error, detail): `load_error` a fixed line (the JSON's), `detail`
    the words of A3 or of YAML — they quote the files' values (workspaces, resource groups):
    the terminal only."""
    from glorfindel.config import ConfigError, load_glorfindel_config
    from glorfindel.detection_rules import load_config

    try:
        gcfg = load_glorfindel_config()
    except ConfigError as exc:
        return [], [], "glorfindel-config.yaml refusé par la lecture stricte (A3)", str(exc)
    try:
        cfg = load_config(rules_file, glorfindel_cfg=gcfg)
    except Exception as exc:      # noqa: BLE001 — the watch would load no rule either
        return [], [], "règles illisibles (la base livrée)", f"{type(exc).__name__}: {exc}"
    if not cfg.rules:
        return [], cfg.notes, "aucune règle chargée : la watch ne détecterait rien", ""
    return cfg.rules, cfg.notes, "", ""


def main(rules_file: str | None, *, live: bool, as_json: bool, query_timeout_s: float, total_s: float,
         echo: Callable[[str], None], console=None, echo_err: Callable[[str], None] | None = None) -> int:
    echo_err = echo_err or (lambda line: None)
    if not rules_file:
        rules, notes, load_error, detail = [], [], "detection_rules.yaml introuvable (--rules PATH)", ""
    else:
        rules, notes, load_error, detail = load_rules(rules_file)
    outcomes = check_rules(rules, live=live, query_timeout_s=query_timeout_s, total_s=total_s) if rules else []
    code = exit_code(outcomes, load_error)
    if as_json:
        # The full words (Azure's, A3's: they may name the infrastructure) to stderr: the CD's
        # journal, private, keeps them; the JSON on stdout has the reduced line only.
        for o in outcomes:
            if o.detail:
                echo_err(f"{o.name} [{o.status}/{o.kind}] : {o.detail}")
        if detail:
            echo_err(f"{load_error} : {detail}")
        echo(json.dumps(report(outcomes, live=live, query_timeout_s=query_timeout_s, total_s=total_s,
                               load_error=load_error), ensure_ascii=False))
        return code
    _print(console, outcomes, notes, load_error + (f" — {detail}" if detail else ""), live, code)
    return code


def _print(console, outcomes, notes, load_error, live, code) -> None:
    from rich.markup import escape
    from rich.table import Table

    if load_error:
        console.print(f"[bold red]✗ {escape(load_error)}[/bold red]")
    table = Table(box=None, pad_edge=False)
    for col in ("rule", "layer", "result"):
        table.add_column(col)
    for o in outcomes:
        if o.status == OK:
            result = f"[green]✓ {o.rows} ligne(s), {o.seconds:g} s[/green]" if live else "[green]✓ liée[/green]"
        elif o.status == TIMEOUT:
            result = f"[yellow]⏱ {KINDS[o.kind]} : {escape(o.error)}[/yellow]"
        elif o.status == UNPROVEN:
            result = f"[yellow]? non prouvée, {KINDS.get(o.kind, o.kind)} ({escape(o.code)}) : " \
                     f"{escape(o.detail or o.error)}[/yellow]"
        else:
            result = f"[red]✗ {KINDS.get(o.kind, o.kind)} ({escape(o.code)}) : {escape(o.detail or o.error)}[/red]"
        table.add_row(escape(o.name), o.layer, result)
    if outcomes:
        console.print(table)
    for note in notes:
        console.print(f"  [yellow]·[/yellow] {escape(note)}")
    n = {s: sum(1 for o in outcomes if o.status == s) for s in (OK, ERROR, UNPROVEN, TIMEOUT)}
    what = "requête lancée une fois, en lecture seule" if live else "liaison seule (--live : chaque requête une fois)"
    colour = "green" if code == EXIT_OK else ("yellow" if code == EXIT_TIMEOUT else "red")
    console.print(f"[{colour}]{n[OK]} ok, {n[ERROR]} en erreur, {n[UNPROVEN]} non prouvée(s), {n[TIMEOUT]} sans réponse[/{colour}] — {what}")
