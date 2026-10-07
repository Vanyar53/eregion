from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from glorfindel.detectors import detector_for  # noqa: E402  (after optional deps)

logger = logging.getLogger("glorfindel.detection_rules")

_STATUS_FILE = Path.home() / ".glorfindel" / "rule_status.json"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class MonitoringBackend:
    """A monitoring engine (LAW workspace, Prometheus endpoint, ...)."""
    name: str
    type: str                  # "azure_monitor", "prometheus", "splunk", ...
    workspace_id: str = ""     # LAW workspace GUID or Prometheus endpoint URL
    endpoint: str = ""         # generic endpoint for non-Azure backends


@dataclass
class Asset:
    """A monitored infrastructure asset (VM, backup vault, storage, ...)."""
    name: str
    type: str                              # "azure_vm", "azure_backup_vault", ...
    resource_id: str = ""                  # full Azure resource ID (VMs, storage)
    monitoring_backends: list[str] = field(default_factory=list)
    # Fields specific to azure_backup_vault
    vault_name: str = ""                   # vault short name (rsv-annatar)
    resource_group: str = ""               # resource group of the vault


@dataclass
class DetectionRule:
    """A detection rule — query + metadata.

    workspace_id and resource_id are resolved at load time (from explicit
    assets) or at runtime (from discovered assets when auto_apply=True).
    """
    name: str
    source: str                # "azure_monitor" | "prometheus" | ...
    workspace_id: str          # resolved from MonitoringBackend
    query: str
    ttp: str
    resource_id: str           # resolved from Asset (empty if auto_apply)
    interval_s: float = 30.0
    enabled: bool = True
    description: str = ""
    # references
    asset_name: str = ""
    monitoring_backend_name: str = ""
    # auto_apply: True when no explicit assets — applies to all discovered
    # assets for the monitoring_backend (filtered by GlorfindelConfig.exceptions)
    auto_apply: bool = False
    expected_latency_s: int = 0


@dataclass
class DetectionConfig:
    """Full detection configuration parsed from detection_rules.yaml."""
    backends: list[MonitoringBackend]
    assets: list[Asset]
    rules: list[DetectionRule]

    def backend(self, name: str) -> MonitoringBackend | None:
        return next((b for b in self.backends if b.name == name), None)

    def asset(self, name: str) -> Asset | None:
        return next((a for a in self.assets if a.name == name), None)

    def asset_for_resource(self, resource_id: str) -> Asset | None:
        return next((a for a in self.assets if a.resource_id == resource_id), None)


# ── Row normalisation ──────────────────────────────────────────────────────────

# Priority-ordered list of (column_name, semantic_label).
# First match wins. Columns absent from a row are skipped.
_INDICATOR_COLUMNS: list[tuple[str, str]] = [
    ("MaxWrite",        "disk_write_rate_bps"),
    ("FailedAttempts",  "failed_auth_count"),
    ("SourceIP",        "source_ip"),
    ("CallerIpAddress", "caller_ip"),
    ("PutBlobCount",    "blob_upload_count"),
    ("EgressBytes",     "egress_bytes"),
    ("SyslogMessage",   "syslog_event"),   # may be overridden below
]

_RESOURCE_COLUMNS = ("Computer", "computer", "AccountName", "StorageAccountName")
_SKIP_GENERIC = frozenset({"TimeGenerated", "_ResourceId", "TenantId", "Type"})


# The CURATED threat-indicator labels (the `_INDICATOR_COLUMNS` semantic labels + the
# privilege_escalation override). A row mapping to one of these is "characterized" — we
# recognise the kind of threat. A generic-fallback column or "unknown" is NOT: we found
# data but can't say what threat it represents. The decide guardrail uses this to refuse
# AUTONOMOUS disruptive action on an uncharacterized signal.
#
# `syslog_event` is deliberately NOT in the set. SyslogMessage names a log SOURCE, not a
# threat: every Syslog-based rule produces it — including the rules the LLM authors in
# the purple loop. Counting its mere presence as "characterized" switched the guardrail
# off for the whole Syslog family. A Syslog row is characterized only by a curated
# pattern: USER=root (privilege_escalation, in normalize_row) or one below.
RECOGNIZED_INDICATOR_KEYS: frozenset = frozenset(
    {label for _, label in _INDICATOR_COLUMNS if label != "syslog_event"}
    | {"privilege_escalation"}
)

# Curated Syslog patterns (lowercase substrings) → the threat they characterize. Bless a
# new one only after a human has checked what the line means. Account creation keeps the
# documented design: characterized-but-ambiguous, so the CONFIDENCE gate (not this
# guardrail) decides — validated on real T1136.001 runs ("new user: name=…").
_CURATED_SYSLOG_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("account_creation", ("new user:", "useradd")),
)


def has_recognized_indicator(row: dict, ttp: str = "") -> bool:
    """True if the row maps to a curated threat indicator (not a generic-fallback column,
    'unknown', nor an uncurated Syslog line). Deterministic, model-independent — used to
    gate autonomous action. Does not change what normalize_row gives the LLM."""
    norm = normalize_row(row, ttp)
    key = norm.get("indicator_key")
    if key == "syslog_event":
        message = str(norm.get("indicator_value", "")).lower()
        return any(p in message for _, patterns in _CURATED_SYSLOG_PATTERNS for p in patterns)
    return key in RECOGNIZED_INDICATOR_KEYS


def normalize_row(row: dict, ttp: str = "") -> dict:
    """Map a raw KQL result row to a concise indicator dict for the LLM.

    Returns {"resource": str, "indicator_key": str, "indicator_value": Any}.
    Preserves the full row in raw_signal.first_result_row — this function only
    adds a normalised summary so the LLM can identify the primary threat signal
    without parsing opaque column names.
    Falls back gracefully when the row has no recognised columns.
    """
    resource = next((row[c] for c in _RESOURCE_COLUMNS if c in row), "")

    for col, label in _INDICATOR_COLUMNS:
        if col not in row:
            continue
        value = row[col]
        # SyslogMessage containing USER=root → more specific label
        if col == "SyslogMessage" and "USER=root" in str(value):
            label = "privilege_escalation"
        return {"resource": resource, "indicator_key": label, "indicator_value": value}

    # Generic fallback: first non-metadata key
    for col, value in row.items():
        if col not in _SKIP_GENERIC:
            return {"resource": resource, "indicator_key": col.lower(), "indicator_value": value}

    return {"resource": resource, "indicator_key": "unknown", "indicator_value": None}


# ── Loading ────────────────────────────────────────────────────────────────────

def _resolve_backend_for_rule(
    rule_name: str,
    named_backend_name: str,
    backend_by_name: dict,
    backends: list,
    source: str,
):
    """Pick the monitoring backend a rule should use — bind it to glorfindel-config.

    A rule references a backend by name; the connection details (workspace_id) live
    in glorfindel-config.yaml. To avoid a brittle name match that fails SILENTLY
    (a typo or a renamed backend → empty workspace_id → a rule that never fires
    and never errors), resolution is:

      1. the explicitly named backend if it exists in config;
      2. otherwise the single config backend of the rule's type (the common
         single-LAW case) — so the name in detection_rules.yaml is optional;
      3. nothing — but always WARNED about (missing name, or ambiguity when
         several backends of the type exist and none is named).

    Returns the chosen MonitoringBackend, or None (caller disables the rule).
    """
    if named_backend_name:
        b = backend_by_name.get(named_backend_name)
        if b is not None:
            return b
        logger.warning(
            "detection rule '%s': monitoring backend '%s' is not defined in "
            "glorfindel-config.yaml", rule_name, named_backend_name,
        )

    candidates = [b for b in backends if b.type == source]
    if len(candidates) == 1:
        chosen = candidates[0]
        if named_backend_name and named_backend_name != chosen.name:
            logger.warning(
                "detection rule '%s': falling back to the only '%s' backend "
                "'%s' from glorfindel-config.yaml", rule_name, source, chosen.name,
            )
        return chosen
    if not candidates:
        logger.warning(
            "detection rule '%s': no '%s' monitoring backend in "
            "glorfindel-config.yaml — rule cannot run", rule_name, source,
        )
    else:
        logger.warning(
            "detection rule '%s': %d '%s' backends defined and none named — "
            "add `monitoring_backends: [<name>]` to disambiguate; rule cannot run",
            rule_name, len(candidates), source,
        )
    return None


_TRUNCATE_RE = re.compile(r"\|\s*(limit|take|top)\b", re.IGNORECASE)


def _truncates_before_vm_filter(query: str) -> bool:
    """A rule applied to every discovered VM runs one unfiltered query per VM and keeps
    the rows of THAT VM client-side (B8). A `limit` / `take` / `top` cuts the rows on the
    server first: `| limit 1` on the sudo rule let a benign sudo elsewhere hide the
    attack for the whole window (third review, T7). Comment lines are ignored."""
    code = "\n".join(line.split("//", 1)[0] for line in query.splitlines())
    return bool(_TRUNCATE_RE.search(code))


def load_config(path: str | Path, glorfindel_cfg=None) -> DetectionConfig:
    """Load detection configuration from YAML.

    glorfindel_cfg (GlorfindelConfig | None): when provided, monitoring backend
    workspace_id and endpoint are resolved from it — detection_rules.yaml only
    needs backend names, not connection details (single source of truth).

    Supports two formats:
    - New (recommended): assets + rules sections, backends from glorfindel_cfg.
    - Legacy: rules with workspace_id and resource_id inline.
      Backward-compatible so existing configs and tests continue to work.
    """
    import os
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    p = Path(path)
    if not p.exists():
        return DetectionConfig(backends=[], assets=[], rules=[])
    raw = os.path.expandvars(p.read_text())
    data = yaml.safe_load(raw)
    if not data or not isinstance(data, dict):
        return DetectionConfig(backends=[], assets=[], rules=[])

    # ── Build backend lookup ──────────────────────────────────────────────────
    # glorfindel_cfg is the source of truth for connection details (workspace_id,
    # endpoint). YAML monitoring_backends (if present) supplement for legacy configs.
    backend_by_name: dict[str, MonitoringBackend] = {}
    if glorfindel_cfg:
        for b in glorfindel_cfg.monitoring_backends:
            backend_by_name[b.name] = MonitoringBackend(
                name=b.name,
                type=b.type,
                workspace_id=b.workspace_id,
                endpoint=b.endpoint,
            )
    for b in data.get("monitoring_backends", []):
        if b["name"] not in backend_by_name:
            backend_by_name[b["name"]] = MonitoringBackend(
                name=b["name"],
                type=b.get("type", "azure_monitor"),
                workspace_id=b.get("workspace_id", ""),
                endpoint=b.get("endpoint", ""),
            )
    backends = list(backend_by_name.values())

    # ── Parse assets ──────────────────────────────────────────────────────────
    assets: list[Asset] = []
    for a in data.get("assets", []):
        assets.append(Asset(
            name=a["name"],
            type=a.get("type", "azure_vm"),
            resource_id=a.get("resource_id", ""),
            monitoring_backends=a.get("monitoring_backends", []),
            vault_name=a.get("vault_name", ""),
            resource_group=a.get("resource_group", ""),
        ))

    asset_by_name = {a.name: a for a in assets}

    # ── Parse rules ───────────────────────────────────────────────────────────
    rules: list[DetectionRule] = []
    for item in data.get("rules", []):
        if not item.get("enabled", True):
            continue

        rule_assets  = item.get("assets", [])
        rule_backends = item.get("monitoring_backends", [])

        # Detect auto-apply: no explicit assets → apply to all discovered assets
        auto_apply = not rule_assets or rule_assets == ["auto"]

        # Which backend NAME does the rule reference (if any)?
        if rule_backends:
            primary_backend_name = rule_backends[0]
        elif item.get("monitoring_backend"):
            primary_backend_name = item["monitoring_backend"]
        else:
            primary_backend_name = ""

        rule_source = item.get("source", "azure_monitor")
        inline_ws = item.get("workspace_id", "")

        if not auto_apply and (backends or assets):
            # Explicit assets: resolve resource_id from graph; backend may come
            # from the asset if the rule didn't name one.
            primary_asset_name = rule_assets[0] if rule_assets else ""
            primary_asset = asset_by_name.get(primary_asset_name)
            resource_id = primary_asset.resource_id if primary_asset else item.get("resource_id", "")
            if not primary_backend_name and primary_asset and primary_asset.monitoring_backends:
                primary_backend_name = primary_asset.monitoring_backends[0]
        elif not auto_apply:
            # Legacy inline format
            resource_id = item.get("resource_id", "")
            primary_asset_name = ""
        else:
            # Auto-apply: resource_id filled at runtime per discovered asset
            resource_id = ""
            primary_asset_name = ""

        # Bind the rule to a config backend. An inline workspace_id (legacy) wins
        # and skips the config lookup; otherwise resolve against glorfindel-config
        # with a forgiving, LOUD fallback (never an empty workspace_id in silence).
        if inline_ws:
            workspace_id = inline_ws
            source = rule_source
            resolved_backend_name = primary_backend_name
        else:
            backend = _resolve_backend_for_rule(
                item["name"], primary_backend_name, backend_by_name, backends, rule_source,
            )
            workspace_id = backend.workspace_id if backend else ""
            source = backend.type if backend else rule_source
            # Asset matching (expand_for_discovered) keys off this name, so it must
            # be the RESOLVED backend's name — not a stale/typo'd reference.
            resolved_backend_name = backend.name if backend else primary_backend_name

        # A rule that couldn't resolve a workspace must not poll silently.
        rule_enabled = True
        if source == "azure_monitor" and not workspace_id:
            logger.warning(
                "detection rule '%s': no workspace_id resolved — rule disabled",
                item["name"],
            )
            rule_enabled = False

        if auto_apply and _truncates_before_vm_filter(item["query"]):
            logger.warning(
                "detection rule '%s': `limit` / `take` / `top` runs on the server BEFORE the "
                "per-VM filter — with several VMs, a row from one VM hides the others "
                "(use `summarize arg_max(TimeGenerated, *) by Computer`)",
                item["name"],
            )

        rules.append(DetectionRule(
            name=item["name"],
            source=source,
            workspace_id=workspace_id,
            query=item["query"],
            ttp=item.get("ttp", ""),
            resource_id=resource_id,
            interval_s=float(item.get("interval_s", 30)),
            enabled=rule_enabled,
            description=item.get("description", ""),
            asset_name=primary_asset_name,
            monitoring_backend_name=resolved_backend_name,
            auto_apply=auto_apply,
            expected_latency_s=int(item.get("expected_latency_s", 0)),
        ))

    return DetectionConfig(backends=backends, assets=assets, rules=rules)


def load_rules(path: str | Path, glorfindel_cfg=None) -> list[DetectionRule]:
    """Return only the rules from a detection config file. Backward-compatible."""
    return load_config(path, glorfindel_cfg=glorfindel_cfg).rules


def pollable_rules(rules: list[DetectionRule]) -> list[DetectionRule]:
    """Rules that can actually query a backend (enabled + a resolved workspace_id)."""
    return [r for r in rules if r.enabled and r.workspace_id]


def detection_inert(rules: list[DetectionRule]) -> bool:
    """True if NO rule can poll — detection fires nothing.

    Happens when glorfindel-config.yaml has no monitoring backend (so every rule
    resolves to an empty workspace_id) or every rule is disabled. Honest signal >
    silence: callers (watch banner, /api/state) surface this so a deployment that
    detects nothing doesn't look healthy — a key defined-but-inert must shout, not
    fail quietly."""
    return len(pollable_rules(rules)) == 0


# ── Status persistence ────────────────────────────────────────────────────────

def _load_status() -> dict:
    try:
        return json.loads(_STATUS_FILE.read_text()) if _STATUS_FILE.exists() else {}
    except Exception:
        return {}


def _save_status(status: dict) -> None:
    """Atomic write (tmp + rename): poll threads rewrite this file while the War Room
    and `rulepoller_recently_matched` read it — a reader used to catch it truncated
    mid-write and see no status at all (flaky test, possible in production)."""
    import os
    import tempfile
    _STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=_STATUS_FILE.parent, prefix=".rule_status.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(status, indent=2))
        os.replace(tmp, _STATUS_FILE)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# Query window of a polled rule. The rule's own `ago()` decides what it looks at; the
# API timespan used to be `now - 2*interval_s` (60 s), which overrides the query's
# window: a row ingested more than ~84 s after its TimeGenerated was never seen. Run of
# 2026-10-05: Perf ingestion 89–109 s → `ransomware-disk-write` matched nothing.
_DEFAULT_LOOKBACK_S = 600.0
_INGESTION_MARGIN_S = 300.0
_AGO_RE = re.compile(r"ago\(\s*(\d+(?:\.\d+)?)\s*([smhd])\s*\)", re.IGNORECASE)
_UNIT_S = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _query_lookback_s(query: str) -> float:
    """Longest `ago(...)` window in a KQL query (seconds); default 10 min."""
    spans = [float(n) * _UNIT_S[u.lower()] for n, u in _AGO_RE.findall(query or "")]
    return max(spans) if spans else _DEFAULT_LOOKBACK_S


def _looks_numeric(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False


def _row_identity(row: dict) -> str:
    """What makes a match "the same detection" across polls.

    A row with TimeGenerated is that event. An aggregated row (summarize … by Computer
    / SourceIP) has none, and its counts grow while the attack runs: its identity is
    its non-numeric columns (who, where) — the same attacker on the same VM is one
    detection for the length of the query window.
    """
    ts = row.get("TimeGenerated")
    if ts:
        return f"ts:{ts}"
    keys = sorted(
        f"{k}={v}" for k, v in row.items()
        if isinstance(v, str) and v and not _looks_numeric(v)
    )
    return "row:" + "|".join(keys)


def _row_attribution(row: dict, resource_id: str, asset_name: str) -> bool | None:
    """Does this row concern this asset? True/False when the row names a resource
    (`_ResourceId` / `ResourceId` / `Computer`), None when it can't tell (a query
    aggregated by attacker IP or storage account)."""
    rid = row.get("_ResourceId") or row.get("ResourceId")
    if isinstance(rid, str) and rid:
        return rid.lower() == (resource_id or "").lower()
    computer = row.get("Computer")
    if isinstance(computer, str) and computer:
        host = computer.split(".")[0].lower()
        names = {(asset_name or "").lower(), (resource_id or "").rstrip("/").split("/")[-1].lower()}
        return host in names or computer.lower() in names
    return None


def rulepoller_recently_matched(ttp: str, within_s: float) -> bool:
    """Return True if a RulePoller rule for this TTP had a match within `within_s` seconds.

    Used by propose_detection_rule to suppress false-positive proposals when the
    RulePoller detected the attack but Annatar's feedback watcher timed out before
    finding the watch file.
    """
    from datetime import datetime, timezone

    status = _load_status()
    now = datetime.now(timezone.utc)
    for entry in status.values():
        if entry.get("ttp") != ttp:
            continue
        last_match = entry.get("last_match")
        if not last_match:
            continue
        try:
            age_s = (now - datetime.fromisoformat(last_match)).total_seconds()
            if 0 <= age_s <= within_s:
                return True
        except Exception:
            pass
    return False


# ── RulePoller ────────────────────────────────────────────────────────────────

_IP_OWNERS_TTL_S = 300.0
# Columns naming the VM that MADE a call (not an attacker's address): a storage call's
# caller is the VM itself (T1041 exfiltration via its managed identity).
_VM_IP_COLUMNS = ("CallerIpAddress",)


def _caller_ip(row: dict) -> str:
    for col in _VM_IP_COLUMNS:
        v = row.get(col)
        if isinstance(v, str) and v:
            # StorageBlobLogs writes "10.0.0.4:52114"; IPv6 isn't routed by this column.
            return v.rsplit(":", 1)[0] if v.count(":") == 1 else v
    return ""


class RulePoller:
    """Polls detection rules continuously and dispatches detection signals.

    One query per rule and per cycle (third review, L13). It used to be one thread per
    (rule, VM), each running the same unfiltered query and keeping its own rows
    client-side: the query volume grew with the number of VMs (~8·N per 30 s for five
    rules, Log Analytics throttles around 20–25 VMs), a `limit` hid the other VMs,
    and a row naming no VM was dispatched once per VM. Now each cycle's rows are
    routed: to the VM the row names (`_ResourceId`, `Computer`), or whose private IP
    made the call (`CallerIpAddress` — T1041), and a row that can't be attributed is
    dispatched once, flagged `unattributed`.
    """

    def __init__(
        self,
        rules: list[DetectionRule],
        dispatch: Callable[[dict], None],
        dry_run: bool = False,
        ip_owners: Callable[[], dict] | None = None,
    ) -> None:
        self._rules = rules
        self._dispatch = dispatch
        self._dry_run = dry_run
        self._stop = threading.Event()
        self._threads: dict[str, threading.Thread] = {}
        self._status: dict = _load_status()
        self._lock = threading.Lock()
        self._registry = None
        self._cfg = None
        # private IP → VM resource id (lowercase), read from Azure, cached.
        self._ip_owners = ip_owners
        self._ip_cache: tuple[float, dict] = (0.0, {})
        self._detectors: dict[str, object] = {}
        # Dedup state: self._status[rule]["dispatched"][target] = {row identity: epoch}
        # — persisted, so a restart doesn't dispatch (and act on) a detection still
        # inside the query window a second time.

    # ── lifecycle ──

    def expand_for_discovered(self, registry, glorfindel_cfg=None) -> None:
        """Auto-apply rules: one poll thread per RULE, routing rows to the assets the
        registry holds at each cycle (a VM discovered later is covered at once, an
        evicted one is no longer). Idempotent — called every minute by the watch."""
        self._registry = registry
        self._cfg = glorfindel_cfg
        for rule in self._rules:
            if rule.auto_apply and rule.enabled:
                self._start_thread(rule)

    def start(self) -> None:
        for rule in self._rules:
            if rule.auto_apply or not rule.enabled:
                continue  # auto_apply starts with the registry; disabled rules don't poll
            self._start_thread(rule)

    def _start_thread(self, rule: DetectionRule) -> None:
        key = f"rule-{rule.name}"
        t = self._threads.get(key)
        if t is not None and t.is_alive():
            return
        t = threading.Thread(target=self._loop, args=(rule,), daemon=True, name=key)
        self._threads[key] = t
        t.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self, rule: DetectionRule) -> None:
        while not self._stop.is_set():
            self.poll_once(rule)
            self._stop.wait(rule.interval_s)

    def status_snapshot(self) -> list[dict]:
        with self._lock:
            out = []
            for rule in self._rules:
                s = self._status.get(rule.name, {})
                out.append({
                    "name": rule.name,
                    "ttp": rule.ttp,
                    "source": rule.source,
                    "workspace_id": rule.workspace_id,
                    "resource_id": rule.resource_id,
                    "asset_name": rule.asset_name,
                    "monitoring_backend_name": rule.monitoring_backend_name,
                    "interval_s": rule.interval_s,
                    "description": rule.description,
                    "last_poll": s.get("last_poll", ""),
                    "last_match": s.get("last_match", ""),
                    "last_error": s.get("last_error", ""),
                    "match_count": s.get("match_count", 0),
                })
            return out

    # ── one cycle ──

    def _targets(self, rule: DetectionRule) -> list[tuple[str, str]]:
        """(resource_id, name) of the assets this rule watches right now."""
        if not rule.auto_apply:
            return [(rule.resource_id, rule.asset_name or rule.resource_id.rstrip("/").split("/")[-1])] \
                if rule.resource_id else []
        if self._registry is None:
            return []
        out = []
        for a in self._registry.for_backend(rule.monitoring_backend_name):
            if not a.resource_id:
                continue
            if self._cfg is not None and self._cfg.is_excluded(a.name, rule.name):
                continue
            out.append((a.resource_id, a.name))
        return out

    def _owners(self) -> dict:
        if self._ip_owners is None:
            return {}
        at, cached = self._ip_cache
        if time.time() - at < _IP_OWNERS_TTL_S:
            return cached
        try:
            owners = {ip: rid.lower() for ip, rid in (self._ip_owners() or {}).items()}
        except Exception as exc:
            logger.warning("rule poller: private IP map unreadable (%s) — keeping the last one", exc)
            owners = cached
        self._ip_cache = (time.time(), owners)
        return owners

    def _route(self, rule: DetectionRule, rows: list[dict],
               targets: list[tuple[str, str]]) -> dict[str, tuple]:
        """target key → ((resource_id, name) | None, rows). A row naming a VM this rule
        doesn't watch (excluded, another backend's) is dropped; one that names none is
        keyed "unattributed"."""
        by_rid = {rid.lower(): (rid, name) for rid, name in targets}
        by_name: dict[str, set] = {}
        for rid, name in targets:
            for n in (name, rid.rstrip("/").split("/")[-1]):
                if n:
                    by_name.setdefault(n.split(".")[0].lower(), set()).add((rid, name))
        out: dict[str, tuple] = {}
        for row in rows:
            named, tgt = False, None
            rid = row.get("_ResourceId") or row.get("ResourceId")
            if isinstance(rid, str) and "/microsoft.compute/virtualmachines/" in rid.lower():
                named, tgt = True, by_rid.get(rid.lower())
            if not named:
                comp = row.get("Computer")
                if isinstance(comp, str) and comp:
                    hits = by_name.get(comp.split(".")[0].lower(), set())
                    # Two watched VMs with this host name (clones in two resource
                    # groups): the name can't tell which — never a guess.
                    if len(hits) <= 1:
                        named, tgt = True, next(iter(hits), None)
            if not named:
                ip = _caller_ip(row)
                owner = self._owners().get(ip) if ip else None
                if owner:
                    named, tgt = True, by_rid.get(owner)
            if named and tgt is None:
                continue
            key = tgt[0].lower() if tgt else "unattributed"
            out.setdefault(key, (tgt, []))[1].append(row)
        return out

    def _detector(self, rule: DetectionRule):
        d = self._detectors.get(rule.name)
        if d is None:
            d = self._detectors[rule.name] = detector_for(rule.source, workspace_id=rule.workspace_id)
        return d

    def poll_once(self, rule: DetectionRule) -> list[dict]:
        """One cycle of one rule: query once, route, dedup, dispatch. Returns the
        signals dispatched (or that would be, in dry-run)."""
        now_iso = datetime.now(timezone.utc).isoformat()
        lookback = _query_lookback_s(rule.query)
        window = lookback + _INGESTION_MARGIN_S
        try:
            now_dt = datetime.now(timezone.utc)
            rows = self._detector(rule).run_query(
                rule.query, timespan=(now_dt - timedelta(seconds=window), now_dt + timedelta(minutes=1)))
        except Exception as exc:
            with self._lock:
                st = self._status.setdefault(rule.name, {})
                st["last_poll"], st["last_error"] = now_iso, str(exc)
                _save_status(self._status)
            return []

        targets = self._targets(rule)
        routed = self._route(rule, rows, targets) if targets else {}
        signals: list[dict] = []
        sent_ids: dict[str, list[str]] = {}
        with self._lock:
            dispatched = self._status.setdefault(rule.name, {}).setdefault("dispatched", {})
            cutoff = time.time() - window
            for key in list(dispatched):
                seen = dispatched[key]
                if isinstance(seen, dict) and "id" in seen and "at" in seen:   # old shape
                    seen = {seen["id"]: seen["at"]}
                dispatched[key] = {i: at for i, at in (seen or {}).items() if float(at) >= cutoff}
            plan = []
            for key, (tgt, krows) in routed.items():
                seen = dispatched.get(key, {})
                new = [r for r in krows if _row_identity(r) not in seen]
                if not new:
                    continue
                # Event rows (TimeGenerated) are one incident per cycle: the newest is
                # sent. Aggregated rows (one per attacker, per account…) each count.
                events = [r for r in new if r.get("TimeGenerated")]
                send = [r for r in new if not r.get("TimeGenerated")]
                if events:
                    send.append(max(events, key=lambda r: str(r["TimeGenerated"])))
                plan.append((key, tgt, send))
                sent_ids[key] = [_row_identity(r) for r in new]

        for key, tgt, send in plan:
            for row in send:
                sig = self._signal(rule, row, tgt, targets, now_iso)
                signals.append(sig)
                if not self._dry_run:
                    self._dispatch(sig)

        with self._lock:
            st = self._status.setdefault(rule.name, {})
            st["last_poll"] = now_iso
            st.pop("last_error", None)
            if signals:
                st["last_match"], st["ttp"] = now_iso, rule.ttp
                st["match_count"] = st.get("match_count", 0) + len(signals)
            # Recorded AFTER the dispatch: a crash in between re-sends (at least once)
            # rather than losing a detection (third review, detail).
            dispatched = st.setdefault("dispatched", {})
            for key, ids in sent_ids.items():
                dispatched.setdefault(key, {}).update({i: time.time() for i in ids})
            _save_status(self._status)
        return signals

    def _signal(self, rule: DetectionRule, row: dict, tgt, targets, now_iso: str) -> dict:
        if tgt is not None:
            resource_id, asset_name = tgt
            attribution = "asset"
        elif not rule.auto_apply:
            # A rule bound to one asset by the operator: its rows are that asset's.
            resource_id, asset_name = targets[0]
            attribution = "asset"
        else:
            # No VM named, none whose IP made the call: never a default target — even
            # with a single monitored VM (third review, L11). The card is anchored on
            # one monitored VM; VM-targeted actions are held.
            resource_id, asset_name = sorted(targets, key=lambda t: t[1])[0]
            attribution = "unattributed"
        ts_compact = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return {
            "signal_id": f"rule-{rule.name}-{uuid.uuid4().hex[:8]}",
            "event": "detection",
            "ttp": rule.ttp,
            "severity": "high",
            "resource_id": resource_id,
            "resource_type": "vm",
            "provider": "azure",
            "timestamp": now_iso,
            "context": {
                "workspace_id": rule.workspace_id,
                "rule_name": rule.name,
                "asset_name": asset_name,
                # Synthetic run_id so store_cycle writes a debug JSONL and the War
                # Room can display the decision. watch-{rule}-{ts}: not an Annatar run.
                "run_id": f"watch-{rule.name}-{ts_compact}",
                "attribution": attribution,
                **({"candidates": sorted(n for _, n in targets)} if attribution == "unattributed" else {}),
            },
            "raw_signal": {
                "detection_source": rule.source,
                "first_result_row": row,
                "normalized_signal": normalize_row(row, ttp=rule.ttp),
            },
        }
