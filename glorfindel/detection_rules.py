from __future__ import annotations

import json
import logging
import math
import re
import threading
import weakref
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

from glorfindel.detectors import (  # noqa: E402  (after optional deps)
    backend_type_of,
    detector_class,
    detector_for,
    is_control_plane_source,
    is_identity_source,
    plane_of,
)

logger = logging.getLogger("glorfindel.detection_rules")

_STATUS_FILE = Path.home() / ".glorfindel" / "rule_status.json"

# P1: the client's layer — the rules of THIS deployment (approved, overriding a base rule,
# disabling one), outside the repository, loaded over the shipped base
# (glorfindel/rules/azure/detection_rules.yaml). Nothing writes the base any more: an update
# of Glorfindel replaces it and never loses a client rule. Read at call time (the tests'
# conftest redirects it to tmp).
_CLIENT_RULES_FILE = Path.home() / ".glorfindel" / "client_rules.yaml"


def client_rules_path() -> Path:
    """Where the client's layer lives (~/.glorfindel/client_rules.yaml)."""
    return _CLIENT_RULES_FILE


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
    # P1: "base" (shipped with Glorfindel) or "client" (the client's layer, which wins).
    layer: str = "base"
    # SEC2: a client rule that took the place of the shipped rule of its name — said at
    # load, in the watch banner and by `glorfindel rules`, never only logged.
    replaces_base: bool = False


@dataclass
class DetectionConfig:
    """Full detection configuration parsed from detection_rules.yaml."""
    backends: list[MonitoringBackend]
    assets: list[Asset]
    rules: list[DetectionRule]
    # P1: what the client's layer did to the base (a rule replaced, one disabled, a
    # name it cannot disable…), in words — the watch prints them at start.
    notes: list[str] = field(default_factory=list)
    client_file: str = ""
    # SEC2: the shipped rules a client rule replaces (their names) — the watch says each.
    overrides: list[str] = field(default_factory=list)
    # SEC2: the shipped rules the client's layer turns off (`disable:`, `enabled: false`).
    disabled_base: list[str] = field(default_factory=list)

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

    A control-plane row (AzureActivity, AL1: it has `OperationNameValue`) gives the
    operation as its indicator, the resource it targets, and who made it — `caller`,
    `caller_ip`, and whether its target is Glorfindel's (`glorfindel_managed`) or its
    caller Glorfindel's own identity (`glorfindel_identity`). Every other row keeps the
    three keys it had.

    An identity row (Entra ID, C2: it has `EntraOperation`) gives the operation as its
    indicator (`identity_operation`), the identity it targets as its resource, its actor and
    the actor's address, and the same two marks.
    """
    if row.get("EntraOperation"):
        return {
            "resource": str(row.get("TargetId") or row.get("TargetName") or ""),
            "indicator_key": "identity_operation",
            "indicator_value": row["EntraOperation"],
            "actor": row.get("ActorName") or row.get("ActorId") or "",
            "actor_ip": row.get("ActorIp") or "",
            "glorfindel_managed": row.get("GlorfindelManaged") is True,
            "glorfindel_identity": row.get("GlorfindelIdentity") is True,
        }
    if row.get("OperationNameValue"):
        return {
            "resource": str(row.get("_ResourceId") or row.get("ResourceId") or ""),
            "indicator_key": "control_plane_operation",
            "indicator_value": row["OperationNameValue"],
            "caller": row.get("Caller") or "",
            "caller_ip": row.get("CallerIpAddress") or "",
            "glorfindel_managed": row.get("GlorfindelManaged") is True,
            "glorfindel_identity": row.get("GlorfindelIdentity") is True,
        }
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


# The only fields where ${VAR} is expanded (SEC2): where a deployment names its workspace
# or its target. A query, a name, a description are read as written — the whole file used
# to be expanded, so a rule's text could pull the process's environment into a query.
_EXPANDED_FIELDS = ("workspace_id", "resource_id", "endpoint")


def _expand_documented(data: dict) -> dict:
    import os
    for key in ("rules", "assets", "monitoring_backends"):
        items = data.get(key)
        for entry in items if isinstance(items, list) else []:
            if isinstance(entry, dict):
                for f in _EXPANDED_FIELDS:
                    if isinstance(entry.get(f), str):
                        entry[f] = os.path.expandvars(entry[f])
    return data


def _read_layer(path: Path, notes: list[str] | None = None) -> dict:
    """One layer's YAML as a dict ({} when the file is absent or empty). `notes`: where to
    say that the file holds something else than a dictionary (the client's layer).
    `${VAR}` is expanded in `_EXPANDED_FIELDS` only (SEC2)."""
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text())
    if data is not None and not isinstance(data, dict) and notes is not None:
        notes.append(f"couche du client ({path}) : le fichier n'est pas un dictionnaire YAML "
                     f"(rules:, disable:…) — ignorée, base seule")
    return _expand_documented(data) if isinstance(data, dict) else {}


# The shortest poll a rule may ask for (SEC2): the fastest shipped rule. A rule that asked
# for 1 s ran its query every second — Log Analytics throttles, and every match is a model
# call.
MIN_INTERVAL_S = 30.0


def shipped_rules_path() -> Path:
    """The base shipped with Glorfindel (glorfindel/rules/azure/detection_rules.yaml)."""
    return Path(__file__).resolve().parent / "rules" / "azure" / "detection_rules.yaml"


def shipped_rule_names(path: str | Path | None = None) -> set[str]:
    """The names of the shipped rules (SEC2): a proposed rule never takes one. An unreadable
    base gives the empty set — and a proposal its own name, as before."""
    try:
        return {r["name"] for r in _named(_read_layer(Path(path) if path else shipped_rules_path()).get("rules"))}
    except Exception:
        return set()


_LAYER_KEYS = ("rules", "disable", "assets", "monitoring_backends")
_STR_FIELDS = {
    "rules": ("query", "ttp", "description", "source", "workspace_id", "resource_id", "monitoring_backend"),
    "assets": ("type", "resource_id", "vault_name", "resource_group"),
    "monitoring_backends": ("type", "workspace_id", "endpoint"),
}


def _invalid_client_entry(key: str, entry) -> str | None:
    """Why an entry of the client's layer cannot load (None: it can). Checked here, before
    load_config converts it: one bad entry (`interval_s: 30s`, `name: [x]`) raised there and
    left the watch without any rule — the base's included."""
    if not isinstance(entry, dict):
        return "n'est pas un dictionnaire"
    if not isinstance(entry.get("name"), str) or not entry["name"].strip():
        return "n'a pas de nom (une chaîne)"
    for field_ in _STR_FIELDS[key]:
        if entry.get(field_) is not None and not isinstance(entry[field_], str):
            return f"`{field_}` n'est pas une chaîne"
    for field_ in ("assets", "monitoring_backends"):
        value = entry.get(field_)
        if value is not None and not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
            return f"`{field_}` n'est pas une liste de noms"
    if key != "rules":
        return None
    if not isinstance(entry.get("enabled", True), bool):
        return "`enabled` n'est ni true ni false"
    for field_, convert in (("interval_s", float), ("expected_latency_s", int)):
        if field_ in entry:
            value = entry[field_]
            try:
                if isinstance(value, bool):
                    raise ValueError
                number = convert(value)
            except (TypeError, ValueError):
                return f"`{field_}` n'est pas un nombre ({value!r})"
            # Under the floor, the rule still loads: load_config polls it at the floor and
            # says so (SEC2) — a rule approved before at 15 s keeps detecting.
            if field_ == "interval_s" and not (math.isfinite(number) and number > 0):
                return f"`interval_s` doit être un nombre de secondes positif ({value!r})"
    if entry.get("enabled", True) and not entry.get("query"):
        return "n'a pas de requête"
    return None


def _entry_label(entry) -> str:
    name = entry.get("name") if isinstance(entry, dict) else None
    return f"« {name} »" if isinstance(name, str) and name.strip() else "une entrée"


def _named(items) -> list[dict]:
    """The entries of a list that have a name (anything else in a layer is skipped)."""
    if not isinstance(items, list):
        return []
    return [i for i in items if isinstance(i, dict) and i.get("name")]


def merge_layers(base: dict, client: dict) -> tuple[dict, list[str], dict[str, str]]:
    """The client's layer over the base (P1) → (merged data, notes, layer of each rule).

    - `rules`: a client rule with a base rule's name REPLACES it (in its place), and that is
      said; any other client rule is added after the base. A client rule `enabled: false`
      with a base rule's name disables it.
    - `disable: [<name>, …]`: base rules not loaded at all; a name that is no base rule is
      said, never silently ignored.
    - `assets`, `monitoring_backends`: the client's entry wins by name, the others are added.
    An entry that cannot load (no name, no query, `interval_s: 30s`, a field of the wrong
    type…) is skipped and said; so is a key that is not a list, or a key we do not know: one
    bad entry must not stop the watch from loading the others, nor the base.
    """
    notes: list[str] = []
    for key, value in client.items():
        if key not in _LAYER_KEYS:
            notes.append(f"couche du client : clé `{key}` inconnue, ignorée ({', '.join(_LAYER_KEYS)})")
        elif value is not None and not isinstance(value, list):
            notes.append(f"couche du client : `{key}` n'est pas une liste, ignoré")

    def entries(key):
        value = client.get(key)
        out = []
        for entry in value if isinstance(value, list) else []:
            reason = _invalid_client_entry(key, entry)
            if reason:
                notes.append(f"couche du client, {key} : {_entry_label(entry)} {reason}, ignorée")
            else:
                out.append(entry)
        return out

    merged = dict(base)
    for key in ("monitoring_backends", "assets"):
        items = list(base.get(key) or [])
        for entry in entries(key):
            at = next((i for i, b in enumerate(items)
                       if isinstance(b, dict) and b.get("name") == entry["name"]), None)
            if at is None:
                items.append(entry)
            else:
                items[at] = entry
                notes.append(f"{key} « {entry['name']} » : celui de la couche du client remplace celui de la base")
        if items or key in base:
            merged[key] = items

    base_rules = _named(base.get("rules"))
    disable = client.get("disable")
    disabled = []
    for n in disable if isinstance(disable, list) else []:
        if isinstance(n, str) and n.strip():
            disabled.append(n)
        else:
            notes.append(f"couche du client, disable : {n!r} n'est pas un nom de règle, ignoré")
    base_names = {r["name"] for r in base_rules}
    for name in disabled:
        if name not in base_names:
            notes.append(f"couche du client : « {name} » à désactiver n'est pas une règle de base — rien n'est désactivé")
    rules: list[dict] = []
    layer: dict[str, str] = {}
    for r in base_rules:
        if r["name"] in disabled:
            notes.append(f"règle de base « {r['name']} » désactivée par la couche du client")
            continue
        rules.append(r)
        layer[r["name"]] = "base"

    for entry in entries("rules"):
        name = entry["name"]
        at = next((i for i, r in enumerate(rules) if r["name"] == name), None)
        if at is None:
            rules.append(entry)
        else:
            if layer.get(name) == "client":
                notes.append(f"couche du client : « {name} » deux fois, la dernière gagne")
            elif entry.get("enabled", True):
                notes.append(f"règle de base « {name} » remplacée par celle de la couche du client")
            else:
                notes.append(f"règle de base « {name} » désactivée par la couche du client")
            rules[at] = entry
        layer[name] = "client"
    merged["rules"] = rules
    return merged, notes, layer


# Notes already logged: /api/state reloads the rules at every refresh of the War Room — a
# note is logged once per process, and kept on DetectionConfig.notes for whoever shows it.
_NOTES_LOGGED: set[str] = set()


def _log_notes(notes: list[str]) -> None:
    for note in notes:
        if note not in _NOTES_LOGGED:
            _NOTES_LOGGED.add(note)
            logger.warning("detection rules: %s", note)


def load_config(path: str | Path, glorfindel_cfg=None, client_layer: str | Path | bool = True) -> DetectionConfig:
    """Load detection configuration from YAML: the shipped base at `path`, then the
    client's layer over it (P1, `client_rules_path()`; `client_layer=False`: the base
    alone; a path: that file as the client's layer).

    glorfindel_cfg (GlorfindelConfig | None): when provided, monitoring backend
    workspace_id and endpoint are resolved from it — detection_rules.yaml only
    needs backend names, not connection details (single source of truth).

    Supports two formats:
    - New (recommended): assets + rules sections, backends from glorfindel_cfg.
    - Legacy: rules with workspace_id and resource_id inline.
      Backward-compatible so existing configs and tests continue to work.

    An unreadable client layer does not stop the base from loading: the error is logged
    and kept in the notes (the watch keeps detecting with the base rules).
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    data = _read_layer(Path(path))
    base_names = {r["name"] for r in _named(data.get("rules"))}
    base_on = {r["name"] for r in _named(data.get("rules")) if r.get("enabled", True)}
    notes: list[str] = []
    layer_of: dict[str, str] = {}
    client_file = ""
    if client_layer:
        cpath = client_rules_path() if client_layer is True else Path(client_layer)
        try:
            client = _read_layer(cpath, notes)
        except Exception as exc:
            client = {}
            notes.append(f"couche du client illisible ({cpath}) : {exc} — base seule")
        if client:
            client_file = str(cpath)
            data, more, layer_of = merge_layers(data, client)
            notes += more
    if not data:
        _log_notes(notes)
        return DetectionConfig(backends=[], assets=[], rules=[], notes=notes, client_file=client_file)

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
    overrides: list[str] = []
    for item in data.get("rules", []):
        if not item.get("enabled", True):
            continue
        replaces_base = layer_of.get(item["name"]) == "client" and item["name"] in base_names
        if replaces_base:
            overrides.append(item["name"])
        interval_s = float(item.get("interval_s", 30))
        if not (math.isfinite(interval_s) and interval_s >= MIN_INTERVAL_S):
            notes.append(f"règle « {item['name']} » : interval_s {item.get('interval_s')!r} sous le "
                         f"minimum — interrogée toutes les {MIN_INTERVAL_S:g} s")
            interval_s = MIN_INTERVAL_S

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
            # An AzureActivity rule reads the azure_monitor workspace (AL1): its backend
            # type is not its source name.
            backend = _resolve_backend_for_rule(
                item["name"], primary_backend_name, backend_by_name, backends,
                backend_type_of(rule_source),
            )
            workspace_id = backend.workspace_id if backend else ""
            if backend is not None and backend_type_of(rule_source) == backend.type:
                source = rule_source
            else:
                source = backend.type if backend else rule_source
            # Asset matching (expand_for_discovered) keys off this name, so it must
            # be the RESOLVED backend's name — not a stale/typo'd reference.
            resolved_backend_name = backend.name if backend else primary_backend_name

        # A rule that couldn't resolve a workspace must not poll silently.
        rule_enabled = True
        if backend_type_of(source) == "azure_monitor" and not workspace_id:
            logger.warning(
                "detection rule '%s': no workspace_id resolved — rule disabled",
                item["name"],
            )
            rule_enabled = False

        if auto_apply and rule_enabled and inline_ws and not resolved_backend_name:
            # The inline form an approval wrote before P1: auto-apply on no backend — the
            # expansion finds no VM for it, the RulePoller drops every row naming one.
            note = (f"règle « {item['name']} » : workspace en ligne sans backend ni assets — elle ne "
                    "s'applique à aucune VM découverte (la lier : monitoring_backends: [<backend>], "
                    "assets: [auto] ; glorfindel migrate-rules le fait pour une règle approuvée avant P1)")
            notes.append(note)

        # A control-plane log arrives late (AzureActivity: minutes, sometimes more than
        # ten): a shorter window drops the row before it is ingested (AL1).
        min_lookback = getattr(detector_class(source), "min_lookback_s", 0.0) or 0.0
        if rule_enabled and _query_lookback_s(item["query"]) < min_lookback:
            notes.append(
                f"règle « {item['name']} » ({source}) : fenêtre "
                f"{int(_query_lookback_s(item['query']) // 60)} min, plus courte que la latence "
                f"d'ingestion de sa source — les lignes arrivées en retard ne sont jamais vues "
                f"(au moins ago({int(min_lookback // 60)}m))")
        # Without its CorrelationId, an operation's identity is its time: two operations
        # at the same instant fold into one card, the second never seen (AL1).
        if rule_enabled and (is_control_plane_source(source) or "azureactivity" in item["query"].lower()) \
                and "correlationid" not in item["query"].lower():
            notes.append(
                f"règle « {item['name']} » ({source}) : la requête ne projette pas "
                f"CorrelationId — deux opérations au même horodatage n'y font qu'une détection, "
                f"la seconde jamais vue (projeter CorrelationId, OperationNameValue, _ResourceId)")
        # An identity finding's dedup key is its EventId (C2): without it, two findings at
        # the same instant fold into one card, the second never seen.
        if rule_enabled and is_identity_source(source) and "eventid" not in item["query"].lower():
            notes.append(
                f"règle « {item['name']} » ({source}) : la requête ne projette pas EventId — "
                f"deux opérations au même horodatage n'y font qu'une détection, la seconde "
                f"jamais vue (projeter EntraKind, EntraOperation, EventId)")
        # Entra's tables read by another source: none of its thresholds, none of its marks
        # (Glorfindel's identity). Its signals still carry `plane: identity` (`_signal`, from
        # the query itself, whatever it projects): decided by the code, without the model.
        if rule_enabled and not is_identity_source(source) and _reads_entra_table(item["query"]):
            notes.append(
                f"règle « {item['name']} » ({source}) : lit un journal d'Entra ID sans la source "
                f"azure_entra — ni ses seuils ni ses marques (identité de Glorfindel) ; "
                f"utiliser source: azure_entra")

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
            interval_s=interval_s,
            enabled=rule_enabled,
            description=item.get("description", ""),
            asset_name=primary_asset_name,
            monitoring_backend_name=resolved_backend_name,
            auto_apply=auto_apply,
            expected_latency_s=int(item.get("expected_latency_s", 0)),
            layer=layer_of.get(item["name"], "base"),
            replaces_base=replaces_base,
        ))

    loaded = {item["name"] for item in data.get("rules", []) if item.get("enabled", True)}
    disabled_base = sorted(base_on - loaded) if client_file else []

    _log_notes(notes)
    return DetectionConfig(backends=backends, assets=assets, rules=rules,
                           notes=notes, client_file=client_file, overrides=overrides,
                           disabled_base=disabled_base)


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
# KQL timespan literals: 10m, 30min, 2h, 2hours, 1d, 1.5days, 90s, 90sec… (third review:
# `ago(30min)` / `ago(2hours)` weren't recognised and fell back to 10 minutes).
_AGO_RE = re.compile(
    r"ago\(\s*(\d+(?:\.\d+)?)\s*(d|days?|h|hrs?|hours?|m|mins?|minutes?|s|secs?|seconds?|ms|milliseconds?)\s*\)",
    re.IGNORECASE)
_UNIT_S = {"d": 86400, "h": 3600, "m": 60, "s": 1}


def _unit_seconds(unit: str) -> float:
    u = unit.lower()
    if u.startswith("ms") or u.startswith("milli"):
        return 0.001
    if u.startswith("min") or u == "m":
        return 60
    return _UNIT_S[u[0]]


def _query_lookback_s(query: str) -> float:
    """Longest `ago(...)` window in a KQL query (seconds); default 10 min."""
    # Comment lines don't count: `// was ago(1d)` must not widen the window.
    code = "\n".join(line.split("//", 1)[0] for line in (query or "").splitlines())
    spans = [float(n) * _unit_seconds(u) for n, u in _AGO_RE.findall(code)]
    return max(spans) if spans else _DEFAULT_LOOKBACK_S


_ENTRA_TABLE_RE = re.compile(
    r"\b(auditlogs|signinlogs|aadserviceprincipalsigninlogs|aadnoninteractiveusersigninlogs|"
    r"aadmanagedidentitysigninlogs)\b", re.IGNORECASE)


def _reads_entra_table(query: str) -> bool:
    """The query reads one of Entra ID's tables (comments left out)."""
    code = "\n".join(line.split("//", 1)[0] for line in (query or "").splitlines())
    return bool(_ENTRA_TABLE_RE.search(code))


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
    # An identity finding (Entra ID, C2) is its EventId — its CorrelationId and target, or
    # a service principal and an address: a line ingested late is the same one.
    if row.get("EntraOperation") and row.get("EventId"):
        return "entra:" + str(row["EventId"]).lower()
    # A control-plane operation (AzureActivity, AL1) is its correlation id, operation and
    # target: its Start, Accept and Success lines — and a line ingested late — are one.
    if row.get("OperationNameValue") and row.get("CorrelationId"):
        return "op:" + "|".join(str(row.get(k) or "").lower()
                                for k in ("CorrelationId", "OperationNameValue", "_ResourceId"))
    ts = row.get("TimeGenerated")
    if ts:
        return f"ts:{ts}"
    keys = sorted(
        f"{k}={v}" for k, v in row.items()
        if isinstance(v, str) and v and not _looks_numeric(v)
    )
    return "row:" + "|".join(keys)


# Control plane (AL1): at most this many cards per rule and poll, each one operation; the
# operations beyond share one summary card that names each of them.
_CONTROL_PLANE_CARDS_PER_POLL = 5


def _grave(row: dict) -> bool:
    """A write on Glorfindel's own rules, or its identity outside what it does (AL1)."""
    return row.get("GlorfindelManaged") is True or row.get("GlorfindelIdentity") is True


def _control_plane_operations(rows: list[dict]) -> list[dict]:
    """One row per operation (its lines Start, Accept, Success share an identity: the
    latest is kept), the gravest first, then the newest."""
    by_op: dict[str, dict] = {}
    for r in rows:
        k = _row_identity(r)
        if k not in by_op or str(r.get("TimeGenerated") or "") > str(by_op[k].get("TimeGenerated") or ""):
            by_op[k] = r
    return sorted(by_op.values(), key=lambda r: (_grave(r), str(r.get("TimeGenerated") or "")),
                  reverse=True)


def _control_plane_summary(rest: list[dict]) -> dict:
    """The card of the operations past the cap: the gravest one's row, carrying the list
    of every one of them (`OmittedOperations`) and either mark if any has it."""
    return {
        **rest[0],
        "GlorfindelManaged": any(r.get("GlorfindelManaged") is True for r in rest),
        "GlorfindelIdentity": any(r.get("GlorfindelIdentity") is True for r in rest),
        "OmittedOperations": [
            {"TimeGenerated": r.get("TimeGenerated") or "",
             "OperationNameValue": r.get("OperationNameValue") or "",
             "ActivityStatusValue": r.get("ActivityStatusValue") or "",
             "Caller": r.get("Caller") or "",
             "_ResourceId": r.get("_ResourceId") or r.get("ResourceId") or "",
             "GlorfindelManaged": r.get("GlorfindelManaged") is True,
             "GlorfindelIdentity": r.get("GlorfindelIdentity") is True,
             # An identity finding (C2): what its card would have said.
             **({"EntraOperation": r.get("EntraOperation") or "",
                 "ActorName": r.get("ActorName") or r.get("ActorId") or "",
                 "TargetName": r.get("TargetName") or "", "TargetId": r.get("TargetId") or ""}
                if r.get("EntraOperation") else {})}
            for r in rest],
    }


# Data sources (SEC2): at most this many cards per rule and poll too — the rows a log can
# be made to hold are not bounded, and each card is a model call. The gravest first; beyond,
# one card per VM names the rows left without their own (`OmittedRows`).
_DATA_CARDS_PER_POLL = 5
# The magnitude a data row is ranked by, in this order (the curated indicators).
_GRAVITY_COLUMNS = ("MaxWrite", "FailedAttempts", "PutBlobCount", "EgressBytes")


def _gravity(row: dict) -> float:
    for col in _GRAVITY_COLUMNS:
        try:
            return float(row[col])
        except (KeyError, TypeError, ValueError):
            continue
    return 0.0


# The rows a summary card carries, the gravest first; beyond, it gives their number.
_SUMMARY_ROWS_MAX = 50


def _data_summary(rest: list[dict]) -> dict:
    """The card of the data rows past the cap: the gravest one's row, carrying the gravest
    of them (`OmittedRows`, at most `_SUMMARY_ROWS_MAX`) and how many there are
    (`OmittedCount`) — none marked sent without being said or counted."""
    return {**rest[0], "OmittedCount": len(rest), "OmittedRows": [
        {k: (v[:300] if isinstance(v, str) else v) for k, v in r.items()
         if isinstance(v, (str, int, float, bool)) or v is None}
        for r in rest[:_SUMMARY_ROWS_MAX]]}


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


class IpOwners:
    """Private IP → VM resource id (lowercase), read from Azure at most once per
    _IP_OWNERS_TTL_S, for whoever reads it: the RulePoller and the watch's attack_started
    lines share one (SEC4c) — each line used to list every VM's interfaces again. An
    unreadable listing keeps the last one. Callable, like the source it wraps."""

    def __init__(self, source: Callable[[], dict]) -> None:
        self._source = source
        self._lock = threading.Lock()
        self._cache: tuple[float, dict] = (0.0, {})

    def __call__(self) -> dict:
        with self._lock:
            at, cached = self._cache
            if at and time.time() - at < _IP_OWNERS_TTL_S:
                return cached
            try:
                owners = {ip: str(rid).lower() for ip, rid in (self._source() or {}).items()}
            except Exception as exc:
                logger.warning("private IP map unreadable (%s) — keeping the last one", exc)
                owners = cached
            self._cache = (time.time(), owners)
            return owners


def shared_ip_owners(source: Callable[[], dict] | None) -> IpOwners | None:
    """`source` behind one IpOwners (itself when it is one already); None stays None."""
    if source is None or isinstance(source, IpOwners):
        return source
    return IpOwners(source)


# Columns naming the VM that MADE a call (not an attacker's address): a storage call's
# caller is the VM itself (T1041 exfiltration via its managed identity).
_VM_IP_COLUMNS = ("CallerIpAddress",)


# A VM's own id in a longer one: an extension, a Run Command, a role assignment scoped on
# the VM (AzureActivity, AL1) names the VM it concerns.
_VM_ID_RE = re.compile(r"^(.*?/providers/microsoft\.compute/virtualmachines/[^/]+)", re.IGNORECASE)


def _vm_id_of(resource_id: str) -> str:
    m = _VM_ID_RE.match(resource_id)
    return (m.group(1) if m else resource_id).lower()


def _caller_ip(row: dict) -> str:
    for col in _VM_IP_COLUMNS:
        v = row.get(col)
        if isinstance(v, str) and v:
            # StorageBlobLogs writes "10.0.0.4:52114"; IPv6 isn't routed by this column.
            return v.rsplit(":", 1)[0] if v.count(":") == 1 else v
    return ""


class RowAttribution:
    """Which VM a detection row is about — the one reading of Glorfindel (the RulePoller's
    routing, and an attack_started's row, SEC4a). Over `targets` (resource_id, name):

      1. the resource it names, `_ResourceId` (or `ResourceId`) of a VM — a sub-resource
         (an extension, a Run Command, a role on the VM) brought back to its VM;
      2. else its `Computer`, cut at the first dot — unless two targets carry that host
         name (clones in two resource groups): the name can't tell which, never a guess;
      3. else the address that made the call (`CallerIpAddress`, a storage call made FROM
         a VM — T1041), when it is a private IP of exactly one VM (`owners()`: IP → id).

    `attribute(row)` → (named, target): named False when the row names no VM; target None
    when the VM it names is not among the targets."""

    def __init__(self, targets: list[tuple[str, str]], owners: Callable[[], dict] | None = None):
        self._owners = owners or (lambda: {})
        self.by_rid = {rid.lower(): (rid, name) for rid, name in targets}
        self.by_name: dict[str, set] = {}
        for rid, name in targets:
            for n in (name, rid.rstrip("/").split("/")[-1]):
                if n:
                    self.by_name.setdefault(n.split(".")[0].lower(), set()).add((rid, name))

    def attribute(self, row: dict) -> tuple[bool, tuple | None]:
        if not isinstance(row, dict):
            return False, None
        rid = row.get("_ResourceId") or row.get("ResourceId")
        if isinstance(rid, str) and "/microsoft.compute/virtualmachines/" in rid.lower():
            return True, self.by_rid.get(_vm_id_of(rid))
        comp = row.get("Computer")
        if isinstance(comp, str) and comp:
            hits = self.by_name.get(comp.split(".")[0].lower(), set())
            # Two watched VMs with this host name (clones in two resource
            # groups): the name can't tell which — never a guess.
            if len(hits) <= 1:
                return True, next(iter(hits), None)
        ip = _caller_ip(row)
        owner = (self._owners() or {}).get(ip) if ip else None
        if owner:
            return True, self.by_rid.get(str(owner).lower())
        return False, None


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

    # Every poller alive, so the tests can stop their threads before the redirected
    # status file is put back: one outlived its test and wrote the operator's real
    # ~/.glorfindel/rule_status.json (sixth review, S5).
    _live: "weakref.WeakSet[RulePoller]" = weakref.WeakSet()

    def __init__(
        self,
        rules: list[DetectionRule],
        dispatch: Callable[[dict], None],
        dry_run: bool = False,
        ip_owners: Callable[[], dict] | None = None,
    ) -> None:
        RulePoller._live.add(self)
        self._rules = rules
        self._dispatch = dispatch
        self._dry_run = dry_run
        self._stop = threading.Event()
        self._threads: dict[str, threading.Thread] = {}
        self._status: dict = _load_status()
        self._lock = threading.Lock()
        self._registry = None
        self._cfg = None
        # private IP → VM resource id (lowercase), read from Azure, cached — the watch
        # hands the IpOwners its attack_started lines read too (SEC4c).
        self._ip_owners = shared_ip_owners(ip_owners)
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

    def stop(self, join_s: float = 0.0) -> None:
        self._stop.set()
        for t in list(self._threads.values()):
            if join_s and t.is_alive() and t is not threading.current_thread():
                t.join(join_s)

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
        return {} if self._ip_owners is None else self._ip_owners()

    def _route(self, rule: DetectionRule, rows: list[dict],
               targets: list[tuple[str, str]]) -> dict[str, tuple]:
        """target key → ((resource_id, name) | None, rows). A row naming a VM this rule
        doesn't watch (excluded, another backend's) is dropped; one that names none is
        keyed "unattributed". Each row read by `attribute_row`."""
        index = RowAttribution(targets, self._owners)
        out: dict[str, tuple] = {}
        for row in rows:
            named, tgt = index.attribute(row)
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
            # The control plane (AL1) and identities (C2): one card per operation.
            control = is_control_plane_source(rule.source) or is_identity_source(rule.source)
            budget = _CONTROL_PLANE_CARDS_PER_POLL
            data_budget = _DATA_CARDS_PER_POLL
            for key, (tgt, krows) in routed.items():
                seen = dispatched.get(key, {})
                new = [r for r in krows if _row_identity(r) not in seen]
                if not new:
                    continue
                if control:
                    # Control plane (AL1): each operation is its own card — two NSG rules
                    # changed in one minute are two findings, never one. Capped per poll;
                    # beyond, one summary card names every operation left without its
                    # own: no row is marked sent without a card.
                    ops = _control_plane_operations(new)
                    send, budget = ops[:budget], max(0, budget - len(ops))
                    rest = ops[len(send):]
                    if rest:
                        send.append(_control_plane_summary(rest))
                    plan.append((key, tgt, send))
                    sent_ids[key] = [_row_identity(r) for r in new]
                    continue
                # Event rows (TimeGenerated) are one incident per cycle: the newest is
                # sent. Aggregated rows (one per attacker, per account…) each count.
                events = [r for r in new if r.get("TimeGenerated")]
                send = [r for r in new if not r.get("TimeGenerated")]
                if events:
                    send.append(max(events, key=lambda r: str(r["TimeGenerated"])))
                # Capped per rule and poll (SEC2), as the control plane: the gravest rows
                # first; the rest of this VM's in one card that names each of them.
                send.sort(key=_gravity, reverse=True)
                rest = send[data_budget:]
                send = send[:data_budget]
                data_budget = max(0, data_budget - len(send))
                if len(rest) == 1:
                    send.append(rest[0])
                elif rest:
                    send.append(_data_summary(rest))
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
        # Control plane (AL1), identities (C2): detection only — `plane` is what `decide`
        # reads.
        plane = plane_of(rule.source)
        # A rule of another source that reads one of Entra ID's tables (a client's, an
        # approved proposal — C2): its rows may name a user (a UPN) without any column that
        # says Entra (`summarize … by UserPrincipalName, IPAddress`). The query says so.
        if plane == "data" and _reads_entra_table(rule.query):
            plane = "identity"
        control = plane in ("control", "identity")
        grave = control and (row.get("GlorfindelManaged") is True or row.get("GlorfindelIdentity") is True)
        return {
            "signal_id": f"rule-{rule.name}-{uuid.uuid4().hex[:8]}",
            "event": "detection",
            "ttp": rule.ttp,
            "severity": "critical" if grave else "high",
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
                **({"plane": plane} if control else {}),
            },
            "raw_signal": {
                "detection_source": rule.source,
                "first_result_row": row,
                "normalized_signal": normalize_row(row, ttp=rule.ttp),
            },
        }
