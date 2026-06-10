"""Glorfindel infrastructure configuration.

Separate from detection_rules.yaml which contains rules only.
Loaded from glorfindel-config.yaml (Docker volume or local dev).
Values are direct (no ${VAR} substitution needed — edit the file directly).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

# Default search paths, first match wins
_DEFAULT_PATHS = [
    Path("glorfindel-config.yaml"),
    Path(__file__).parent.parent / "glorfindel-config.yaml",
    Path.home() / ".glorfindel" / "config.yaml",
]


@dataclass
class DiscoveryConfig:
    enabled: bool = True
    interval_s: float = 1800.0   # 30 min default


@dataclass
class MonitoringBackendConfig:
    name: str
    type: str                    # "azure_monitor", "prometheus", ...
    workspace_id: str = ""       # LAW workspace GUID or Prometheus URL
    endpoint: str = ""
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)


@dataclass
class ActionBackendConfig:
    name: str
    type: str                    # "azure_backup_vault"
    vault_name: str = ""
    resource_group: str = ""


@dataclass
class ExceptionConfig:
    """Opt-out rule: prevent a rule (or all rules) from being applied to an asset."""
    asset_pattern: str           # fnmatch pattern matched against VM name
    exclude_all: bool = False    # exclude from all rules
    exclude_rules: list[str] = field(default_factory=list)  # specific rule names

    def matches(self, asset_name: str) -> bool:
        return fnmatch.fnmatch(asset_name, self.asset_pattern)

    def excludes_rule(self, rule_name: str) -> bool:
        return self.exclude_all or rule_name in self.exclude_rules


# Autonomy modes — resolved per asset, defaults to the safest (human_only).
# full_auto is deferred: the mechanism resolves it but config validation refuses
# the value for now. Order of precedence: asset match > global default.
VALID_AUTONOMY_MODES = {"human_only", "non_disruptive"}
DEFERRED_AUTONOMY_MODES = {"full_auto"}


@dataclass
class AutonomyRule:
    """An asset-scoped autonomy mode override (fnmatch, like ExceptionConfig)."""
    match: str                   # fnmatch pattern matched against VM name
    mode: str

    def matches(self, asset_name: str) -> bool:
        return fnmatch.fnmatch(asset_name, self.match)


@dataclass
class AutonomyConfig:
    """Per-asset autonomy policy.

    - human_only (default): nothing executes autonomously — every action, even
      reversible ones (isolate_vm/block/snapshot), is recommended and escalated.
    - non_disruptive: current behaviour — AUTONOMOUS_ACTIONS run, destructive gated.

    allow_destructive is a SEPARATE axis from the mode (Review 2026-06-10):
    delete_resource/wipe_storage are NEVER controlled by a mode. Empty = never
    autonomous, regardless of mode.
    """
    default: str = "human_only"
    assets: list[AutonomyRule] = field(default_factory=list)
    allow_destructive: list[str] = field(default_factory=list)

    def resolve(self, asset_name: str) -> str:
        """Resolve the autonomy mode for an asset. asset > global default.

        Unknown assets fall back to the global default — never an accidental
        inheritance toward a more permissive mode.
        """
        for rule in self.assets:
            if rule.matches(asset_name):
                return rule.mode
        return self.default


@dataclass
class GlorfindelConfig:
    monitoring_backends: list[MonitoringBackendConfig] = field(default_factory=list)
    action_backends: list[ActionBackendConfig] = field(default_factory=list)
    exceptions: list[ExceptionConfig] = field(default_factory=list)
    autonomy: AutonomyConfig = field(default_factory=AutonomyConfig)

    def monitoring_backend(self, name: str) -> MonitoringBackendConfig | None:
        return next((b for b in self.monitoring_backends if b.name == name), None)

    def action_backend(self, name: str) -> ActionBackendConfig | None:
        return next((b for b in self.action_backends if b.name == name), None)

    def backup_vault(self) -> ActionBackendConfig | None:
        return next(
            (b for b in self.action_backends if b.type == "azure_backup_vault"),
            None,
        )

    def is_excluded(self, asset_name: str, rule_name: str) -> bool:
        """Return True if the asset should NOT be monitored by the given rule."""
        return any(
            exc.matches(asset_name) and exc.excludes_rule(rule_name)
            for exc in self.exceptions
        )


def load_glorfindel_config(path: str | Path | None = None) -> GlorfindelConfig:
    """Load infrastructure config from glorfindel-config.yaml.

    If path is None, searches default locations. Returns empty config if not found.
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")

    if path is not None:
        candidates = [Path(path)]
    else:
        candidates = _DEFAULT_PATHS

    cfg_path = next((p for p in candidates if p.exists()), None)
    if cfg_path is None:
        return GlorfindelConfig()

    data = yaml.safe_load(cfg_path.read_text()) or {}

    monitoring_backends = []
    for b in data.get("monitoring_backends", []):
        disc_raw = b.get("discovery", {})
        monitoring_backends.append(MonitoringBackendConfig(
            name=b["name"],
            type=b.get("type", "azure_monitor"),
            workspace_id=b.get("workspace_id", ""),
            endpoint=b.get("endpoint", ""),
            discovery=DiscoveryConfig(
                enabled=disc_raw.get("enabled", True),
                interval_s=float(disc_raw.get("interval_s", 1800)),
            ),
        ))

    action_backends = []
    for b in data.get("action_backends", []):
        action_backends.append(ActionBackendConfig(
            name=b["name"],
            type=b.get("type", "azure_backup_vault"),
            vault_name=b.get("vault_name", ""),
            resource_group=b.get("resource_group", ""),
        ))

    exceptions = []
    for e in data.get("exceptions", []):
        exceptions.append(ExceptionConfig(
            asset_pattern=e["asset_pattern"],
            exclude_all=e.get("exclude_all", False),
            exclude_rules=e.get("exclude_rules", []),
        ))

    autonomy = _parse_autonomy(data.get("autonomy", {}))

    return GlorfindelConfig(
        monitoring_backends=monitoring_backends,
        action_backends=action_backends,
        exceptions=exceptions,
        autonomy=autonomy,
    )


def _validate_mode(mode: str, where: str) -> str:
    """Validate an autonomy mode value, raising a clear error for refused values."""
    if mode in VALID_AUTONOMY_MODES:
        return mode
    if mode in DEFERRED_AUTONOMY_MODES:
        raise ValueError(
            f"Autonomy mode '{mode}' ({where}) is not available yet — it is deferred. "
            f"Use one of {sorted(VALID_AUTONOMY_MODES)}."
        )
    raise ValueError(
        f"Unknown autonomy mode '{mode}' ({where}). "
        f"Valid modes: {sorted(VALID_AUTONOMY_MODES)}."
    )


def _parse_autonomy(raw: dict) -> AutonomyConfig:
    """Parse + validate the autonomy section. Empty/absent → safe defaults."""
    default = _validate_mode(raw.get("default", "human_only"), where="autonomy.default")
    assets = []
    for a in raw.get("assets", []):
        mode = _validate_mode(a["mode"], where=f"autonomy.assets[match={a.get('match', '?')}]")
        assets.append(AutonomyRule(match=a["match"], mode=mode))
    return AutonomyConfig(
        default=default,
        assets=assets,
        allow_destructive=list(raw.get("allow_destructive", [])),
    )


def set_asset_mode(asset_name: str, mode: str, path: str | Path | None = None) -> str:
    """Set the autonomy mode for a single asset and persist to glorfindel-config.yaml.

    Backend for the War Room mode selector / change-mode endpoint. Validates the
    mode (refuses full_auto / unknown), upserts an exact-match `autonomy.assets`
    entry for asset_name, and writes the file back. Returns the resolved path.

    NOTE: this rewrites the YAML via safe_dump — inline comments are not preserved.
    Intended for UI-driven edits; hand-edited configs keep their comments as long
    as the mode is changed through the file directly.
    """
    if yaml is None:
        raise ImportError("PyYAML is required: pip install pyyaml")
    _validate_mode(mode, where=f"set_asset_mode({asset_name})")

    if path is not None:
        cfg_path = Path(path)
    else:
        cfg_path = next((p for p in _DEFAULT_PATHS if p.exists()), _DEFAULT_PATHS[0])

    data = {}
    if cfg_path.exists():
        data = yaml.safe_load(cfg_path.read_text()) or {}

    autonomy = data.setdefault("autonomy", {})
    autonomy.setdefault("default", "human_only")
    assets = autonomy.setdefault("assets", [])

    for entry in assets:
        if entry.get("match") == asset_name:
            entry["mode"] = mode
            break
    else:
        assets.append({"match": asset_name, "mode": mode})

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    return str(cfg_path)
