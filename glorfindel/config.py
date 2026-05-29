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


@dataclass
class GlorfindelConfig:
    monitoring_backends: list[MonitoringBackendConfig] = field(default_factory=list)
    action_backends: list[ActionBackendConfig] = field(default_factory=list)
    exceptions: list[ExceptionConfig] = field(default_factory=list)

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

    return GlorfindelConfig(
        monitoring_backends=monitoring_backends,
        action_backends=action_backends,
        exceptions=exceptions,
    )
