from __future__ import annotations

import textwrap

import pytest

from glorfindel.config import (
    GlorfindelConfig,
    ExceptionConfig,
    MonitoringBackendConfig,
    ActionBackendConfig,
    DiscoveryConfig,
    AutonomyConfig,
    AutonomyRule,
    load_glorfindel_config,
)


FULL_YAML = textwrap.dedent("""\
    monitoring_backends:
      - name: law-test
        type: azure_monitor
        workspace_id: "ws-guid-123"
        discovery:
          enabled: true
          interval_s: 900

    action_backends:
      - name: rsv-test
        type: azure_backup_vault
        vault_name: "rsv-test"
        resource_group: "rg-test"

    exceptions:
      - asset_pattern: "vm-dev-*"
        exclude_all: true
      - asset_pattern: "vm-staging"
        exclude_rules: [ssh-brute-force]
""")

MINIMAL_YAML = textwrap.dedent("""\
    monitoring_backends:
      - name: law-minimal
        type: azure_monitor
        workspace_id: "ws-abc"
""")


# ── load_glorfindel_config ──────────────────────────────────────────────────────

def test_load_full_config(tmp_path):
    f = tmp_path / "glorfindel-config.yaml"
    f.write_text(FULL_YAML)
    cfg = load_glorfindel_config(f)
    assert len(cfg.monitoring_backends) == 1
    assert cfg.monitoring_backends[0].name == "law-test"
    assert cfg.monitoring_backends[0].workspace_id == "ws-guid-123"
    assert cfg.monitoring_backends[0].discovery.interval_s == 900
    assert len(cfg.action_backends) == 1
    assert cfg.action_backends[0].vault_name == "rsv-test"
    assert len(cfg.exceptions) == 2


def test_load_minimal_config(tmp_path):
    f = tmp_path / "glorfindel-config.yaml"
    f.write_text(MINIMAL_YAML)
    cfg = load_glorfindel_config(f)
    assert len(cfg.monitoring_backends) == 1
    assert cfg.action_backends == []
    assert cfg.exceptions == []


def test_load_missing_config_returns_empty(tmp_path):
    cfg = load_glorfindel_config(tmp_path / "nonexistent.yaml")
    assert cfg.monitoring_backends == []
    assert cfg.action_backends == []
    assert cfg.exceptions == []


def test_discovery_defaults(tmp_path):
    yaml = textwrap.dedent("""\
        monitoring_backends:
          - name: law-def
            type: azure_monitor
            workspace_id: ws
    """)
    f = tmp_path / "cfg.yaml"
    f.write_text(yaml)
    cfg = load_glorfindel_config(f)
    disc = cfg.monitoring_backends[0].discovery
    assert disc.enabled is True
    assert disc.interval_s == 1800.0


# ── GlorfindelConfig helpers ───────────────────────────────────────────────────

def test_monitoring_backend_lookup():
    cfg = GlorfindelConfig(
        monitoring_backends=[
            MonitoringBackendConfig(name="law-a", type="azure_monitor"),
            MonitoringBackendConfig(name="law-b", type="prometheus"),
        ]
    )
    assert cfg.monitoring_backend("law-a").type == "azure_monitor"
    assert cfg.monitoring_backend("missing") is None


def test_action_backend_lookup():
    cfg = GlorfindelConfig(
        action_backends=[
            ActionBackendConfig(name="rsv-main", type="azure_backup_vault", vault_name="rsv"),
        ]
    )
    assert cfg.action_backend("rsv-main").vault_name == "rsv"
    assert cfg.action_backend("missing") is None


def test_backup_vault_helper():
    cfg = GlorfindelConfig(
        action_backends=[
            ActionBackendConfig(name="rsv-main", type="azure_backup_vault"),
        ]
    )
    assert cfg.backup_vault() is not None
    assert cfg.backup_vault().name == "rsv-main"


def test_backup_vault_none_when_empty():
    assert GlorfindelConfig().backup_vault() is None


# ── ExceptionConfig ────────────────────────────────────────────────────────────

def test_exception_exclude_all():
    exc = ExceptionConfig(asset_pattern="vm-dev-*", exclude_all=True)
    assert exc.matches("vm-dev-foo")
    assert not exc.matches("vm-prod-foo")
    assert exc.excludes_rule("any-rule")


def test_exception_exclude_specific_rules():
    exc = ExceptionConfig(asset_pattern="vm-staging", exclude_rules=["ssh-brute-force"])
    assert exc.matches("vm-staging")
    assert exc.excludes_rule("ssh-brute-force")
    assert not exc.excludes_rule("disk-write-anomaly")


def test_is_excluded_via_config():
    cfg = GlorfindelConfig(
        exceptions=[
            ExceptionConfig(asset_pattern="vm-dev-*", exclude_all=True),
            ExceptionConfig(asset_pattern="vm-staging", exclude_rules=["ssh-brute-force"]),
        ]
    )
    assert cfg.is_excluded("vm-dev-foo", "any-rule")
    assert cfg.is_excluded("vm-staging", "ssh-brute-force")
    assert not cfg.is_excluded("vm-staging", "disk-write-anomaly")
    assert not cfg.is_excluded("vm-prod", "any-rule")


# ── AutonomyConfig ─────────────────────────────────────────────────────────────

def test_autonomy_default_is_human_only():
    """Absent autonomy section → safe default human_only."""
    cfg = GlorfindelConfig()
    assert cfg.autonomy.default == "human_only"
    assert cfg.autonomy.resolve("any-vm") == "human_only"


def test_autonomy_resolve_asset_overrides_default():
    autonomy = AutonomyConfig(
        default="human_only",
        assets=[AutonomyRule(match="vm-dev-*", mode="non_disruptive")],
    )
    assert autonomy.resolve("vm-dev-01") == "non_disruptive"
    assert autonomy.resolve("vm-prod-db") == "human_only"  # falls back to default


def test_autonomy_unknown_asset_falls_back_to_default():
    autonomy = AutonomyConfig(
        default="non_disruptive",
        assets=[AutonomyRule(match="vm-prod-db", mode="human_only")],
    )
    # unknown asset → global default, never accidental permissive inheritance
    assert autonomy.resolve("vm-unknown") == "non_disruptive"


def test_load_autonomy_section(tmp_path):
    cfg_file = tmp_path / "glorfindel-config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        autonomy:
          default: human_only
          allow_destructive: []
          assets:
            - match: "vm-dev-*"
              mode: non_disruptive
            - match: "vm-prod-db"
              mode: human_only
    """))
    cfg = load_glorfindel_config(cfg_file)
    assert cfg.autonomy.default == "human_only"
    assert cfg.autonomy.resolve("vm-dev-99") == "non_disruptive"
    assert cfg.autonomy.resolve("vm-prod-db") == "human_only"
    assert cfg.autonomy.allow_destructive == []


def test_load_autonomy_refuses_full_auto_default(tmp_path):
    cfg_file = tmp_path / "glorfindel-config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        autonomy:
          default: full_auto
    """))
    with pytest.raises(ValueError, match="full_auto"):
        load_glorfindel_config(cfg_file)


def test_load_autonomy_refuses_full_auto_asset(tmp_path):
    cfg_file = tmp_path / "glorfindel-config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        autonomy:
          default: human_only
          assets:
            - match: "vm-*"
              mode: full_auto
    """))
    with pytest.raises(ValueError, match="full_auto"):
        load_glorfindel_config(cfg_file)


def test_load_autonomy_refuses_unknown_mode(tmp_path):
    cfg_file = tmp_path / "glorfindel-config.yaml"
    cfg_file.write_text(textwrap.dedent("""
        autonomy:
          default: yolo_mode
    """))
    with pytest.raises(ValueError, match="Unknown autonomy mode"):
        load_glorfindel_config(cfg_file)


def test_set_asset_mode_adds_new_entry(tmp_path):
    from glorfindel.config import set_asset_mode
    cfg_file = tmp_path / "glorfindel-config.yaml"
    set_asset_mode("vm-prod-db", "human_only", path=cfg_file)
    cfg = load_glorfindel_config(cfg_file)
    assert cfg.autonomy.resolve("vm-prod-db") == "human_only"


def test_set_asset_mode_updates_existing_entry(tmp_path):
    from glorfindel.config import set_asset_mode
    cfg_file = tmp_path / "glorfindel-config.yaml"
    set_asset_mode("vm-dev-01", "human_only", path=cfg_file)
    set_asset_mode("vm-dev-01", "non_disruptive", path=cfg_file)
    cfg = load_glorfindel_config(cfg_file)
    assert cfg.autonomy.resolve("vm-dev-01") == "non_disruptive"
    # only one entry for the asset — updated, not duplicated
    assert sum(1 for a in cfg.autonomy.assets if a.match == "vm-dev-01") == 1


def test_set_asset_mode_refuses_full_auto(tmp_path):
    from glorfindel.config import set_asset_mode
    cfg_file = tmp_path / "glorfindel-config.yaml"
    with pytest.raises(ValueError, match="full_auto"):
        set_asset_mode("vm-x", "full_auto", path=cfg_file)


def test_set_asset_mode_preserves_other_sections(tmp_path):
    from glorfindel.config import set_asset_mode
    cfg_file = tmp_path / "glorfindel-config.yaml"
    cfg_file.write_text(MINIMAL_YAML)
    set_asset_mode("vm-a", "non_disruptive", path=cfg_file)
    cfg = load_glorfindel_config(cfg_file)
    # monitoring_backends from MINIMAL_YAML survive the rewrite
    assert len(cfg.monitoring_backends) == 1
    assert cfg.autonomy.resolve("vm-a") == "non_disruptive"
