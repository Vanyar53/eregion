from __future__ import annotations

import textwrap

import pytest

from glorfindel.config import (
    GlorfindelConfig,
    ExceptionConfig,
    MonitoringBackendConfig,
    ActionBackendConfig,
    DiscoveryConfig,
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
