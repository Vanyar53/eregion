from __future__ import annotations

import textwrap

import pytest

from glorfindel.config import (
    GlorfindelConfig,
    ExceptionConfig,
    MonitoringBackendConfig,
    ActionBackendConfig,
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
        restore_staging_storage: "ststaging"

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
    assert cfg.action_backends[0].restore_staging_storage == "ststaging"
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


def test_autonomy_exact_match_wins_over_broad_pattern():
    """An exact entry (e.g. written by the War Room dropdown) beats a broad wildcard,
    regardless of list order."""
    autonomy = AutonomyConfig(
        default="human_only",
        assets=[
            AutonomyRule(match="vm-*", mode="non_disruptive"),     # broad, listed first
            AutonomyRule(match="vm-prod-db", mode="human_only"),   # exact, listed later
        ],
    )
    assert autonomy.resolve("vm-prod-db") == "human_only"   # exact wins
    assert autonomy.resolve("vm-dev-01") == "non_disruptive"  # only the broad matches


def test_autonomy_longest_wildcard_wins():
    """Among wildcard matches, the most specific (longest) pattern wins."""
    autonomy = AutonomyConfig(
        default="human_only",
        assets=[
            AutonomyRule(match="vm-*", mode="non_disruptive"),
            AutonomyRule(match="vm-prod-*", mode="human_only"),
        ],
    )
    assert autonomy.resolve("vm-prod-web") == "human_only"   # vm-prod-* more specific
    assert autonomy.resolve("vm-dev-web") == "non_disruptive"  # only vm-* matches


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


def test_isolation_section(tmp_path):
    from glorfindel.config import load_glorfindel_config
    f = tmp_path / "glorfindel-config.yaml"
    f.write_text("isolation:\n  quarantine_nsg: false\n  quarantine_rg: rg-glorfindel\n")
    cfg = load_glorfindel_config(f)
    assert cfg.isolation.quarantine_nsg is False and cfg.isolation.quarantine_rg == "rg-glorfindel"
    f.write_text("monitoring_backends: []\n")
    assert load_glorfindel_config(f).isolation.quarantine_nsg is True     # default on


def test_a_config_mounted_alone_is_written_in_place(monkeypatch, tmp_path):
    """docker-compose mounts glorfindel-config.yaml on its own: a rename over it fails
    with EBUSY (measured, seventh review U3) — the War Room's mode change failed. It is
    written in place under the lock instead, replacing the content, never appending."""
    import errno
    import os
    from glorfindel import config
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("autonomy:\n  default: human_only\n" + "# padding\n" * 50)

    def busy(src, dst):
        raise OSError(errno.EBUSY, "Device or resource busy")

    monkeypatch.setattr(os, "replace", busy)
    inode = cfg.stat().st_ino
    config.set_asset_mode("vm-a", "non_disruptive", path=cfg)
    config.set_asset_mode("vm-a", "human_only", path=cfg)
    config.set_default_mode("human_only", path=cfg)
    assert cfg.stat().st_ino == inode                     # the same file, written in place
    text = cfg.read_text()
    assert text.count("autonomy:") == 1 and "padding" not in text
    auto = config.load_glorfindel_config(cfg).autonomy
    assert [(r.match, r.mode) for r in auto.assets] == [("vm-a", "human_only")]
    assert not list(tmp_path.glob(".glorfindel-config.yaml.*.tmp"))


def test_a_config_that_can_be_replaced_still_is(tmp_path):
    """Outside a container the atomic replace stays: a reader sees the old file or the
    new one, never a half."""
    from glorfindel import config
    cfg = tmp_path / "glorfindel-config.yaml"
    config.set_asset_mode("vm-b", "non_disruptive", path=cfg)        # created
    inode = cfg.stat().st_ino
    config.set_default_mode("human_only", path=cfg)
    assert cfg.stat().st_ino != inode
    auto = config.load_glorfindel_config(cfg).autonomy
    assert auto.default == "human_only" and auto.assets[0].mode == "non_disruptive"


# ── A3: a badly written config is refused, with a clear message ─────────────────

def _refused(tmp_path, text: str) -> str:
    from glorfindel.config import ConfigError
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text(textwrap.dedent(text))
    with pytest.raises(ConfigError) as exc:
        load_glorfindel_config(cfg)
    return str(exc.value)


def test_an_unknown_key_is_refused_with_the_key_it_resembles(tmp_path):
    """`quarantaine_nsg: false` was ignored: the quarantine stayed on, nothing said."""
    msg = _refused(tmp_path, """
        isolation:
          quarantaine_nsg: false
    """)
    assert "isolation.quarantaine_nsg" in msg and "clé inconnue" in msg and "« quarantine_nsg »" in msg


@pytest.mark.parametrize("where, text", [
    ("", "notifications: {}\n"),
    ("monitoring_backends[0].workspaceid", "monitoring_backends:\n  - name: law\n    workspaceid: ws\n"),
    ("monitoring_backends[0].discovery.interval", "monitoring_backends:\n  - name: law\n"
                                                  "    discovery:\n      interval: 60\n"),
    ("action_backends[0].staging_storage", "action_backends:\n  - name: rsv\n    staging_storage: st\n"),
    ("exceptions[0].rules", "exceptions:\n  - asset_pattern: vm-*\n    rules: [x]\n"),
    ("autonomy.assets[0].modes", "autonomy:\n  assets:\n    - match: vm-a\n      mode: human_only\n"
                                 "      modes: x\n"),
    ("autonomy.allow_destructives", "autonomy:\n  allow_destructives: []\n"),
])
def test_unknown_keys_are_refused_at_every_level(tmp_path, where, text):
    msg = _refused(tmp_path, text)
    assert "clé inconnue" in msg and (where or "notifications") in msg


@pytest.mark.parametrize("where, text, close", [
    ("monitoring_backends[0].type", "monitoring_backends:\n  - name: law\n    type: azure_monitr\n",
     "azure_monitor"),
    ("action_backends[0].type", "action_backends:\n  - name: rsv\n    type: azure_backup\n",
     "azure_backup_vault"),
])
def test_an_unknown_backend_type_is_refused(tmp_path, where, text, close):
    """A3, first review: `type: azure_monitr` was a backend nothing read — no discovery,
    no rule bound to it — in silence."""
    msg = _refused(tmp_path, text)
    assert f"{where} : type inconnu" in msg and f"« {close} »" in msg


def test_the_known_backend_types_load(tmp_path):
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("monitoring_backends:\n  - name: law\n    type: azure_monitor\n"
                   "  - name: prom\n    type: prometheus\n"
                   "action_backends:\n  - name: rsv\n    type: azure_backup_vault\n")
    c = load_glorfindel_config(cfg)
    assert [b.type for b in c.monitoring_backends] == ["azure_monitor", "prometheus"]
    assert c.backup_vault().name == "rsv"


@pytest.mark.parametrize("key, text", [
    ("isolation.quarantine_nsg", "isolation:\n  quarantine_nsg: \"false\"\n"),
    ("exceptions[0].exclude_all", "exceptions:\n  - asset_pattern: vm-*\n    exclude_all: \"false\"\n"),
    ("monitoring_backends[0].discovery.enabled", "monitoring_backends:\n  - name: law\n"
                                                 "    discovery:\n      enabled: \"false\"\n"),
])
def test_false_in_quotes_is_refused(tmp_path, key, text):
    """"false" in quotes is a non-empty string, true for Python: `exclude_all: "false"`
    took the VM out of every rule."""
    msg = _refused(tmp_path, text)
    assert key in msg and "écrire false sans guillemets" in msg


@pytest.mark.parametrize("key, text, said", [
    ("autonomy.allow_destructive", "autonomy:\n  allow_destructive: \"vm-*\"\n", "écrire [vm-*]"),
    ("exceptions[0].exclude_rules", "exceptions:\n  - asset_pattern: vm-*\n    exclude_rules: ssh-brute-force\n",
     "une liste est attendue"),
    ("isolation.forensic_sources", "isolation:\n  forensic_sources: 10.0.0.4\n", "une liste est attendue"),
    ("monitoring_backends[0].discovery.interval_s", "monitoring_backends:\n  - name: law\n"
                                                    "    discovery:\n      interval_s: \"900\"\n", "nombre"),
    ("monitoring_backends[0].discovery.interval_s", "monitoring_backends:\n  - name: law\n"
                                                    "    discovery:\n      interval_s: 0\n", "positif"),
    ("monitoring_backends[0].name", "monitoring_backends:\n  - type: azure_monitor\n", "obligatoire"),
    ("monitoring_backends[0].workspace_id", "monitoring_backends:\n  - name: law\n    workspace_id: 42\n",
     "un texte est attendu"),
    ("autonomy.assets", "autonomy:\n  assets: {match: vm-a, mode: human_only}\n", "une liste"),
    ("exceptions[0]", "exceptions:\n  - vm-dev-*\n", "une table"),
    ("autonomy.assets[0].mode", "autonomy:\n  assets:\n    - match: vm-a\n", "obligatoire"),
])
def test_wrong_types_are_refused(tmp_path, key, text, said):
    """`allow_destructive: "vm-*"` was read as the patterns v, m, - and * — the last one
    matching every VM; `exclude_rules: ssh-brute-force` matched by substring."""
    msg = _refused(tmp_path, text)
    assert key in msg and said in msg


def test_every_problem_is_said_at_once(tmp_path):
    msg = _refused(tmp_path, """
        isolation:
          quarantaine_nsg: false
          forensic_ports: [ssh]
        exceptions:
          - asset_pattern: vm-*
            exclude_all: "true"
        autonomy:
          default: full_auto
    """)
    assert "4 problèmes" in msg
    for part in ("quarantaine_nsg", "forensic_ports", "exclude_all", "full_auto"):
        assert part in msg
    assert str(tmp_path / "glorfindel-config.yaml") in msg


def test_empty_sections_written_as_comments_are_fine(tmp_path):
    """`exceptions:` with every item commented out reads as null: empty, not an error."""
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("exceptions:\n  # - asset_pattern: vm-dev-*\nautonomy:\n  assets:\n  allow_destructive:\n")
    loaded = load_glorfindel_config(cfg)
    assert loaded.exceptions == [] and loaded.autonomy.assets == [] and loaded.autonomy.allow_destructive == []


def test_the_shipped_example_and_the_terraform_fragment_load(tmp_path):
    """What an operator starts from must pass the strict reading."""
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    example = load_glorfindel_config(root / "glorfindel-config.yaml.example")
    assert example.monitoring_backends and example.action_backends
    tf = (root / "infra" / "terraform" / "outputs.tf").read_text()
    fragment = re.search(r"<<-YAML\n(.*?)\n\s*YAML", tf, re.S).group(1)
    fragment = re.sub(r"\$\{[^}]+\}", "x", textwrap.dedent(fragment))
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text(fragment)
    assert load_glorfindel_config(cfg).backup_vault().restore_staging_storage == "x"


def test_the_watch_does_not_start_on_a_refused_config(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from glorfindel import config
    from glorfindel.cli import cli
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("isolation:\n  quarantine_nsg: \"false\"\n")
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [cfg])
    runs = tmp_path / "runs"
    runs.mkdir()

    class Started(Exception):
        pass

    def started(*a, **k):
        raise Started("the watch went on")      # past the check: stop here, never loop
    monkeypatch.setattr("glorfindel.agent.GlorfindelAgent", started)
    monkeypatch.setattr("glorfindel.actions.migrate_state_files", started)
    result = CliRunner().invoke(cli, ["watch", str(runs), "--dry-run"])
    assert not isinstance(result.exception, Started)
    assert result.exit_code == 2
    assert "refusé" in result.output and "isolation.quarantine_nsg" in result.output
