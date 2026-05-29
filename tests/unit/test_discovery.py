from __future__ import annotations

import json
from dataclasses import asdict
from unittest.mock import MagicMock, patch

from glorfindel.config import (
    GlorfindelConfig,
    MonitoringBackendConfig,
    DiscoveryConfig,
    ExceptionConfig,
)
from glorfindel.detection_rules import DetectionRule
from glorfindel.discovery import (
    AssetRegistry,
    DiscoveredAsset,
    DiscoveryService,
    _discover_from_azure_monitor,
    _discover_from_backend,
)


def _asset(name, backend="law", rid=""):
    return DiscoveredAsset(
        name=name,
        resource_id=rid,
        monitoring_backend=backend,
        last_seen="2026-01-01T00:00:00Z",
    )


def _mock_detector(rows):
    m = MagicMock()
    m.run_query.return_value = rows
    return m


def _law_cfg(interval_s=1800, enabled=True):
    return GlorfindelConfig(
        monitoring_backends=[
            MonitoringBackendConfig(
                name="law",
                type="azure_monitor",
                workspace_id="ws",
                discovery=DiscoveryConfig(enabled=enabled, interval_s=interval_s),
            )
        ]
    )


# ── AssetRegistry ──────────────────────────────────────────────────────────────

def test_registry_update_and_all(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a"), _asset("vm-b")])
    assert {a.name for a in reg.all()} == {"vm-a", "vm-b"}


def test_registry_update_overwrites(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", rid="/old")])
    reg.update([_asset("vm-a", rid="/new")])
    assert reg.all()[0].resource_id == "/new"


def test_registry_for_backend(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law-1"), _asset("vm-b", backend="law-2")])
    assert len(reg.for_backend("law-1")) == 1
    assert reg.for_backend("law-1")[0].name == "vm-a"
    assert reg.for_backend("missing") == []


def test_registry_persists_to_disk(tmp_path):
    path = tmp_path / "assets.json"
    reg = AssetRegistry(path=path)
    reg.update([_asset("vm-a", rid="/r")])
    assert path.exists()
    assert json.loads(path.read_text())[0]["name"] == "vm-a"


def test_registry_loads_from_disk(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text(json.dumps([asdict(_asset("vm-a", rid="/r"))]))
    reg = AssetRegistry(path=path)
    assert len(reg.all()) == 1
    assert reg.all()[0].name == "vm-a"


def test_registry_handles_corrupt_disk(tmp_path):
    path = tmp_path / "assets.json"
    path.write_text("not valid json{{{")
    reg = AssetRegistry(path=path)
    assert reg.all() == []


def test_registry_to_dicts(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", rid="/r")])
    dicts = reg.to_dicts()
    assert isinstance(dicts[0], dict)
    assert dicts[0]["name"] == "vm-a"


# ── replace_for_backend ────────────────────────────────────────────────────────

def test_replace_for_backend_evicts_removed(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law"), _asset("vm-b", backend="law")])
    reg.replace_for_backend("law", [_asset("vm-a", backend="law")])
    names = {a.name for a in reg.all()}
    assert "vm-a" in names
    assert "vm-b" not in names


def test_replace_for_backend_keeps_other_backends(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law-1"), _asset("vm-b", backend="law-2")])
    reg.replace_for_backend("law-1", [])
    assert len(reg.for_backend("law-2")) == 1
    assert reg.for_backend("law-2")[0].name == "vm-b"


def test_replace_for_backend_empty_valid_evicts_all(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law"), _asset("vm-b", backend="law")])
    reg.replace_for_backend("law", [])
    assert reg.for_backend("law") == []


# ── _discover_from_azure_monitor ───────────────────────────────────────────────

def test_discover_azure_monitor_returns_assets():
    rows = [
        {"Computer": "vm-victim", "ResourceId": "/sub/vm-victim"},
        {"Computer": "vm-other.corp", "ResourceId": "/sub/vm-other"},
    ]
    with patch(
        "glorfindel.detectors.detector_for",
        return_value=_mock_detector(rows),
    ):
        assets = _discover_from_azure_monitor("law-test", "ws-guid")
    assert len(assets) == 2
    assert {a.name for a in assets} == {"vm-victim", "vm-other"}


def test_discover_azure_monitor_strips_fqdn():
    rows = [{"Computer": "vm-host.foo.bar.corp", "ResourceId": "/sub/vm-host"}]
    with patch(
        "glorfindel.detectors.detector_for",
        return_value=_mock_detector(rows),
    ):
        assets = _discover_from_azure_monitor("law-test", "ws-guid")
    assert assets[0].name == "vm-host"
    assert assets[0].extra["fqdn"] == "vm-host.foo.bar.corp"


def test_discover_azure_monitor_skips_empty_computer():
    rows = [
        {"Computer": "", "ResourceId": "/r"},
        {"Computer": None, "ResourceId": "/r2"},
    ]
    with patch(
        "glorfindel.detectors.detector_for",
        return_value=_mock_detector(rows),
    ):
        assets = _discover_from_azure_monitor("law-test", "ws-guid")
    assert assets == []


def test_discover_azure_monitor_handles_exception():
    with patch(
        "glorfindel.detectors.detector_for",
        side_effect=Exception("Azure error"),
    ):
        assets = _discover_from_azure_monitor("law-test", "ws-guid")
    assert assets is None  # failure → keep cache, not evict


def test_discover_azure_monitor_empty_query_result():
    with patch(
        "glorfindel.detectors.detector_for",
        return_value=_mock_detector([]),
    ):
        assets = _discover_from_azure_monitor("law-test", "ws-guid")
    assert assets == []  # valid empty — all VMs gone


def test_discover_from_backend_unsupported_returns_empty():
    """Unsupported backend → empty list (not None — not an error)."""
    class FakeBackend:
        type = "splunk"
        name = "splunk-test"
        workspace_id = ""
    assert _discover_from_backend(FakeBackend()) == []


# ── DiscoveryService ───────────────────────────────────────────────────────────

def test_discovery_service_skips_start_in_dry_run(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    svc = DiscoveryService(_law_cfg(), reg, dry_run=True)
    svc.start()
    assert svc._thread is None


def test_discovery_service_run_once_uses_replace(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-old", backend="law")])
    svc = DiscoveryService(_law_cfg(), reg, dry_run=False)

    with patch(
        "glorfindel.discovery._discover_from_backend",
        return_value=[_asset("vm-new", backend="law", rid="/r")],
    ):
        svc.run_once()

    names = {a.name for a in reg.all()}
    assert "vm-new" in names
    assert "vm-old" not in names  # evicted by replace


def test_discovery_service_keeps_cache_on_error(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law")])
    svc = DiscoveryService(_law_cfg(), reg, dry_run=False)

    with patch("glorfindel.discovery._discover_from_backend", return_value=None):
        svc.run_once()

    assert len(reg.all()) == 1
    assert reg.all()[0].name == "vm-a"


def test_discovery_service_skips_disabled_backend(tmp_path):
    reg = AssetRegistry(path=tmp_path / "assets.json")
    svc = DiscoveryService(_law_cfg(enabled=False), reg, dry_run=False)

    with patch(
        "glorfindel.discovery._discover_from_backend",
        return_value=[],
    ) as mock_disc:
        svc.run_once()

    mock_disc.assert_not_called()


# ── expand_for_discovered (RulePoller integration) ────────────────────────────

def _auto_rule(interval_s=30.0):
    return DetectionRule(
        name="disk-write",
        source="azure_monitor",
        workspace_id="ws",
        query="Perf | limit 1",
        ttp="T1486",
        resource_id="",
        auto_apply=True,
        monitoring_backend_name="law",
        interval_s=interval_s,
    )


def test_expand_for_discovered_starts_threads(tmp_path):
    from glorfindel.detection_rules import RulePoller

    poller = RulePoller([_auto_rule()], lambda s: None, dry_run=True)
    poller.start()

    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law", rid="/sub/vm-a")])
    poller.expand_for_discovered(reg)

    assert any("vm-a" in t.name for t in poller._threads)


def test_expand_for_discovered_respects_exceptions(tmp_path):
    from glorfindel.detection_rules import RulePoller

    poller = RulePoller([_auto_rule()], lambda s: None, dry_run=True)
    poller.start()

    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-dev-1", backend="law", rid="/sub/vm-dev-1")])

    cfg = GlorfindelConfig(
        exceptions=[ExceptionConfig(asset_pattern="vm-dev-*", exclude_all=True)]
    )
    poller.expand_for_discovered(reg, glorfindel_cfg=cfg)
    assert not any("vm-dev-1" in t.name for t in poller._threads)


def test_expand_for_discovered_not_duplicate(tmp_path):
    from glorfindel.detection_rules import RulePoller

    poller = RulePoller([_auto_rule()], lambda s: None, dry_run=True)
    poller.start()

    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law", rid="/sub/vm-a")])

    poller.expand_for_discovered(reg)
    count_after_first = len(poller._threads)
    poller.expand_for_discovered(reg)
    assert len(poller._threads) == count_after_first


def test_poll_thread_self_evicts_when_asset_removed(tmp_path):
    """Thread exits naturally when its asset disappears from the registry."""
    from glorfindel.detection_rules import RulePoller

    reg = AssetRegistry(path=tmp_path / "assets.json")
    reg.update([_asset("vm-a", backend="law", rid="/sub/vm-a")])

    # Mock Azure so the poll loop is near-instant (no real HTTP calls)
    with patch(
        "glorfindel.detection_rules.detector_for",
        return_value=MagicMock(**{"poll_alert.return_value": None}),
    ):
        poller = RulePoller([_auto_rule(interval_s=0.05)], lambda s: None, dry_run=True)
        poller.start()
        poller.expand_for_discovered(reg)

        thread = next(t for t in poller._threads if "vm-a" in t.name)

        # Evict — thread exits at start of next poll cycle (<50ms away)
        reg.replace_for_backend("law", [])
        thread.join(timeout=2.0)

    assert not thread.is_alive()
