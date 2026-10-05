"""War Room API — exposure and regressions (revue 2026-09).

No Azure, no LLM: connectors and audit are stubbed. Requires the war-room extra.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402

import glorfindel.api as api  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    return TestClient(api.app)


def test_audit_resource_endpoint_no_longer_raises_nameerror(client, monkeypatch):
    """`os` was never imported in api.py: GET /api/audit/<vm> — called by the War Room
    per-VM readiness panel — raised NameError (HTTP 500) on every call since 053156b."""
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    monkeypatch.setattr(api, "_find_resource_id", lambda vm: rid)
    result = MagicMock()
    result.to_dict.return_value = {"resource_id": rid, "ready": True, "checks": []}
    seen = {}

    def _run(resource_id, connector, vault, vault_rg, staging):
        seen.update(vault=vault, vault_rg=vault_rg)
        return result
    monkeypatch.setattr("glorfindel.audit.run", _run)
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: MagicMock())

    r = client.get("/api/audit/vm")
    assert r.status_code == 200
    assert r.json()["ready"] is True
    assert seen["vault"]          # resolved from config or the env/legacy default


def test_open_access_without_token(client):
    assert client.get("/").status_code == 200


def test_token_required_when_configured(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "s3cret")
    c = TestClient(api.app)
    assert c.get("/").status_code == 401
    assert c.get("/api/discovered").status_code == 401
    assert c.post("/api/autonomy/vm", json={"mode": "non_disruptive"}).status_code == 401
    assert c.get("/", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_token_in_url_sets_a_cookie_and_strips_the_token(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "s3cret")
    c = TestClient(api.app)
    r = c.get("/?token=s3cret&tab=feed", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/?tab=feed"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/").status_code == 200          # cookie now carried by the client


def test_live_feed_websocket_requires_the_token(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "s3cret")
    c = TestClient(api.app)
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/api/feed") as ws:
            ws.receive_json()


def test_serve_listens_on_loopback_by_default():
    import inspect
    assert inspect.signature(api.serve).parameters["host"].default == "127.0.0.1"


def test_war_room_cli_defaults_to_loopback():
    from glorfindel.cli import war_room
    host = next(p for p in war_room.params if p.name == "host")
    assert host.default == "127.0.0.1"


def test_state_exposes_partial_shared_and_bypassed_isolation(client):
    """A partial or bypassed isolation must never render as a plain ISOLATED."""
    from glorfindel.actions import _save_isolation_state
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    _save_isolation_state("vm", {
        "resource_id": rid, "isolated_at": "2026-10-05T10:00:00+00:00",
        "nsg_scope": "nic", "partial": True, "failed_nic": "nic-b",
        "placements": [{"nsg_rg": "rg", "nsg_name": "nsg-tier", "scope": "nic", "shared_nsg": True,
                        "shadowed_by": [{"rule": "allow-ssh", "priority": 100,
                                         "direction": "Inbound", "ports": "22"}]}],
    })
    r = client.get("/api/state")
    assert r.status_code == 200
    vm = next(x for x in r.json()["resources"] if x["vm_name"] == "vm")
    iso = next(s for s in vm["states"] if s["type"] == "isolated")
    assert iso["partial"] is True and iso["failed_nic"] == "nic-b"
    assert iso["shared"] is True
    assert [s["rule"] for s in iso["shadowed"]] == ["allow-ssh"]


def test_browser_without_token_gets_a_token_form(monkeypatch):
    monkeypatch.setenv("GLORFINDEL_WARROOM_TOKEN", "s3cret")
    c = TestClient(api.app)
    r = c.get("/", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r.status_code == 401
    assert 'name="token"' in r.text and "<form" in r.text
    # API clients still get JSON
    assert c.get("/api/state").headers["content-type"].startswith("application/json")


def test_approved_isolation_is_verified_and_traced(client, monkeypatch, tmp_path):
    """The approve route executed the held isolation without verifying it nor leaving
    a trace in runs/ (real run, 2026-10-05). Sessions left open → verification_failed."""
    from glorfindel import escalations
    monkeypatch.chdir(tmp_path)
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    esc = escalations.record(signal_id="s1", resource_id=rid, action="isolate_vm",
                             escalation_type="mode_hold", reason="held")
    esc_id = esc["id"] if isinstance(esc, dict) else escalations.pending()[0]["id"]
    conn = MagicMock()
    conn.isolate_vm.return_value = {"status": "isolated",
                                    "drain": {"status": "failed", "error": "403 runCommand"}}
    conn.verify_isolation.return_value = {"verified": True, "method": "nsg_check"}
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: conn)

    r = client.post(f"/api/action/approve/{esc_id}")
    assert r.json()["verification"]["verified"] is False
    assert [e["escalation_type"] for e in escalations.pending()] == ["verification_failed"]
    assert "isolate_vm" in (tmp_path / "runs" / "manual_actions.jsonl").read_text()
