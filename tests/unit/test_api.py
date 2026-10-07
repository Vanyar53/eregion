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
    monkeypatch.setenv("GLORFINDEL_BACKUP_VAULT", "rsv-test")

    r = client.get("/api/audit/vm")
    assert r.status_code == 200
    assert r.json()["ready"] is True
    assert seen["vault"] == "rsv-test"    # from the env (no retired default any more)


def test_snapshot_without_a_vault_says_so(client, monkeypatch):
    monkeypatch.delenv("GLORFINDEL_BACKUP_VAULT", raising=False)
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    monkeypatch.setattr(api, "_find_resource_id", lambda vm: rid)
    assert "Aucun coffre" in client.post("/api/action/snapshot/vm").json()["error"]


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


def test_approved_release_is_verified_after_the_rules_are_removed(client, monkeypatch, tmp_path):
    """The CLI release checks only before removing the rules (validation run, 2026-10-05)."""
    from glorfindel import escalations
    monkeypatch.chdir(tmp_path)
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    escalations.record(signal_id="s1", resource_id=rid, action="release_isolation",
                       escalation_type="mode_hold", reason="held")
    esc_id = escalations.pending()[0]["id"]
    conn = MagicMock()
    conn.verify_release.return_value = {"verified": True, "method": "nsg_check"}
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: conn)

    async def _released(vm_name):
        return {"ok": True, "stdout": "released"}
    monkeypatch.setattr(api, "action_release", _released)

    r = client.post(f"/api/action/approve/{esc_id}")
    assert r.json()["verification"]["verified"] is True
    conn.verify_release.assert_called_once_with(rid)


def test_activation_refuses_reserves_that_were_not_shown(client, monkeypatch):
    """L6: no VM leaves human_only without its reserves having been shown — enforced
    by the server, also on the older /api/autonomy route."""
    from glorfindel import readiness
    assessment = readiness._verdict("vm", [readiness._reason("no_drain", "reserve", "sessions survive")])
    monkeypatch.setattr(api, "_assess_vm", lambda vm: assessment)
    switched = []
    monkeypatch.setattr("glorfindel.config.set_asset_mode", lambda vm, mode: switched.append((vm, mode)) or "cfg.yaml")

    assert "no_drain" in client.post("/api/activate/vm", json={"acknowledged": []}).json()["error"]
    assert "error" in client.post("/api/autonomy/vm", json={"mode": "non_disruptive"}).json()
    assert switched == []
    r = client.post("/api/activate/vm", json={"acknowledged": ["no_drain"]}).json()
    assert r["ok"] and switched == [("vm", "non_disruptive")]
    # What was shown and accepted is what the watch's gate reads.
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "non_disruptive"
    client.post("/api/autonomy/vm", json={"mode": "human_only"})          # back: no check
    assert switched[-1] == ("vm", "human_only")
    assert readiness.effective_mode("vm", "non_disruptive")[0] == "human_only"   # shown again next time


def test_state_shows_a_vm_held_by_its_readiness(client, monkeypatch):
    """Global default autonomous, VM not confirmed: the card shows human-only and why."""
    from glorfindel import escalations
    from glorfindel.config import AutonomyConfig, GlorfindelConfig
    monkeypatch.setattr("glorfindel.config.load_glorfindel_config",
                        lambda *a, **k: GlorfindelConfig(autonomy=AutonomyConfig(default="non_disruptive")))
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    escalations.record(signal_id="s", resource_id=rid, action="isolate_vm",
                       escalation_type="mode_hold", reason="r")
    state = client.get("/api/state").json()
    assert state["autonomy_modes"]["vm"] == "human_only"
    assert state["autonomy_holds"]["vm"]["configured"] == "non_disruptive"
    assert state["autonomy_holds"]["vm"]["reason"] == "not_checked"


def test_an_ambiguous_vm_name_is_refused(client, monkeypatch):
    """Two VMs named web in two resource groups (now both in the registry): resolving
    the name to the first match could release the OTHER one (third review, T1)."""
    from glorfindel.actions import _save_isolation_state
    a = "/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.Compute/virtualMachines/web"
    b = a.replace("rg-a", "rg-b")
    _save_isolation_state(a, {"resource_id": a})
    _save_isolation_state(b, {"resource_id": b})
    ran = []
    monkeypatch.setattr(api.subprocess, "run", lambda *x, **k: ran.append(x))
    r = client.post("/api/action/release/web")
    assert r.status_code == 409 and "2 VMs" in r.json()["error"] and ran == []



# ── Quatrième passe (Q4) : ce qu'une approbation peut exécuter ───────────────────────

def _card(etype="mode_hold", action="isolate_vm", age_h=0.0, **extra):
    from datetime import datetime, timedelta, timezone
    from glorfindel import escalations
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    eid = escalations.record(signal_id="s", resource_id=rid, action=action, escalation_type=etype,
                             reason="r", **extra)
    if age_h:
        import json
        lines = escalations._STORE.read_text().splitlines()
        old = (datetime.now(timezone.utc) - timedelta(hours=age_h)).isoformat()
        rows = [json.loads(line) for line in lines if line.strip()]
        for r in rows:
            if r["id"] == eid:
                r["last_seen"] = r["timestamp"] = old
        escalations._STORE.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return eid


def test_an_unattributed_card_cannot_be_executed(client, monkeypatch):
    """Anchored on a VM the detection did not name: approving isolated that VM."""
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: (_ for _ in ()).throw(AssertionError("no Azure")))
    eid = _card("unattributed_signal")
    assert "non attribuée" in client.post(f"/api/action/approve/{eid}").json()["error"]


def test_a_stale_card_cannot_be_executed(client, monkeypatch):
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: (_ for _ in ()).throw(AssertionError("no Azure")))
    eid = _card(age_h=5)
    assert "vieille" in client.post(f"/api/action/approve/{eid}").json()["error"]


def test_an_approval_refuses_anything_but_one_ip(client, monkeypatch):
    """`ip=*&scope=subnet` cut a whole subnet (fourth review, Q4)."""
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda **k: (_ for _ in ()).throw(AssertionError("no Azure")))
    eid = _card(action="block_suspicious_ip")
    for bad in ("*", "10.0.0.0/8", "Internet", "0.0.0.0"):
        r = client.post(f"/api/action/approve/{eid}", params={"ip": bad, "scope": "subnet"}).json()
        assert "IP" in r["error"], bad
