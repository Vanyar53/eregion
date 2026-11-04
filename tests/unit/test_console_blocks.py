"""CON-K (#498): a VM's blocks in the console — each acted on by its own IP, all of them said.

« Extend to subnet » promoted the VM's FIRST block whatever row it sat on, and said « the whole
subnet » whatever the promotion left out; « Unblock » ran a reset (every block and the
isolation). Now a row's buttons name its IP, the route matches it against the VM's blocks, the
promotion's outcome says what the subnet rule leaves out (`said`, `whole`), and an unblock takes
off that IP alone. The card says several blocks in one line, the list in its window (decision A
of 03/11). No Azure: the connector and the CLI are stubbed; the block state is the conftest's tmp.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

import eregion_console.api as api  # noqa: E402

from .console_client import console  # noqa: E402

WEB = "/subscriptions/s/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/web"
DB = "/subscriptions/s/resourceGroups/rg-app/providers/Microsoft.Compute/virtualMachines/db"
OLD, NEW, OTHER = "203.0.113.7", "198.51.100.9", "192.0.2.44"
JS = (Path(api.__file__).parent / "static" / "glorfindel.js").read_text()


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("GLORFINDEL_WARROOM_TOKEN", raising=False)
    return console()


@pytest.fixture()
def blocks():
    """web blocked for OLD then NEW (VM-scoped), db for OTHER."""
    from glorfindel.actions import _save_block_state
    for ip in (OLD, NEW):
        _save_block_state("web", ip, WEB, nsg="rg-app/nsg-web", nsg_scope="nic", rule=f"r-{ip}")
    _save_block_state("db", OTHER, DB, nsg="rg-app/nsg-db", nsg_scope="nic", rule=f"r-{OTHER}")


class _Connector:
    """The connector as the route builds it: records each promotion, answers `outcome`."""
    calls: list = []
    outcome: dict = {}

    def __init__(self, **_):
        pass

    def block_suspicious_ip(self, ip, rid, scope="vm", replace=False):
        _Connector.calls.append((ip, rid, scope, replace))
        return {"status": "blocked", "ip": ip, "scoped": False, **_Connector.outcome}


@pytest.fixture()
def connector(monkeypatch):
    _Connector.calls, _Connector.outcome = [], {}
    monkeypatch.setattr("glorfindel.actions.AzureConnector", _Connector)
    return _Connector


@pytest.fixture()
def ran(monkeypatch):
    """The CLI as the routes run it: the argv, exit 0."""
    import subprocess
    out = []

    def _run(argv, **_):
        out.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")
    monkeypatch.setattr(api.subprocess, "run", _run)
    return out


def _promote(client, vm="web", **params):
    return client.post(f"/api/action/block-promote/{vm}", json={}, params=params).json()


# ── Extend to subnet: the row's IP, never the VM's first block ─────────────────────────────

@pytest.mark.parametrize("ip", [OLD, NEW])
def test_extend_promotes_the_rows_ip_never_the_vms_first_block(client, blocks, connector, ip):
    d = _promote(client, ip=ip)
    assert connector.calls == [(ip, WEB, "subnet", True)], d
    assert d["ok"] and d["ip"] == ip and d["whole"] is True and d["said"] == [], d


@pytest.mark.parametrize("ip, why", [("", "Which IP?"), ("203.0.113.99", "not blocked on web"),
                                     (OTHER, "not blocked on web")])
def test_extend_without_the_rows_ip_or_with_one_not_blocked_on_the_vm_is_refused(client, blocks, connector, ip, why):
    """No IP: refused, never the first block taken in its place. An IP blocked on another VM
    (db's) is not web's to promote."""
    d = _promote(client, ip=ip)
    assert why in d["error"] and connector.calls == [], d


def test_extend_of_a_block_already_subnet_wide_is_refused(client, connector):
    from glorfindel.actions import _save_block_state
    _save_block_state("web", OLD, WEB, nsg="rg-net/nsg-subnet", nsg_scope="subnet", rule="r", scoped=False)
    d = _promote(client, ip=OLD)
    assert "already blocked for the whole subnet" in d["error"] and connector.calls == [], d


# ── What the promotion leaves out is said, never « the whole subnet » ───────────────────────

KEPT = "rg-net/nsg-tier/glorfindel-block-x gardée : retournée en autorisation, elle ouvre 10.0.0.4 (batch-nic)"
BYPASS = "Blocage de 198.51.100.9 contourné : 'allow-ssh-any' (priorité 100, Inbound, ports 22) passe avant le deny de Glorfindel."
EXPOSURE = "Port de la menace bloqué ; 198.51.100.9 atteint encore d'autres ports : 'allow-web' (priorité 110, Inbound, ports 443)."


@pytest.mark.parametrize("outcome, named", [
    ({"status": "blocked_partial", "uncovered_nics": ["web-nic2"]}, ["web-nic2", "still reaches"]),
    ({"status": "blocked_partial", "nics_unread": "403 Forbidden"}, ["403 Forbidden", "unverified"]),
    ({"kept_rules": [KEPT]}, [KEPT]),
    ({"bypass": BYPASS}, [BYPASS]),
    ({"exposure": EXPOSURE}, [EXPOSURE]),
    ({"status": "blocked_partial"}, ["blocked_partial"]),
], ids=["nic-on-another-subnet", "nics-unread", "rule-kept", "bypass", "exposure", "partial-unsaid"])
def test_a_promotion_short_of_the_whole_subnet_says_what_it_leaves_out(client, blocks, connector, outcome, named):
    """Each outcome the connector reports (blocks.py, _block_ip_subnet; nsg.py, the shadowing):
    `whole` false, the NIC, the rule, the allow named as the connector names it."""
    connector.outcome = outcome
    d = _promote(client, ip=NEW)
    said = " ".join(d["said"])
    assert d["ok"] and d["whole"] is False and all(n in said for n in named), d


def test_the_page_says_the_whole_subnet_only_when_the_outcome_holds_it_whole():
    """The toast « whole subnet » is the `whole === true` branch alone; anything else opens the
    window that names what is left out, each line escaped."""
    body = JS[JS.index("async function doBlockPromote"):JS.index("\n}\n", JS.index("async function doBlockPromote"))]
    assert "if (d.whole === true) toast(`✓ Block of ${d.ip} extended to the whole subnet`);" in body
    assert "else _showPromotionSaid(vmName, d);" in body
    assert JS.count("extended to the whole subnet") == 1, "said once, on the whole branch"
    said = JS[JS.index("function _showPromotionSaid"):JS.index("\n}\n", JS.index("function _showPromotionSaid"))]
    assert "said.map(x => `<div style=\"color:var(--orange);margin:4px 0 4px 8px\">• ${_attr(x)}</div>`)" in said
    assert "?${new URLSearchParams({ ip })}" in body, "the row's IP sent"


# ── Unblock: the row's IP alone ──────────────────────────────────────────────────────────────

def test_unblock_takes_off_the_rows_ip_alone_never_a_reset(client, blocks, ran):
    d = client.post("/api/action/unblock/web", json={}, params={"ip": OLD}).json()
    assert d["ok"] and d["ip"] == OLD, d
    assert [a[1:] for a in ran] == [["unblock", "--yes", "--", OLD, WEB]], ran


@pytest.mark.parametrize("ip", ["", "203.0.113.99", OTHER])
def test_unblock_of_an_ip_not_blocked_on_the_vm_runs_nothing(client, blocks, ran, ip):
    d = client.post("/api/action/unblock/web", json={}, params={"ip": ip}).json()
    assert d["error"] and ran == [], d


def test_unblock_takes_off_a_subnet_wide_block_by_its_ip(client, ran):
    """The PROTECT card's row (a block promoted to the subnet): its IP too, never a reset."""
    from glorfindel.actions import _save_block_state
    _save_block_state("web", OLD, WEB, nsg="rg-net/nsg-subnet", nsg_scope="subnet", rule="r", scoped=False)
    assert client.post("/api/action/unblock/web", json={}, params={"ip": OLD}).json()["ok"]
    assert [a[1:] for a in ran] == [["unblock", "--yes", "--", OLD, WEB]], ran


def test_a_partial_unblock_is_not_ok(client, blocks, monkeypatch):
    """`glorfindel unblock` exits 2 when rules stay: the console says it failed."""
    import subprocess
    monkeypatch.setattr(api.subprocess, "run", lambda argv, **_: subprocess.CompletedProcess(
        argv, 2, stdout="✗ Blocage partiellement retiré — règles encore en place", stderr=""))
    assert client.post("/api/action/unblock/web", json={}, params={"ip": OLD}).json()["ok"] is False


@pytest.mark.parametrize("route", ["unblock", "block-promote"])
def test_an_ambiguous_vm_name_is_refused(client, connector, ran, route):
    """Two VMs named web: the IP does not choose between them — refused (T1)."""
    from glorfindel.actions import _save_block_state
    _save_block_state("web", OLD, WEB, nsg="n", nsg_scope="nic", rule="r")
    _save_block_state("web", OLD, WEB.replace("rg-app", "rg-b"), nsg="n", nsg_scope="nic", rule="r")
    r = client.post(f"/api/action/{route}/web", json={}, params={"ip": OLD})
    assert r.status_code == 409 and "2 VMs" in r.json()["error"] and ran == [] and connector.calls == []


def test_the_cli_reads_the_routes_argv(monkeypatch):
    """`unblock --yes -- <ip> <rid>`, as the route runs it: the IP and the VM, in that order."""
    from click.testing import CliRunner

    from glorfindel.cli import cli
    seen = []

    class _C:
        def __init__(self, **_):
            pass

        def unblock_ip(self, ip, rid):
            seen.append((ip, rid))
            return {"status": "ok", "deleted_rules": []}
    monkeypatch.setattr("glorfindel.actions.AzureConnector", _C)
    monkeypatch.setattr("glorfindel.cli._record_manual_action", lambda *a, **k: None)
    r = CliRunner().invoke(cli, ["unblock", "--yes", "--", OLD, WEB])
    assert r.exit_code == 0 and seen == [(OLD, WEB)], r.output


# ── The card: several blocks in one line, the list in its window ─────────────────────────────

def _fn(name: str) -> str:
    i = JS.index(f"function {name}(")
    return JS[i:JS.index("\n}\n", i)]


def test_the_card_says_several_blocks_in_one_line_never_one_badge_each():
    """Collapsed and expanded: two blocks or more → one summary (×N, newest, oldest) and the
    window; one block → its badge and its buttons. The first block alone, attached to the
    decision row, hid the others (CON-K)."""
    card = _fn("_renderAssetNode")
    assert "const blocks = _blocksOf(states);" in card
    assert "states.find(s => s.type === 'blocked')" not in card, "a block chosen for the row hides the others"
    assert "...(blocks.length > 1 ? [_blocksSummary(blocks, vm_name)] : blocks.map(s =>" in card
    assert "badge   = blocks.length > 1 ? _blocksSummary(blocks, vm_name) : _blockBadge(blocks[0], vm_name);" in card
    assert "corrBtn = blocks.length > 1 ? _manageBtn(blocks, vm_name) : _blockBtns(blocks[0], vm_name);" in card
    assert "${blocks.length > 1 ? _blocksSummary(blocks, vm_name) + _manageBtn(blocks, vm_name)" in card
    assert "BLOCKED ×${n} IPs · newest ${_ageShort(bs[0].since)} · oldest ${_ageShort(bs[n - 1].since)}" in _fn("_blocksSummary")
    order = _fn("_blocksOf")
    assert "sort((a, b) => t(b) - t(a))" in order and "s.scoped !== false" in order


def test_each_row_acts_on_its_own_ip():
    """The window lists every block with its buttons; each button names its row's IP."""
    assert "_on('click', 'confirmExtendSubnet', vmName, s.ip)" in _fn("_extendBtn")
    assert "_on('click', 'confirmUnblockIp', vmName, s.ip)" in _fn("_blockBtns")
    win = _fn("showBlocks")
    assert "_blocksOf(r?.states)" in win and "${_blockBtns(s, vmName)}" in win
    assert "_on('input', 'filterBlocks')" in win and "_applyReadOnlyGuards(body);" in win
    assert "/api/action/unblock/${_seg(vmName)}?${new URLSearchParams({ ip })}" in _fn("doUnblockIp")
    assert "confirmUnblock(" not in JS and "doRevert(vmName, ip)" not in JS, "no row runs a reset"
    actions = JS[JS.index("const ACTIONS = {"):JS.index("\n};", JS.index("const ACTIONS = {"))]
    assert all(re.search(rf"\b{n}\b", actions) for n in ("showBlocks", "filterBlocks", "confirmUnblockIp"))
    assert "input: 'input'" in JS[JS.index("const _EVENTS = {"):JS.index("};", JS.index("const _EVENTS = {"))]


def test_the_subnet_wide_row_unblocks_its_ip():
    """The PROTECT card's subnet-wide row: its IP, never a reset of its VM."""
    assert "_on('click', 'confirmUnblockIp', b.vm_name, b.ip)" in JS
