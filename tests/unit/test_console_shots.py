"""DOC1 (#365): Dagorlad shown — its captures and its loop come from the sample data, and from
nothing else; neither the sample, the images nor the pages carry a real identifier.

The renderer (``scripts/console_shots.py``) needs a Chromium: the CI never runs it. These tests
read what it guards, without a browser, Azure or a model: the sample and its identifiers, the
refusals of the script and of the server it starts, the server reaching only the loopback, the
board the sample gives (a refusal among the wires), and the images bound to the sample
(``docs/images/dagorlad/shots.json``).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "console_shots.py"
_spec = importlib.util.spec_from_file_location("console_shots", SCRIPT)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)

SAMPLE = json.loads(cs.SAMPLE.read_text(encoding="utf-8"))
IMAGES = ROOT / "docs" / "images" / "dagorlad"


# ── The sample ──────────────────────────────────────────────────────────────────────────

def test_the_sample_carries_no_identifier_but_the_allowed_ones():
    assert cs.doc_refusal(SAMPLE) == ""
    assert cs.identifiers(cs.SAMPLE.read_text(encoding="utf-8")) == []
    assert SAMPLE["subscription"] == "00000000-0000-0000-0000-000000000000"


def _with(path: list, value) -> dict:
    doc = json.loads(json.dumps(SAMPLE))
    node = doc
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return doc


@pytest.mark.parametrize("path, value, said", [
    (["subscription"], "3f2b8c1e-7d4a-4e9b-9a61-2c5d8e0f1a7b", "subscription"),
    (["runs", 0, "note"], "tenant 3f2b8c1e-7d4a-4e9b-9a61-2c5d8e0f1a7b", "3f2b8c1e"),
    (["runs", 0, "note"], "H0 at 10.20.30.40", "10.20.30.40"),
    (["runs", 0, "note"], "seen from 52.168.10.4", "52.168.10.4"),
    (["targets", 0, "name"], "vm-prod-db", "vm-prod-db"),
    (["targets", 0, "resource_group"], "rg-customer", "rg-customer"),
    (["runs", 0, "note"], "glorfindel.westeurope.cloudapp.azure.com", "cloudapp.azure.com"),
    (["runs", 0, "note"], "H0 is at 10.20.30.40.", "10.20.30.40"),
    (["runs", 0, "note"], "subscription 3F2B8C1E-7D4A-4E9B-9A61-2C5D8E0F1A7B", "3F2B8C1E"),
], ids=["subscription", "guid", "private-ip", "public-ip", "vm-name", "group", "host", "ip-ending-a-sentence",
        "guid-in-capitals"])
def test_a_sample_with_a_real_identifier_is_refused(path, value, said):
    reason = cs.doc_refusal(_with(path, value))
    assert reason and said in reason


@pytest.mark.parametrize("host", ["h0.example.me", "console.team.ai", "bench.acme.co", "eregion.my-company.de",
                                  "watch.internal.sh", "glorfindel.contoso.onmicrosoft.com", "H0.Example.ME"])
def test_a_host_under_any_domain_is_an_identifier(host):
    assert cs.identifiers(f"the console of {host}, reached at night") == [host]


def test_the_files_of_the_repository_are_no_hosts():
    text = ("docs/dagorlad.md, scripts/console_shots.py, shots.json, glorfindel-config.yaml, ci.yml, board.png, "
            "loop.webp, index.html, notes.txt, pyproject.toml, uv.lock, console.js, console.css, main.tf, tour.mp4, "
            "tour.webm, debug.jsonl")
    assert cs.identifiers(text) == []


def test_the_documentation_addresses_and_the_zero_guid_are_allowed():
    doc = _with(["runs", 0, "note"], "from 192.0.2.10, 198.51.100.7 and 203.0.113.250, "
                                     "subscription 00000000-0000-0000-0000-000000000000")
    assert cs.doc_refusal(doc) == ""


# ── The script's refusals: nothing but the sample, the video outside the repository ──────

def test_only_the_shipped_sample_is_rendered(tmp_path, capsys):
    copy = tmp_path / "dagorlad_sample.json"
    shutil.copy(cs.SAMPLE, copy)
    assert cs.main(["--sample", str(copy), "--check"]) == 2
    assert "not the shipped sample" in capsys.readouterr().err


def test_a_video_inside_the_repository_is_refused(capsys):
    assert cs.main(["--video", str(ROOT / "docs" / "dagorlad.mp4"), "--check"]) == 2
    assert "outside the repository" in capsys.readouterr().err


def test_a_video_in_build_or_outside_is_not_refused_for_its_place(tmp_path):
    assert not cs._inside_repo(ROOT / "build" / "dagorlad.mp4")
    assert not cs._inside_repo(tmp_path / "dagorlad.mp4")
    assert cs._inside_repo(ROOT / "docs" / "images" / "dagorlad" / "tour.mp4")


def test_a_missing_tool_is_said_and_nothing_is_rendered(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("EREGION_CHROMIUM", str(tmp_path / "no-chromium"))
    monkeypatch.setenv("EREGION_FFMPEG", str(tmp_path / "no-ffmpeg"))
    before = sorted(p.name for p in IMAGES.iterdir())
    assert cs.main(["--video", str(tmp_path / "tour.mp4")]) == 3
    err = capsys.readouterr().err
    assert "a Chromium" in err and "ffmpeg" in err and "nothing rendered" in err
    assert sorted(p.name for p in IMAGES.iterdir()) == before


# ── The server: its throwaway directory, no Azure variable, the loopback only ────────────

def test_the_servers_environment_is_built_from_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    env = cs.server_env(tmp_path, "t")
    assert not [k for k in env if k.startswith(("AZURE_", "ARM_", "ANTHROPIC", "OPENAI"))]
    assert env["HOME"] == str(tmp_path / "home") and env["EREGION_CONSOLE_TOKEN"] == "t"


def test_the_server_starts_only_in_its_throwaway_directory(tmp_path):
    work = tmp_path / "w"
    where = cs.materialize(SAMPLE, work)
    assert cs.serve_refusal(work, {}, where["home"], where["cwd"]) == ""
    assert "AZURE_SUBSCRIPTION_ID" in cs.serve_refusal(work, {"AZURE_SUBSCRIPTION_ID": "s"},
                                                       where["home"], where["cwd"])
    # Another HOME — even one that carries the sample's mark — or a working directory without it.
    other = tmp_path / "other"
    other.mkdir()
    shutil.copy(where["home"] / cs.MARK, other / cs.MARK)
    assert "HOME" in cs.serve_refusal(work, {}, other, where["cwd"])
    (where["cwd"] / cs.MARK).unlink()
    assert "no mark" in cs.serve_refusal(work, {}, where["home"], where["cwd"])


def _in_a_process(code: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], env=env, cwd=cwd, capture_output=True,
                          text=True, timeout=60)


def test_the_guard_lets_the_loopback_and_nothing_else(tmp_path):
    code = f"""
import importlib.util, socket
spec = importlib.util.spec_from_file_location("cs", {str(SCRIPT)!r})
cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)
cs.loopback_only()
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
socket.create_connection(srv.getsockname(), timeout=2).close()
print("loopback ok")
def raw(where):
    s = socket.socket(); s.settimeout(1); s.connect(where)
for how, where in ((raw, ("192.0.2.1", 443)), (socket.create_connection, ("192.0.2.1", 443)),
                   (socket.create_connection, ("example.com", 443))):
    try:
        how(where)
        print("REACHED", where)
    except PermissionError as e:
        print("refused", e)
    except OSError as e:
        print("OTHER", where, e)
"""
    r = _in_a_process(code, {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)}, tmp_path)
    assert "loopback ok" in r.stdout, r.stderr
    assert r.stdout.count("refused console_shots: no") == 3, r.stdout + r.stderr


def test_the_server_reaches_nothing_once_started(tmp_path):
    """serve() as the script runs it, uvicorn replaced by a connection to the documentation's
    address: refused by the guard, before anything listens."""
    work = tmp_path / "w"
    cs.materialize(SAMPLE, work)
    code = f"""
import importlib.util, socket, sys, uvicorn
from pathlib import Path
spec = importlib.util.spec_from_file_location("cs", {str(SCRIPT)!r})
cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)
uvicorn.run = lambda *a, **k: socket.create_connection(("192.0.2.1", 443), timeout=1)
sys.exit(cs.serve(Path({str(work)!r}), 0))
"""
    env = cs.server_env(work, "t")
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), *sys.path])
    r = _in_a_process(code, env, work / "cwd")
    assert r.returncode != 0 and "off the loopback (192.0.2.1)" in r.stderr, r.stdout + r.stderr


def test_materialize_writes_only_into_its_directory(tmp_path):
    work = tmp_path / "w"
    where = cs.materialize(SAMPLE, work)
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert files and all(work in p.parents for p in files)
    windows = list((where["runs"] / "exercises").glob("*.json"))
    assert len(windows) == sum(1 for r in SAMPLE["runs"] if r.get("window"))
    assert (where["home"] / ".glorfindel" / "watch_heartbeat").is_file()
    text = "".join(p.read_text(encoding="utf-8") for p in files)
    assert cs.identifiers(text) == []


# ── What the sample shows: the board, its refusal, the name to type, the request ─────────

@pytest.fixture()
def board(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from .console_client import console

    import eregion_console.api as api
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    monkeypatch.setenv("EREGION_CONSOLE_SECTIONS", "annatar,gothmog")
    monkeypatch.setenv("EREGION_BENCH", SAMPLE["bench"])
    cs.install(api, SAMPLE, put=monkeypatch.setattr)
    api._targets_cache.update(at=0.0, value=None)
    yield console()
    api._targets_cache.update(at=0.0, value=None)


def _rid(name: str) -> str:
    return cs.resource_id(SAMPLE, next(t for t in SAMPLE["targets"] if t["name"] == name))


def test_the_sample_board_shows_the_enrolled_targets_only(board):
    b = board.get("/api/dagorlad/board").json()
    assert [t["name"] for t in b["targets"]] == ["vm-celebrimbor-gondolin", "vm-celebrimbor-twin", "vm-sentinel"]
    assert b["glorfindel"]["gate"] == "" and b["glorfindel"]["rules"] == len(SAMPLE["rules"])


def test_the_sample_wires_hold_a_refusal_and_a_name_to_type(board):
    wires = [("wire", f"{e}@{_rid(t)}") for e, t in SAMPLE["board"]]
    p = board.get("/api/dagorlad/plan", params=wires).json()["wires"]
    codes = {(v["experiment"], v["target_name"]): v["code"] for v in p}
    assert codes[("T1486", "vm-sentinel")] == "zone_forbids"
    assert [c for c in codes.values() if c] == ["zone_forbids"]
    twin = next(v for v in p if v["target_name"] == "vm-celebrimbor-twin")
    assert "typed_name" in [w["code"] for w in twin["warnings"]]


def test_the_loop_ends_on_a_request_and_its_command(board):
    ok, _refused, typed = SAMPLE["loop"]
    r = board.post("/api/dagorlad/requests",
                   json={"wires": [{"experiment": e, "target": _rid(t)} for e, t in (ok, typed)]})
    assert r.status_code == 200, r.text
    assert r.json()["command"].startswith("make orodruin-exercise REQUEST=r-")


# ── The images: rendered from this sample, small enough ──────────────────────────────────

def test_the_images_are_the_samples_and_small_enough():
    manifest = json.loads((IMAGES / cs.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["sample_sha256"] == cs.sha256(cs.SAMPLE), (
        "the sample changed since the images were rendered: python scripts/console_shots.py")
    assert sorted(manifest["images"]) == ["board.png", "loop.webp", "runs.png"]
    for name, digest in manifest["images"].items():
        data = (IMAGES / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, f"{name} is not the one rendered"
        assert len(data) <= (cs.MAX_LOOP if name.endswith(".webp") else cs.MAX_PNG), name
    assert sorted(p.name for p in IMAGES.iterdir()) == sorted([*manifest["images"], cs.MANIFEST])


def test_the_loop_is_an_animated_webp_of_ten_to_fifteen_seconds():
    data = (IMAGES / "loop.webp").read_bytes()
    chunks = list(cs._chunks(data))
    assert chunks[0][0] == b"VP8X" and chunks[0][1][0] & 0x02           # animated
    frames = [c for t, c in chunks if t == b"ANMF"]
    total_ms = sum(int.from_bytes(f[12:15], "little") for f in frames)
    assert len(frames) > 10 and 10_000 <= total_ms <= 15_000

