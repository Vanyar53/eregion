"""`make orodruin-exercise REQUEST=<id>` (DG-b, docs/design/console.md §7): the command the operator
carries — the request pulled from the console's host (H0, by SSH), shown wire by wire, the name of
each destructive wire's target typed here, then copied to Orodruin and launched there.

Run for real against a fake `ssh` and a fake `scp` first on PATH, which record what they receive
and serve the request H0 holds: nothing connects, nothing reaches Azure. The oracles are written
here.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")

RID = "r-20261030T075200Z-a1b2c3"
VM = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
REQUEST = {"id": RID, "at": "2026-10-30T07:52:00+00:00",
           "wires": [{"experiment": "T1110.001", "target": VM, "rank": 1},
                     {"experiment": "T1486", "target": VM, "rank": 2}]}


@pytest.fixture
def fake_hosts(tmp_path):
    """`ssh` and `scp` that log their argv; `ssh … cat .eregion/console/requests/<id>.json`
    answers with the request H0 holds (``h0/``), `scp` copies to ``orodruin/``."""
    bindir, h0, oro = tmp_path / "bin", tmp_path / "h0", tmp_path / "orodruin"
    for d in (bindir, h0, oro):
        d.mkdir()
    log = tmp_path / "calls.jsonl"
    common = (f"#!{sys.executable}\nimport json, os, shutil, sys\n"
              f"open({str(log)!r}, 'a').write(json.dumps({{'cmd': os.path.basename(sys.argv[0]), "
              "'argv': sys.argv[1:]}) + '\\n')\n")
    (bindir / "ssh").write_text(common + (
        "cmd = sys.argv[-1]\n"
        "if cmd.startswith('cat .eregion/console/requests/'):\n"
        f"    p = os.path.join({str(h0)!r}, cmd.rsplit('/', 1)[-1])\n"
        "    sys.stdout.write(open(p).read()) if os.path.exists(p) else sys.exit(1)\n"))
    (bindir / "scp").write_text(common + (
        "for a in sys.argv[1:-1]:\n"
        f"    shutil.copy(a, {str(oro)!r}) if os.path.isfile(a) else None\n"))
    for f in ("ssh", "scp"):
        (bindir / f).chmod(0o755)

    def calls():
        return [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []
    return bindir, h0, oro, calls


def _make(fake, *args, stdin="", env_extra=None):
    bindir = fake[0]
    env = {k: v for k, v in os.environ.items() if k not in ("REQUEST", "HOST_SSH_FINGERPRINT")}
    env.update({"PATH": f"{bindir}{os.pathsep}{env['PATH']}", "HOME": str(bindir.parent)},
               **(env_extra or {}))
    return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "orodruin-exercise",
                           f"PYTHON={sys.executable}", "HOST_IP=10.0.0.4", "ORO_IP=10.0.0.5", *args],
                          capture_output=True, text=True, input=stdin, env=env, timeout=60)


def _serve(h0: Path, doc=REQUEST):
    (h0 / f"{doc['id']}.json").write_text(json.dumps(doc))


@needs_make
def test_the_request_goes_from_h0_to_orodruin_with_the_names_typed_here(fake_hosts):
    bindir, h0, oro, calls = fake_hosts
    _serve(h0)
    res = _make(fake_hosts, f"REQUEST={RID}", stdin="vm-celebrimbor-gondolin\ny\n")
    assert res.returncode == 0, res.stdout + res.stderr
    # Shown wire by wire, the destructive one flagged, its name asked for.
    assert "T1110.001" in res.stdout and "T1486" in res.stdout and "DESTRUCTIVE" in res.stdout
    assert "Wire 2: type the name of its target VM" in res.stdout
    assert "Wire 1: type" not in res.stdout
    seen = calls()
    assert [c["cmd"] for c in seen] == ["ssh", "ssh", "scp", "ssh"]
    assert seen[0]["argv"][-2:] == ["glorfindel@10.0.0.4", f"cat .eregion/console/requests/{RID}.json"]
    assert seen[1]["argv"][-1] == "mkdir -p requests && chmod 700 requests"
    assert seen[2]["argv"][-1] == "orodruin@10.0.0.5:requests/"
    run = seen[3]["argv"][-1]
    assert run.endswith(f"python -m eregion_core.exercise_runner /app/requests/{RID}.json")
    assert "-v $HOME/requests:/app/requests:ro" in run and "--env-file orodruin.env" in run
    # What reached Orodruin: the request as H0 holds it, and the names typed beside it.
    assert json.loads((oro / f"{RID}.json").read_text()) == REQUEST
    assert json.loads((oro / f"{RID}.typed.json").read_text()) == {
        "request": RID, "typed": {"2": "vm-celebrimbor-gondolin"}}


@needs_make
@pytest.mark.parametrize("stdin, said", [
    ("vm-celebrimbor-bree\ny\n", "is not its target"),     # another name typed
    ("\ny\n", "is not its target"),                        # no name
    ("vm-celebrimbor-gondolin\nn\n", "Nothing sent"),       # the operator stops
])
def test_a_wrong_name_or_a_no_sends_nothing(fake_hosts, stdin, said):
    bindir, h0, oro, calls = fake_hosts
    _serve(h0)
    res = _make(fake_hosts, f"REQUEST={RID}", stdin=stdin)
    assert res.returncode != 0
    assert said in res.stdout + res.stderr
    assert [c["cmd"] for c in calls()] == ["ssh"]            # pulled, nothing else
    assert not any(oro.iterdir())


@needs_make
def test_dry_run_shows_and_asks_then_sends_nothing(fake_hosts):
    bindir, h0, oro, calls = fake_hosts
    _serve(h0)
    res = _make(fake_hosts, f"REQUEST={RID}", "DRY_RUN=1", stdin="vm-celebrimbor-gondolin\ny\n")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "DRY_RUN : rien n'est envoyé" in res.stdout
    assert f"python -m eregion_core.exercise_runner /app/requests/{RID}.json" in res.stdout
    assert [c["cmd"] for c in calls()] == ["ssh"]
    assert not any(oro.iterdir())


@needs_make
@pytest.mark.parametrize("value", ["", "../x", "r-1", "r-20261030T075200Z-a1b2c3;id", "$(id)",
                                   "-oProxyCommand=x"])
def test_a_request_id_is_checked_before_any_command(fake_hosts, value):
    res = _make(fake_hosts, f"REQUEST={value}", stdin="y\n")
    assert res.returncode != 0
    assert fake_hosts[3]() == []                             # neither ssh nor scp


@needs_make
def test_request_is_never_read_from_the_environment(fake_hosts):
    bindir, h0, oro, calls = fake_hosts
    _serve(h0)
    res = _make(fake_hosts, stdin="y\n", env_extra={"REQUEST": RID})
    assert res.returncode != 0 and "REQUEST vient de l'environnement" in res.stderr
    assert calls() == []


@needs_make
def test_a_request_forged_with_a_field_more_is_refused_before_anything_is_sent(fake_hosts):
    bindir, h0, oro, calls = fake_hosts
    forged = json.loads(json.dumps(REQUEST))
    forged["wires"][1]["typed_name"] = "vm-celebrimbor-gondolin"   # a name H0 would have « typed »
    _serve(h0, forged)
    res = _make(fake_hosts, f"REQUEST={RID}", stdin="y\n")
    assert res.returncode != 0 and "never holds" in res.stderr
    assert [c["cmd"] for c in calls()] == ["ssh"] and not any(oro.iterdir())


@needs_make
def test_a_local_console_is_read_from_this_machine(fake_hosts):
    bindir, h0, oro, calls = fake_hosts
    local = bindir.parent / ".eregion" / "console" / "requests"
    local.mkdir(parents=True)
    (local / f"{RID}.json").write_text(json.dumps(REQUEST))
    res = _make(fake_hosts, f"REQUEST={RID}", "REQUEST_FROM=local", "DRY_RUN=1",
                stdin="vm-celebrimbor-gondolin\ny\n")
    assert res.returncode == 0, res.stdout + res.stderr
    assert calls() == []


def test_the_target_is_phony_and_has_its_help_line():
    phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
    assert "orodruin-exercise" in phony
    assert "make orodruin-exercise REQUEST=<id>" in MAKEFILE.split("# ── Help", 1)[1]


def test_h0_is_reached_only_once_its_host_key_is_checked():
    """V-32: the pull from H0 goes through glorfindel-host-known and HOST_SSH (its pinned key)."""
    head = next(ln for ln in MAKEFILE.splitlines() if ln.startswith("orodruin-exercise: $(if"))
    assert "glorfindel-host-known" in head
    recipe = MAKEFILE.split(head, 1)[1].split("\n\n", 1)[0]
    assert '$(HOST_SSH) "cat .eregion/console/requests/$$id.json"' in recipe


@needs_make
def test_another_request_served_under_this_id_sends_nothing(fake_hosts):
    """DG-b review, point 4: the content's id is the one asked for, or nothing goes to Orodruin."""
    bindir, h0, oro, calls = fake_hosts
    other = {**REQUEST, "id": "r-20261030T075200Z-ffffff"}
    (h0 / f"{RID}.json").write_text(json.dumps(other))
    res = _make(fake_hosts, f"REQUEST={RID}", stdin="vm-celebrimbor-gondolin\ny\n")
    assert res.returncode != 0 and "not r-20261030T075200Z-a1b2c3" in res.stdout
    assert [c["cmd"] for c in calls()] == ["ssh"] and not any(oro.iterdir())
