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
        "    sys.stdout.write(open(p).read()) if os.path.exists(p) else sys.exit(1)\n"
        # DG-d: H0's instance drill, or « none here » (3): the command takes the shipped one then.
        "if cmd.startswith('test -e .eregion/console/drills/'):\n"
        f"    p = os.path.join({str(h0)!r}, 'drills', cmd.split()[2].rsplit('/', 1)[-1])\n"
        "    sys.exit(4) if os.path.islink(p) and f'test ! -L {cmd.split()[2]} || exit 4' in cmd else None\n"
        "    sys.stdout.write(open(p).read()) if os.path.exists(p) else sys.exit(3)\n"))
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
    # The host key's check is known_host.sh's (tests/unit/test_host_ssh.py): taken as done here.
    fingerprint = [] if any(a.startswith("HOST_SSH_FINGERPRINT=") for a in args) else ["HOST_SSH_FINGERPRINT=SHA256:test"]
    return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "-o", "glorfindel-host-known", "-o", "orodruin-known",
                           "orodruin-exercise", f"PYTHON={sys.executable}", "HOST_IP=10.0.0.4", "ORO_IP=10.0.0.5",
                           *fingerprint, *args],
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
    # R-11: the names typed do not stay on Orodruin — removed when the run ends, however it ends.
    assert run.startswith(f"trap 'rm -f requests/{RID}.typed.json' EXIT HUP INT TERM; ")
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


@needs_make
def test_a_request_from_h0_needs_its_host_keys_fingerprint(fake_hosts):
    """DG-b review, point 8: never accept-new for what makes Orodruin act."""
    bindir, h0, oro, calls = fake_hosts
    _serve(h0)
    res = _make(fake_hosts, f"REQUEST={RID}", "HOST_SSH_FINGERPRINT=", stdin="vm-celebrimbor-gondolin\ny\n")
    assert res.returncode != 0 and "HOST_SSH_FINGERPRINT requis" in res.stderr
    assert calls() == []


# ── DG-d: make orodruin-exercise DRILL=<name> [TARGETS=…] ─────────────────────────────────

SUB = "00000000-0000-0000-0000-000000000000"
VMS = [{"name": n, "resource_id": VM.rsplit("/", 1)[0] + "/" + n, "rg_tags": {"eregion-target": "celebrimbor"},
        "tags": {"eregion-target": "celebrimbor", "eregion-zone": z}}
       for n, z in (("vm-celebrimbor-gondolin", "bench"), ("vm-celebrimbor-rivendell", "bench"),
                    ("vm-sentinel", "production"))]


def _drill_env(tmp_path) -> dict:
    """The bench's scope (the bench's VMs: ``_vms``, on the command line — no Azure here)."""
    (tmp_path / "vms.json").write_text(json.dumps(VMS))
    return {"AZURE_SUBSCRIPTION_ID": SUB, "EREGION_BENCH": "celebrimbor"}


def _vms(tmp_path) -> str:
    return f"DRILL_VMS={tmp_path / 'vms.json'}"


def _sent(oro: Path) -> dict:
    [req] = [p for p in oro.iterdir() if not p.name.endswith(".typed.json")]
    return json.loads(req.read_text())


@needs_make
def test_a_shipped_drill_goes_to_orodruin_on_the_vms_given(fake_hosts, tmp_path):
    """A shipped drill (drills/bl1-reponse.yaml: a fault, then T1136.001, on the bench), H0 holding
    no drill of that name: its wires on the VM given by TARGETS, a request, shown, sent."""
    bindir, h0, oro, calls = fake_hosts
    res = _make(fake_hosts, "DRILL=bl1-reponse", "TARGETS=vm-celebrimbor-rivendell", _vms(tmp_path), stdin="y\n",
                env_extra=_drill_env(tmp_path))
    assert res.returncode == 0, res.stdout + res.stderr
    seen = calls()
    assert [c["cmd"] for c in seen] == ["ssh", "ssh", "scp", "ssh"]
    f = ".eregion/console/drills/bl1-reponse.yaml"
    # Absent (3): the shipped one; a link (4): refused, never followed nor replaced by the shipped one.
    assert seen[0]["argv"][-1] == f"test -e {f} || test -L {f} || exit 3; test ! -L {f} || exit 4; cat {f}"
    req = _sent(oro)
    rivendell = VMS[1]["resource_id"]
    assert [(w["experiment"], w["target"]) for w in req["wires"]] == [("vm-shutdown", rivendell), ("T1136.001", rivendell)]
    assert seen[3]["argv"][-1].endswith(f"python -m eregion_core.exercise_runner /app/requests/{req['id']}.json")
    assert "drill bl1-reponse (shipped, 2 wire(s))" in res.stderr


@needs_make
def test_a_shipped_drill_without_targets_sends_nothing_and_lists_the_candidates(fake_hosts, tmp_path):
    bindir, h0, oro, calls = fake_hosts
    res = _make(fake_hosts, "DRILL=bl1-reponse", _vms(tmp_path), stdin="y\n", env_extra=_drill_env(tmp_path))
    assert res.returncode != 0
    assert "choose: vm-celebrimbor-gondolin | vm-celebrimbor-rivendell" in res.stderr
    assert "TARGETS=all" in res.stderr and "nothing is sent" in res.stderr
    assert [c["cmd"] for c in calls()] == ["ssh"] and not any(oro.iterdir())


@needs_make
def test_an_instance_drill_from_h0_lays_on_its_named_vms(fake_hosts, tmp_path):
    bindir, h0, oro, calls = fake_hosts
    (h0 / "drills").mkdir()
    (h0 / "drills" / "ssh-mine.yaml").write_text(
        "name: ssh-mine\nauthor: operator\nupdated: '2026-11-03T10:00:00+00:00'\n"
        "wires:\n  - experiment: T1136.001\n    target: {name: vm-sentinel}\n")
    res = _make(fake_hosts, "DRILL=ssh-mine", _vms(tmp_path), stdin="y\n", env_extra=_drill_env(tmp_path))
    assert res.returncode == 0, res.stdout + res.stderr
    assert [(w["experiment"], w["target"]) for w in _sent(oro)["wires"]] == [("T1136.001", VMS[2]["resource_id"])]
    assert "drill ssh-mine (instance, 1 wire(s))" in res.stderr


@needs_make
def test_dry_run_of_a_drill_shows_and_asks_then_sends_nothing(fake_hosts, tmp_path):
    bindir, h0, oro, calls = fake_hosts
    res = _make(fake_hosts, "DRILL=sentinelle", "TARGETS=all", "DRY_RUN=1", _vms(tmp_path), stdin="y\n",
                env_extra=_drill_env(tmp_path))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "DRY_RUN : rien n'est envoyé" in res.stdout and "vm-sentinel" in res.stdout
    assert [c["cmd"] for c in calls()] == ["ssh"] and not any(oro.iterdir())


@needs_make
@pytest.mark.parametrize("args, said", [
    (("DRILL=bl1-reponse", f"REQUEST={RID}"), "pas les deux"),
    (("DRILL=../x",), "not a drill's name"),
    (("DRILL=x;id",), "not a drill's name"),
    (("DRILL=A",), "not a drill's name"),
])
def test_a_drills_name_is_checked_before_any_command(fake_hosts, tmp_path, args, said):
    res = _make(fake_hosts, *args, _vms(tmp_path), stdin="y\n", env_extra=_drill_env(tmp_path))
    assert res.returncode != 0 and said in res.stdout + res.stderr
    assert fake_hosts[3]() == []                                       # neither ssh nor scp


@needs_make
@pytest.mark.parametrize("args, said", [
    (("DRILL=nothing-here",), "pas de drill nothing-here"),
    (("DRILL=bl1-reponse", "TARGETS=vm-a;id"), "not a VM's name"),
    (("DRILL=bl1-reponse", "TARGETS=vm-sentinel"), "the candidate of no wire"),
])
def test_a_drill_that_cannot_be_placed_sends_nothing(fake_hosts, tmp_path, args, said):
    res = _make(fake_hosts, *args, _vms(tmp_path), stdin="y\n", env_extra=_drill_env(tmp_path))
    assert res.returncode != 0 and said in res.stdout + res.stderr
    assert not any(fake_hosts[2].iterdir())
    assert [c["cmd"] for c in fake_hosts[3]()] == ["ssh"]              # the drill read, nothing more


@needs_make
def test_an_instance_drill_that_is_a_link_on_h0_is_never_read_nor_the_shipped_one_in_its_place(fake_hosts, tmp_path):
    bindir, h0, oro, calls = fake_hosts
    (h0 / "drills").mkdir()
    (h0 / "elsewhere.yaml").write_text("name: bl1-reponse\n")
    (h0 / "drills" / "bl1-reponse.yaml").symlink_to(h0 / "elsewhere.yaml")
    res = _make(fake_hosts, "DRILL=bl1-reponse", "TARGETS=all", _vms(tmp_path), stdin="y\n",
                env_extra=_drill_env(tmp_path))
    assert res.returncode != 0 and "est un lien, jamais suivi" in res.stderr
    assert [c["cmd"] for c in calls()] == ["ssh"] and not any(oro.iterdir())


@needs_make
@pytest.mark.parametrize("dangling", [False, True])
def test_a_local_instance_drill_that_is_a_link_is_never_read_nor_the_shipped_one(fake_hosts, tmp_path, dangling):
    bindir, h0, oro, calls = fake_hosts
    own = tmp_path / ".eregion" / "console" / "drills"            # HOME is the fake's tmp
    own.mkdir(parents=True)
    if not dangling:
        (tmp_path / "elsewhere.yaml").write_text("name: bl1-reponse\n")
    (own / "bl1-reponse.yaml").symlink_to(tmp_path / "elsewhere.yaml")
    res = _make(fake_hosts, "DRILL=bl1-reponse", "TARGETS=all", "REQUEST_FROM=local", _vms(tmp_path),
                stdin="y\n", env_extra=_drill_env(tmp_path))
    assert res.returncode != 0 and "est un lien, jamais suivi" in res.stderr
    assert calls() == [] and not any(oro.iterdir())


@needs_make
@pytest.mark.parametrize("var", ["DRILL", "TARGETS", "DRILL_VMS"])
def test_drill_targets_and_vms_are_never_read_from_the_environment(fake_hosts, tmp_path, var):
    value = {"DRILL": "bl1-reponse", "TARGETS": "all", "DRILL_VMS": str(tmp_path / "vms.json")}[var]
    env = {**_drill_env(tmp_path), var: value}
    args = () if var == "DRILL" else ("DRILL=bl1-reponse",)
    res = _make(fake_hosts, *args, stdin="y\n", env_extra=env)
    assert res.returncode != 0 and "viennent de l'environnement" in res.stderr
    assert fake_hosts[3]() == []
