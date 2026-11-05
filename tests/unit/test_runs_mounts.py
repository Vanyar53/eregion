"""SEC18 (N-05, #455): who mounts which directory of runs/ — the compose file, the Makefile's docker
runs (the workstation and Orodruin), H0's deployment — and what the readers make of a file out of
its writer's place.

The oracle is written here: each directory of runs/ has its writers (OWNERS), the services that may
mount it read-write; every other mount of it is read-only; no service mounts runs/ whole (the one
migration of the former layout aside, run once at a deployment); an injector mounts neither the
watch's directory nor the console's, not even read-only. Then the readers: the watch, the console
never read an injector's signal put in another writer's directory, and say it. No container
starts, nothing reaches Azure.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest
import yaml

from eregion_core import runs_layout

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
DEPLOY = (ROOT / "infra" / "glorfindel-host" / "deploy.sh").read_text(encoding="utf-8")

# The writers of each directory: compose services, and the Makefile's docker runs by their variable.
OWNERS = {
    "glorfindel": {"watch", "GLORFINDEL_VOLS"},
    "console": {"war-room", "bot", "GLORFINDEL_VOLS"},
    "annatar": {"annatar", "ANNATAR_VOLS", "ORO_RUN", "ORO_RUN_REQUEST"},
    "gothmog": {"gothmog", "ORO_RUN_GOTHMOG", "ORO_RUN_REQUEST"},
    # One run at a time on the injectors' host (R-10): its lock and its journal are every
    # injector's there — the one directory of several writers, all of them red.
    "orodruin": {"annatar", "gothmog", "ANNATAR_VOLS", "ORO_RUN", "ORO_RUN_GOTHMOG", "ORO_RUN_CONTRACT",
                 "ORO_RUN_REQUEST"},
    # The local channel of verdicts: the watch writes it, the red reads it, read-only.
    "verdicts": {"watch", "GLORFINDEL_VOLS"},
    # FS1b: the bot's requests of the action queue — a writer of its own.
    "bot": {"bot"},
}
RED = {"annatar", "gothmog", "ANNATAR_VOLS", "ORO_RUN", "ORO_RUN_GOTHMOG", "ORO_RUN_CONTRACT", "ORO_RUN_REQUEST"}
# The Makefile's docker runs that mount runs/, by variable. ORO_MIGRATE mounts it whole, once.
MAKE_RUNS = ("ANNATAR_VOLS", "GLORFINDEL_VOLS", "ORO_RUN", "ORO_RUN_GOTHMOG", "ORO_RUN_CONTRACT",
             "ORO_RUN_REQUEST")
_MOUNT = re.compile(r"(?P<src>\S*runs\}?(?:/(?P<sw>[a-z]+)(?P<ssub>/[a-z]+)?)?):(?P<dst>/app/runs(?:/(?P<dw>[a-z]+)(?P<dsub>/[a-z]+)?)?)(?P<ro>:ro)?$")


def _variable(name: str) -> str:
    """A Makefile variable's text (its continuation lines joined), ``$(call ORO_MOUNT,x)``
    expanded as make would."""
    m = re.search(rf"^{name}\s*:?=(.*?)(?<!\\)$", MAKEFILE, re.M | re.S)
    assert m, name
    text = m.group(1).replace("\\\n", " ")
    return re.sub(r"\$\(call ORO_MOUNT,(\w+)\)", r"-v $$HOME/runs/\1:/app/runs/\1", text)


def _mounts() -> dict[str, list[tuple[str, str, bool]]]:
    """Every mount of runs/ by who mounts it: (source's writer or "" for runs/ whole, target's,
    read-only)."""
    out: dict[str, list] = {}
    for name, s in COMPOSE.items():
        out[name] = [_parse(v) for v in s.get("volumes") or [] if "/app/runs" in v]
    for name in MAKE_RUNS:
        text = _variable(name)
        out[name] = [_parse(v) for v in re.findall(r"-v (\S+)", text) if "/app/runs" in v]
    return out


def _parse(volume: str) -> tuple[str, str, bool]:
    m = _MOUNT.search(volume)
    assert m, volume
    assert (m["ssub"] or "") == (m["dsub"] or ""), volume
    return m["sw"] or "", m["dw"] or "", bool(m["ro"])


def _subdirs() -> dict[str, list[tuple[str, str, bool]]]:
    """FS1b: the mounts of a subdirectory of a writer's — (writer, its subdirectory, read-only)."""
    out: dict[str, list] = {}
    for name, s in COMPOSE.items():
        for v in s.get("volumes") or []:
            m = _MOUNT.search(v) if "/app/runs" in v else None
            if m and m["ssub"]:
                out.setdefault(name, []).append((m["sw"], m["ssub"], bool(m["ro"])))
    return out


def test_no_service_mounts_runs_whole():
    """M3222, M3223: never runs/ entire — each its directories, by name."""
    for who, mounts in _mounts().items():
        assert mounts, who
        for src, dst, _ in mounts:
            assert src and src == dst and src in runs_layout.WRITERS, (who, src, dst)


def test_the_bot_mounts_the_watchs_receipts_only_read_only():
    """FS1b: of the watch's directory, the bot mounts runs/glorfindel/queue — its receipts and its
    status — read-only, and nothing else; the watch mounts the bot's requests read-only; no other
    service mounts a subdirectory."""
    assert _subdirs() == {"bot": [("glorfindel", "/queue", True)]}
    assert ("bot", True) in {(w, ro) for w, _, ro in _mounts()["watch"]}
    assert "${EREGION_RUNS:-./runs}/bot:/app/runs/bot" in COMPOSE["bot"]["volumes"]


def test_a_writers_directory_is_mounted_read_write_by_its_writers_only():
    """M3221: the watch mounts the injectors' read-only; each service writes its own."""
    for who, mounts in _mounts().items():
        for writer, _, ro in mounts:
            if not ro:
                assert who in OWNERS[writer], f"{who} mounts runs/{writer} read-write"


def test_the_red_never_mounts_the_watchs_directory_nor_the_consoles():
    """M3220, M3224: neither read-write nor read-only — the watch's reasoning and the operator's
    gestures are not the red's to read; its detection comes through the return channel, or the
    local channel of verdicts, read-only: the one directory of the blue it sees (M3320)."""
    for who in RED:
        writers = {w for w, _, _ in _mounts()[who]}
        assert not writers & {"glorfindel", "console"}, (who, writers)
        assert all(ro for w, _, ro in _mounts()[who] if w == "verdicts"), who


def test_each_service_mounts_what_it_writes_and_reads():
    want = {"watch": {("glorfindel", False), ("annatar", True), ("gothmog", True), ("console", True),
                      ("verdicts", False), ("bot", True)},
            "war-room": {("console", False), ("glorfindel", True), ("annatar", True), ("gothmog", True)},
            "bot": {("console", False), ("annatar", True), ("bot", False), ("glorfindel", True)},
            "annatar": {("annatar", False), ("orodruin", False), ("verdicts", True)},
            "gothmog": {("gothmog", False), ("orodruin", False), ("verdicts", True)},
            "ANNATAR_VOLS": {("annatar", False), ("orodruin", False), ("verdicts", True)},
            "ORO_RUN": {("annatar", False), ("orodruin", False)},
            "ORO_RUN_GOTHMOG": {("gothmog", False), ("orodruin", False)},
            "ORO_RUN_CONTRACT": {("orodruin", False)},
            "ORO_RUN_REQUEST": {("annatar", False), ("gothmog", False), ("orodruin", False)}}
    got = {who: {(w, ro) for w, _, ro in mounts} for who, mounts in _mounts().items()}
    for who, mounts in want.items():
        assert got[who] == mounts, who


def test_the_only_whole_mount_is_the_migration_at_a_deployment():
    """The migration of the former layout mounts ~/runs whole, once: at the deployment of the
    injectors' image (orodruin-push, orodruin-push-dev), nowhere else."""
    assert "-v $$HOME/runs:/app/runs " in _variable("ORO_MIGRATE")
    assert "python -m eregion_core.runs_layout migrate /app/runs" in _variable("ORO_MIGRATE")
    users = [ln for ln in MAKEFILE.splitlines() if "$(ORO_MIGRATE)" in ln]
    assert len(users) == 2
    targets = [t for t in ("orodruin-push:", "orodruin-push-dev:")]
    for target in targets:
        body = MAKEFILE.split(f"\n{target}", 1)[1].split("\n\n", 1)[0]
        assert "$(ORO_MIGRATE)" in body, target
    assert not re.search(r"-v \$\(PWD\)/runs:/app/runs|\$\{EREGION_RUNS:-\./runs\}:/app/runs", MAKEFILE)


def test_each_writers_directory_is_made_before_a_container_mounts_it():
    """Left to docker, a missing directory is made by root: the service (not root) could not
    write it. The workstation, a team, Orodruin, H0 make them first, as the operator."""
    assert "runs-migrate" in MAKEFILE.split("\nglorfindel-start:", 1)[1].split("\n", 1)[0]
    for w in runs_layout.WRITERS:
        assert f"runs/{w}" in _variable("RUNS_DIRS")
    assert "$(RUNS_DIRS) &&" in _variable("DOCKER_ANNATAR") and "$(RUNS_DIRS) &&" in _variable("DOCKER_GLORFINDEL")
    oro = _variable("ORO_DIRS")
    assert all(f"$$HOME/runs/{w}" in oro for w in ("annatar", "gothmog", "orodruin"))
    # No watch on Orodruin: no local channel of verdicts there — the storage channel carries them.
    assert "verdicts" not in oro and _variable("ORO_MIGRATE").rstrip().endswith("--orodruin")
    for name in ("ORO_RUN", "ORO_RUN_GOTHMOG", "ORO_RUN_CONTRACT", "ORO_RUN_REQUEST"):
        assert "verdicts" not in _variable(name), name
    for name in ("ORO_RUN", "ORO_RUN_GOTHMOG", "ORO_RUN_CONTRACT", "ORO_RUN_REQUEST"):
        assert _variable(name).strip().startswith("$(ORO_DIRS) docker run"), name
    team = MAKEFILE.split("\nteam-start:", 1)[1].split("\n\n", 1)[0]
    assert 'runs_layout migrate "$(TEAM_DIR)/runs"' in team
    # M3343: a team's services stopped first when its former layout holds something
    stop = team.index('runs_layout pending "$(TEAM_DIR)/runs"')
    assert stop < team.index("stop watch war-room bot") < team.index('runs_layout migrate "$(TEAM_DIR)/runs"')


def test_h0_moves_the_former_layout_before_it_starts_the_services():
    """M3239: on H0, deploy.sh's start migrates runs/ on the host, then starts compose — and a
    reference from before SEC18 (no runs_layout) is started as it was."""
    start = DEPLOY.split("\nstart() {", 1)[1].split("\n}", 1)[0]
    migrate = start.index("python3 -m eregion_core.runs_layout migrate runs")
    assert migrate < start.index("docker compose --profile bot up")
    assert "if [ -f eregion_core/runs_layout.py ]" in start and "|| die" in start


def test_the_orodruin_module_mounts_nothing_of_runs():
    """The module of Orodruin makes ~/runs at the VM's first boot; its directories are made by
    the Makefile's docker runs and the migration — its custom_data unchanged (changing it would
    replace the VM)."""
    tf = (ROOT / "infra" / "orodruin" / "main.tf").read_text(encoding="utf-8")
    assert "/app/runs" not in tf
    assert "mkdir -p /home/${var.admin_username}/runs /home/${var.admin_username}/.annatar" in tf


# ── What the readers make of a file out of its place ─────────────────────────────────────

def test_the_watch_never_reads_a_signal_out_of_annatars_directory_and_says_it(tmp_path, monkeypatch):
    """M3225, M3226: an attack_started put in the console's directory and one flat in runs/ (the
    former layout) never reach the watch's decision; each is said once; Annatar's own does."""
    from tests.unit.test_signal_origin import _line, _run_watch

    t0 = time.time() - 60
    stray = json.dumps(_line("attack_started", signal_id="stray", raw_signal={"attack_time": t0})) + "\n"

    def prepare(signals: Path) -> None:
        (signals.parent / "console").mkdir()
        (signals.parent / "console" / "c_signals.jsonl").write_text(stray)
        (signals.parent / "flat_signals.jsonl").write_text(stray)

    responded, polled, out = _run_watch(tmp_path, monkeypatch, [_line("attack_started", raw_signal={"attack_time": t0})],
                                        expect=1, prepare=prepare)
    assert len(polled) == 1 and [d["event"] for d in responded] == ["detection"], out
    squash = "".join(out.split())             # the terminal's width aside
    assert squash.count("console/c_signals.jsonl:pasunfichierdeconsole") == 1, out
    assert squash.count("flat_signals.jsonl:anciennedisposition") == 1 and "makeruns-migrate" in squash


def test_the_console_reads_each_line_from_its_writers_directory_only(tmp_path, monkeypatch, capsys):
    """M3238: the live feed's history — an injector's signal in the console's directory, a cycle
    in Annatar's, a gesture in the watch's: none shown, each said once; each writer's own shown."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    import eregion_console.api as api
    monkeypatch.chdir(tmp_path)
    runs = tmp_path / "runs"
    for w in runs_layout.WRITERS:
        (runs / w).mkdir(parents=True)
    now = "2026-11-03T10:00:00+00:00"
    sig = json.dumps({"timestamp": now, "event": "attack_started", "ttp": "T1110.001", "resource_id": "/x/vm-a"})
    cyc = json.dumps({"timestamp": now, "action": "isolate_vm", "signal": {"ttp": "T1110.001", "resource_id": "/x/vm-a"}})
    (runs / "annatar" / "r1_signals.jsonl").write_text(sig + "\n")
    (runs / "glorfindel" / "watch-x_debug.jsonl").write_text(cyc + "\n")
    (runs / "console" / "manual_actions.jsonl").write_text(cyc + "\n")
    (runs / "console" / "forged_signals.jsonl").write_text(sig + "\n")
    (runs / "annatar" / "forged_debug.jsonl").write_text(cyc + "\n")
    (runs / "glorfindel" / "manual_actions.jsonl").write_text(cyc + "\n")
    got = api._load_recent(40)
    assert sorted(e["type"] for e in got) == ["action", "action", "signal"]
    api._run_reports()
    api._run_reports()
    out = capsys.readouterr().out
    for name in ("console/forged_signals.jsonl", "annatar/forged_debug.jsonl", "glorfindel/manual_actions.jsonl"):
        assert out.count(name) == 1, (name, out)



def _shell(text: str, home: Path):
    import subprocess
    script = text.replace("$$", "$").rstrip().removesuffix("&&")
    return subprocess.run(["bash", "-c", script], cwd=home, env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
                          capture_output=True, text=True)


@pytest.mark.parametrize("name", ["RUNS_DIRS", "ORO_DIRS"])
def test_a_writers_directory_that_is_a_link_is_never_made_nor_mounted(name, tmp_path):
    """M3333, M3334: the workstation's and Orodruin's: a link in place of runs/annatar stops the
    command before docker — its target never written."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "runs").mkdir()
    (tmp_path / "runs" / "annatar").symlink_to(elsewhere)
    res = _shell(_variable(name), tmp_path)
    assert res.returncode != 0 and "lien" in res.stderr, res
    assert list(elsewhere.iterdir()) == []
    (tmp_path / "runs" / "annatar").unlink()
    assert _shell(_variable(name), tmp_path).returncode == 0 and (tmp_path / "runs" / "annatar").is_dir()


def test_h0_refuses_a_writers_directory_that_is_a_link(tmp_path):
    """M3335: deploy.sh holds each writer's directory as a real one before anything starts, and
    stops the services before moving a former layout."""
    start = DEPLOY.split("\nstart() {", 1)[1].split("\n}", 1)[0]
    check = start.index('[ ! -L "$d" ]')
    assert check < start.index("python3 -m eregion_core.runs_layout migrate runs")
    assert all(f"runs/{w}" in start for w in runs_layout.WRITERS)
    assert start.index("runs_layout pending runs") < start.index("migrate runs ||")
    assert "stop watch war-room bot" in start


def test_the_console_holds_a_window_against_its_directory(tmp_path, monkeypatch):
    """M3338: a window of Gothmog's in Annatar's directory is shown refused, never counted."""
    pytest.importorskip("fastapi")
    import eregion_console.api as api
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    d = tmp_path / "runs" / "annatar" / "exercises"
    d.mkdir(parents=True)
    (d / "g1.json").write_text(json.dumps({"run_id": "g1", "injector": "gothmog", "kind": "fault",
                                           "start": "2026-11-03T10:00:00+00:00", "targets": []}))
    [w] = api._read_windows()
    assert "jamais crue" in w["refusal"] and api._held_windows() == {}
