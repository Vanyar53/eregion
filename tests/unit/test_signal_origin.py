"""SEC3 (#274) — the runs/ channel and Glorfindel's local state.

runs/ is written by the injectors as well as by Glorfindel. The watch takes from it only what
an injector emits, each for what it is, and only its fields (glorfindel/signal_origin.py); a
recovery_complete lifts an isolation alone only when Glorfindel's own path built it. The state
files are owner-only and written whole. No Azure call, no model call.
"""
from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from glorfindel import signal_origin

ROOT = Path(__file__).resolve().parents[2]
VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"


def _line(event: str, **over) -> dict:
    sig = {"signal_id": f"20261028T100000Z_{event}", "timestamp": "2026-10-28T10:00:00+00:00",
           "provider": "azure", "resource_id": VM, "resource_type": "vm", "ttp": "T1486",
           "severity": "critical", "event": event, "raw_signal": {}, "context": {"run_id": "20261028T100000Z"}}
    sig.update(over)
    return sig


# ── What the channel admits ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("event", ["recovery_complete", "detection", "detection_timeout", "fault_started",
                                   "release_isolation", "", "x" * 500])
def test_only_what_an_injector_emits_is_admitted(event):
    adm = signal_origin.admit(_line(event))
    assert adm.signal is None and adm.refused
    if event == "recovery_complete":
        assert "glorfindel restore" in adm.refused


def test_an_attack_started_keeps_only_the_fields_an_injector_writes():
    """A line cannot hand the defender a query of its own, an IP to block, or a verdict:
    the detection comes from the watch's rule for the technique."""
    data = _line("attack_started",
                 raw_signal={"attack_time": 1.0, "detection_timeout_s": 300, "detection_max_s": 180,
                             "detection_query": "print x=1", "log_analytics_workspace_id": "w",
                             "detection_source": "azure_monitor", "first_result_row": {"MaxWrite": 1e9}},
                 context={"run_id": "20261028T100000Z", "scenario": "s", "suspicious_ip": "203.0.113.9",
                          "attribution": "asset", "plane": "data"},
                 extra="x")
    adm = signal_origin.admit(data)
    assert adm.what == "poll"
    assert adm.signal["raw_signal"] == {"attack_time": 1.0, "detection_timeout_s": 300, "detection_max_s": 180}
    assert adm.signal["context"] == {"run_id": "20261028T100000Z", "scenario": "s"}
    assert "extra" not in adm.signal
    assert {"raw_signal.detection_query", "raw_signal.first_result_row", "context.suspicious_ip",
            "context.attribution", "extra"} <= set(adm.dropped)


def test_a_detection_missed_is_a_proposal_and_an_attack_adapted_a_note():
    missed = signal_origin.admit(_line("detection_missed", raw_signal={"failed_query": "q",
                                                                       "detection_hints": {"a": 1}},
                                       context={"run_id": "r1", "workspace_id": "w", "detection_timeout_s": 300}))
    assert missed.what == "propose" and missed.signal["raw_signal"]["detection_hints"] == {"a": 1}
    assert signal_origin.admit(_line("attack_adapted", raw_signal={"blocked_ip": "1.2.3.4"})).what == "note"


@pytest.mark.parametrize("run_id", ["../../root/.glorfindel/escalations", "a/b", "..", "-x", "", None])
def test_a_run_id_is_a_plain_name(run_id):
    """It names files (runs/<run_id>_debug.jsonl): never a path."""
    adm = signal_origin.admit(_line("attack_started", context={"run_id": run_id}))
    assert (adm.signal is None) is (run_id not in ("", None))


def test_the_inventory_of_the_injectors_is_the_channels():
    """Every event Annatar emits, with every field it writes, is what the channel admits —
    an event or a field added on Annatar's side without the channel would be lost (or, the
    other way, a list grown with no one emitting it). Gothmog writes runs/gothmog/, unread."""
    tree = ast.parse((ROOT / "annatar" / "runner" / "engine.py").read_text(encoding="utf-8"))
    emitted: dict[str, dict[str, set]] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "emit"):
            continue
        kw = {k.arg: k.value for k in node.keywords}
        event = kw["event"].value
        parts = emitted.setdefault(event, {"raw_signal": set(), "context": set()})
        for arg, part in (("raw_signal", "raw_signal"), ("metrics", "context")):
            if isinstance(kw.get(arg), ast.Dict):
                parts[part] |= {k.value for k in kw[arg].keys}
    assert set(emitted) == set(signal_origin.CHANNEL_EVENTS)
    for event, parts in emitted.items():
        fields = signal_origin._FIELDS[event]
        assert parts["raw_signal"] <= set(fields["raw_signal"]), event
        assert parts["context"] | {"run_id", "scenario"} <= set(fields["context"]), event
    emitter = (ROOT / "annatar" / "signals" / "emitter.py").read_text(encoding="utf-8")
    assert '"run_id": self.run_id' in emitter and '"scenario": self.scenario_name' in emitter
    gothmog = (ROOT / "gothmog" / "signals" / "emitter.py").read_text(encoding="utf-8")
    assert "SIGNALS_SUBDIR" in gothmog


def test_a_refusal_is_logged_and_counted(caplog):
    with caplog.at_level("WARNING"):
        signal_origin.refuse(_line("recovery_complete"), "pas d'ici", "x_signals.jsonl")
        signal_origin.refuse(_line("recovery_complete"), "pas d'ici", "x_signals.jsonl")
    assert signal_origin.refused_counts() == {"recovery_complete": 2}
    kept = json.loads(signal_origin.REFUSALS_FILE.read_text())
    assert kept["counts"] == {"recovery_complete": 2} and kept["last"]["source"] == "x_signals.jsonl"
    assert "recovery_complete" in caplog.text
    assert stat.S_IMODE(signal_origin.REFUSALS_FILE.stat().st_mode) == 0o600


# ── The watch, end to end ─────────────────────────────────────────────────────────────

_FORGER = """
import json, sys
lines = json.loads(sys.argv[2])
with open(sys.argv[1], "a") as f:
    for line in lines:
        f.write(json.dumps(line) + "\\n")
"""


def _run_watch(tmp_path, monkeypatch, lines, expect):
    """The watch (dry-run) on tmp_path/runs, HOME in tmp_path; `lines` appended by ANOTHER
    process once it runs. Returns (what reached respond, what the poll was asked, output)."""
    from click.testing import CliRunner

    from glorfindel import cli
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    runs = tmp_path / "runs"
    runs.mkdir()
    responded: list[dict] = []
    polled: list[dict] = []

    class _Agent:
        def __init__(self, **kw):
            self.autonomy = SimpleNamespace(default="human_only", assets=[])
            self.config_error = ""
            self.connector = SimpleNamespace(permission_mode=lambda: "read_write")

        def respond(self, data):
            responded.append(data)
            return {"action": "none", "escalate": False, "confidence": 0.0, "outcome": {}}

    def _resolve(data):
        polled.append(data)
        return {**data, "event": "detection"}

    monkeypatch.setattr("glorfindel.agent.GlorfindelAgent", _Agent)
    monkeypatch.setattr("glorfindel.agent.resolve_attack_started", _resolve)
    monkeypatch.setattr(cli, "_find_rules_file", lambda: None)
    monkeypatch.setattr(cli, "_render_decision", lambda *a, **k: None)
    monkeypatch.setattr("eregion_core.inscription.TagEnrollment", lambda *a, **k: (lambda rid: True))
    import atexit
    import signal as signalmod
    monkeypatch.setattr(atexit, "register", lambda *a, **k: None)
    monkeypatch.setattr(signalmod, "signal", lambda *a, **k: None)
    real_sleep = time.sleep
    calls = [0]
    beat_seen: list[bool] = []
    inside = [False]

    def _sleep(s):
        # Only the watch's own loop: not a worker, nor subprocess's wait below.
        if threading.current_thread() is not threading.main_thread() or inside[0]:
            return real_sleep(s)
        calls[0] += 1
        if calls[0] == 1:
            beat = home / ".glorfindel" / "injectors" / "watch_heartbeat"
            # Theirs to read (the injectors' image may run as another user): nothing secret.
            beat_seen.append(beat.is_file() and stat.S_IMODE(beat.stat().st_mode) == 0o644)
            inside[0] = True
            try:
                subprocess.run([sys.executable, "-c", _FORGER, str(runs / "forged_signals.jsonl"),
                                json.dumps(lines)], check=True, timeout=60)
            finally:
                inside[0] = False
            return
        if calls[0] == 2:
            deadline = time.monotonic() + 10
            while len(responded) < expect and time.monotonic() < deadline:
                real_sleep(0.05)
            real_sleep(0.2)                    # what else would arrive, given the time
            raise KeyboardInterrupt
        return real_sleep(0)

    monkeypatch.setattr(cli.time, "sleep", _sleep)
    result = CliRunner().invoke(cli.cli, ["watch", str(runs), "--dry-run", "--interval", "0"])
    assert result.exit_code == 0, result.output
    assert beat_seen == [True]
    assert not (home / ".glorfindel" / "injectors" / "watch_heartbeat").exists()     # removed at stop
    return responded, polled, result.output


def test_a_recovery_complete_written_in_runs_by_another_process_never_acts(tmp_path, monkeypatch):
    """V-05: the forged recovery_complete (Run Command "neutralized"), a forged detection
    carrying its own row, an unknown event and a run id that is a path never reach the
    defender's decision; the attack_started reaches the poll without the query it brought,
    the detection_missed its proposal. Each refusal is said and counted."""
    lines = [
        _line("recovery_complete", raw_signal={"run_command_neutralized": True}),
        _line("detection", raw_signal={"first_result_row": {"Computer": "web", "MaxWrite": 1e9}}),
        _line("something_else"),
        _line("attack_started", context={"run_id": "../../x"}),
        _line("attack_started", raw_signal={"attack_time": 1.0, "detection_query": "print x=1"}),
        _line("detection_missed", raw_signal={"failed_query": "q"}),
        _line("attack_adapted", raw_signal={"blocked_ip": "203.0.113.9"}),
    ]
    responded, polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=2)
    assert sorted(d["event"] for d in responded) == ["detection", "detection_missed"], out
    assert not [d for d in responded if d.get("raw_signal", {}).get("first_result_row")]
    assert [p["raw_signal"] for p in polled] == [{"attack_time": 1.0}]
    assert signal_origin.refused_counts() == {"recovery_complete": 1, "detection": 1, "something_else": 1,
                                              "attack_started": 1}
    assert out.count("Signal refusé") == 4
    assert "attack_adapted noté" in out


# ── recovery_complete: only Glorfindel's own path ─────────────────────────────────────

def test_respond_vouches_only_for_the_defenders_directory(tmp_path, monkeypatch):
    """`glorfindel respond` on a file of runs/ (which the injectors write) vouches for
    nothing; on a file of ~/.glorfindel/recovery_signals/, written by `glorfindel restore`,
    its recovery_complete is Glorfindel's."""
    from click.testing import CliRunner

    from glorfindel import cli
    seen: list[bool] = []

    class _Agent:
        def __init__(self, **kw):
            pass

        def respond(self, data):
            seen.append(signal_origin.vouched(data))
            return {"action": "none", "escalate": False, "confidence": 0.0, "outcome": {}}

    monkeypatch.setattr("glorfindel.agent.GlorfindelAgent", _Agent)
    monkeypatch.setattr(cli, "_render_decision", lambda *a, **k: None)
    forged = tmp_path / "runs" / "recovery" / "x_signals.jsonl"
    forged.parent.mkdir(parents=True)
    forged.write_text(json.dumps(_line("recovery_complete", signal_id="a_recovery_complete")) + "\n")
    ours = signal_origin.write_recovery_signal(_line("recovery_complete", signal_id="b_recovery_complete",
                                                     context={"run_id": "b"}))
    for f in (forged, ours):
        assert CliRunner().invoke(cli.cli, ["respond", str(f), "--dry-run"]).exit_code == 0
    assert seen == [False, True]
    assert stat.S_IMODE(ours.stat().st_mode) == 0o600
    assert stat.S_IMODE(ours.parent.stat().st_mode) == 0o700


def test_the_restore_signal_is_vouched_for_in_its_own_process_only(tmp_path):
    """Built by `glorfindel restore`: vouched here. The same line in another process — the
    watch — is not."""
    from glorfindel.cli import _build_recovery_signal
    sig = _build_recovery_signal(VM, {"run_command_neutralized": True}, 60)
    assert signal_origin.vouched(sig)
    code = ("import json, sys; from glorfindel import signal_origin; "
            "print(signal_origin.vouched(json.loads(sys.argv[1])))")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    out = subprocess.run([sys.executable, "-c", code, json.dumps(sig)], capture_output=True, text=True,
                         env=env, timeout=60)
    assert out.stdout.strip() == "False", out.stderr


# ── V-27: owner-only state, written whole ─────────────────────────────────────────────

def test_state_files_are_owner_only(tmp_path):
    from glorfindel import actions, escalations
    actions._save_isolation_state(VM, {"resource_id": VM, "placements": []})
    actions._save_block_state("web", "203.0.113.9", VM)
    escalations.record(signal_id="s", resource_id=VM, action="isolate_vm", escalation_type="mode_hold",
                       reason="r")
    for d in (actions._ISOLATION_STATE_DIR, actions._BLOCK_STATE_DIR):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700, d
        for f in d.glob("*.json"):
            assert stat.S_IMODE(f.stat().st_mode) == 0o600, f
    assert stat.S_IMODE(escalations._STORE.stat().st_mode) == 0o600


def test_the_watch_start_makes_an_earlier_versions_state_owner_only():
    from glorfindel import actions
    d = actions._ISOLATION_STATE_DIR
    d.mkdir(parents=True)
    f = d / f"web--{actions._rid_hash(VM)}.json"
    f.write_text(json.dumps({"resource_id": VM, "placements": []}))
    os.chmod(d, 0o755)
    os.chmod(f, 0o644)
    actions.migrate_state_files()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700 and stat.S_IMODE(f.stat().st_mode) == 0o600


def test_unreadable_states_names_what_cannot_be_read():
    from glorfindel import actions
    actions._save_isolation_state(VM, {"resource_id": VM, "placements": []})
    actions._save_block_state("web", "203.0.113.9", VM)
    assert actions.unreadable_states() == []
    (actions._ISOLATION_STATE_DIR / "x--00000000.json").write_text("{")
    (actions._BLOCK_STATE_DIR / "y--00000000.json").write_text('[1]')
    assert actions.unreadable_states() == ["blocks/y--00000000.json", "isolation/x--00000000.json"]
