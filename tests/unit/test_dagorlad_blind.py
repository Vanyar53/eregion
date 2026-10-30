"""Glorfindel stays blind to Dagorlad (docs/design/console.md §7, « Glorfindel reste aveugle »; DG-b
review, point 9): a cycle of `decide` replayed with a request present — in the console's directory,
its names typed beside it, its status and Orodruin's verdict pulled into runs/orodruin/, its window
naming it — sends the model the same message, to the byte.

No Azure, no model: the message is built, never sent. Crosses components on purpose (Glorfindel's
message, the shared core's request): TOGETHER. The oracle is written here: the message without any
of it.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from eregion_core import exercise_request as xr
from glorfindel.agent import _build_user_message

VM = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-celebrimbor"
      "/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin")
SIGNAL = {"signal_id": "s-1", "run_id": "watch-ransomware-1", "resource_id": VM, "event": "detection",
          "raw_signal": {"ttp": "T1486", "normalized_signal": {
              "indicator_key": "disk_write_mbps", "indicator_value": 212, "resource": "vm-celebrimbor-gondolin"}}}
PAST = [{"summary": "isolate_vm on vm-celebrimbor-gondolin, verified", "source": "exercise"}]


def test_a_request_present_changes_nothing_glorfindel_tells_the_model(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    console_dir = tmp_path / "home" / ".eregion" / "console" / "requests"
    monkeypatch.setenv(xr.REQUESTS_ENV, str(console_dir))
    (tmp_path / "runs").mkdir()
    before = _build_user_message(SIGNAL, PAST).encode()

    # The red side's plan, everywhere it may lie on a host where the watch runs.
    req = xr.new([("T1486", VM), ("vm-shutdown", VM)], now=datetime(2026, 10, 30, 8, tzinfo=timezone.utc))
    xr.write(req, console_dir)
    (console_dir / f"{req.id}.typed.json").write_text(json.dumps({"request": req.id, "typed": {"1": "vm-celebrimbor-gondolin"}}))
    pulled = tmp_path / "runs" / "orodruin"
    (pulled / "requests").mkdir(parents=True)
    (pulled / "contract.json").write_text(json.dumps({"verdict": "armed", "codes": [], "at": "2026-10-30T08:00:00+00:00"}))
    (pulled / "requests" / f"{req.id}.json").write_text(json.dumps({
        "request": req.id, "state": "running", "at": "2026-10-30T08:01:00+00:00", "codes": [],
        "wires": [{"rank": 1, "state": "running", "code": "", "runs": ["20261030T080100Z-ab12"], "result": ""},
                  {"rank": 2, "state": "queued", "code": "", "runs": [], "result": ""}]}))

    after = _build_user_message(SIGNAL, PAST).encode()
    assert after == before
    assert req.id.encode() not in after
