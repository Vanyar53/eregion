"""`make celebrimbor-start` / `celebrimbor-stop`: the bench, all or part (21/10).

The recipe really runs, against a fake `az` first on the PATH that records its calls and
answers `az vm list` with what the test gives: no Azure. Without VM= nor ALL=1, `stop`
spares the VMs tagged always-on — bree, the real load the hosted Glorfindel (H0) watches.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")

GONDOLIN = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
BREE = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"


def _make(tmp_path, target, *args, listed=""):
    """Run ``make target args`` with the fake az; return (exit code, output, az calls)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "az.log"
    log.write_text("")
    az = bin_dir / "az"
    az.write_text('#!/bin/sh\necho "$*" >> "$FAKE_AZ_LOG"\n'
                  'case "$1 $2" in "vm list") printf \'%b\' "$FAKE_AZ_LIST" ;; esac\n')
    az.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "FAKE_AZ_LOG": str(log), "FAKE_AZ_LIST": listed}
    env.pop("VM", None)
    env.pop("ALL", None)
    env.pop("INSTANCE", None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout + res.stderr, log.read_text().splitlines()


def _query(calls):
    (listing,) = [c for c in calls if c.startswith("vm list")]
    return listing


def test_stop_without_options_spares_the_always_on_vms(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-stop",
                             listed=f"{GONDOLIN}\\tvm-celebrimbor-gondolin\\tNone\\n")
    assert code == 0, out
    assert "tags.\"always-on\" != 'true'" in _query(calls)
    assert "les VM always-on sont épargnées" in out
    assert "az vm deallocate : vm-celebrimbor-gondolin" in out
    assert calls[-1] == f"vm deallocate --ids {GONDOLIN}"


def test_stop_all_takes_the_always_on_vms_too(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-stop", "ALL=1",
                             listed=f"{GONDOLIN}\\tvm-celebrimbor-gondolin\\tNone\\n"
                                    f"{BREE}\\tvm-celebrimbor-bree\\ttrue\\n")
    assert code == 0, out
    assert "always-on" not in _query(calls).split("].")[0]
    assert "vm-celebrimbor-bree  (always-on)" in out
    assert calls[-1] == f"vm deallocate --ids {GONDOLIN} {BREE}"


def test_one_vm_by_its_short_name(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-stop", "VM=gondolin",
                             listed=f"{GONDOLIN}\\tvm-celebrimbor-gondolin\\tNone\\n")
    assert code == 0, out
    q = _query(calls)
    assert "(name=='gondolin' || ends_with(name, '-gondolin'))" in q
    assert "!= 'true'" not in q  # named explicitly: stopped even if always-on
    assert "épargnées" not in out


def test_start_never_skips_a_vm_and_can_take_one(tmp_path):
    code, out, calls = _make(tmp_path, "celebrimbor-start",
                             listed=f"{BREE}\\tvm-celebrimbor-bree\\n{GONDOLIN}\\tvm-celebrimbor-gondolin\\n")
    assert code == 0, out
    assert "always-on" not in _query(calls)
    assert calls[-1] == f"vm start --ids {BREE} {GONDOLIN}"
    code, out, calls = _make(tmp_path, "celebrimbor-start", "VM=gondolin",
                             listed=f"{GONDOLIN}\\tvm-celebrimbor-gondolin\\n")
    assert code == 0, out
    assert "ends_with(name, '-gondolin')" in _query(calls)
    assert "az vm start : vm-celebrimbor-gondolin" in out


@pytest.mark.parametrize("target", ["celebrimbor-stop", "celebrimbor-start"])
def test_a_malformed_vm_name_is_refused_before_any_az_call(tmp_path, target):
    code, out, calls = _make(tmp_path, target, "VM=gondolin';x")
    assert code != 0
    assert "VM invalide" in out
    assert calls == []


@pytest.mark.parametrize("target", ["celebrimbor-stop", "celebrimbor-start"])
def test_nothing_found_is_said_and_nothing_acts(tmp_path, target):
    code, out, calls = _make(tmp_path, target, "VM=nowhere", listed="")
    assert code == 0, out
    assert "Aucune VM celebrimbor" in out and "VM 'nowhere'" in out
    assert all(c.startswith("vm list") for c in calls)
