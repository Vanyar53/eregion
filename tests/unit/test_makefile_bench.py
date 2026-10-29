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


# ── celebrimbor-up: the plan shown and confirmed, unless YES=1 (SEC6, P-10) ─────────────

@pytest.mark.parametrize("args", [(), ("TOPO=multinic",)])
@pytest.mark.parametrize("yes", [False, True])
def test_up_applies_without_confirmation_only_with_yes(yes, args):
    """Like the other Terraform targets: `make celebrimbor-up` shows the plan and asks; only
    YES=1 passes -auto-approve. Read with `make -n`: nothing runs, no Terraform called."""
    env = {k: v for k, v in os.environ.items() if k not in ("YES", "TOPO", "INSTANCE")}
    res = subprocess.run(["make", "-n", "-s", "--no-print-directory", "-C", str(ROOT), "celebrimbor-up",
                          *args, *(["YES=1"] if yes else [])], env=env, capture_output=True, text=True,
                         timeout=60)
    assert res.returncode == 0, res.stderr
    applies = [line for line in res.stdout.splitlines() if " apply" in line]
    assert len(applies) == 2                       # the TOPO branch and the other
    assert all(("auto-approve" in line) is yes for line in applies)


# ── SEC7 : Orodruin planifié sans l'état de glorfindel-host ───────────────────────────────
# Its precondition (`watch_principal_id == "" || watch_subnet_id != ""`) passes with both empty:
# on a machine where infra/glorfindel-host's state does not read, the plan would take the hosted
# watch's read of the channel and its subnet away. The Makefile refuses then, unless NO_WATCH=1.
# A fake `terraform` answers the outputs; ORO_TF echoes: nothing is planned.

def _oro(tmp_path, target, *args, principal="", subnet=""):
    fake = tmp_path / "tf"
    fake.write_text("#!/bin/sh\n"
                    'case "$*" in *principal_id*) [ -n "$FAKE_PRINCIPAL" ] && echo "$FAKE_PRINCIPAL" && exit 0;;\n'
                    '  *subnet_id*) [ -n "$FAKE_SUBNET" ] && echo "$FAKE_SUBNET" && exit 0;; esac\n'
                    'echo "No state" >&2; exit 1\n')
    fake.chmod(0o755)
    env = {**os.environ, "FAKE_PRINCIPAL": principal, "FAKE_SUBNET": subnet}
    env.pop("NO_WATCH", None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target,
                          f"HOST_TF={fake}", "ORO_TF=echo terraform", "OPERATOR_CIDR=198.51.100.1/32", *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res.returncode, res.stdout, res.stderr


PRINCIPAL = "00000000-0000-0000-0000-00000000abcd"
SUBNET = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/x/subnets/s"


@pytest.mark.parametrize("target", ["orodruin-plan", "orodruin-up", "orodruin-lock"])
def test_orodruin_is_not_planned_without_the_hosted_watch_state(tmp_path, target):
    code, out, err = _oro(tmp_path, target)
    assert code != 0 and "terraform plan" not in out and "terraform apply" not in out
    assert "glorfindel-host ne se lit pas" in err and "NO_WATCH=1" in err
    code, out, err = _oro(tmp_path, target, principal=PRINCIPAL)          # the subnet missing
    assert code != 0 and "terraform" not in out.replace("terraform init", "")


def test_orodruin_plans_with_the_hosted_watch_state_or_no_watch_said(tmp_path):
    code, out, err = _oro(tmp_path, "orodruin-plan", principal=PRINCIPAL, subnet=SUBNET)
    assert code == 0, err
    assert f"watch_principal_id={PRINCIPAL}" in out and "terraform plan" in out
    assert SUBNET not in out                       # the subnet stays in terraform's environment (M124)
    code, out, err = _oro(tmp_path, "orodruin-plan", "NO_WATCH=1")
    assert code == 0, err
    assert "terraform plan" in out
