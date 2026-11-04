"""V-32 (SEC7): the host key of the hosted Glorfindel (H0), pinned by its fingerprint.

Before, every command toward H0 ran `ssh -o StrictHostKeyChecking=accept-new`: the host key
accepted at first contact, whoever answered at that address. Now the fingerprint the operator
read on the VM (HOST_SSH_FINGERPRINT, in his environment, never in the repository) decides:
a dedicated known_hosts is written from the key the host presents only when it has that
fingerprint, ssh then trusts that file alone, and a key of another fingerprint — presented or
recorded — refuses before anything runs. Without it, accept-new stays, and the command says so.

The recipes really run (`make glorfindel-host-ssh`), against a fake `ssh-keyscan` (it answers
with a key the test generated) and a fake `ssh` that records its arguments; the real
`ssh-keygen` computes the fingerprints. No VM, no network. The keys are throwaway, made here.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IP = "192.0.2.10"   # TEST-NET-1: no machine answers there
pytestmark = pytest.mark.skipif(not (shutil.which("make") and shutil.which("ssh-keygen")),
                                reason="make or ssh-keygen not installed")


def _key(tmp_path, name):
    """A throwaway ed25519 host key: (its known_hosts line for IP, its fingerprint)."""
    path = tmp_path / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)
    pub = path.with_suffix(".pub").read_text().split()
    fp = subprocess.run(["ssh-keygen", "-lf", str(path.with_suffix(".pub"))], capture_output=True,
                        text=True, check=True).stdout.split()[1]
    return f"{IP} {pub[0]} {pub[1]}", fp


def _make(tmp_path, *args, presented=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "ssh.log"
    log.write_text("")
    (bin_dir / "ssh").write_text('#!/bin/sh\necho "$*" >> "$FAKE_SSH_LOG"\n')
    (bin_dir / "ssh-keyscan").write_text('#!/bin/sh\nprintf "%s\\n" "$FAKE_PRESENTED"\n')
    for f in ("ssh", "ssh-keyscan"):
        (bin_dir / f).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_SSH_LOG": str(log), "FAKE_PRESENTED": presented}
    for k in ("HOST_SSH_FINGERPRINT", "HOST_KNOWN_HOSTS", "HOST_IP", "HOST_SSH_KEY"):
        env.pop(k, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "glorfindel-host-ssh",
                          f"HOST_IP={IP}", *args], env=env, capture_output=True, text=True, timeout=60)
    return res, log.read_text().splitlines()


def test_a_host_presenting_the_expected_key_is_written_then_trusted_alone(tmp_path):
    line, fp = _key(tmp_path, "h0")
    known = tmp_path / "kh"
    res, calls = _make(tmp_path, f"HOST_SSH_FINGERPRINT={fp}", f"HOST_KNOWN_HOSTS={known}", presented=line)
    assert res.returncode == 0, res.stderr
    assert known.read_text().strip() == line and oct(known.stat().st_mode & 0o777) == "0o600"
    assert len(calls) == 1
    assert f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known}" in calls[0]
    assert "accept-new" not in calls[0]
    # Next time, the file is read, the host not asked: the same key goes on.
    res, calls = _make(tmp_path, f"HOST_SSH_FINGERPRINT={fp}", f"HOST_KNOWN_HOSTS={known}", presented="")
    assert res.returncode == 0 and len(calls) == 1


def test_a_host_presenting_another_key_is_refused_before_anything_runs(tmp_path):
    _, fp = _key(tmp_path, "h0")
    other, _ = _key(tmp_path, "intruder")
    known = tmp_path / "kh"
    res, calls = _make(tmp_path, f"HOST_SSH_FINGERPRINT={fp}", f"HOST_KNOWN_HOSTS={known}", presented=other)
    assert res.returncode != 0 and calls == []
    assert "n'a pas l'empreinte HOST_SSH_FINGERPRINT" in res.stderr and not known.exists()


def test_a_recorded_key_that_no_longer_has_the_fingerprint_refuses(tmp_path):
    """The VM rebuilt (a new key, a new fingerprint posed): the old file refuses, and says how out."""
    old, _ = _key(tmp_path, "h0-old")
    new, fp_new = _key(tmp_path, "h0-new")
    known = tmp_path / "kh"
    known.write_text(old + "\n")
    res, calls = _make(tmp_path, f"HOST_SSH_FINGERPRINT={fp_new}", f"HOST_KNOWN_HOSTS={known}", presented=new)
    assert res.returncode != 0 and calls == []
    assert "VM reconstruite" in res.stderr and str(known) in res.stderr
    assert known.read_text() == old + "\n"            # never rewritten in silence


def test_without_a_fingerprint_accept_new_stays_and_says_so(tmp_path):
    res, calls = _make(tmp_path, presented="")
    assert res.returncode == 0, res.stderr
    assert "HOST_SSH_FINGERPRINT absent" in res.stderr
    assert len(calls) == 1 and "-o StrictHostKeyChecking=accept-new" in calls[0]


def test_a_fingerprint_that_is_not_one_refuses(tmp_path):
    res, calls = _make(tmp_path, "HOST_SSH_FINGERPRINT=xyz", presented="")
    assert res.returncode != 0 and calls == [] and "SHA256:" in res.stderr


def test_every_command_toward_h0_checks_the_key_first_and_orodruin_keeps_its_own():
    """Each target whose recipe reaches H0 (HOST_SSH, HOST_SSH_TTY, its scp, its tunnel) waits
    on glorfindel-host-known; Orodruin's ssh never takes H0's known_hosts."""
    import re
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    rules = re.findall(r"(?m)^(glorfindel-host-[\w-]+):([^\n=]*)\n((?:\t.*\n)*)", text)
    reaching = {name: deps for name, deps, recipe in rules
                if re.search(r"\$\(HOST_SSH(_TTY|_OPTS)?\)|status\.sh", recipe)}
    assert {"glorfindel-host-push", "glorfindel-host-start", "glorfindel-host-tunnel",
            "glorfindel-host-status", "glorfindel-host-cd-install"} <= set(reaching)
    assert {n for n, deps in reaching.items() if "glorfindel-host-known" not in deps} == set()
    assert "$(SSH_OPTS)" not in "".join(r for n, _, r in rules if n != "glorfindel-host-known")
    assert re.search(r"(?m)^ORO_SSH\s*=\s*ssh \$\(SSH_OPTS\)", text)


# ── SEC14 (V-32, V-34): Orodruin's host key pinned too, never accept-new; its containers hardened ──

def _make_oro(tmp_path, target, *args, presented="", az_out=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "ssh.log"
    log.write_text("")
    # printf, not echo: dash's echo would turn a remote command's « \n » into a line of its own (OI3).
    (bin_dir / "ssh").write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FAKE_SSH_LOG"\n')
    (bin_dir / "ssh-keyscan").write_text('#!/bin/sh\nprintf "%s\\n" "$FAKE_PRESENTED"\n')
    (bin_dir / "az").write_text('#!/bin/sh\necho "az $*" >> "$FAKE_SSH_LOG"\nprintf "%s\\n" "$FAKE_AZ"\n')
    (bin_dir / "git").write_text("#!/bin/sh\nexit 0\n")      # orodruin-check's git fetch: no network (OI3)
    for f in ("ssh", "ssh-keyscan", "az", "git"):
        (bin_dir / f).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_SSH_LOG": str(log), "FAKE_PRESENTED": presented, "FAKE_AZ": az_out}
    for k in ("ORO_SSH_FINGERPRINT", "ORO_KNOWN_HOSTS", "ORO_IP", "HOST_SSH_KEY", "VM_ID"):
        env.pop(k, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), target, f"ORO_IP={IP}", *args],
                         env=env, capture_output=True, text=True, timeout=60)
    return res, log.read_text().splitlines()


def test_orodruin_presenting_its_pinned_key_is_written_then_trusted_alone(tmp_path):
    line, fp = _key(tmp_path, "oro")
    known = tmp_path / "okh"
    res, calls = _make_oro(tmp_path, "orodruin-check", f"ORO_SSH_FINGERPRINT={fp}",
                           f"ORO_KNOWN_HOSTS={known}", presented=line)
    assert res.returncode == 0, res.stderr
    assert known.read_text().strip() == line
    # OI3: the image in service read first (~/.eregion-image), then the contract — each strict.
    assert len(calls) == 2 and ".eregion-image" in calls[0] and "python -m eregion_core.orodruin" in calls[1]
    assert all(f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known}" in c for c in calls)
    assert not any("accept-new" in c for c in calls)


STRICT_ORO = ("-o StrictHostKeyChecking=yes", "-o HostKeyAlgorithms=ssh-ed25519")


def test_the_update_s_ssh_takes_the_pinned_key_alone(tmp_path):
    """OI3: orodruin-update (run by orodruin-start) checks the host key first (orodruin-known), then
    reads the image in service through SSH_OPTS — the known_hosts written from the pinned key, ed25519
    only, never accept-new. The git here answers nothing: the comparison stops there, said."""
    line, fp = _key(tmp_path, "oro")
    known = tmp_path / "okh"
    res, calls = _make_oro(tmp_path, "orodruin-update", f"ORO_SSH_FINGERPRINT={fp}",
                           f"ORO_KNOWN_HOSTS={known}", presented=line)
    assert known.read_text().strip() == line, res.stderr        # orodruin-known ran, before
    assert calls and ".eregion-image" in calls[0], (calls, res.stderr)
    for c in calls:
        assert all(o in c for o in STRICT_ORO) and f"-o UserKnownHostsFile={known}" in c, c
        assert "accept-new" not in c
    assert res.returncode != 0 and "rien n'est mis à jour" in res.stderr


def test_the_update_without_its_fingerprint_sends_nothing(tmp_path):
    res, calls = _make_oro(tmp_path, "orodruin-update", presented="")
    assert res.returncode != 0 and calls == [] and "ORO_SSH_FINGERPRINT requis" in res.stderr


def test_orodruin_without_its_fingerprint_is_refused_never_accept_new(tmp_path):
    res, calls = _make_oro(tmp_path, "orodruin-check", presented="")
    assert res.returncode != 0 and calls == []
    assert "ORO_SSH_FINGERPRINT requis" in res.stderr and "jamais accept-new" in res.stderr


def test_orodruin_presenting_another_key_is_refused_before_anything_runs(tmp_path):
    _, fp = _key(tmp_path, "oro")
    other, _ = _key(tmp_path, "intruder")
    res, calls = _make_oro(tmp_path, "gothmog-run", f"ORO_SSH_FINGERPRINT={fp}",
                           f"ORO_KNOWN_HOSTS={tmp_path / 'okh'}", presented=other)
    assert res.returncode != 0 and calls == []
    assert "n'a pas l'empreinte ORO_SSH_FINGERPRINT" in res.stderr


def test_every_command_toward_orodruin_checks_its_key_first():
    """Each target whose recipe reaches Orodruin (ORO_SSH, SSH_OPTS: ssh, scp, an archive | ssh docker load)
    waits on orodruin-known — orodruin-exercise too, unless DRY_RUN, which sends nothing; and
    Orodruin's ssh options never accept a key on first contact."""
    import re
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    rules = re.findall(r"(?m)^([\w-]+):(?!=)([^\n]*)\n((?:\t.*\n)*)", text)
    reaching = {name: deps for name, deps, recipe in rules
                if re.search(r"\$\((ORO_SSH|SSH_OPTS)\)", recipe) and name != "orodruin-known"}
    assert {"orodruin-push", "orodruin-push-dev", "orodruin-check", "orodruin-ssh", "orodruin-exercise",
            "gothmog-preflight", "gothmog-run", "orodruin-campaign-plan", "orodruin-campaign-run"} <= set(reaching)
    assert {n for n, deps in reaching.items() if "orodruin-known" not in deps} == set()
    assert "$(if $(DRY_RUN),,orodruin-known)" in reaching["orodruin-exercise"]
    ssh_opts = re.search(r"(?m)^SSH_OPTS\s*=(.*)$", text).group(1)
    assert "StrictHostKeyChecking=yes" in ssh_opts and "UserKnownHostsFile=$(ORO_KNOWN_HOSTS)" in ssh_opts
    assert "accept-new" not in ssh_opts


def test_the_fingerprint_is_read_on_the_vm_through_azure(tmp_path):
    _, fp = _key(tmp_path, "oro")
    vm = ("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-x/providers"
          "/Microsoft.Compute/virtualMachines/vm-x")
    answer = f"Enable succeeded:\n[stdout]\n256 {fp} root@vm-x (ED25519)\n\n[stderr]\n"
    res, calls = _make_oro(tmp_path, "orodruin-fingerprint", f"VM_ID={vm}", az_out=answer)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == f"export ORO_SSH_FINGERPRINT={fp}"
    assert calls[0].startswith(f"az vm run-command invoke --ids {vm} --command-id RunShellScript")
    res, _ = _make_oro(tmp_path, "orodruin-fingerprint", f"VM_ID={vm}", az_out="Enable succeeded: nothing")
    assert res.returncode != 0 and "pas d'empreinte" in res.stderr and "export" not in res.stdout


def test_every_injector_container_on_orodruin_runs_hardened_as_compose_does():
    """V-34: read-only root, /tmp in tmpfs, no capability, no privilege gained — every `docker run`
    of Orodruin's section goes through ORO_HARDEN."""
    import re
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    harden = re.search(r"(?m)^ORO_HARDEN\s*=(.*)$", text).group(1).split()
    assert harden == ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt",
                      "no-new-privileges:true"]
    section = text.split("# ── Orodruin (O1)", 1)[1].split("# ── Profils d'usage", 1)[0]
    runs = [ln for ln in section.splitlines() if "docker run" in ln and not ln.startswith("#")]
    assert len(runs) >= 2 and all("docker run --rm $(ORO_HARDEN) " in ln for ln in runs), runs
