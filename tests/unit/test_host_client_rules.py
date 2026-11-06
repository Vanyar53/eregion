"""WL1 (#595): the bench's rules reach the client's layer of the hosted Glorfindel (H0), merged.

`make glorfindel-host-client-rules` reads H0's `~/.glorfindel/client_rules.yaml` by ssh, merges each
rule of `infra/glorfindel-host/client_rules.bench.yaml` into it by name
(`infra/glorfindel-host/host_client_rules.py`), reads the result back as the watch will, and puts it
in place on H0 under the layer's lock, only if the layer did not change since it was read. Then the
watch restarts and `glorfindel rules` says what runs. A rule approved on H0 is never lost.

The recipe really runs, against a fake `ssh` that runs its command in a directory standing for H0's
home, a fake `scp` that copies there, and a fake `docker` that records its calls; the real `flock`
holds the lock. No VM, no network, no Azure, no model.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "infra" / "glorfindel-host"))
import host_client_rules  # noqa: E402

from glorfindel.detection_rules import shipped_rules_path  # noqa: E402

BENCH = ROOT / "infra" / "glorfindel-host" / "client_rules.bench.yaml"
NAME = "sudo-privilege-escalation"
IP = "192.0.2.10"   # TEST-NET-1: no machine answers there
APPROVED = {"name": "log-clearing", "ttp": "T1070.002", "assets": ["auto"], "monitoring_backends": ["law-main"],
            "query": 'Syslog\n| where SyslogMessage has "rm -f /var/log"\n'}
needs_tools = pytest.mark.skipif(not (shutil.which("make") and shutil.which("flock")),
                                 reason="make or flock not installed")


def _h0_layer(home: Path, data: dict | None, raw: str | None = None) -> Path:
    path = home / ".glorfindel" / "client_rules.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    if raw is not None:
        path.write_text(raw)
    elif data is not None:
        path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


def _make(tmp_path, *args, touch_on_push: bool = False):
    home = tmp_path / "h0"
    (home / ".glorfindel").mkdir(parents=True, exist_ok=True)
    (home / "eregion").mkdir(exist_ok=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    log.write_text("")
    (bin_dir / "ssh").write_text(
        '#!/bin/sh\necho "ssh $*" >> "$FAKE_LOG"\n'
        'while [ $# -gt 0 ]; do case "$1" in *@*) shift; break;; esac; shift; done\n'
        'cd "$FAKE_H0" && exec sh -c "$*"\n')
    # The last two arguments: the local file, then user@host:path (relative to H0's home).
    (bin_dir / "scp").write_text(
        '#!/bin/sh\necho "scp $*" >> "$FAKE_LOG"\n'
        'for a; do src=$dst; dst=$a; done\n'
        'cp "$src" "$FAKE_H0/${dst#*:}"\n'
        # An approval on H0 between the read and the write (the console, the CLI).
        'case "$dst" in *.push) [ -n "$FAKE_TOUCH" ] && echo "# approuvée entre-temps" >> "$FAKE_H0/.glorfindel/client_rules.yaml";; esac\n'
        'exit 0\n')
    (bin_dir / "docker").write_text('#!/bin/sh\necho "docker $*" >> "$FAKE_LOG"\n')
    (bin_dir / "ssh-keyscan").write_text("#!/bin/sh\n")
    for f in ("ssh", "scp", "docker", "ssh-keyscan"):
        (bin_dir / f).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "HOME": str(tmp_path),
           "FAKE_LOG": str(log), "FAKE_H0": str(home), "FAKE_TOUCH": "1" if touch_on_push else ""}
    for k in ("HOST_SSH_FINGERPRINT", "HOST_KNOWN_HOSTS", "HOST_IP", "HOST_SSH_KEY", "CLIENT_RULES"):
        env.pop(k, None)
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "glorfindel-host-client-rules",
                          f"HOST_IP={IP}", f"PYTHON={sys.executable}", *args],
                         env=env, capture_output=True, text=True, timeout=120)
    return res, log.read_text().splitlines(), home


def _rules(path: Path) -> dict:
    return {r["name"]: r for r in yaml.safe_load(path.read_text())["rules"]}


def _left_over(home: Path) -> list[str]:
    return sorted(p.name for p in (home / ".glorfindel").iterdir()
                  if p.name.startswith(".client_rules.yaml.") and not p.name.endswith(".lock"))


@needs_tools
def test_the_bench_rule_is_merged_beside_the_rules_approved_on_h0(tmp_path):
    layer = _h0_layer(tmp_path / "h0", {"rules": [APPROVED], "disable": ["data-exfiltration-blob"]})
    res, calls, home = _make(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    rules = _rules(layer)
    assert rules["log-clearing"] == APPROVED                      # the approval stays
    assert rules[NAME] == yaml.safe_load(BENCH.read_text())["rules"][0]
    assert yaml.safe_load(layer.read_text())["disable"] == ["data-exfiltration-blob"]
    assert oct(layer.stat().st_mode & 0o777) == "0o600" and _left_over(home) == []
    assert f"ajoutée : « {NAME} »" in res.stdout and "couche du client écrite" in res.stdout
    assert "remplacée par celle de la couche du client" in res.stdout   # what the watch will say
    assert "docker compose restart watch" in calls
    assert any(c == "docker exec eregion-watch glorfindel rules" for c in calls)


@needs_tools
def test_an_h0_without_a_layer_gets_one_and_a_second_push_changes_nothing(tmp_path):
    res, _, home = _make(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    layer = home / ".glorfindel" / "client_rules.yaml"
    assert list(_rules(layer)) == [NAME]
    first = layer.read_text()
    res, _, _ = _make(tmp_path)
    assert res.returncode == 0 and f"inchangée : « {NAME} »" in res.stdout
    assert layer.read_text() == first


@needs_tools
def test_a_layer_changed_during_the_push_is_never_replaced(tmp_path):
    layer = _h0_layer(tmp_path / "h0", {"rules": [APPROVED]})
    res, calls, home = _make(tmp_path, touch_on_push=True)
    assert res.returncode != 0
    assert "a changé pendant le push" in res.stdout + res.stderr
    assert list(_rules(layer)) == ["log-clearing"] and layer.read_text().endswith("# approuvée entre-temps\n")
    assert _left_over(home) == [] and not any(c.startswith("docker") for c in calls)


@needs_tools
def test_an_unreadable_layer_on_h0_is_refused_before_anything_is_sent(tmp_path):
    _h0_layer(tmp_path / "h0", None, raw="rules: [unclosed\n")
    res, calls, _ = _make(tmp_path)
    assert res.returncode != 0 and "illisible" in res.stderr
    assert not any(c.startswith(("scp", "docker")) for c in calls)


@needs_tools
def test_a_stale_copy_of_the_base_is_refused_before_anything_is_sent(tmp_path):
    data = yaml.safe_load(BENCH.read_text())
    data["rules"][0]["base_sha256"] = "0" * 64      # the fingerprint of no shipped rule
    stale = tmp_path / "stale.yaml"
    stale.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    res, calls, home = _make(tmp_path, f"CLIENT_RULES={stale}")
    assert res.returncode != 0 and "dérive" in res.stderr
    assert not any(c.startswith(("scp", "docker")) for c in calls)
    assert not (home / ".glorfindel" / "client_rules.yaml").exists()


def test_the_target_waits_on_the_host_key_check():
    text = (ROOT / "Makefile").read_text()
    assert "\nglorfindel-host-client-rules: glorfindel-host-known\n" in text


# ── The merge itself ────────────────────────────────────────────────────────────────

def _write(path: Path, data) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
    return path


def test_merge_replaces_by_name_and_keeps_every_other_entry(tmp_path):
    old = {**yaml.safe_load(BENCH.read_text())["rules"][0], "interval_s": 60}
    h0 = _write(tmp_path / "h0.yaml", {"rules": [APPROVED, old], "assets": [{"name": "a", "type": "azure_vm"}]})
    out = tmp_path / "out.yaml"
    said = host_client_rules.merge(BENCH, h0, out)
    assert f"remplacée : « {NAME} »" in said
    data = yaml.safe_load(out.read_text())
    assert [r["name"] for r in data["rules"]] == ["log-clearing", NAME]
    assert data["rules"][1]["interval_s"] == 30 and data["assets"] == [{"name": "a", "type": "azure_vm"}]
    assert not list(tmp_path.glob(".out.yaml.*"))


@pytest.mark.parametrize("content", [
    "rules: [unclosed\n", "- a list\n", "rules: {}\n", "disable: [x]\nrules: []\n", "rules: []\n",
    "rules:\n  - query: x\n",
])
def test_merge_refuses_a_rules_file_it_cannot_read_whole(tmp_path, content):
    src = tmp_path / "src.yaml"
    src.write_text(content)
    with pytest.raises(host_client_rules.rule_layers.ClientLayerError):
        host_client_rules.merge(src, _write(tmp_path / "h0.yaml", {"rules": []}), tmp_path / "out.yaml")
    assert not (tmp_path / "out.yaml").exists()


def test_merge_refuses_a_rule_the_watch_would_skip(tmp_path):
    rule = {**yaml.safe_load(BENCH.read_text())["rules"][0], "interval_s": "30s"}
    src = _write(tmp_path / "src.yaml", {"rules": [rule]})
    with pytest.raises(host_client_rules.rule_layers.ClientLayerError, match="ignorée par la watch"):
        host_client_rules.merge(src, tmp_path / "absent.yaml", tmp_path / "out.yaml")
    assert not (tmp_path / "out.yaml").exists()


def test_merge_reads_against_the_base_of_this_checkout():
    assert host_client_rules.shipped_rules_path() == shipped_rules_path()


def test_the_cli_says_its_usage_and_exits_2(capsys):
    assert host_client_rules.main([]) == 2
    assert "host_client_rules.py RULES.yaml H0_LAYER.yaml OUT.yaml" in capsys.readouterr().err
