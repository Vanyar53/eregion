"""UI-1c (#205): the hosted console's token under its two names, from the operator's machine.

H0's host.env carries the token under its former name, GLORFINDEL_WARROOM_TOKEN; a new host's
under EREGION_CONSOLE_TOKEN. `make glorfindel-host-url` / `-tunnel` and
`make glorfindel-host-status` (infra/glorfindel-host/status.sh) find it under either, with the
console's rule — the new name when it is not empty, else the former (eregion_console/api.py) —
and status.sh never prints it nor puts it on a command line. The recipes really run, against
fake `ssh`, `az`, `docker` and `curl` first on the PATH: no Azure, no VM. Every token here is a
fake, and an assertion looks for it, never prints it.
"""
import importlib.util
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from eregion_core.models import DEFAULT_LLM_MODEL

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "infra" / "glorfindel-host"
NEW, OLD = "EREGION_CONSOLE_TOKEN", "GLORFINDEL_WARROOM_TOKEN"
TOK_NEW, TOK_OLD = "fake-new-tok-7Qe2", "fake-old-tok-9Zr4"

_spec = importlib.util.spec_from_file_location("host_env_ui1c", HOST / "host_env.py")
host_env = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(host_env)

needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")

# host.env content → the token the console takes (None: no token at all).
CASES = {
    "new": (f"{NEW}={TOK_NEW}\n", TOK_NEW),
    "old (H0)": (f"AZURE_SUBSCRIPTION_ID=sub\n{OLD}={TOK_OLD}\n", TOK_OLD),
    "new empty, old set": (f"{NEW}=\n{OLD}={TOK_OLD}\n", TOK_OLD),
    "old first, new empty after": (f"{OLD}={TOK_OLD}\n{NEW}=\n", TOK_OLD),
    "both, they differ": (f"{OLD}={TOK_OLD}\n{NEW}={TOK_NEW}\n", TOK_NEW),
    "new with a trailing comment": (f"{NEW}={TOK_NEW}   # [console]\n", TOK_NEW),
    # docker compose takes « # [console] » as the value (measured with `docker compose config`,
    # 27/10): so does every reader here — and `host_env.py --check` refuses it before a push.
    "new only a comment, old set": (f"{NEW}=        # [console]\n{OLD}={TOK_OLD}\n", "# [console]"),
    "the last line wins": (f"{NEW}=fake-stale\n{NEW}={TOK_NEW}\n", TOK_NEW),
    "neither": ("AZURE_SUBSCRIPTION_ID=sub\n# EREGION_CONSOLE_TOKEN=commented-out\n", None),
}


def _make(tmp_path, *args, environ=None):
    env = {**os.environ, "HOME": str(tmp_path), **(environ or {})}
    for k in (NEW, OLD, "HOST_ENV", "HOST_IP"):
        env.pop(k, None)
    return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), *args],
                          env=env, capture_output=True, text=True, timeout=60)


def _host_env(tmp_path, content) -> Path:
    path = tmp_path / "host.env"
    path.write_text(content, encoding="utf-8")
    return path


# ── make glorfindel-host-url / -tunnel ────────────────────────────────────────────────────

@needs_make
@pytest.mark.parametrize("case", list(CASES))
def test_host_url_takes_the_token_under_either_name(tmp_path, case):
    content, token = CASES[case]
    res = _make(tmp_path, "glorfindel-host-url", f"HOST_ENV={_host_env(tmp_path, content)}")
    if token is None:
        assert res.returncode != 0
        assert "aucun jeton de la console" in res.stderr and "?token=" not in res.stdout
        return
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == f"http://localhost:7007/?token={token}"


def _fake_ssh(tmp_path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "ssh.log"
    log.write_text("")
    ssh = bin_dir / "ssh"
    ssh.write_text('#!/bin/sh\necho "$*" >> "$FAKE_SSH_LOG"\n')
    ssh.chmod(0o755)
    return bin_dir, log


@needs_make
@pytest.mark.parametrize("case", ["new", "old (H0)", "new empty, old set", "neither"])
def test_host_tunnel_shows_the_console_url_under_either_name(tmp_path, case):
    content, token = CASES[case]
    bin_dir, log = _fake_ssh(tmp_path)
    res = _make(tmp_path, "glorfindel-host-tunnel", "HOST_IP=203.0.113.9",
                f"HOST_ENV={_host_env(tmp_path, content)}",
                environ={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "FAKE_SSH_LOG": str(log)})
    assert res.returncode == 0, res.stderr
    assert "War Room" not in res.stdout
    if token is None:
        assert "aucun jeton de la console" in res.stdout and "?token=" not in res.stdout
    else:
        assert f"Console → http://localhost:7007/?token={token}\n" in res.stdout
    # The tunnel opens either way: the console may run without a token, on the VM's loopback.
    assert "-N -L 7007:127.0.0.1:7007 glorfindel@203.0.113.9" in log.read_text()


@needs_make
def test_the_displayed_lines_name_the_console():
    """The lines « War Room → … » the Makefile printed became « Console → … » (UI-1c)."""
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    shown = [line for line in text.splitlines() if line.lstrip().startswith("@echo")]
    assert not [line for line in shown if "War Room" in line]
    # SEC1: the start targets print the URL with its token through `make console-url`.
    assert sum("console-url" in line and "$(MAKE)" in line for line in text.splitlines()) >= 4
    assert any("Console   →  http://localhost:" in line and "?token=" in line for line in text.splitlines())


# ── make glorfindel-host-status (status.sh) ───────────────────────────────────────────────

_FAKE_CURL = r'''#!/bin/bash
# Records its arguments; reads its headers from argv and from stdin (-H @-); answers as the
# console does: 401 JSON unless the bearer is FAKE_CONSOLE_TOKEN (empty: no token, open).
printf '%s\n' "$*" >> "$FAKE_CURL_ARGV"
auth=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-H" ]; then
    if [ "$a" = "@-" ]; then
      while IFS= read -r line; do case "$line" in Authorization:*) auth="$line";; esac; done
    else
      case "$a" in Authorization:*) auth="$a";; esac
    fi
  fi
  prev="$a"
done
url="${@: -1}"
if [ -n "$FAKE_CONSOLE_TOKEN" ] && [ "$auth" != "Authorization: Bearer $FAKE_CONSOLE_TOKEN" ]; then
  echo "refused ${auth:+with-a-header}" >> "$FAKE_CURL_SEEN"
  echo '{"error": "Eregion console: open /?token=<EREGION_CONSOLE_TOKEN> once"}'
  exit 0
fi
echo "accepted ${auth:+with-a-header}" >> "$FAKE_CURL_SEEN"
case "$url" in
  */api/to-judge*) echo '{"cards": [{"action": "isolate_vm", "rule_name": "ssh-brute-force", "occurrences": 2, "first_seen": "2026-10-27T08:00:00"}]}';;
  */api/report*) echo '{"cards": 3, "judged": 1, "exercises": 0, "disruptive": {"false_rate": null}}';;
esac
'''

_FAKE_DOCKER = '''#!/bin/sh
case "$1" in
  inspect) echo "running depuis 2026-10-27T08:00:00Z";;
  exec) echo 0;;
esac
exit 0
'''

# The two ssh of status.sh: deploy.sh --show (answered here), then the remote script, run in
# the fake VM's home with its stdin.
_FAKE_SSH = '''#!/bin/bash
case "${@: -1}" in *--show*) cat > /dev/null; echo "  ✓ référence déployée : fake"; exit 0;; esac
cd "$FAKE_VM_HOME" && exec bash -c "${@: -1}"
'''


def _status(tmp_path, dotenv, console_token):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, text in (("curl", _FAKE_CURL), ("docker", _FAKE_DOCKER), ("ssh", _FAKE_SSH),
                       ("az", "#!/bin/sh\nexit 0\n")):
        (bin_dir / name).write_text(text)
        (bin_dir / name).chmod(0o755)
    vm_home = tmp_path / "vmhome"
    (vm_home / "eregion").mkdir(parents=True, exist_ok=True)
    (vm_home / "eregion" / ".env").write_text(dotenv, encoding="utf-8")
    argv, seen = tmp_path / "curl.argv", tmp_path / "curl.seen"
    argv.write_text("")
    seen.write_text("")
    res = _make(tmp_path, "glorfindel-host-status", "HOST_IP=203.0.113.9",
                f"HOST_BACKUPS={tmp_path / 'backups'}",
                environ={"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
                         "FAKE_VM_HOME": str(vm_home), "FAKE_CURL_ARGV": str(argv),
                         "FAKE_CURL_SEEN": str(seen), "FAKE_CONSOLE_TOKEN": console_token})
    return res, argv.read_text(), seen.read_text().split("\n")[:-1]


@needs_make
@pytest.mark.parametrize("case", ["new", "old (H0)", "new empty, old set", "both, they differ",
                                  "new with a trailing comment"])
def test_status_reads_the_console_under_either_name_and_never_shows_the_token(tmp_path, case):
    content, token = CASES[case]
    res, argv, seen = _status(tmp_path, content, console_token=token)
    out = res.stdout + res.stderr
    assert res.returncode == 0, out
    assert seen == ["accepted with-a-header", "accepted with-a-header"]
    assert "⚠ à juger : 1" in out and "isolate_vm · ssh-brute-force · 2x" in out
    assert "7 jours : 3 carte(s), 1 jugée(s)" in out
    # Never printed, never on a command line (ps shows those): only through curl's stdin.
    for t in (TOK_NEW, TOK_OLD):
        assert t not in out and t not in argv
    assert "War Room" not in out
    assert "console  eregion-war-room" in out and "erreurs 24 h console" in out


@needs_make
def test_status_says_a_refused_token_and_a_missing_one(tmp_path):
    # The VM's .env holds a token the console does not take: said, not « pas de réponse ».
    res, argv, seen = _status(tmp_path, CASES["old (H0)"][0], console_token="fake-other")
    out = res.stdout + res.stderr
    assert "✗ console : jeton refusé" in out and seen[0] == "refused with-a-header"
    assert TOK_OLD not in out and TOK_OLD not in argv
    # Neither name: said; the console is asked without a header (open on the VM's loopback).
    res, argv, seen = _status(tmp_path, CASES["neither"][0], console_token="")
    out = res.stdout + res.stderr
    assert "⚠ console : aucun jeton dans .env" in out
    assert seen == ["accepted ", "accepted "] and "⚠ à juger : 1" in out
    assert "commented-out" not in argv


# ── the rule, the same everywhere ─────────────────────────────────────────────────────────

@needs_make
@pytest.mark.parametrize("case", list(CASES))
def test_make_host_env_and_the_console_agree_on_the_token(tmp_path, case, monkeypatch):
    """The Makefile, host_env.py and the console itself take the same token from one host.env
    (status.sh is held by the tests above, with the same cases)."""
    from eregion_console import api

    content, token = CASES[case]
    path = _host_env(tmp_path, content)
    res = _make(tmp_path, "glorfindel-host-url", f"HOST_ENV={path}")
    by_make = res.stdout.strip().removeprefix("http://localhost:7007/?token=") if res.returncode == 0 else None
    parsed = host_env.read_env(path)
    name = host_env.token_name(parsed)
    by_host_env = parsed[name] if name else None
    # docker compose passes both, `${VAR:-}`: empty when host.env lacks them.
    monkeypatch.setenv(NEW, parsed.get(NEW, ""))
    monkeypatch.setenv(OLD, parsed.get(OLD, ""))
    by_console = api.console_token() or None
    assert by_make == by_host_env == by_console == token


# ── host_env.py: a new host gets the new name, an old host.env stays valid ───────────────

def test_a_new_host_gets_the_new_name_only(tmp_path, monkeypatch, capsys):
    for k in list(host_env.COPIED) + [NEW, OLD]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    dst = tmp_path / "host.env"
    host_env.main(str(dst))
    written = host_env.read_env(dst)
    assert len(written[NEW]) >= 24 and OLD not in written
    assert written[NEW] not in capsys.readouterr().out          # the keys, never a value
    assert oct(dst.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize("case", ["new", "old (H0)", "new empty, old set", "both, they differ"])
def test_check_accepts_either_name_and_never_prints_the_token(tmp_path, case, capsys):
    content, token = CASES[case]
    assert host_env.check(str(_host_env(tmp_path, content))) == 0
    out = capsys.readouterr().out
    assert token not in out
    if token == TOK_OLD:
        assert f"former name, {OLD}" in out and "nothing to rename" in out
    else:
        assert f"under {NEW}" in out


@pytest.mark.parametrize("case, why", [("neither", "no console token"),
                                       ("new only a comment, old set", "holds a comment")])
def test_check_refuses_a_host_env_without_a_token(tmp_path, case, why):
    with pytest.raises(SystemExit) as exc:
        host_env.check(str(_host_env(tmp_path, CASES[case][0])))
    assert why in str(exc.value)


def test_an_existing_host_env_under_the_old_name_is_never_rewritten(tmp_path, monkeypatch):
    """No forced rename: host_env.py refuses to overwrite H0's host.env (its token would change)."""
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "key")
    content = CASES["old (H0)"][0]
    path = _host_env(tmp_path, content)
    with pytest.raises(SystemExit) as exc:
        host_env.main(str(path))
    assert "exists" in str(exc.value)
    assert path.read_text(encoding="utf-8") == content


def test_push_checks_the_token_before_anything_reaches_the_vm():
    text = (ROOT / "Makefile").read_text(encoding="utf-8")
    recipe = text.split("\nglorfindel-host-push: glorfindel-host-known\n", 1)[1].split("\n\n", 1)[0]
    check = recipe.index("host_env.py --check infra/glorfindel-host/host.env")
    assert check < recipe.index("scp ")


# ── host.env.example: a variable left empty stays empty ───────────────────────────────────

def test_the_example_leaves_every_empty_variable_empty():
    """`KEY=   # note` is « # note » for docker compose (measured with `docker compose config`,
    27/10): copied as is, an unfilled webhook URL or Discord id took the comment as its value.
    Read with compose's rule (host_env.read_env), only the two set values remain; the model
    is the code's default."""
    path = HOST / "host.env.example"
    values = host_env.read_env(path)
    assert {k: v for k, v in values.items() if v} == {
        "GLORFINDEL_LLM_MODEL": DEFAULT_LLM_MODEL, "GLORFINDEL_READ_ONLY": "1"}
    assert not [k for k, v in values.items() if v.startswith("#")]
    # Every comment above its line, never beside it: none beside a filled value either.
    beside = [line for line in path.read_text(encoding="utf-8").splitlines()
              if not line.lstrip().startswith("#") and "=" in line and "#" in line.split("=", 1)[1]]
    assert beside == []
    assert {"AZURE_SUBSCRIPTION_ID", "DISCORD_PING_ROLE", "DISCORD_ALLOWED_USERS", "DISCORD_ALLOWED_ROLES",
            "GLORFINDEL_WEBHOOK_URL", NEW} <= set(values)
