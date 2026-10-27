"""L23 (#228): no Makefile target puts a secret's value on a command line.

`docker run -e AZURE_CLIENT_SECRET=$(…)` showed the value in `ps`, in the shell's history and
in `make -n`. Each secret now goes to the container by its NAME (`-e AZURE_CLIENT_SECRET`); the
value is chosen by the recipe's shell (ANNATAR_/GLORFINDEL_AZURE_CLIENT_* first, then
AZURE_CLIENT_*) and set in the environment of `docker run` only.

The canary renders every target with `make -n`, with a fake value for every secret the
Makefile names, and looks for those values in what would run. Then the recipes that start a
container really run, against a fake `docker` first on the PATH: its arguments never carry a
secret, and its environment carries the right one. No docker, no Azure, no network: every
tool a recipe or a `$(shell …)` would reach out with is a stub.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"

pytestmark = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")

# What the Makefile could carry as a secret: every name it mentions that looks like one, and
# those it must at least cover (a new one matching the pattern is covered without editing here).
SECRET_NAME = re.compile(r"\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|API_KEY|PASSWORD|WEBHOOK_URL)[A-Z0-9_]*\b")
KNOWN = {"AZURE_CLIENT_SECRET", "ANNATAR_AZURE_CLIENT_SECRET", "GLORFINDEL_AZURE_CLIENT_SECRET",
         "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "MISTRAL_API_KEY", "AZURE_API_KEY",
         "DISCORD_BOT_TOKEN", "GLORFINDEL_WEBHOOK_URL", "EREGION_CONSOLE_TOKEN",
         "GLORFINDEL_WARROOM_TOKEN"}
# The tools a recipe or a $(shell …) reaches out with: stubs that do nothing.
STUBS = ("docker", "terraform", "az", "curl", "ssh", "scp", "uv", "gh")


def _secrets() -> dict[str, str]:
    names = set(SECRET_NAME.findall(MAKEFILE.read_text(encoding="utf-8"))) | KNOWN
    return {name: f"hy1-canary-{name.lower().replace('_', '-')}" for name in sorted(names)}


def _targets() -> list[str]:
    out = []
    for line in MAKEFILE.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)", line)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def _env(tmp_path: Path, secrets: dict[str, str]) -> dict[str, str]:
    """From scratch: none of the developer's own variables (a real key, MAKEFLAGS) leaks in."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    for tool in STUBS:
        stub = bin_dir / tool
        if tool == "docker":   # records its arguments, then the secret its environment carries
            stub.write_text('#!/bin/sh\nprintf "ARGV %s\\n" "$*" >> "$FAKE_DOCKER_LOG"\n'
                            'printf "ENV %s %s\\n" "${AZURE_CLIENT_ID-unset}" '
                            '"${AZURE_CLIENT_SECRET-unset}" >> "$FAKE_DOCKER_LOG"\n')
        else:
            stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {"PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(home), "TMPDIR": str(tmp_path), "PWD": str(ROOT), "LC_ALL": "C",
            "FAKE_DOCKER_LOG": str(log), **secrets}


def _leaks(text: str, secrets: dict[str, str]) -> dict[str, list[str]]:
    return {name: [line.strip()[:160] for line in text.splitlines() if value in line]
            for name, value in secrets.items() if value in text}


def test_no_target_puts_a_secret_s_value_on_a_command_line(tmp_path):
    """The canary: every target as `make -n` renders it, every secret set to a fake value."""
    secrets, targets = _secrets(), _targets()
    assert len(targets) > 50 and {"annatar-run", "glorfindel-watch", "annatar-shell"} <= set(targets)
    proc = subprocess.run(["make", "-n", "-k", "--no-print-directory", *targets], cwd=ROOT,
                          env=_env(tmp_path, secrets), capture_output=True, text=True, timeout=120)
    rendered = proc.stdout + proc.stderr
    # What it rendered is the recipes, the containers' ones included: the check sees them.
    assert "docker run" in rendered and "-e AZURE_CLIENT_SECRET " in rendered, rendered[-2000:]
    assert _leaks(rendered, secrets) == {}


def _docker_calls(tmp_path, target, secrets):
    log = tmp_path / "docker.log"
    log.write_text("")
    proc = subprocess.run(["make", "--no-print-directory", target], cwd=ROOT,
                          env=_env(tmp_path, secrets), capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = log.read_text().splitlines()
    runs = [(argv, env) for argv, env in zip(lines[::2], lines[1::2]) if " run " in f"{argv} "]
    assert runs, lines
    return runs, proc.stdout + proc.stderr


@pytest.mark.parametrize("target, side", [("annatar-dry-run", "ANNATAR"), ("annatar-shell", "ANNATAR"),
                                          ("glorfindel-list", "GLORFINDEL"), ("glorfindel-shell", "GLORFINDEL")])
def test_the_container_gets_its_own_principal_by_name(tmp_path, target, side):
    """Run for real (a fake docker): the secret is in docker's environment, never its arguments;
    the component's own principal first, the shared one as a fallback."""
    other = "GLORFINDEL" if side == "ANNATAR" else "ANNATAR"
    secrets = {"AZURE_CLIENT_ID": "shared-id", "AZURE_CLIENT_SECRET": "hy1-canary-shared",
               f"{side}_AZURE_CLIENT_ID": "own-id", f"{side}_AZURE_CLIENT_SECRET": "hy1-canary-own",
               f"{other}_AZURE_CLIENT_ID": "other-id", f"{other}_AZURE_CLIENT_SECRET": "hy1-canary-other"}
    runs, output = _docker_calls(tmp_path, target, secrets)
    for argv, env in runs:
        assert "hy1-canary" not in argv, argv
        assert "-e AZURE_CLIENT_SECRET " in f"{argv} " and "-e AZURE_CLIENT_ID " in f"{argv} "
        assert env == "ENV own-id hy1-canary-own", env
    assert "hy1-canary" not in output

    # Without its own principal, the shared one.
    del secrets[f"{side}_AZURE_CLIENT_ID"], secrets[f"{side}_AZURE_CLIENT_SECRET"]
    runs, _ = _docker_calls(tmp_path, target, secrets)
    assert [env for _, env in runs] == ["ENV shared-id hy1-canary-shared"] * len(runs)
