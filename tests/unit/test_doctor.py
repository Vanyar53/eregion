"""GS1 (#520): make doctor checks what a first start needs, without the cloud nor the model, and
never says a secret (scripts/doctor.py; mutants M3620–M3627 in scripts/mutants/GS1.py).

Every probe is swapped here: no docker, no port bound, no file of the operator read — the repo
and the HOME are tmp directories.
"""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("doctor", REPO / "scripts" / "doctor.py")
doctor = importlib.util.module_from_spec(_spec)
sys.modules["doctor"] = doctor
_spec.loader.exec_module(doctor)

SUB = "00000000-0000-4000-8000-000000000001"
TENANT = "00000000-0000-4000-8000-000000000002"
APP = "00000000-0000-4000-8000-000000000003"
WORKSPACE = "00000000-0000-4000-8000-000000000004"
# What must never be printed: each a value of a variable or a line of an env file.
SECRETS = ("s3cret-client-sentinel", "sk-ant-sentinel-model-key", "https://sentinel.blob.example/watch",
           "https://sentinel.blob.example/exercises", "sentinel-scope")
WATCH_KEY = "ed25519:" + "A" * 42 + "E="          # 32 bytes of base64, a key of the right form
FINGERPRINT = "SHA256:" + "B" * 43


def good_env(**over) -> dict:
    env = {"AZURE_SUBSCRIPTION_ID": SUB, "AZURE_TENANT_ID": TENANT,
           "GLORFINDEL_AZURE_CLIENT_ID": APP, "GLORFINDEL_AZURE_CLIENT_SECRET": SECRETS[0],
           "EREGION_CONSOLE_AZURE_CLIENT_ID": APP, "EREGION_CONSOLE_AZURE_CLIENT_SECRET": SECRETS[0],
           "GLORFINDEL_READ_ONLY": "1", "ANTHROPIC_API_KEY": SECRETS[1],
           "ORO_SSH_FINGERPRINT": FINGERPRINT, "HOST_SSH_FINGERPRINT": FINGERPRINT}
    env.update(over)
    return {k: v for k, v in env.items() if v is not None}


class Recorder:
    """Every command the doctor would run, answered as told."""

    def __init__(self, rc=0, stdout=""):
        self.calls, self.rc, self.stdout = [], rc, stdout

    def __call__(self, cmd):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, self.rc, self.stdout, "")


_PROBES = doctor.Probes


def probes(**over) -> doctor.Probes:
    p = _PROBES(which=lambda name: f"/usr/bin/{name}", run=Recorder(), port_free=lambda n: True,
                      uid=os.getuid, python=(3, 12, 1))
    for k, v in over.items():
        setattr(p, k, v)
    return p


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "glorfindel-config.yaml").write_text(
        "monitoring_backends:\n  - name: law\n    type: azure_monitor\n"
        f"    workspace_id: \"{WORKSPACE}\"\naction_backends: []\n")
    (r / ".venv" / "bin").mkdir(parents=True)
    (r / ".venv" / "bin" / "python").write_text("")
    return r


@pytest.fixture
def home(tmp_path):
    h = tmp_path / "home"
    h.mkdir()
    return h


def bench_files(repo: Path, oro: dict | None = None, host: dict | None = None) -> None:
    oro_env = {"AZURE_SUBSCRIPTION_ID": SUB, "EREGION_WATCH_KEY": WATCH_KEY,
               "EREGION_WATCH_CHANNEL": SECRETS[2], "EREGION_WATCH_CHANNEL_SCOPE": SECRETS[4],
               "EREGION_EXERCISE_CHANNEL": SECRETS[3], "EREGION_CHANNEL_SCOPE": SECRETS[4]}
    host_env = {"AZURE_SUBSCRIPTION_ID": SUB, "ANTHROPIC_API_KEY": SECRETS[1],
                "EREGION_WATCH_CHANNEL": SECRETS[2], "EREGION_EXERCISE_CHANNEL": SECRETS[3]}
    oro_env.update(oro or {})
    host_env.update(host or {})
    for rel, values in ((doctor.ORODRUIN_ENV, oro_env), (doctor.HOST_ENV, host_env)):
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{k}={v}\n" for k, v in values.items() if v is not None))
    tf = repo / doctor.TFVARS
    tf.parent.mkdir(parents=True, exist_ok=True)
    tf.write_text('admin_ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexamplekeyonly me@box"\n')


def failed(checks) -> list[str]:
    return [c.name for c in checks if c.status == doctor.FAIL]


def test_all_green_on_the_discover_profile_exits_0(repo, home):
    checks = doctor.run_checks("discover", good_env(), home, repo, probes())
    assert failed(checks) == []
    assert doctor.exit_code(checks) == 0
    assert "Tout est prêt." in doctor.render(checks)


def test_one_failure_exits_1_and_says_the_command_that_fixes_it(repo, home):
    checks = doctor.run_checks("discover", good_env(), home, repo,
                               probes(which=lambda n: None if n == "docker" else f"/usr/bin/{n}"))
    assert failed(checks) == ["docker absent"]
    assert doctor.exit_code(checks) == 1
    text = doctor.render(checks)
    assert "→ installer Docker" in text and "1 point(s) à corriger" in text


def test_an_optional_thing_missing_is_said_but_never_fails(repo, home):
    checks = doctor.run_checks("discover", good_env(EREGION_CONSOLE_AZURE_CLIENT_ID=None,
                                                    EREGION_CONSOLE_AZURE_CLIENT_SECRET=None),
                               home, repo, probes(which=lambda n: None if n == "direnv" else f"/usr/bin/{n}"))
    warned = [c.name for c in checks if c.status == doctor.WARN]
    assert any("direnv" in w for w in warned) and any("la console" in w for w in warned)
    assert doctor.exit_code(checks) == 0


@pytest.mark.parametrize("profile", doctor.PROFILES)
def test_no_value_is_ever_printed(repo, home, profile, capsys, monkeypatch):
    """A secret is read for its presence and its shape, never written out — the env files of the
    bench included, whatever the checks find."""
    bench_files(repo, host={"EREGION_WATCH_CHANNEL": SECRETS[2] + "-other"})
    env = good_env(GLORFINDEL_BOT_AZURE_CLIENT_ID=SECRETS[0])          # a half pair: said, not shown
    checks = doctor.run_checks(profile, env, home, repo, probes())
    text = doctor.render(checks)
    assert failed(checks)                                               # something to say
    assert [s for s in SECRETS if s in text] == []
    monkeypatch.setattr(doctor, "REPO", repo)
    monkeypatch.setenv("HOME", str(home))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(doctor, "Probes", lambda: probes())
    doctor.main(["--profile", profile])
    out = capsys.readouterr()
    assert [s for s in SECRETS if s in out.out + out.err] == []


def test_the_values_of_envrc_example_are_refused_as_unfilled():
    """Copied and not filled, .envrc.example sets every variable to a placeholder: none passes."""
    example = doctor.env_file(REPO / ".envrc.example")
    checks = doctor.variables("discover", example)
    names = " ".join(failed(checks))
    for var in ("AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "GLORFINDEL_AZURE_CLIENT_ID", "ANTHROPIC_API_KEY"):
        assert var in names, var


def test_a_half_pair_fails_and_the_watch_needs_its_principal():
    half = doctor.variables("discover", good_env(EREGION_CONSOLE_AZURE_CLIENT_SECRET=None))
    assert any("EREGION_CONSOLE_AZURE_CLIENT_ID / EREGION_CONSOLE_AZURE_CLIENT_SECRET" in n for n in failed(half))
    none = doctor.variables("discover", good_env(GLORFINDEL_AZURE_CLIENT_ID=None, GLORFINDEL_AZURE_CLIENT_SECRET=None))
    assert any("aucun principal pour la watch" in n for n in failed(none))


def test_observation_asks_for_read_only_as_glorfindel_reads_it():
    from glorfindel.config import _SWITCH_OFF
    assert doctor.SWITCH_OFF == _SWITCH_OFF
    for off in ("", "0", "false", "off"):
        assert any("GLORFINDEL_READ_ONLY" in n for n in failed(doctor.variables("discover", good_env(GLORFINDEL_READ_ONLY=off))))
    assert not failed(doctor.variables("discover", good_env(GLORFINDEL_READ_ONLY="yes")))


def test_the_model_key_follows_the_provider_of_the_model():
    from eregion_core.models import DEFAULT_LLM_MODEL
    assert DEFAULT_LLM_MODEL.split("/", 1)[0] == doctor.DEFAULT_PROVIDER
    assert failed(doctor.model(good_env(ANTHROPIC_API_KEY=None)))
    assert failed(doctor.model(good_env(ANTHROPIC_API_KEY="sk-ant-...")))
    assert failed(doctor.model(good_env(GLORFINDEL_LLM_MODEL="openai/gpt-4o")))
    assert not failed(doctor.model(good_env(GLORFINDEL_LLM_MODEL="openai/gpt-4o", OPENAI_API_KEY="k")))
    local = good_env(ANTHROPIC_API_KEY=None, GLORFINDEL_LLM_MODEL="ollama/qwen2.5")
    assert failed(doctor.model(local))                                         # no endpoint
    assert failed(doctor.model({**local, "GLORFINDEL_LLM_BASE_URL": "http://localhost:11434"}))  # the container's own
    assert not failed(doctor.model({**local, "GLORFINDEL_LLM_BASE_URL": "http://host.docker.internal:11434"}))


def test_the_configuration_must_be_a_file_read_as_the_watch_reads_it(repo):
    assert not failed(doctor.configuration(repo))
    cfg = repo / "glorfindel-config.yaml"
    cfg.unlink()
    assert any("absent" in n for n in failed(doctor.configuration(repo)))
    cfg.mkdir()                                     # what docker makes when the file is missing
    assert any("est un dossier" in n for n in failed(doctor.configuration(repo)))
    cfg.rmdir()
    cfg.write_text((REPO / "glorfindel-config.yaml.example").read_text())
    assert any("workspace_id" in n for n in failed(doctor.configuration(repo)))   # the example's placeholder
    cfg.write_text(f"monitoring_backends:\n  - name: law\n    type: azure_monitor\n    workspace_id: \"{WORKSPACE}\"\n"
                   "quarantaine_nsg: false\n")
    assert any("refusé par la watch" in n for n in failed(doctor.configuration(repo)))


def test_a_state_directory_not_the_operators_fails_with_its_fix(repo, home):
    (home / ".glorfindel").mkdir()
    (repo / "runs").mkdir()
    assert not failed(doctor.state(home, repo, os.getuid()))
    other = doctor.state(home, repo, os.getuid() + 1)
    assert any("~/.glorfindel n'est pas à ton nom" in c.name and "fix-state-ownership" in c.fix for c in other)
    assert any(c.name.startswith("runs n'est pas à ton nom") for c in other)


def test_a_link_or_an_open_watch_key_directory_fails(repo, home, tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir()
    (repo / "runs").mkdir()
    (repo / "runs" / "glorfindel").symlink_to(target)
    key = home / ".eregion" / "watch-key"
    key.mkdir(parents=True, mode=0o755)
    key.chmod(0o755)
    names = failed(doctor.state(home, repo, os.getuid()))
    assert any("runs/glorfindel n'est pas un dossier" in n for n in names)
    assert any("watch-key lisible par d'autres" in n for n in names)
    key.chmod(0o700)
    assert not any("watch-key" in n for n in failed(doctor.state(home, repo, os.getuid())))


def test_the_port_free_or_held_by_the_console_passes_anything_else_fails():
    env = good_env()
    assert not failed(doctor.port(env, probes()))
    console = probes(port_free=lambda n: False, run=Recorder(stdout="eregion-war-room\n"))
    assert not failed(doctor.port(env, console))
    assert console.run.calls == [["docker", "ps", "--filter", "publish=7007", "--format", "{{.Names}}"]]
    assert failed(doctor.port(env, probes(port_free=lambda n: False, run=Recorder(stdout="nginx\n"))))
    seen = []
    doctor.port(good_env(EREGION_CONSOLE_PORT="7101"), probes(port_free=lambda n: seen.append(n) or True))
    assert seen == [7101]


def test_only_local_commands_run(repo, home):
    """No az, no terraform, no model: what the doctor runs is docker's own, local."""
    rec = Recorder()
    bench_files(repo)
    for profile in doctor.PROFILES:
        doctor.run_checks(profile, good_env(), home, repo, probes(run=rec, port_free=lambda n: False))
    assert rec.calls and all(c[0] == "docker" and c[1] in ("info", "compose", "ps") for c in rec.calls)


def test_the_bench_ready_to_attack_is_green(repo, home):
    bench_files(repo)
    checks = doctor.run_checks("bench", good_env(), home, repo, probes())
    assert failed(checks) == []
    assert any("terraform" in c.name for c in checks) and any("EREGION_WATCH_KEY" in c.name for c in checks)


@pytest.mark.parametrize("oro,host,said", [
    ({"EREGION_WATCH_KEY": ""}, {}, "EREGION_WATCH_KEY vide ou mal formé"),
    ({"EREGION_WATCH_KEY": "ed25519:short="}, {}, "EREGION_WATCH_KEY vide ou mal formé"),
    ({"EREGION_WATCH_CHANNEL": ""}, {}, "orodruin.env : EREGION_WATCH_CHANNEL vide"),
    ({}, {"EREGION_WATCH_CHANNEL": SECRETS[2] + "x"}, "EREGION_WATCH_CHANNEL : orodruin.env et host.env diffèrent"),
    ({}, {"AZURE_SUBSCRIPTION_ID": TENANT}, "AZURE_SUBSCRIPTION_ID : orodruin.env et host.env diffèrent"),
    ({"AZURE_CLIENT_ID": APP}, {}, "masqueraient l'identité managée"),
    ({}, {"ANTHROPIC_API_KEY": ""}, "anthropic"),
])
def test_the_bench_says_what_would_refuse_a_run(repo, home, oro, host, said):
    bench_files(repo, oro, host)
    names = failed(doctor.run_checks("bench", good_env(), home, repo, probes()))
    assert any(said in n for n in names), names


def test_the_bench_needs_its_files_and_its_fingerprint(repo, home):
    names = failed(doctor.run_checks("bench", good_env(ORO_SSH_FINGERPRINT=None), home, repo, probes()))
    for said in ("ORO_SSH_FINGERPRINT", "orodruin.env absent", "host.env absent", "terraform.tfvars absent"):
        assert any(said in n for n in names), said


def test_an_unknown_profile_is_refused(capsys):
    assert doctor.main(["--profile", "prod"]) == 2
    assert "discover ou bench" in capsys.readouterr().err


def test_make_doctor_takes_the_venv_when_there_and_passes_the_profile():
    make = (REPO / "Makefile").read_text()
    rule = make.split("\ndoctor:\n", 1)[1].split("\n\n", 1)[0]
    assert ".venv/bin/python" in rule and "python3" in rule and '--profile "$(PROFILE)"' in rule
    assert "PROFILE ?= discover" in make and "make doctor [PROFILE=discover|bench]" in make
