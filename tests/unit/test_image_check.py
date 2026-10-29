"""CI1 (#267): the images built and proven in CI — scripts/image_check.py and its workflow
(.github/workflows/images.yml), read without docker: a fake runner stands for it, and the
code the checks run in the image runs here, on this interpreter, against the same files."""
from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import image_check as ic  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "images.yml"
CD = ROOT / "infra" / "glorfindel-host" / "cd" / "eregion_cd.py"
VERSION = ic.version()


def _done(argv, code=0, out=""):
    return subprocess.CompletedProcess(argv, code, out, "")


class Docker:
    """A fake docker: every command recorded; `answers` gives (code, stdout) by the check's argv[0..1]."""

    def __init__(self, answers=None, build_code=0, image="img:t"):
        self.calls, self.answers, self.build_code, self.image = [], answers or {}, build_code, image

    def __call__(self, argv):
        self.calls.append(argv)
        if argv[1] == "build":
            return _done(argv, self.build_code, "built")
        inside = argv[argv.index(self.image) + 1:]
        if inside[-1:] == ["--version"]:
            return _done(argv, *self.answers.get("version", (0, f"{inside[0]}, version {VERSION}\n")))
        for key, (code, out) in self.answers.items():
            if key in " ".join(inside):
                return _done(argv, code, out)
        return _done(argv)

    def runs(self):
        return [c for c in self.calls if c[1] == "run"]


def _wf():
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    doc["on"] = doc.get("on", doc.pop(True, None))
    return doc


def _steps():
    return _wf()["jobs"]["image"]["steps"]


def _build_step():
    (step,) = [s for s in _steps() if str(s.get("uses", "")).startswith("docker/build-push-action@")]
    return step


# ── The script ───────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name", sorted(ic.IMAGES))
def test_every_check_passes_and_the_script_says_so(name, capsys):
    docker = Docker()
    assert ic.main([name, "--image", "img:t"], runner=docker) == 0
    assert len(docker.runs()) == len(ic.IMAGES[name].checks)
    assert capsys.readouterr().out.count("✓") == len(ic.IMAGES[name].checks)


@pytest.mark.parametrize("name", sorted(ic.IMAGES))
def test_a_version_other_than_pyprojects_fails(name, capsys):
    docker = Docker({"version": (0, f"{name}, version 0.1.0\n")})
    assert ic.main([name, "--image", "img:t"], runner=docker) == 1
    assert f"dit « 0.1.0 », pas {VERSION}" in capsys.readouterr().out


def test_a_version_command_that_says_nothing_fails():
    assert ic.main(["glorfindel", "--image", "img:t"], runner=Docker({"version": (0, "")})) == 1


def test_a_failing_command_fails_with_its_last_lines(capsys):
    docker = Docker({"import glorfindel.cli": (1, "Traceback\nModuleNotFoundError: No module named 'eregion_console'\n")})
    assert ic.main(["glorfindel", "--image", "img:t"], runner=docker) == 1
    out = capsys.readouterr().out
    assert "✗ la watch, le bot et la console importent — code 1" in out
    assert "No module named 'eregion_console'" in out


def test_every_check_runs_even_after_a_failure(capsys):
    """The log says all that is wrong at once: the version wrong, the imports still checked."""
    docker = Docker({"version": (1, "boom")})
    assert ic.main(["annatar", "--image", "img:t"], runner=docker) == 1
    assert len(docker.runs()) == len(ic.IMAGES["annatar"].checks)
    assert capsys.readouterr().out.count("✓") == len(ic.IMAGES["annatar"].checks) - 1


def test_each_check_runs_without_network_environment_or_start(tmp_path):
    docker = Docker()
    ic.check_image("glorfindel", "img:t", runner=docker)
    for argv in docker.runs():
        assert argv[:5] == ["docker", "run", "--rm", "--network", "none"]
        assert not {"-e", "--env", "--env-file", "--privileged", "-d", "--detach"} & set(argv)
        assert not any(a.startswith(("--env", "--network=")) for a in argv)
        assert argv[argv.index("img:t") + 1:], "a command, never the image's CMD"


def test_the_example_config_is_mounted_read_only_where_compose_mounts_it():
    docker = Docker()
    ic.check_image("glorfindel", "img:t", runner=docker)
    (cfg,) = [a for c in docker.runs() for a in c if a.endswith(":ro")]
    assert cfg == f"{ROOT / 'glorfindel-config.yaml.example'}:/app/glorfindel-config.yaml:ro"
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert ":/app/glorfindel-config.yaml" in compose
    assert all(a.endswith(":ro") for c in docker.runs() for i, a in enumerate(c) if c[i - 1] == "-v")


def test_a_mounted_file_absent_from_the_repository_fails_before_docker(monkeypatch, tmp_path, capsys):
    gone = tmp_path / "glorfindel-config.yaml.example"
    checks = tuple(replace(c, mounts=tuple((gone, inside) for _, inside in c.mounts))
                   for c in ic.IMAGES["glorfindel"].checks)
    monkeypatch.setitem(ic.IMAGES, "glorfindel", ic.Image("glorfindel/Dockerfile", "eregion-glorfindel:ci", checks))
    docker = Docker()
    assert ic.check_image("glorfindel", "img:t", runner=docker) is False
    assert len(docker.runs()) == len(checks) - 1
    assert "absent du dépôt" in capsys.readouterr().out


def test_build_is_the_ci_s_build(capsys):
    docker = Docker()
    assert ic.main(["annatar", "--build", "--image", "img:t"], runner=docker) == 0
    assert docker.calls[0] == ["docker", "build", "-f", str(ROOT / "annatar/Dockerfile"), "-t", "img:t", str(ROOT)]
    assert not any("--build-arg" in a for a in docker.calls[0])


def test_a_failed_build_fails_without_checking(capsys):
    docker = Docker(build_code=1)
    assert ic.main(["glorfindel", "--build", "--image", "img:t"], runner=docker) == 1
    assert docker.runs() == []
    assert "✗ docker build glorfindel" in capsys.readouterr().out


def test_the_default_image_is_the_ci_s_tag():
    docker = Docker(image="eregion-glorfindel:ci")
    assert ic.main(["glorfindel"], runner=docker) == 0
    assert all("eregion-glorfindel:ci" in c for c in docker.runs())


def test_no_docker_says_so(capsys):
    def missing(argv):
        raise FileNotFoundError("docker")
    assert ic.main(["glorfindel"], runner=missing) == 2
    assert "docker introuvable" in capsys.readouterr().out


def test_the_version_is_pyprojects(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "eregion"\nversion = "9.8.7"\n')
    assert ic.version(tmp_path / "pyproject.toml") == "9.8.7"
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION)


# ── The code each check runs in the image, run here ──────────────────────────────────────────

def _python(code, *args):
    return subprocess.run([sys.executable, "-c", code, *args], capture_output=True, text=True, cwd=ROOT,
                          check=False)


def test_the_config_check_passes_the_example_and_refuses_a_bad_or_absent_file(tmp_path):
    read = lambda p: _python(ic.READ_CONFIG.replace(ic.CONFIG_IN_IMAGE, str(p)))   # noqa: E731
    assert read(ROOT / ic.EXAMPLE_CONFIG).returncode == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("quarantaine_nsg: false\n")          # a key nobody reads (A3)
    assert read(bad).returncode != 0
    assert read(tmp_path / "absent.yaml").returncode != 0, "an absent file would load as an empty config"


def test_the_absence_check_names_what_is_there():
    res = _python(ic.ABSENT, "json", "no_such_module_ci1", "no_such_parent_ci1.sub")
    assert (res.returncode, res.stdout.split()) == (1, ["json"])
    assert _python(ic.ABSENT, "no_such_module_ci1", "no_such_parent_ci1.sub").returncode == 0


def test_the_injectors_image_holds_none_of_glorfindels_dependencies():
    import component_check as cc
    assert set(ic.NOT_IN_INJECTORS) >= {"glorfindel", "eregion_console", *cc.GLORFINDEL_ONLY_DEPS}


def test_the_root_check_refuses_root_only():
    if __import__("os").getuid() == 0:
        pytest.skip("the suite runs as root here")
    assert _python(ic.NOT_ROOT).returncode == 0
    assert "getuid() == 0" in ic.NOT_ROOT


def test_the_imports_are_the_cds_preflight():
    """The CD (eregion_cd.py, preflight, step 5) checks its candidate with the same imports and the
    same config path: what the CI proves is what H0 would refuse."""
    cd = CD.read_text(encoding="utf-8")
    assert f'"import {ic.GLORFINDEL_IMPORTS}"' in cd
    assert f':{ic.CONFIG_IN_IMAGE}:ro"' in cd
    assert "load_glorfindel_config" in ic.READ_CONFIG and "load_glorfindel_config" in cd


# ── The workflow ─────────────────────────────────────────────────────────────────────────────

def _copied(dockerfile: Path) -> set[str]:
    out = set()
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        words = line.split()
        if words[:1] in (["COPY"], ["ADD"]):
            srcs = [w for w in words[1:] if not w.startswith("--")][:-1]
            out |= {s.rstrip("/") for s in srcs}
    return out


def _covered(path: str, patterns: list[str]) -> bool:
    for p in patterns:
        if p.endswith("/**") and (path == p[:-3] or path.startswith(p[:-2])):
            return True
        if fnmatch.fnmatchcase(path, p):
            return True
    return False


def test_the_workflow_runs_on_pull_requests_and_main_with_the_same_paths():
    on = _wf()["on"]
    assert on["push"]["branches"] == ["main"]
    assert on["push"]["paths"] == on["pull_request"]["paths"]
    assert set(on) == {"push", "pull_request"}


@pytest.mark.parametrize("name", sorted(ic.IMAGES))
def test_everything_an_image_takes_is_in_the_paths(name):
    dockerfile = ROOT / ic.IMAGES[name].dockerfile
    takes = _copied(dockerfile) | {ic.IMAGES[name].dockerfile, ".dockerignore", ".github/workflows/images.yml",
                                   "scripts/image_check.py", ic.EXAMPLE_CONFIG, "docker-compose.yml"}
    assert len(_copied(dockerfile)) >= 5
    for event in ("push", "pull_request"):
        assert [t for t in sorted(takes) if not _covered(t, _wf()["on"][event]["paths"])] == []


def test_what_counts_as_covered():
    assert _covered("glorfindel/Dockerfile", ["glorfindel/**"])
    assert _covered("requirements", ["requirements/**"])
    assert not _covered("requirements/glorfindel.txt", ["requirements"])
    assert not _covered("glorfindel-config.yaml.example", ["glorfindel/**"])
    assert _copied(ROOT / "glorfindel/Dockerfile") >= {"requirements/glorfindel.txt", "pyproject.toml", "glorfindel"}


def test_one_job_per_image_built_as_the_script_builds_it():
    job = _wf()["jobs"]["image"]
    assert job["strategy"]["matrix"]["image"] == list(ic.IMAGES)
    assert job["timeout-minutes"] <= 30
    with_ = _build_step()["with"]
    for name, image in ic.IMAGES.items():
        assert with_["file"].replace("${{ matrix.image }}", name) == image.dockerfile
        assert with_["tags"].replace("${{ matrix.image }}", name) == image.default
    assert with_["context"] == "."
    assert "build-args" not in with_


def test_never_pushed_no_registry_no_secret():
    text = WORKFLOW.read_text(encoding="utf-8")
    with_ = _build_step()["with"]
    assert with_["push"] is False and with_["load"] is True
    assert "secrets." not in text and "login-action" not in text and "docker.io" not in text
    assert _wf()["permissions"] == {"contents": "read"}
    assert "ghcr.io" not in text


def test_the_build_uses_githubs_cache_one_scope_per_image():
    with_ = _build_step()["with"]
    assert with_["cache-from"] == "type=gha,scope=${{ matrix.image }}"
    assert with_["cache-to"] == "type=gha,mode=max,scope=${{ matrix.image }}"
    assert any(str(s.get("uses", "")).startswith("docker/setup-buildx-action@") for s in _steps())


def test_the_check_step_runs_the_script_on_the_built_image():
    steps = _steps()
    run = [s for s in steps if "image_check.py" in str(s.get("run", ""))]
    assert len(run) == 1 and steps.index(run[0]) > steps.index(_build_step())
    assert run[0]["run"].strip() == 'python3 scripts/image_check.py "$IMAGE"'
    assert run[0]["env"] == {"IMAGE": "${{ matrix.image }}"}
    assert [s for s in steps if s.get("uses", "").startswith("actions/checkout@")][0]["with"] == {
        "persist-credentials": False}


def test_make_images_check_builds_and_checks_both_as_the_ci_does():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    body = make[make.index("\nimages-check:"):].split("\n\n")[0]
    for name in ic.IMAGES:
        assert f"scripts/image_check.py {name} --build" in body
