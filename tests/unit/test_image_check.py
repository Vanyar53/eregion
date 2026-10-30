"""CI1 (#267): the images built and proven in CI — scripts/image_check.py and its workflow
(.github/workflows/images.yml), read without docker: a fake runner stands for it, and the
code the checks run in the image runs here, on this interpreter, against the same files."""
from __future__ import annotations

import ast
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


# DEP1 (#282): litellm's call path, in this interpreter's environment — the dev lock in CI; each
# image's own lock in images.yml, where the same code runs with `--network none`. No key, no
# model, no network: litellm's mock answers, and its cost map is its local copy. Here every
# proxy is a closed port: a request the check would make fails, and litellm says so.
_NO_KEYS = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AZURE_API_KEY", "GLORFINDEL_LLM_MODEL",
            "GLORFINDEL_LLM_BASE_URL", "LITELLM_LOCAL_MODEL_COST_MAP", "NO_PROXY", "no_proxy")
_DEAD_PROXY = "http://127.0.0.1:9"


def _litellm_call(tmp_path, monkeypatch, pythonpath=""):
    monkeypatch.setenv("HOME", str(tmp_path))
    for key in _NO_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.setenv(key, _DEAD_PROXY)
    if pythonpath:
        monkeypatch.setenv("PYTHONPATH", pythonpath)
    return _python(ic.LITELLM_CALL)


def test_the_litellm_check_makes_a_tool_call_here(tmp_path, monkeypatch):
    pytest.importorskip("litellm")
    res = _litellm_call(tmp_path, monkeypatch)
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.split() == ["probe", '{"ok":', "true}"]
    assert "Failed to fetch remote model cost map" not in res.stderr, "the check reached the network"


def test_the_litellm_check_fails_on_a_release_that_imports_but_cannot_call(tmp_path, monkeypatch):
    """19/10's shape: `import litellm` passes, the call raises « No module named 'mcp' »."""
    fake = tmp_path / "fake"
    (fake / "litellm").mkdir(parents=True)
    (fake / "litellm" / "__init__.py").write_text(
        "suppress_debug_info = False\n"
        "def completion(**kw):\n"
        "    raise ModuleNotFoundError(\"No module named 'mcp'\")\n")
    res = _litellm_call(tmp_path, monkeypatch, pythonpath=str(fake))
    assert res.returncode != 0
    assert "No module named 'mcp'" in res.stderr


def test_the_litellm_check_fails_on_an_answer_without_its_tool_call(tmp_path, monkeypatch):
    fake = tmp_path / "fake"
    (fake / "litellm").mkdir(parents=True)
    (fake / "litellm" / "__init__.py").write_text(
        "from types import SimpleNamespace as N\n"
        "suppress_debug_info = False\n"
        "def completion(**kw):\n"
        "    fn = N(name='other', arguments='{}')\n"
        "    return N(choices=[N(message=N(tool_calls=[N(function=fn)]))])\n")
    assert _litellm_call(tmp_path, monkeypatch, pythonpath=str(fake)).returncode == 1


def test_the_root_check_refuses_root_only():
    if __import__("os").getuid() == 0:
        pytest.skip("the suite runs as root here")
    assert _python(ic.NOT_ROOT).returncode == 0
    assert "getuid() == 0" in ic.NOT_ROOT



def test_each_image_keeps_its_checks():
    """Frozen, image by image: a check that disappears fails here, not silently in the CI. Each
    probe is in the right image's argv — the imports, the absence of Glorfindel, not root."""
    names = {name: [c.name for c in image.checks] for name, image in ic.IMAGES.items()}
    assert names == {
        "glorfindel": ["glorfindel --version", "la watch, le bot et la console importent",
                       "glorfindel-config.yaml.example sous la lecture stricte d'A3", ic.LITELLM_CHECK,
                       "pas root"],
        "annatar": ["annatar --version", "Annatar et Gothmog importent",
                    "ni Glorfindel, ni la console, ni leurs dépendances (D1)", ic.LITELLM_CHECK, "pas root"],
    }
    argv = {name: [c.argv for c in image.checks] for name, image in ic.IMAGES.items()}
    assert ("glorfindel", "--version") in argv["glorfindel"] and ("annatar", "--version") in argv["annatar"]
    assert ("python", "-c", f"import {ic.GLORFINDEL_IMPORTS}") in argv["glorfindel"]
    assert ("python", "-c", ic.READ_CONFIG) in argv["glorfindel"]
    assert ("python", "-c", f"import {ic.INJECTOR_IMPORTS}") in argv["annatar"]
    assert ("python", "-c", ic.ABSENT, *ic.NOT_IN_INJECTORS) in argv["annatar"]
    for name in ic.IMAGES:
        assert ("python", "-c", ic.NOT_ROOT) in argv[name]
        assert ("python", "-c", ic.LITELLM_CALL) in argv[name]
        assert [c.says_version for c in ic.IMAGES[name].checks] == [True, False, False, False, False]
    assert ic.INJECTOR_IMPORTS == "annatar.cli, gothmog.cli"


# ── H0's preflight, read: each docker run it makes has its check here ─────────────────────────

# What the CD does in its candidate that the CI of the images does not, with the reason.
CD_ONLY = {
    "compose": "compose rendered with H0's .env: H0's own; the CI renders each profile "
                           "(make profiles-check, components.yml, tests/unit/test_profiles.py)",
}


def _cd_preflight_calls():
    """Every sh("docker", …) of eregion_cd.py's preflight: (its words after `docker`, the command
    in the image — the constants after the image's name — and its mount targets)."""
    tree = ast.parse(CD.read_text(encoding="utf-8"))
    (fn,) = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "preflight"]
    calls = []
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "sh"):
            continue
        args = node.args
        if not (args and isinstance(args[0], ast.Constant) and args[0].value == "docker"):
            continue
        words = tuple(a.value for a in args[1:3] if isinstance(a, ast.Constant))
        img = next((i for i, a in enumerate(args) if isinstance(a, ast.Name)), None)
        inside = tuple(a.value for a in args[img + 1:]) if img is not None else ()
        assert all(isinstance(a, ast.Constant) for a in args[img + 1:]) if img is not None else True
        mounts = tuple(ast.unparse(a).split(":")[-2] for a in args[:img or 0] if isinstance(a, ast.JoinedStr))
        calls.append((node.lineno, words, inside, mounts))
    return sorted(calls)


def _covers(check, inside, mounts) -> bool:
    if check.argv[:2] == ("python", "-c") and inside[:2] == ("python", "-c"):
        statements = [s.strip() for s in inside[2].split(";") if s.strip()]
        same = all(s in check.argv[2] for s in statements)
    else:
        same = check.argv == inside
    return same and set(mounts) == {m for _, m in check.mounts}


def test_every_docker_run_of_the_cds_preflight_has_its_check():
    """The other way too: a check the CD adds to its preflight fails here until the CI does it, or
    its reason is written in CD_ONLY."""
    calls = _cd_preflight_calls()
    runs = [c for c in calls if c[1] == ("run", "--rm")]
    assert len(runs) >= 3
    for line, _, inside, mounts in runs:
        assert any(_covers(c, inside, mounts) for c in ic.IMAGES["glorfindel"].checks), (line, inside)
    assert sorted(c[1][0] for c in calls if c not in runs) == sorted(CD_ONLY)


def test_what_the_preflight_reader_reads():
    calls = _cd_preflight_calls()
    insides = [c[2] for c in calls if c[1] == ("run", "--rm")]
    assert ("glorfindel", "--version") in insides
    assert ("python", "-c", f"import {ic.GLORFINDEL_IMPORTS}") in insides
    assert [c[3] for c in calls if c[3]] == [("/app/glorfindel-config.yaml",)]
    check = ic.Check("x", ("python", "-c", "import a; load('p')"))
    assert _covers(check, ("python", "-c", "load('p')"), ())
    assert not _covers(check, ("python", "-c", "import a; open('q')"), ())
    assert not _covers(check, ("python", "-c", "load('p')"), ("/app/x",))


# ── The decision: does the change go into an image ────────────────────────────────────────────

def _diff(*files, code=0, merge=True):
    def runner(argv):
        if argv[:2] == ["git", "rev-parse"]:
            assert argv == ["git", "rev-parse", "--verify", "-q", "HEAD^2"]
            return _done(argv, 0 if merge else 1, "")
        assert argv == ["git", "diff", "--no-renames", "--name-only", "-z", "HEAD^1", "HEAD"]
        return _done(argv, code, "".join(f + "\0" for f in files))
    return runner


@pytest.mark.parametrize("files, build", [
    (("docs/operations.md", "README.md"), False),
    (("tests/unit/test_x.py",), False),
    (("requirements/glorfindel.txt",), True),
    (("glorfindel/Dockerfile",), True),
    (("README.md", "pyproject.toml"), True),
    (("a file\nwith a newline", "eregion_core/signals.py"), True),
    (("glorfindelx/thing.py",), False),
    (("glorfindel-config.yaml.example",), True),
])
def test_a_pull_request_builds_when_its_diff_touches_an_image(files, build):
    assert ic.touched("pull_request", _diff(*files))[0] is build


def test_a_push_always_builds_without_reading_the_diff():
    def no_git(argv):
        raise AssertionError("a push builds: no diff read")
    assert ic.touched("push", no_git) == (True, "push : toujours construit")
    assert ic.touched("", no_git)[0] is True


def test_an_unreadable_diff_builds():
    assert ic.touched("pull_request", _diff(code=128))[0] is True


def test_a_head_that_is_not_the_merge_commit_builds():
    """SEC7: the diff HEAD^1..HEAD is the pull request's only on its merge commit; on another
    HEAD (a checkout of the PR's head), HEAD^1 is no base — built, the diff never read."""
    assert ic.touched("pull_request", _diff("docs/x.md", merge=False)) == (
        True, "HEAD n'est pas le commit de fusion de la PR : construit")


def test_in_the_ci_without_its_output_the_decision_fails(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert ic.main(["touched", "--event", "pull_request"], runner=_diff("docs/x.md")) == 1
    assert "GITHUB_OUTPUT" in capsys.readouterr().out
    monkeypatch.delenv("GITHUB_ACTIONS")
    assert ic.main(["touched", "--event", "pull_request"], runner=_diff("docs/x.md")) == 0   # make images-check


def test_the_decision_goes_to_githubs_output(tmp_path, monkeypatch, capsys):
    out = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    assert ic.main(["touched", "--event", "pull_request"], runner=_diff("docs/x.md")) == 0
    assert ic.main(["touched", "--event", "pull_request"], runner=_diff("scripts/image_check.py")) == 0
    assert out.read_text() == "build=false\nbuild=true\n"
    assert "build=false — " in capsys.readouterr().out


# ── The workflow ─────────────────────────────────────────────────────────────────────────────

def _instructions(text: str) -> list[tuple[str, list[str]]]:
    """A Dockerfile's instructions as docker reads them: a line continued by `\\` joined to the
    next, comments dropped, the keyword in upper case (docker ignores its case)."""
    out, cur = [], ""
    for line in text.splitlines():
        if not cur and line.lstrip().startswith("#"):
            continue
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        cur += line
        if cur.split():
            words = cur.split()
            out.append((words[0].upper(), words[1:]))
        cur = ""
    return out


def _copied(dockerfile: Path) -> set[str]:
    return _copied_text(dockerfile.read_text(encoding="utf-8"))


def _copied_text(text: str) -> set[str]:
    out = set()
    for keyword, words in _instructions(text):
        if keyword not in ("COPY", "ADD"):
            continue
        assert not (words and words[0].startswith("[")), "the JSON form of COPY is not read: write it plain"
        assert not any(w.startswith("--from") for w in words), "a COPY from another stage is not read"
        srcs = [w for w in words if not w.startswith("--")][:-1]
        out |= {s.rstrip("/") for s in srcs}
    return out


def test_the_copy_reader_reads_continued_and_lower_case_lines():
    text = "FROM x\n# COPY not/this .\ncopy a/ \\\n    b.txt \\\n    /app/\nCOPY --chown=1:1 c .\nRUN echo\n"
    assert _copied_text(text) == {"a", "b.txt", "c"}
    with pytest.raises(AssertionError):
        _copied_text('COPY ["a", "/app/"]\n')
    with pytest.raises(AssertionError):
        _copied_text("COPY --from=build /x /y\n")


def test_the_workflow_runs_on_every_pull_request_and_main_unfiltered():
    """No `paths`: a filtered workflow leaves a required check « expected » on a pull request it
    skips. The first step decides instead (touched)."""
    on = _wf()["on"]
    assert set(on) == {"push", "pull_request", "merge_group"}
    assert on["push"] == {"branches": ["main"]}
    assert on["pull_request"] is None and on["merge_group"] is None
    assert "paths" not in WORKFLOW.read_text(encoding="utf-8").split("\njobs:")[0].replace("`paths`", "")


def test_the_first_step_decides_and_every_later_step_obeys():
    steps = _steps()
    first = steps[1]
    assert steps[0]["uses"].startswith("actions/checkout@")
    assert steps[0]["with"] == {"fetch-depth": 2, "persist-credentials": False}
    assert first["id"] == "touched"
    assert first["run"].strip() == 'python3 scripts/image_check.py touched --event "$EVENT"'
    assert first["env"] == {"EVENT": "${{ github.event_name }}"}
    # A missing output builds (SEC7): the steps skip only on an explicit false.
    assert all(s.get("if") == "steps.touched.outputs.build != 'false'" for s in steps[2:])
    assert len(steps) == 5


def test_the_job_names_are_the_checks_to_require():
    job = _wf()["jobs"]["image"]
    assert job["name"] == "image (${{ matrix.image }})"
    ops = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    assert all(f"`image ({name})`" in ops for name in ic.IMAGES)


@pytest.mark.parametrize("name", sorted(ic.IMAGES))
def test_everything_an_image_takes_is_in_the_paths(name):
    dockerfile = ROOT / ic.IMAGES[name].dockerfile
    takes = _copied(dockerfile) | {ic.IMAGES[name].dockerfile, ".dockerignore", ".github/workflows/images.yml",
                                   "scripts/image_check.py", ic.EXAMPLE_CONFIG}
    assert len(_copied(dockerfile)) >= 5
    assert [t for t in sorted(takes) if not ic.covered(t)] == []


def test_what_counts_as_covered():
    assert ic.covered("glorfindel/Dockerfile", ("glorfindel/**",))
    assert ic.covered("requirements", ("requirements/**",))
    assert not ic.covered("requirements/glorfindel.txt", ("requirements",))
    assert not ic.covered("glorfindel-config.yaml.example", ("glorfindel/**",))
    assert not ic.covered("glorfindelx/a.py", ("glorfindel/**",))
    assert ic.covered("pyproject.toml") and not ic.covered("docs/operations.md") and not ic.covered("tests/unit/x.py")
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


def test_the_cache_is_read_everywhere_and_written_by_mains_pushes_only():
    with_ = _build_step()["with"]
    assert with_["cache-from"] == "type=gha,scope=${{ matrix.image }}"
    assert with_["cache-to"] == ("${{ github.event_name == 'push' && "
                                 "format('type=gha,mode=max,scope={0}', matrix.image) || '' }}")
    assert _wf()["on"]["push"]["branches"] == ["main"]
    assert any(str(s.get("uses", "")).startswith("docker/setup-buildx-action@") for s in _steps())


def test_the_check_step_runs_the_script_on_the_built_image():
    steps = _steps()
    run = [s for s in steps if "image_check.py" in str(s.get("run", "")) and "touched" not in s["run"]]
    assert len(run) == 1 and steps.index(run[0]) > steps.index(_build_step())
    assert run[0]["run"].strip() == 'python3 scripts/image_check.py "$IMAGE"'
    assert run[0]["env"] == {"IMAGE": "${{ matrix.image }}"}


def test_make_images_check_builds_and_checks_both_as_the_ci_does():
    make = (ROOT / "Makefile").read_text(encoding="utf-8")
    body = make[make.index("\nimages-check:"):].split("\n\n")[0]
    for name in ic.IMAGES:
        assert f"scripts/image_check.py {name} --build" in body
