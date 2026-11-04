from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

from annatar.cli import _AnnatarCli


# ── _AnnatarCli error rendering (mirrors glorfindel's _GlorfindelCli) ───────────

def _group_raising(exc: Exception):
    @click.group(cls=_AnnatarCli)
    def g():
        pass

    @g.command()
    def boom():
        raise exc

    return g


def test_operational_error_renders_clean_not_traceback():
    """A ValueError (e.g. campaign in a terminal state) → one-liner + exit 1,
    NO raw Python traceback through click."""
    g = _group_raising(ValueError("campaign X is 'done' — re-plan to run again"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "re-plan to run again" in res.output
    assert "Traceback" not in res.output


def test_missing_creds_render_env_hint():
    g = _group_raising(RuntimeError("AZURE_SUBSCRIPTION_ID is not set"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code == 1
    assert "Traceback" not in res.output
    assert ".envrc" in res.output or "direnv" in res.output


def test_debug_env_restores_full_traceback(monkeypatch):
    """ANNATAR_DEBUG=1 re-raises so real bugs surface with a full stack."""
    monkeypatch.setenv("ANNATAR_DEBUG", "1")
    g = _group_raising(RuntimeError("kaboom"))
    res = CliRunner().invoke(g, ["boom"])
    assert res.exit_code != 0
    assert isinstance(res.exception, RuntimeError)


def test_click_usage_errors_still_render_normally():
    """A real usage error (unknown command) keeps Click's own handling."""
    g = _group_raising(RuntimeError("unused"))
    res = CliRunner().invoke(g, ["does-not-exist"])
    assert res.exit_code != 0
    assert "No such command" in res.output


def test_subcommand_help_exits_zero_without_a_fake_error():
    from click.testing import CliRunner
    from annatar.cli import cli
    result = CliRunner().invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "✗" not in result.output


# ── annatar validate says a failure by its exit code (AV1, #524) ────────────────
# A script or a CI that trusts `annatar validate` (make annatar-validate) reads the code: an
# invalid scenario exits 1 with its cause, --all exits 1 as soon as one is invalid and lists
# them; all valid: 0.

_VALID = ("name: av1-valid\ndescription: d\nmitre: T1486\n"
          "target:\n  type: azure_vm\n  resource_group: rg\nsteps: []\n")
_NO_TARGET = "name: av1-bad\ndescription: d\nmitre: T1486\nsteps: []\n"


@pytest.fixture
def wide_console(monkeypatch):
    """The CLI's console, wide: a long tmp path is never wrapped across lines."""
    from rich.console import Console
    monkeypatch.setattr("annatar.cli.console", Console(width=1000))


def _validate(*args):
    from annatar.cli import cli
    return CliRunner().invoke(cli, ["validate", *args])


def _scenarios(tmp_path, monkeypatch, files: dict[str, str]):
    """A scenarios root of its own: <tmp>/annatar/scenarios/azure/<name>."""
    root = tmp_path / "annatar" / "scenarios"
    (root / "azure").mkdir(parents=True)
    for name, text in files.items():
        (root / "azure" / name).write_text(text)
    monkeypatch.setattr("annatar.runner.parser.scenarios_root", lambda: root)
    return root


def _invalid_listed(output: str) -> list[str]:
    """The invalid scenarios the closing list of --all names, in order."""
    assert " invalid / " in output, output
    tail = output.split(" invalid / ", 1)[1].splitlines()[1:]
    return [line.split("FAIL", 1)[1].strip() for line in tail if "FAIL" in line]


def test_validate_one_invalid_scenario_exits_1_and_says_why(tmp_path, wide_console):
    bad = tmp_path / "bad.yaml"
    bad.write_text(_NO_TARGET)
    res = _validate(str(bad))
    assert res.exit_code == 1, res.output
    assert f"FAIL {bad} is invalid" in res.output
    assert "Missing required field: 'target'" in res.output
    assert "Traceback" not in res.output


def test_validate_one_valid_scenario_exits_0(tmp_path, wide_console):
    good = tmp_path / "good.yaml"
    good.write_text(_VALID)
    res = _validate(str(good))
    assert res.exit_code == 0, res.output
    assert f"OK {good} is valid" in res.output


def test_validate_a_name_that_resolves_to_nothing_exits_1(tmp_path, monkeypatch, wide_console):
    _scenarios(tmp_path, monkeypatch, {"good.yaml": _VALID})
    res = _validate("av1-no-such-scenario")
    assert res.exit_code == 1, res.output
    assert "Not found" in res.output


def test_validate_all_exits_1_when_one_is_invalid_and_lists_the_invalid_ones(
        tmp_path, monkeypatch, wide_console):
    _scenarios(tmp_path, monkeypatch, {
        "a-good.yaml": _VALID,
        "b-bad.yaml": _NO_TARGET,
        "c-good.yaml": _VALID.replace("av1-valid", "av1-valid-2"),
        "d-broken.yaml": "name: [unclosed",
    })
    res = _validate("--all")
    assert res.exit_code == 1, res.output
    assert "2 invalid / 4 scenario(s)" in res.output
    assert _invalid_listed(res.output) == ["annatar/scenarios/azure/b-bad.yaml",
                                           "annatar/scenarios/azure/d-broken.yaml"]
    # each cause said under its scenario
    assert "Missing required field: 'target'" in res.output
    assert "YAML parse error" in res.output
    assert "All " not in res.output


def test_validate_with_no_argument_is_all_and_exits_1_too(tmp_path, monkeypatch, wide_console):
    _scenarios(tmp_path, monkeypatch, {"bad.yaml": "name: av1-bad\n"})
    res = _validate()   # make annatar-validate with no SCENARIO
    assert res.exit_code == 1, res.output
    assert _invalid_listed(res.output) == ["annatar/scenarios/azure/bad.yaml"]


def test_validate_all_valid_exits_0(tmp_path, monkeypatch, wide_console):
    _scenarios(tmp_path, monkeypatch, {"a.yaml": _VALID, "b.yaml": _VALID})
    res = _validate("--all")
    assert res.exit_code == 0, res.output
    assert "All 2 scenario(s) valid" in res.output
    assert "invalid" not in res.output


def test_validate_all_says_an_empty_or_list_file_and_goes_on_to_the_others(
        tmp_path, monkeypatch, wide_console):
    """An empty file, a YAML list or a target that is no mapping is a scenario that is invalid,
    with its cause — not a TypeError that stops --all before the scenarios after it."""
    _scenarios(tmp_path, monkeypatch, {
        "a-empty.yaml": "",
        "b-list.yaml": "- name: av1\n",
        "c-target.yaml": _VALID.replace("target:\n  type: azure_vm\n  resource_group: rg\n",
                                        "target: 3\n"),
        "c2-engine.yaml": _VALID + "engine: [atomic]\n",
        "d-bad.yaml": "name: av1-bad\n",
        "e-good.yaml": _VALID,
    })
    res = _validate("--all")
    assert res.exit_code == 1, res.output
    assert not isinstance(res.exception, TypeError)
    assert _invalid_listed(res.output) == [
        f"annatar/scenarios/azure/{n}.yaml"
        for n in ("a-empty", "b-list", "c-target", "c2-engine", "d-bad")]
    assert "this file is empty" in res.output
    assert "this file is a list" in res.output
    assert "target must be a mapping" in res.output
    assert "engine '['atomic']' is not one of" in res.output
    assert "OK   annatar/scenarios/azure/e-good.yaml" in res.output


def test_validate_says_the_cause_as_written_never_read_as_markup(tmp_path, wide_console):
    bad = tmp_path / "bad.yaml"
    bad.write_text(_VALID + "engine: '[bold]stratus'\nengine_ref: x\n")
    res = _validate(str(bad))
    assert res.exit_code == 1, res.output
    assert "engine '[bold]stratus' is not one of" in res.output


def test_the_shipped_scenarios_all_validate():
    """make annatar-validate with no SCENARIO keeps exiting 0 on what the repository ships."""
    res = _validate("--all")
    assert res.exit_code == 0, res.output
