"""H2 (#266) — `glorfindel rules check [--live]`: every loaded rule run once, read-only.

Against a fake backend (no Azure): the detector the rule poller would use is replaced by
`FakeBackend`, which answers by what the query holds — rows, none, a syntax error, a table
absent, an answer that never comes. The rules are loaded as the watch loads them: the base,
the client's layer, the rules approved into it (P1).
"""
import json
import threading
import time

import pytest
from click.testing import CliRunner

from glorfindel import rule_check
from glorfindel.detection_rules import client_rules_path

# Placeholders only: never an identifier of a real infrastructure.
WS = "00000000-0000-0000-0000-0000000000aa"
SUB = "00000000-0000-0000-0000-0000000000bb"
VM_ID = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"

# What Log Analytics answers to a query it cannot read — its shape (azure-core's
# HttpResponseError, the inner error nested), the identifiers it may carry.
AZURE_SYNTAX = (
    "(BadArgumentError) The request had some invalid properties\n"
    "Code: BadArgumentError\nMessage: The request had some invalid properties\n"
    f"Target: /subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.OperationalInsights/"
    f"workspaces/law-example (workspace {WS}, vm-example-01.internal.example.net, 10.0.0.4)\n"
    'Inner error: {"code": "SemanticError", "message": "A semantic error occurred.", '
    '"innererror": {"code": "SYN0002", "message": "Query could not be parsed at \'BROKEN\' on line [1,8]: '
    'syntax error near \'vm-example-01\'"}}')
AZURE_TABLE = (
    "(BadArgumentError) The request had some invalid properties\n"
    'Inner error: {"code": "SemanticError", "innererror": {"code": "SEM0100", '
    '"message": "\'where\' operator: Failed to resolve table or column expression named \'NoSuchTable\'"}}')

BASE = """\
rules:
  - name: ssh-brute-force
    ttp: T1110.001
    assets: [auto]
    query: |
      Syslog | where TimeGenerated > ago(15m) | where SyslogMessage has "Failed password"
  - name: sudo-root
    ttp: T1548.003
    assets: [auto]
    query: |
      Syslog | where SyslogMessage has "USER=root"
"""


class Hang(Exception):
    pass


class FakeBackend:
    """A detector: `run_query` only (what the rule poller calls). Every call recorded."""

    def __init__(self, calls: list, release: threading.Event):
        self.calls, self.release = calls, release

    def run_query(self, query: str, timespan=None):
        self.calls.append((query, timespan))
        if "BROKEN" in query:
            raise Exception(AZURE_SYNTAX)
        if "NoSuchTable" in query:
            raise Exception(AZURE_TABLE)
        if "SLOW" in query:
            self.release.wait(30)       # longer than any test's budget
            return []
        if "ROWS" in query:
            return [{"Computer": "vm-example-01", "FailedAttempts": 12}]
        return []


@pytest.fixture
def backend(monkeypatch):
    calls: list = []
    release = threading.Event()
    made: list = []

    def detector_for(source, **kw):
        made.append((source, kw.get("workspace_id")))
        return FakeBackend(calls, release)

    import glorfindel.detectors as detectors
    monkeypatch.setattr(detectors, "detector_for", detector_for)
    yield type("B", (), {"calls": calls, "made": made})
    release.set()


def _gcfg(backends=True):
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig
    return GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-main", type="azure_monitor", workspace_id=WS)] if backends else [])


@pytest.fixture
def config(monkeypatch):
    import glorfindel.config as config
    state = {"cfg": _gcfg()}
    monkeypatch.setattr(config, "load_glorfindel_config", lambda *a, **k: state["cfg"])
    return state


def _base(tmp_path, text=BASE) -> str:
    path = tmp_path / "base.yaml"
    path.write_text(text)
    return str(path)


def _layer(text: str) -> None:
    client_rules_path().parent.mkdir(parents=True, exist_ok=True)
    client_rules_path().write_text(text)


def _check(*args):
    from glorfindel.cli import cli
    return CliRunner().invoke(cli, ["rules", "check", *args], catch_exceptions=False)


def _json(res) -> dict:
    return json.loads(res.output.strip().splitlines()[-1])


def _by_name(out: dict) -> dict:
    return {r["name"]: r for r in out["rules"]}


# ── the command, alone ─────────────────────────────────────────────────────────────

def test_a_valid_rule_without_rows_is_ok(tmp_path, backend, config):
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 0, res.output
    out = _json(res)
    assert out["schema"] == rule_check.SCHEMA and out["live"] is True
    assert out["counts"] == {"ok": 2, "error": 0, "timeout": 0}
    assert {r["status"] for r in out["rules"]} == {"ok"} and {r["rows"] for r in out["rules"]} == {0}


def test_each_query_runs_once_on_its_backend_with_the_pollers_window(tmp_path, backend, config):
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 0
    assert len(backend.calls) == 2                                   # once each, never again
    assert backend.made == [("azure_monitor", WS)]                    # one detector per backend
    (q1, (start, end)), _ = backend.calls
    assert "Failed password" in q1
    assert 15 * 60 + 300 - 5 <= (end - start).total_seconds() - 60 <= 15 * 60 + 300 + 5   # ago(15m) + margin


def test_rows_found_are_ok_too(tmp_path, backend, config):
    base = BASE.replace('"Failed password"', '"Failed password" // ROWS')
    out = _json(_check("--rules", _base(tmp_path, base), "--live", "--json"))
    assert _by_name(out)["ssh-brute-force"] == {**_by_name(out)["ssh-brute-force"], "status": "ok", "rows": 1}


@pytest.mark.parametrize("marker, kind", [("BROKEN(", "syntax"), ("NoSuchTable", "table")])
def test_an_invalid_query_is_an_error_said_without_the_infrastructure(tmp_path, backend, config, marker, kind):
    base = BASE.replace('Syslog | where SyslogMessage has "USER=root"', f"{marker} | take 1")
    res = _check("--rules", _base(tmp_path, base), "--live", "--json")
    assert res.exit_code == 1
    out = _json(res)
    bad = _by_name(out)["sudo-root"]
    assert bad["status"] == "error" and bad["kind"] == kind
    assert _by_name(out)["ssh-brute-force"]["status"] == "ok"
    text = json.dumps(out)
    for secret in (WS, SUB, "/subscriptions/", "rg-example", "law-example", "vm-example-01", "10.0.0.4",
                   "internal.example.net"):
        assert secret not in text, secret
    if kind == "table":
        assert "'NoSuchTable'" in bad["error"]                        # a KQL name is kept
    else:
        assert "syntax error" in bad["error"]


def test_no_backend_bound_is_an_error_and_nothing_is_queried(tmp_path, backend, config):
    config["cfg"] = _gcfg(backends=False)
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 1
    out = _json(res)
    assert {(r["status"], r["kind"]) for r in out["rules"]} == {("error", "backend")}
    assert backend.calls == []


def test_a_backend_without_a_workspace_is_an_error_and_nothing_is_queried(tmp_path, backend, config):
    """The backend is named and found, its workspace empty: the rule loads disabled — said, never sent."""
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig
    config["cfg"] = GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-main", type="azure_monitor", workspace_id="")])
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 1
    assert {(r["kind"], "aucun workspace" in r["error"]) for r in _json(res)["rules"]} == {("backend", True)}
    assert backend.calls == []


def test_an_approved_rule_on_no_backend_is_an_error(tmp_path, backend, config):
    """The inline form an approval wrote before P1: a workspace, no backend, auto-apply on no VM."""
    _layer(f"rules:\n  - name: log-clearing\n    workspace_id: {WS}\n    query: |\n      Syslog | take 1\n")
    out = _json(_check("--rules", _base(tmp_path), "--live", "--json"))
    approved = _by_name(out)["log-clearing"]
    assert approved["layer"] == "client" and approved["status"] == "error" and approved["kind"] == "backend"
    assert "aucune VM" in approved["error"]
    assert len(backend.calls) == 2                       # the two base rules ran; not the unbound one


def test_the_client_layer_is_checked_as_the_watch_loads_it(tmp_path, backend, config):
    _layer("rules:\n  - name: log-clearing\n    assets: [auto]\n    monitoring_backends: [law-main]\n"
           "    query: |\n      NoSuchTable | take 1\n")
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 1
    approved = _by_name(_json(res))["log-clearing"]
    assert (approved["layer"], approved["status"], approved["kind"]) == ("client", "error", "table")


def test_a_static_rule_on_no_resource_and_an_unknown_source_are_errors(tmp_path, backend, config):
    base = BASE + ("  - name: on-nothing\n    assets: [undefined-asset]\n    monitoring_backends: [law-main]\n"
                   "    query: |\n      Syslog | take 1\n"
                   f"  - name: elsewhere\n    source: prometheus\n    workspace_id: {WS}\n"
                   "    query: up\n")
    out = _json(_check("--rules", _base(tmp_path, base), "--live", "--json"))
    assert _by_name(out)["on-nothing"]["status"] == "error"
    assert _by_name(out)["elsewhere"]["status"] == "error" and "prometheus" in _by_name(out)["elsewhere"]["error"]


def test_a_query_without_an_answer_is_said_without_a_loop(tmp_path, backend, config):
    base = BASE.replace('Syslog | where SyslogMessage has "USER=root"', "Syslog // SLOW")
    started = time.monotonic()
    res = _check("--rules", _base(tmp_path, base), "--live", "--json", "--query-timeout", "0.3")
    assert time.monotonic() - started < 5
    assert res.exit_code == rule_check.EXIT_TIMEOUT
    slow = _by_name(_json(res))["sudo-root"]
    assert slow["status"] == "timeout" and slow["kind"] == "timeout" and "0.3 s" in slow["error"]
    assert sum("SLOW" in q for q, _ in backend.calls) == 1        # sent once, never again


def test_the_whole_check_is_bounded_too(tmp_path, backend, config):
    base = "rules:\n" + "".join(f"  - name: slow-{i}\n    assets: [auto]\n    query: |\n      Syslog // SLOW {i}\n"
                                for i in range(5))
    started = time.monotonic()
    res = _check("--rules", _base(tmp_path, base), "--live", "--json", "--query-timeout", "0.4", "--total", "0.6")
    assert time.monotonic() - started < 5
    out = _json(res)
    assert res.exit_code == rule_check.EXIT_TIMEOUT
    assert [r["kind"] for r in out["rules"]] == ["timeout", "timeout", "budget", "budget", "budget"]
    assert len(backend.calls) == 2                                   # the rules past the budget never sent


def test_the_last_query_gets_what_is_left_of_the_total_not_more(backend, config):
    from glorfindel.detection_rules import DetectionRule
    rules = [DetectionRule(name=f"slow-{i}", source="azure_monitor", workspace_id=WS, query=f"Syslog // SLOW {i}",
                           ttp="", resource_id="", auto_apply=True, monitoring_backend_name="law-main")
             for i in range(3)]
    started = time.monotonic()
    out = rule_check.check_rules(rules, live=True, query_timeout_s=1.0, total_s=1.5)
    elapsed = time.monotonic() - started
    assert 1.4 <= elapsed < 1.8, elapsed                  # 1.0 + the 0.5 left — never 1.0 + 1.0
    assert [o.kind for o in out] == ["timeout", "timeout", "budget"]


@pytest.mark.parametrize("args", [("--query-timeout", "0"), ("--total", "inf"), ("--total", "99999")])
def test_the_bounds_are_bounded(tmp_path, backend, config, args):
    from glorfindel.cli import cli
    res = CliRunner().invoke(cli, ["rules", "check", "--rules", _base(tmp_path), *args])
    assert res.exit_code == 2 and backend.calls == []


def test_without_live_nothing_is_queried(tmp_path, backend, config):
    res = _check("--rules", _base(tmp_path), "--json")
    assert res.exit_code == 0 and _json(res)["live"] is False
    assert backend.made == [] and backend.calls == []


def test_nothing_is_written_no_poller_no_model(tmp_path, backend, config, monkeypatch):
    """Read-only: no rule status, no dispatch, no model, no file anywhere under HOME."""
    import glorfindel.detection_rules as dr

    def forbidden(*a, **k):
        raise AssertionError("written")
    monkeypatch.setattr(dr, "_save_status", forbidden)
    monkeypatch.setattr(dr.RulePoller, "__init__", forbidden)
    try:
        import litellm
        monkeypatch.setattr(litellm, "completion", forbidden)
    except ImportError:
        pass
    monkeypatch.setenv("HOME", str(tmp_path / "home"))            # Path.home(), for anything that asks
    monkeypatch.setattr(dr, "_STATUS_FILE", tmp_path / "glorfindel-home" / "rule_status.json")
    _layer("rules: []\n")                                          # the client's layer: read, never written
    base = _base(tmp_path, BASE.replace('"USER=root"', '"USER=root" // ROWS'))
    tree = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    res = _check("--rules", base, "--live", "--json")
    assert res.exit_code == 0, res.output
    assert {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")} == tree


def test_a_config_refused_by_a3_is_an_error_its_words_in_the_terminal_only(tmp_path, backend, monkeypatch):
    import glorfindel.config as config

    def refused(*a, **k):
        raise config.ConfigError(f"clé inconnue : quarantaine_nsg (workspace {WS})")
    monkeypatch.setattr(config, "load_glorfindel_config", refused)
    res = _check("--rules", _base(tmp_path), "--live", "--json")
    assert res.exit_code == 1
    out = _json(res)
    assert "A3" in out["error"] and "quarantaine_nsg" not in res.output and WS not in res.output
    human = _check("--rules", _base(tmp_path), "--live")
    assert human.exit_code == 1 and "quarantaine_nsg" in human.output


def test_no_rule_loaded_is_an_error(tmp_path, backend, config):
    res = _check("--rules", _base(tmp_path, "rules: []\n"), "--live", "--json")
    assert res.exit_code == 1 and "aucune règle" in _json(res)["error"]


def test_the_terminal_says_each_rule(tmp_path, backend, config):
    base = BASE.replace('Syslog | where SyslogMessage has "USER=root"', "BROKEN( | take 1")
    res = _check("--rules", _base(tmp_path, base), "--live")
    assert res.exit_code == 1
    assert "ssh-brute-force" in res.output and "sudo-root" in res.output
    assert "1 ok, 1 en erreur, 0 sans réponse" in " ".join(res.output.split())


def test_glorfindel_rules_still_lists(tmp_path, config):
    from glorfindel.cli import cli
    res = CliRunner().invoke(cli, ["rules", "--rules", _base(tmp_path)], catch_exceptions=False)
    assert res.exit_code == 0 and "ssh-brute-force" in res.output and "Couche du client" in res.output


def test_the_groups_rules_option_reaches_check(tmp_path, backend, config):
    from glorfindel.cli import cli
    res = CliRunner().invoke(cli, ["rules", "--rules", _base(tmp_path), "check", "--json"], catch_exceptions=False)
    assert res.exit_code == 0 and _json(res)["counts"]["ok"] == 2


# ── the reduction ──────────────────────────────────────────────────────────────────

def test_scrub_keeps_the_kind_never_where():
    s = rule_check.scrub(f"workspace {WS} at {VM_ID} via https://api.example.net/v1?x=1 from 10.1.2.3:443 "
                         "host vm-a.internal.example.net, user ops@example.org, name 'vm-example-01', table 'Perf', "
                         "file client_rules.yaml")
    for gone in (WS, SUB, "rg-example", "api.example.net", "10.1.2.3", "internal.example.net", "ops@example.org",
                 "vm-example-01"):
        assert gone not in s, gone
    assert "'Perf'" in s and "client_rules.yaml" in s
    assert len(rule_check.scrub("x" * 1000)) <= 200 and "\n" not in rule_check.scrub("a\nb")


def test_reduce_error_takes_the_innermost_message():
    kind, line, full = rule_check.reduce_error(Exception(AZURE_TABLE))
    assert kind == "table" and line.startswith("'where' operator: Failed to resolve table") and "SEM0100" in full


@pytest.mark.parametrize("text, kind", [
    ("(AuthorizationFailed) The client does not have authorization", "access"),
    ("(WorkspaceNotFound) The workspace could not be found", "workspace"),
    ("(BadArgumentError) Query could not be parsed", "syntax"),
    ("ServiceRequestError: connection reset", "other"),
])
def test_errors_are_classified(text, kind):
    assert rule_check.classify(text) == kind
