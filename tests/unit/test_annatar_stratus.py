"""R2 — the Stratus Red Team adapter: a technique id is resolved against a CLOSED allow-list
(the catalog's ``engine: stratus`` entries), the pinned binary is checked at run time, the
warmup → detonate → revert → cleanup cycle runs from an armed Orodruin with every phase
journaled, and a read-only Graph probe verifies the initial state before and after. Anything the
adapter cannot run faithfully is refused (fail closed). No Azure, no LLM, no subprocess reaches a
real binary — a FAKE Stratus (an injected runner) and dry_run throughout.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from annatar.engines.stratus import (
    BINARY_LABEL,
    PHASES,
    STRATUS_DIR,
    GraphProbe,
    StratusError,
    airgap_env,
    allowed_techniques,
    describe,
    pinned_digests,
    resolve,
    verify_binary,
)
from annatar.executors.stratus_host import StratusExecutor, staged_layout
from annatar.runner.engine import Engine
from annatar.runner.parser import KNOWN_ENGINES, Scenario, ScenarioParser
from eregion_core.orodruin import CapReached, Passive, Session

TID = "azure.execution.vm-run-command"
FIC = "azure.persistence.backdoor-managed-identity-fic"
RG_SCOPE = "/subscriptions/sub-123/resourceGroups/rg-celebrimbor"
ENROLLED = {"eregion-target": "celebrimbor", "eregion-zone": "bench"}


# ── A temp pinned binary, to exercise the guards deterministically ────────────────────

def _fake_binary(tmp_path: Path, content: bytes = b"fake-stratus-binary\n") -> tuple[Path, str]:
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    path = d / "stratus"
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def _stratus_dir(tmp_path: Path, digest: str) -> Path:
    d = tmp_path / "pin"
    d.mkdir(exist_ok=True)
    (d / "PIN").write_text(f"#   {digest}  {BINARY_LABEL}\n", encoding="utf-8")
    return d


def _catalog(engine_ref: str = TID, **over) -> dict:
    entry = {"ttp": "T1651", "tactic": "execution", "status": "planned",
             "name": "Run Command", "engine": "stratus", "engine_ref": engine_ref}
    entry.update(over)
    return {entry["ttp"]: entry}


def _session(tmp_path: Path, max_injections: int = 20) -> Session:
    return Session(run_id="r1", injector="annatar", max_injections=max_injections,
                   path=tmp_path / "audit.jsonl", offhost=lambda *a, **k: None)


def _journal(session: Session) -> list[dict]:
    return [json.loads(x) for x in session.path.read_text().splitlines() if x.strip()]


def _ok_run(record: list | None = None):
    def run(argv, **kw):
        if record is not None:
            record.append(SimpleNamespace(argv=argv, env=kw.get("env")))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    return run


# ── The closed allow-list is the catalog (fail closed on the rest) ────────────────────

def test_allowed_techniques_is_the_catalog_closed_list():
    allowed = allowed_techniques()
    assert TID in allowed and FIC in allowed
    assert all(a.startswith("azure.") for a in allowed)


def test_resolve_refuses_a_technique_off_the_allowlist(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    with pytest.raises(StratusError, match="closed allow-list"):
        resolve("azure.execution.not-in-catalog", binary_path=binary,
                stratus_dir=_stratus_dir(tmp_path, digest), catalog=_catalog())


@pytest.mark.parametrize("bad", [
    "aws.execution.vm-run-command",          # not Azure
    "gcp.persistence.x",                      # not Azure
    "azure.execution.vm-run-command/extra",   # a path separator
    "azure.Execution.vm-run-command",         # upper case
    "azure.execution.--help",                 # an option-looking segment
    "azure.execution.vm run command",         # a space
    "",                                        # empty
])
def test_resolve_refuses_a_malformed_id(tmp_path, bad):
    binary, digest = _fake_binary(tmp_path)
    with pytest.raises(StratusError):
        resolve(bad, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog(engine_ref=bad))


# ── The pinned binary is checked at run time (SEC5) ───────────────────────────────────

def test_verify_binary_accepts_the_pinned_bytes(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    assert verify_binary(binary, _stratus_dir(tmp_path, digest)) == digest


def test_verify_binary_refuses_a_changed_binary(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    binary.write_bytes(b"tampered\n")   # the bytes on disk are no longer the pinned ones
    with pytest.raises(StratusError, match="does not match its sha256"):
        verify_binary(binary, _stratus_dir(tmp_path, digest))


def test_verify_binary_refuses_when_pin_has_no_binary(tmp_path):
    binary, _ = _fake_binary(tmp_path)
    d = tmp_path / "stratus"
    d.mkdir()
    (d / "PIN").write_text("# a PIN with no binary line\n", encoding="utf-8")
    with pytest.raises(StratusError, match="no sha256"):
        verify_binary(binary, d)


def test_verify_binary_refuses_a_missing_binary(tmp_path):
    digest = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(StratusError, match="cannot be read"):
        verify_binary(tmp_path / "absent", _stratus_dir(tmp_path, digest))


def test_repo_pin_records_the_stratus_binary():
    """The committed PIN carries the v2.38.0 Linux x86_64 binary digest the adapter checks."""
    digests = pinned_digests(STRATUS_DIR)
    assert digests.get(BINARY_LABEL) == \
        "376ceff19c170194f6adbc2f883e8b5658e99a13cb1057f0ab118524411d57bb"


# ── A resolved technique carries its phases, verified binary and probe ────────────────

def test_resolve_builds_the_four_phases(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    r = resolve(TID, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog())
    assert [p.name for p in r.phases] == ["warmup", "detonate", "revert", "cleanup"]
    for p in r.phases:
        assert p.argv == [str(binary), p.name, TID]   # the exact process argv: binary phase id
    assert r.binary_digest == digest
    assert r.ttp == "T1651" and r.tactic == "execution"
    assert r.graph_probe is None


def test_graph_probe_defaults_to_expect_absent(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    cat = _catalog(engine_ref=FIC, graph_probe={   # no expect_absent → defaults to True
        "name": "fic-absent", "read": "/v1.0/applications?$select=id"})
    r = resolve(FIC, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest), catalog=cat)
    assert r.graph_probe.expect_absent is True


def test_resolve_parses_a_read_only_graph_probe(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    cat = _catalog(engine_ref=FIC, graph_probe={
        "name": "fic-absent", "read": "/v1.0/applications?$select=id", "expect_absent": True})
    r = resolve(FIC, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest), catalog=cat)
    assert r.graph_probe.request() == ("GET", "/v1.0/applications?$select=id")


def test_describe_needs_no_binary(tmp_path):
    info = describe(TID, catalog=_catalog())
    assert info["technique_id"] == TID and info["phases"] == list(PHASES)


def test_describe_fails_closed_off_the_allowlist():
    with pytest.raises(StratusError, match="closed allow-list"):
        describe("azure.execution.nope", catalog=_catalog())


# ── The Graph probe can only read ─────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "https://graph.microsoft.com/v1.0/applications",   # a scheme/host
    "/beta/applications",                               # not v1.0
    "/v1.0/applications\n/users",                       # a newline
    "/v1.0/app lications",                              # a space
    "/v1.0/<script>",                                   # angle brackets
])
def test_graph_probe_rejects_a_non_read_path(bad):
    with pytest.raises(StratusError, match="can only read"):
        GraphProbe(name="p", read=bad).request()


def test_graph_probe_holds_on_absence_and_presence():
    probe = GraphProbe(name="p", read="/v1.0/applications", expect_absent=True)
    assert probe.holds({"value": []}) is True        # absent as expected
    assert probe.holds({"value": [{"id": "x"}]}) is False  # present: not clean
    present = GraphProbe(name="p", read="/v1.0/applications", expect_absent=False)
    assert present.holds({"value": [{"id": "x"}]}) is True


# ── The offline environment (Orodruin has no Internet) ────────────────────────────────

def test_airgap_env_points_terraform_offline(tmp_path):
    env = airgap_env(tmp_path / "home", plugin_cache=tmp_path / "cache",
                     terraformrc=tmp_path / "rc")
    assert env["HOME"] == str(tmp_path / "home")
    assert env["TF_PLUGIN_CACHE_DIR"] == str(tmp_path / "cache")
    assert env["TF_CLI_CONFIG_FILE"] == str(tmp_path / "rc")


def test_staged_layout_reads_the_environment():
    layout = staged_layout(env={"EREGION_STRATUS_BINARY": "/x/stratus"})
    assert layout.binary == "/x/stratus"
    assert layout.home and layout.plugin_cache and layout.terraformrc   # defaults for the rest


# ── The executor journals every phase through the armed contract ──────────────────────

def _executor(tmp_path, *, dry_run=False, run=None, get=None, session=None, record=None):
    binary, digest = _fake_binary(tmp_path)
    r = resolve(TID, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog(graph_probe={"name": "absent",
                                              "read": "/v1.0/applications?$select=id"}))
    return StratusExecutor(r, session if session is not None else _session(tmp_path),
                           target=RG_SCOPE, dry_run=dry_run,
                           run=run or _ok_run(record), get=get)


def test_executor_journals_each_phase_before_it_runs(tmp_path):
    session = _session(tmp_path)
    ex = _executor(tmp_path, session=session)
    for name in PHASES:
        ex.run_phase(name)
    assert session.calls == len(PHASES)   # four injector calls, counted against the cap
    journal = _journal(session)
    actions = [r["action"] for r in journal if r.get("outcome") == "about_to_call"]
    assert actions == [f"stratus:{p}" for p in PHASES]
    assert all(r["target"] == RG_SCOPE for r in journal)


def test_executor_sends_the_exact_argv_and_offline_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # inherited by the subprocess
    record: list = []
    ex = _executor(tmp_path, record=record)
    ex.detonate()
    assert record[0].argv[1:] == ["detonate", TID]
    assert record[0].env["AZURE_SUBSCRIPTION_ID"] == "sub-123"   # credentials inherited
    assert record[0].env["HOME"] == ex.layout.home               # offline override layered on
    assert "TF_PLUGIN_CACHE_DIR" in record[0].env


def test_executor_passive_without_a_session(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    r = resolve(TID, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog())
    ex = StratusExecutor(r, None, target=RG_SCOPE, run=_ok_run())   # no armed contract
    with pytest.raises(Passive):
        ex.warmup()


def test_executor_dry_run_starts_no_process_and_journals_nothing(tmp_path):
    session = _session(tmp_path)

    def boom(*a, **k):
        raise AssertionError("no process in dry_run")

    ex = _executor(tmp_path, dry_run=True, run=boom, session=session)
    assert ex.warmup() == ""
    assert session.calls == 0           # nothing runs, nothing is counted
    assert not session.path.exists()    # nothing is journaled


def test_executor_raises_on_a_nonzero_exit(tmp_path):
    def fail(argv, **k):
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")

    ex = _executor(tmp_path, run=fail)
    with pytest.raises(RuntimeError, match="exited 1"):
        ex.detonate()


def test_executor_cap_is_enforced(tmp_path):
    ex = _executor(tmp_path, session=_session(tmp_path, max_injections=2))
    ex.warmup()
    ex.detonate()
    with pytest.raises(CapReached):
        ex.revert()


# ── The read-only Graph probe (before / after) ────────────────────────────────────────

def test_graph_probe_reads_and_is_declared_not_counted(tmp_path):
    session = _session(tmp_path)
    seen: list = []

    def get(path):
        seen.append(path)
        return {"value": []}   # the technique's objects are absent — the initial state holds

    ex = _executor(tmp_path, session=session, get=get)
    assert ex.probe_initial_state("before") is True
    assert seen == ["/v1.0/applications?$select=id"]
    assert session.calls == 0   # a read: declared, never counted against the cap
    declared = [r for r in _journal(session) if r.get("outcome") == "declared"]
    assert declared and declared[0]["action"] == "stratus:graph-probe:before"


def test_graph_probe_none_when_the_technique_declares_none(tmp_path):
    binary, digest = _fake_binary(tmp_path)
    r = resolve(TID, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog())   # no graph_probe
    ex = StratusExecutor(r, _session(tmp_path), target=RG_SCOPE, run=_ok_run())
    assert ex.probe_initial_state("before") is None


# ── Engine dispatch: the cycle on the control plane ───────────────────────────────────

def _scenario(**over) -> Scenario:
    raw = {"name": "stratus run", "mitre": "T1651", "engine": "stratus", "engine_ref": TID,
           "target": {"type": "azure_subscription", "resource_group": "rg-celebrimbor",
                      "subscription_id": "sub-123"},
           "detection": {"timeout": "300s"}}
    raw.update(over)
    return Scenario(name=raw["name"], description="", mitre=raw["mitre"], version="1.0.0",
                    target=raw["target"], setup=[], steps=[], detection=raw["detection"],
                    detection_hints={}, raw=raw, engine="stratus", engine_ref=raw["engine_ref"])


def _fake_executor(tmp_path, *, before=True, after=True, rg_tags=None, detonate_raises=False):
    binary, digest = _fake_binary(tmp_path)
    r = resolve(TID, binary_path=binary, stratus_dir=_stratus_dir(tmp_path, digest),
                catalog=_catalog())
    calls: list = []

    class Fake:
        target = RG_SCOPE
        binary_digest = r.binary_digest
        resolved = r

        def resource_group_tags(self, sub, rg):
            return ENROLLED if rg_tags is None else rg_tags

        def warmup(self):
            calls.append("warmup")

        def detonate(self):
            calls.append("detonate")
            if detonate_raises:
                raise RuntimeError("detonate failed")

        def revert(self):
            calls.append("revert")

        def cleanup(self):
            calls.append("cleanup")

        def probe_initial_state(self, when):
            calls.append(f"probe:{when}")
            return before if when == "before" else after

    return Fake(), r, calls


def _signals(tmp_path):
    out = []
    for f in (tmp_path / "runs" / "annatar").glob("*_signals.jsonl"):
        out += [json.loads(x)["event"] for x in f.read_text().splitlines() if x.strip()]
    return out


def _report(tmp_path):
    return json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())


def test_run_stratus_cycle_runs_all_phases_and_emits_attack_started(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake, r, calls = _fake_executor(tmp_path)
    engine = Engine()
    engine._run_stratus_cycle(_scenario(), fake, "20260101T000000Z", r)
    assert calls == ["warmup", "probe:before", "detonate", "revert", "cleanup", "probe:after"]
    assert "attack_started" in _signals(tmp_path)
    rpt = _report(tmp_path)
    assert rpt["result"] == "PASS"
    assert rpt["metrics"]["engine"] == "stratus"
    assert rpt["metrics"]["detection"] == "unknown"      # control-plane detection is ID1
    assert "ID1" in rpt["metrics"]["detection_note"]


def test_run_stratus_cycle_cleans_up_even_when_detonate_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake, r, calls = _fake_executor(tmp_path, detonate_raises=True)
    engine = Engine()
    with pytest.raises(RuntimeError, match="detonate failed"):
        engine._run_stratus_cycle(_scenario(), fake, "20260101T000001Z", r)
    assert "cleanup" in calls                       # the prerequisites are always destroyed
    assert "attack_started" not in _signals(tmp_path)   # no effect, no signal


def test_run_stratus_cycle_does_not_detonate_on_a_dirty_initial_state(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake, r, calls = _fake_executor(tmp_path, before=False)
    engine = Engine()
    out = engine._run_stratus_cycle(_scenario(), fake, "20260101T000002Z", r)
    assert "detonate" not in calls
    assert out.detection == "unknown" and out.error and "not clean" in out.error
    assert "cleanup" in calls   # warmup provisioned, so cleanup still destroys


def test_run_stratus_refuses_an_unenrolled_group(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    fake, r, _ = _fake_executor(tmp_path, rg_tags={})   # no enrollment tags
    engine = Engine()
    out = engine._run_stratus(_scenario(), "20260101T000003Z", _session(tmp_path), r,
                              executor=fake)
    assert out.refused and out.error.startswith("safety:")


def test_run_stratus_refuses_a_target_without_subscription(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    fake, r, _ = _fake_executor(tmp_path)
    sc = _scenario(target={"type": "azure_subscription", "resource_group": "rg-celebrimbor"})
    out = Engine()._run_stratus(sc, "20260101T000004Z", _session(tmp_path), r, executor=fake)
    assert out.refused and "subscription_id" in out.error


# ── Authoring + dispatch surface ──────────────────────────────────────────────────────

def test_known_engines_has_stratus():
    assert "stratus" in KNOWN_ENGINES


def test_parser_accepts_a_stratus_scenario(tmp_path):
    import yaml
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump({
        "name": "s", "description": "d", "mitre": "T1651", "engine": "stratus",
        "engine_ref": TID,
        "target": {"type": "azure_subscription", "resource_group": "rg-celebrimbor"},
    }), encoding="utf-8")
    assert ScenarioParser().validate(str(path)).valid


def test_parser_refuses_a_stratus_scenario_without_engine_ref(tmp_path):
    import yaml
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump({
        "name": "s", "description": "d", "mitre": "T1651", "engine": "stratus",
        "target": {"type": "azure_subscription", "resource_group": "rg-celebrimbor"},
    }), encoding="utf-8")
    result = ScenarioParser().validate(str(path))
    assert not result.valid and any("engine_ref" in e for e in result.errors)


def test_dry_run_display_shows_the_cycle(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    import yaml
    path = tmp_path / "s.yaml"
    path.write_text(yaml.safe_dump({
        "name": "s", "description": "d", "mitre": "T1651", "engine": "stratus",
        "engine_ref": TID,
        "target": {"type": "azure_subscription", "resource_group": "rg-celebrimbor"},
        "detection": {"timeout": "300s"},
    }), encoding="utf-8")
    Engine(dry_run=True).run(str(path), skip_confirm=True)
    out = capsys.readouterr().out
    assert TID in out and "warmup" in out and "detonate" in out
