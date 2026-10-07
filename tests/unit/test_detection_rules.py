from __future__ import annotations

import textwrap
import time


from glorfindel.detection_rules import (
    DetectionRule,
    RulePoller,
    _load_status,
    _save_status,
    load_rules,
    load_config,
    normalize_row,
    rulepoller_recently_matched,
)


# ── load_config (new format) ────────────────────────────────────────────────────

NEW_FORMAT_YAML = textwrap.dedent("""\
    monitoring_backends:
      - name: law-test
        type: azure_monitor
        workspace_id: ws-abc

    assets:
      - name: vm-test
        type: azure_vm
        resource_id: /subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1
        monitoring_backends: [law-test]

    rules:
      - name: test-rule
        ttp: T1486
        assets: [vm-test]
        interval_s: 30
        enabled: true
        description: Test rule new format
        query: "Perf | limit 1"
""")


def test_load_config_new_format(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    cfg = load_config(f)
    assert len(cfg.backends) == 1
    assert cfg.backends[0].name == "law-test"
    assert cfg.backends[0].workspace_id == "ws-abc"
    assert len(cfg.assets) == 1
    assert cfg.assets[0].name == "vm-test"
    assert cfg.assets[0].monitoring_backends == ["law-test"]
    assert len(cfg.rules) == 1
    r = cfg.rules[0]
    assert r.workspace_id == "ws-abc"   # resolved from backend
    assert r.resource_id == "/subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    assert r.source == "azure_monitor"  # resolved from backend type
    assert r.asset_name == "vm-test"
    assert r.monitoring_backend_name == "law-test"


def test_load_config_backend_lookup(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    cfg = load_config(f)
    assert cfg.backend("law-test") is not None
    assert cfg.backend("nonexistent") is None
    assert cfg.asset("vm-test") is not None
    assert cfg.asset_for_resource(
        "/subscriptions/sub/rg/providers/Microsoft.Compute/virtualMachines/vm1"
    ) is not None


def test_load_config_empty_resolves_gracefully(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(textwrap.dedent("""\
        monitoring_backends: []
        assets: []
        rules: []
    """))
    cfg = load_config(f)
    assert cfg.backends == []
    assert cfg.assets == []
    assert cfg.rules == []


def test_load_rules_new_format_backward_compat(tmp_path):
    """load_rules() still works with new format."""
    f = tmp_path / "rules.yaml"
    f.write_text(NEW_FORMAT_YAML)
    rules = load_rules(f)
    assert len(rules) == 1
    assert rules[0].workspace_id == "ws-abc"


# ── backend binding: rules bind to glorfindel-config, not a brittle name match ───

def _auto_rule_yaml(backends_block: str, rule_backend_line: str) -> str:
    return (
        "monitoring_backends:\n" + backends_block +
        "rules:\n"
        "  - name: disk-write\n"
        "    ttp: T1486\n"
        "    assets: [auto]\n"
        + rule_backend_line +
        '    query: "Perf | limit 1"\n'
    )


_ONE_BACKEND = "  - name: law-prod\n    type: azure_monitor\n    workspace_id: ws-prod\n"


def test_rule_falls_back_to_single_backend_on_name_mismatch(tmp_path, caplog):
    """Rule names a backend absent from config → binds to the single config backend,
    loudly (never an empty workspace_id in silence)."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, "    monitoring_backends: [law-annatar]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"             # bound to the config backend
    assert r.source == "azure_monitor"
    assert r.monitoring_backend_name == "law-prod"  # resolved name drives asset matching
    assert r.enabled is True
    assert any("law-annatar" in m for m in caplog.messages)  # warned, not silent


def test_rule_binds_to_single_backend_when_unnamed(tmp_path):
    """Rule with no monitoring_backends → uses the single config backend directly."""
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, ""))
    r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"
    assert r.monitoring_backend_name == "law-prod"
    assert r.enabled is True


def test_named_backend_is_honored_without_fallback(tmp_path, caplog):
    """A correctly named backend resolves to itself, no fallback warning."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(_ONE_BACKEND, "    monitoring_backends: [law-prod]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == "ws-prod"
    assert r.monitoring_backend_name == "law-prod"
    assert not [m for m in caplog.messages if "limit" not in m]  # no backend warning


def test_rule_disabled_when_no_backend(tmp_path, caplog):
    """No backend resolvable → empty workspace → rule DISABLED + warned (not silent)."""
    import logging
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml("monitoring_backends: []\n",
                                 "    monitoring_backends: [law-annatar]\n"))
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.workspace_id == ""
    assert r.enabled is False
    assert any("cannot run" in m or "no workspace_id" in m for m in caplog.messages)


def _rule(name="r", ws="ws", enabled=True):
    return DetectionRule(
        name=name, source="azure_monitor", workspace_id=ws, query="q",
        ttp="T1486", resource_id="", enabled=enabled,
    )


def test_has_recognized_indicator():
    """Curated threat indicators are recognized; a generic-fallback column or empty row
    is NOT (drives the decide deterministic guardrail)."""
    from glorfindel.detection_rules import has_recognized_indicator
    assert has_recognized_indicator({"Computer": "vm", "MaxWrite": 1e8}) is True
    assert has_recognized_indicator(
        {"Computer": "vm", "FailedAttempts": 40, "SourceIP": "1.2.3.4"}) is True
    assert has_recognized_indicator({"SyslogMessage": "sudo: USER=root"}) is True
    # generic fallback (unknown column) → NOT a recognized threat indicator
    assert has_recognized_indicator({"Activity": "anomalous login", "Computer": "vm"}) is False
    assert has_recognized_indicator({}) is False


def test_syslog_is_characterized_only_by_a_curated_pattern():
    """SyslogMessage is a log SOURCE: its mere presence no longer counts. Curated
    patterns do — USER=root and account creation (real T1136.001 rows)."""
    from glorfindel.detection_rules import has_recognized_indicator, normalize_row
    t1136 = ("new user: name=testuser-annatar, UID=2001, GID=2001, "
             "home=/home/testuser-annatar, shell=/sbin/nologin")
    assert has_recognized_indicator({"SyslogMessage": t1136}) is True
    assert has_recognized_indicator({"SyslogMessage": "sudo: USER=root ; COMMAND=/bin/sh"}) is True
    assert has_recognized_indicator({"SyslogMessage": "CRON[812]: session opened for user root"}) is False
    assert has_recognized_indicator({"SyslogMessage": "systemd[1]: Started Daily apt."}) is False
    # What the LLM sees is unchanged (normalize_row untouched → no prompt change).
    assert normalize_row({"SyslogMessage": t1136})["indicator_key"] == "syslog_event"


def test_detection_inert_true_when_nothing_can_poll():
    """No rule with a resolved workspace_id (empty config) or all disabled → inert."""
    from glorfindel.detection_rules import detection_inert
    assert detection_inert([_rule(ws=""), _rule(ws="", enabled=False)]) is True
    assert detection_inert([]) is True


def test_detection_inert_false_with_one_pollable_rule():
    from glorfindel.detection_rules import detection_inert, pollable_rules
    rules = [_rule(name="dead", ws=""), _rule(name="live", ws="ws-1")]
    assert detection_inert(rules) is False
    assert [r.name for r in pollable_rules(rules)] == ["live"]


def test_rule_disabled_when_ambiguous_backends(tmp_path, caplog):
    """Several backends of the type and none named → ambiguous → disabled + warned."""
    import logging
    two = (
        "  - name: law-a\n    type: azure_monitor\n    workspace_id: ws-a\n"
        "  - name: law-b\n    type: azure_monitor\n    workspace_id: ws-b\n"
    )
    f = tmp_path / "rules.yaml"
    f.write_text(_auto_rule_yaml(two, ""))  # no name → ambiguous
    with caplog.at_level(logging.WARNING, logger="glorfindel.detection_rules"):
        r = load_config(f).rules[0]
    assert r.enabled is False
    assert any("disambiguate" in m for m in caplog.messages)


# ── load_rules (legacy format) ──────────────────────────────────────────────────

VALID_YAML = textwrap.dedent("""\
    rules:
      - name: test-rule
        source: azure_monitor
        workspace_id: ws-123
        query: "Perf | limit 1"
        ttp: T1486
        resource_id: /subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1
        interval_s: 30
        enabled: true
        description: Test rule
""")


def test_load_rules_valid(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text(VALID_YAML)
    rules = load_rules(f)
    assert len(rules) == 1
    r = rules[0]
    assert r.name == "test-rule"
    assert r.source == "azure_monitor"
    assert r.ttp == "T1486"
    assert r.interval_s == 30.0
    assert r.enabled is True


def test_load_rules_missing_file(tmp_path):
    rules = load_rules(tmp_path / "nonexistent.yaml")
    assert rules == []


def test_load_rules_empty_file(tmp_path):
    f = tmp_path / "empty.yaml"
    f.write_text("")
    rules = load_rules(f)
    assert rules == []


def test_load_rules_disabled_skipped(tmp_path):
    yaml = textwrap.dedent("""\
        rules:
          - name: active-rule
            source: azure_monitor
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1486
            resource_id: /subscriptions/sub/rg/vm1
            enabled: true
          - name: disabled-rule
            source: azure_monitor
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1110
            resource_id: /subscriptions/sub/rg/vm1
            enabled: false
    """)
    f = tmp_path / "rules.yaml"
    f.write_text(yaml)
    rules = load_rules(f)
    assert len(rules) == 1
    assert rules[0].name == "active-rule"


def test_load_rules_defaults(tmp_path):
    yaml = textwrap.dedent("""\
        rules:
          - name: minimal
            workspace_id: ws-1
            query: "Perf | limit 1"
            ttp: T1486
            resource_id: /subscriptions/sub/rg/vm1
    """)
    f = tmp_path / "rules.yaml"
    f.write_text(yaml)
    rules = load_rules(f)
    assert rules[0].source == "azure_monitor"
    assert rules[0].interval_s == 30.0
    assert rules[0].description == ""


# ── status persistence ───────────────────────────────────────────────────────────

# ── rulepoller_recently_matched ───────────────────────────────────────────────

def test_rulepoller_recently_matched_true(tmp_path, monkeypatch):
    """Returns True when a matching TTP had a recent match."""
    from datetime import datetime, timezone
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    now_iso = datetime.now(timezone.utc).isoformat()
    _save_status({"sudo-rule": {"last_match": now_iso, "ttp": "T1548.003"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is True


def test_rulepoller_recently_matched_expired(tmp_path, monkeypatch):
    """Returns False when the last match is older than within_s."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    old_iso = "2020-01-01T00:00:00+00:00"
    _save_status({"sudo-rule": {"last_match": old_iso, "ttp": "T1548.003"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_rulepoller_recently_matched_wrong_ttp(tmp_path, monkeypatch):
    """Returns False when TTP doesn't match."""
    from datetime import datetime, timezone
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    now_iso = datetime.now(timezone.utc).isoformat()
    _save_status({"ssh-rule": {"last_match": now_iso, "ttp": "T1110.001"}})
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_rulepoller_recently_matched_no_status(tmp_path, monkeypatch):
    """Returns False when no status file exists."""
    monkeypatch.setattr("glorfindel.detection_rules._STATUS_FILE", tmp_path / "rs.json")
    assert rulepoller_recently_matched("T1548.003", within_s=300) is False


def test_poller_stores_ttp_in_status():
    """rule_status.json must include ttp after a match — required by rulepoller_recently_matched."""
    rule = _make_rule(name="test-rule", ttp="T1548.003")
    p, _ = _poller(_Det([{"TimeGenerated": "2026-06-01T13:00:00Z", "Computer": "vm1"}]), [rule])
    p.poll_once(rule)
    assert _load_status().get("test-rule", {}).get("ttp") == "T1548.003"


def test_status_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "rule_status.json",
    )
    _save_status({"rule-a": {"last_poll": "2026-01-01T00:00:00+00:00", "match_count": 3}})
    loaded = _load_status()
    assert loaded["rule-a"]["match_count"] == 3


def test_load_status_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "glorfindel.detection_rules._STATUS_FILE",
        tmp_path / "nonexistent.json",
    )
    assert _load_status() == {}


# ── normalize_row ────────────────────────────────────────────────────────────────

def test_normalize_row_disk_write():
    row = {"Computer": "vm1", "MaxWrite": 52428800, "TimeGenerated": "2026-05-31T19:00:00Z"}
    n = normalize_row(row, ttp="T1486")
    assert n["indicator_key"] == "disk_write_rate_bps"
    assert n["indicator_value"] == 52428800
    assert n["resource"] == "vm1"


def test_normalize_row_failed_auth():
    row = {"Computer": "vm1", "SourceIP": "185.220.101.1", "FailedAttempts": "34"}
    n = normalize_row(row, ttp="T1110.001")
    assert n["indicator_key"] == "failed_auth_count"
    assert n["indicator_value"] == "34"


def test_normalize_row_privilege_escalation():
    row = {"Computer": "vm1", "SyslogMessage": "sudo[12009]: USER=root COMMAND=/bin/bash"}
    n = normalize_row(row, ttp="T1548.003")
    assert n["indicator_key"] == "privilege_escalation"
    assert "USER=root" in str(n["indicator_value"])


def test_normalize_row_syslog_generic():
    row = {"Computer": "vm1", "SyslogMessage": "sshd: Accepted password for user"}
    n = normalize_row(row)
    assert n["indicator_key"] == "syslog_event"


def test_normalize_row_blob_exfil():
    row = {"AccountName": "storageannatar", "CallerIpAddress": "1.2.3.4", "PutBlobCount": 5}
    n = normalize_row(row, ttp="T1041")
    assert n["indicator_key"] == "caller_ip"
    assert n["resource"] == "storageannatar"


def test_normalize_row_unknown_fallback():
    row = {"TimeGenerated": "2026-01-01", "_ResourceId": "/sub/rg/vm"}
    n = normalize_row(row)
    assert n["indicator_key"] == "unknown"
    assert n["indicator_value"] is None


def test_normalize_row_generic_fallback():
    row = {"TimeGenerated": "2026-01-01", "MyCustomMetric": 42}
    n = normalize_row(row)
    assert n["indicator_key"] == "mycustommetric"
    assert n["indicator_value"] == 42


def test_poller_signal_contains_normalized_signal():
    """Dispatched signals must include raw_signal.normalized_signal."""
    rule = _make_rule(ttp="T1486")
    row = {"TimeGenerated": "2026-05-31T19:13:29Z", "Computer": "vm1", "MaxWrite": 60000000}
    p, sent = _poller(_Det([row]), [rule])
    p.poll_once(rule)
    norm = sent[0]["raw_signal"].get("normalized_signal", {})
    assert norm["indicator_key"] == "disk_write_rate_bps"
    assert norm["resource"] == "vm1"


# ── RulePoller ───────────────────────────────────────────────────────────────────

def _wait_for(cond, timeout: float = 5.0) -> bool:
    """Wait on a CONDITION, not a fixed duration: a 0.3s sleep failed whenever the
    poll thread hadn't run enough times yet (scheduling-dependent flake under load)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return False


def _make_rule(**kwargs) -> DetectionRule:
    base = dict(
        name="rule-x",
        source="azure_monitor",
        workspace_id="ws-1",
        query="Perf | limit 1",
        ttp="T1486",
        resource_id="/subscriptions/sub/rg/vm1",
        interval_s=0.1,
        enabled=True,
        description="",
    )
    base.update(kwargs)
    return DetectionRule(**base)


class _Asset:
    def __init__(self, name):
        self.name = name
        self.resource_id = f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/{name}"


class _Registry:
    def __init__(self, *names):
        self.assets = [_Asset(n) for n in names]

    def for_backend(self, _name):
        return self.assets


class _Det:
    """A detector whose query returns `rows` (or raises `error`); records each call."""
    def __init__(self, rows=None, error=None):
        self.rows, self.error, self.calls = list(rows or []), error, []

    def run_query(self, query, timespan=None):
        self.calls.append(timespan)
        if self.error:
            raise self.error
        return list(self.rows)


def _vm(name):
    return _Asset(name).resource_id


def _auto_rule(**kw):
    base = dict(name="ransomware-disk-write", auto_apply=True, resource_id="",
                query="Perf | where TimeGenerated > ago(10m) | summarize MaxWrite=max(CounterValue) by Computer")
    base.update(kw)
    return _make_rule(**base)


def _poller(det, rules=(), registry=None, dry_run=False, ip_owners=None, cfg=None):
    sent: list = []
    p = RulePoller(list(rules), sent.append, dry_run=dry_run, ip_owners=ip_owners)
    p._detector = lambda rule: det
    p._registry, p._cfg = registry, cfg
    return p, sent


def test_poller_dispatches_on_match():
    rule = _make_rule()
    p, sent = _poller(_Det([{"Computer": "vm1"}]), [rule])
    p.poll_once(rule)
    assert len(sent) == 1
    sig = sent[0]
    assert sig["event"] == "detection" and sig["ttp"] == "T1486"
    assert sig["resource_id"] == "/subscriptions/sub/rg/vm1"
    assert sig["raw_signal"]["first_result_row"] == {"Computer": "vm1"}
    assert "normalized_signal" in sig["raw_signal"]


def test_poller_dry_run_no_dispatch():
    rule = _make_rule()
    p, sent = _poller(_Det([{"Computer": "vm1"}]), [rule], dry_run=True)
    assert len(p.poll_once(rule)) == 1 and sent == []


def test_poller_no_match_no_dispatch():
    rule = _make_rule()
    p, sent = _poller(_Det([]), [rule])
    p.poll_once(rule)
    assert sent == [] and p.status_snapshot()[0]["last_poll"]


def test_poller_records_error_status_then_clears_it():
    rule = _make_rule()
    det = _Det(error=RuntimeError("workspace query not successful"))
    p, sent = _poller(det, [rule])
    p.poll_once(rule)
    assert "not successful" in p.status_snapshot()[0]["last_error"] and sent == []
    det.error = None
    p.poll_once(rule)
    assert p.status_snapshot()[0]["last_error"] == ""


def test_poller_status_snapshot_and_ttp():
    rule = _make_rule()
    p, _ = _poller(_Det([{"Computer": "vm1"}]), [rule])
    p.poll_once(rule)
    snap = p.status_snapshot()[0]
    assert snap["match_count"] == 1 and snap["last_match"] and snap["ttp"] == "T1486"


def test_poller_signal_has_unique_ids():
    rule = _make_rule()
    p, sent = _poller(_Det([{"Computer": "vm1", "SourceIP": "203.0.113.1"},
                            {"Computer": "vm1", "SourceIP": "203.0.113.2"}]), [rule])
    p.poll_once(rule)
    assert len({s["signal_id"] for s in sent}) == 2


def test_poller_deduplicates_same_row_and_sends_a_new_one():
    rule = _make_rule()
    det = _Det([{"Computer": "vm1", "TimeGenerated": "2026-10-07T10:00:00Z"}])
    p, sent = _poller(det, [rule])
    p.poll_once(rule)
    p.poll_once(rule)
    assert len(sent) == 1
    det.rows.append({"Computer": "vm1", "TimeGenerated": "2026-10-07T10:05:00Z"})
    p.poll_once(rule)
    assert len(sent) == 2


# ── Run Azure du 2026-10-05 / troisième passe : fenêtre, routage, déduplication ──────

def test_query_lookback_follows_the_rules_ago():
    from glorfindel.detection_rules import _query_lookback_s
    assert _query_lookback_s("Perf | where TimeGenerated > ago(10m)") == 600
    assert _query_lookback_s("X | where TimeGenerated > ago(5m) | join (Y | where T > ago(1h))") == 3600
    assert _query_lookback_s("Perf | limit 1") == 600          # no ago(): default


def test_poller_window_covers_late_ingestion():
    """The API timespan used to start 2*interval (60 s) back and overrode the query's
    ago(10m): rows ingested 89–109 s late (real run, 05/10) were never seen."""
    det = _Det([])
    rule = _auto_rule()
    p, _ = _poller(det, [rule], registry=_Registry("vm1"))
    before = time.time()
    p.poll_once(rule)
    assert det.calls[0][0].timestamp() <= before - 600


def test_row_attribution():
    from glorfindel.detection_rules import _row_attribution
    rid = _vm("vm1")
    assert _row_attribution({"Computer": "vm1"}, rid, "vm1") is True
    assert _row_attribution({"Computer": "vm2.internal"}, rid, "vm1") is False
    assert _row_attribution({"_ResourceId": rid.upper()}, rid, "vm1") is True
    assert _row_attribution({"CallerIpAddress": "10.0.0.4"}, rid, "vm1") is None


def test_one_query_per_rule_whatever_the_number_of_vms():
    """It was one unfiltered query per (rule, VM), ~3 per cycle each: the volume grew
    with the VMs and hit Log Analytics limits around 20–25 VMs (third review, T10)."""
    det = _Det([])
    rule = _auto_rule()
    p, _ = _poller(det, [rule], registry=_Registry(*[f"vm{i}" for i in range(12)]))
    p.poll_once(rule)
    assert len(det.calls) == 1


def test_rows_are_routed_to_the_vm_they_name():
    rule = _auto_rule()
    p, sent = _poller(_Det([{"Computer": "vm1", "MaxWrite": 9e7},
                            {"Computer": "vm2.contoso.internal", "MaxWrite": 8e7},
                            {"Computer": "vm9", "MaxWrite": 9e7}]),      # not monitored
                      [rule], registry=_Registry("vm1", "vm2"))
    p.poll_once(rule)
    assert sorted(s["resource_id"] for s in sent) == [_vm("vm1"), _vm("vm2")]
    assert all(s["context"]["attribution"] == "asset" for s in sent)


def test_an_excluded_vm_gets_nothing():
    class Cfg:
        def is_excluded(self, asset, rule):
            return asset == "vm2"
    rule = _auto_rule()
    p, sent = _poller(_Det([{"Computer": "vm2", "MaxWrite": 9e7}]), [rule],
                      registry=_Registry("vm1", "vm2"), cfg=Cfg())
    p.poll_once(rule)
    assert sent == []


def test_a_storage_call_is_routed_to_the_vm_whose_ip_made_it():
    """T1041 rows name no VM (summarised by caller IP and account): in multi-VM the
    isolation was always held, with one escalation per VM (third review, T8)."""
    rule = _auto_rule(name="data-exfiltration-blob", ttp="T1041",
                      query="StorageBlobLogs | where TimeGenerated > ago(5m)")
    p, sent = _poller(_Det([{"CallerIpAddress": "10.0.0.5:51234", "AccountName": "st", "PutBlobCount": 3}]),
                      [rule], registry=_Registry("vm1", "vm2"),
                      ip_owners=lambda: {"10.0.0.5": _vm("vm2")})
    p.poll_once(rule)
    assert [s["resource_id"] for s in sent] == [_vm("vm2")]
    assert sent[0]["context"]["attribution"] == "asset"


def test_an_unattributed_row_is_sent_once_and_flagged():
    """It was dispatched once per VM — N decisions, N blocks of the same IP fighting
    for the same priority (T8). And with a single VM it was attributed to it by default
    (L11): never a default target now."""
    rule = _auto_rule(name="data-exfiltration-blob", ttp="T1041",
                      query="StorageBlobLogs | where TimeGenerated > ago(5m)")
    row = {"CallerIpAddress": "10.9.9.9", "AccountName": "st", "PutBlobCount": 1}
    for registry in (_Registry("vm1", "vm2", "vm3"), _Registry("vm1")):
        p, sent = _poller(_Det([row]), [rule], registry=registry, ip_owners=lambda: {})
        p.poll_once(rule)
        assert len(sent) == 1 and sent[0]["context"]["attribution"] == "unattributed"
        assert sent[0]["context"]["candidates"] == sorted(a.name for a in registry.assets)
        import glorfindel.detection_rules as dr
        dr._save_status({})


def test_aggregated_row_dispatched_once_while_its_counts_grow():
    rule = _auto_rule()
    det = _Det([{"Computer": "vm1", "SourceIP": "203.0.113.9", "FailedAttempts": 12}])
    p, sent = _poller(det, [rule], registry=_Registry("vm1"))
    p.poll_once(rule)
    det.rows = [{"Computer": "vm1", "SourceIP": "203.0.113.9", "FailedAttempts": 40}]
    p.poll_once(rule)
    assert len(sent) == 1


def test_alternating_rows_are_not_redispatched_and_a_second_attacker_is_not_hidden():
    """Only the first row was kept, and only the last identity remembered: two
    attackers in alternating order re-dispatched every poll (93 sends in 0.5 s in the
    review's simulation), or B stayed hidden behind A for 10 minutes (T9)."""
    rule = _auto_rule()
    a = {"Computer": "vm1", "SourceIP": "203.0.113.1", "FailedAttempts": 10}
    b = {"Computer": "vm1", "SourceIP": "203.0.113.2", "FailedAttempts": 10}
    det = _Det([a])
    p, sent = _poller(det, [rule], registry=_Registry("vm1"))
    p.poll_once(rule)
    det.rows = [a, b]
    p.poll_once(rule)
    det.rows = [b, a]
    p.poll_once(rule)
    assert [s["raw_signal"]["first_result_row"]["SourceIP"] for s in sent] == ["203.0.113.1", "203.0.113.2"]


def test_event_rows_make_one_signal_per_cycle():
    rule = _auto_rule()
    rows = [{"Computer": "vm1", "TimeGenerated": f"2026-10-07T10:0{i}:00Z"} for i in range(3)]
    p, sent = _poller(_Det(rows), [rule], registry=_Registry("vm1"))
    p.poll_once(rule)
    assert len(sent) == 1 and sent[0]["raw_signal"]["first_result_row"]["TimeGenerated"].endswith("02:00Z")


def test_dedup_survives_a_restart():
    rule = _auto_rule()
    row = {"Computer": "vm1", "TimeGenerated": "2026-10-07T10:00:00Z"}
    p, sent = _poller(_Det([row]), [rule], registry=_Registry("vm1"))
    p.poll_once(rule)
    p2, sent2 = _poller(_Det([row]), [rule], registry=_Registry("vm1"))      # new process
    p2.poll_once(rule)
    assert len(sent) == 1 and sent2 == []


def test_dedup_reads_the_previous_state_shape():
    import glorfindel.detection_rules as dr
    rule = _auto_rule()
    row = {"Computer": "vm1", "TimeGenerated": "2026-10-07T10:00:00Z"}
    dr._save_status({rule.name: {"dispatched": {_vm("vm1").lower(): {"id": dr._row_identity(row), "at": time.time()}}}})
    p, sent = _poller(_Det([row]), [rule], registry=_Registry("vm1"))
    p.poll_once(rule)
    assert sent == []


def test_a_vm_discovered_later_is_covered_without_a_new_thread():
    """Expansion starts one thread per RULE; each cycle reads the registry (a VM turned
    on after the watch started used to have no poller for the life of the watch)."""
    rule = _auto_rule(interval_s=60)
    reg = _Registry("vm1")
    det = _Det([{"Computer": "vm2", "MaxWrite": 9e7}])
    p, sent = _poller(det, [rule], registry=reg)
    p.poll_once(rule)
    assert sent == []
    reg.assets.append(_Asset("vm2"))
    p.poll_once(rule)
    assert [s["resource_id"] for s in sent] == [_vm("vm2")]
    p.expand_for_discovered(reg)
    p.expand_for_discovered(reg)
    assert [t.name for t in p._threads.values()] == ["rule-ransomware-disk-write"]
    p.stop()


def test_shipped_rules_do_not_truncate_before_the_vm_filter():
    """`| limit 1` ran on the server before the per-VM filter: a benign sudo on another
    VM hid the attack (third review, T7). Same check warns on LLM-authored rules."""
    from pathlib import Path
    import yaml
    from glorfindel.detection_rules import _truncates_before_vm_filter
    path = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
    for r in yaml.safe_load(path.read_text())["rules"]:
        if "auto" in (r.get("assets") or []):
            assert not _truncates_before_vm_filter(r["query"]), r["name"]
    assert _truncates_before_vm_filter("Syslog\n| where x\n| limit 1")
    assert not _truncates_before_vm_filter("Syslog\n// no | limit here\n| summarize arg_max(TimeGenerated, *) by Computer")


def test_ransomware_rule_reads_the_sampling_step_from_the_data():
    """Two samples ≤ 25 s apart never exist at Azure's default 60-s sampling: the rule
    never fired there (third review, T6). Coarse series use one sample."""
    from pathlib import Path
    import yaml
    path = Path(__file__).resolve().parents[2] / "glorfindel/rules/azure/detection_rules.yaml"
    q = next(r["query"] for r in yaml.safe_load(path.read_text())["rules"] if r["name"] == "ransomware-disk-write")
    assert "Step = min(Gap)" in q and "not(Fine) and Rate > 25000000" in q


def test_a_host_name_shared_by_two_vms_attributes_nothing():
    """Clones in two resource groups: the host name can't tell which VM — the row
    names its _ResourceId (shipped rules emit it), or it is unattributed."""
    class _TwoWebs:
        def __init__(self):
            a, b = _Asset("web"), _Asset("web")
            b.resource_id = b.resource_id.replace("/rg/", "/rg-b/")
            self.assets = [a, b]

        def for_backend(self, _n):
            return self.assets
    reg = _TwoWebs()
    rule = _auto_rule()
    p, sent = _poller(_Det([{"Computer": "web", "MaxWrite": 9e7}]), [rule], registry=reg)
    p.poll_once(rule)
    assert sent[0]["context"]["attribution"] == "unattributed"
    p2, sent2 = _poller(_Det([{"Computer": "web", "_ResourceId": reg.assets[1].resource_id, "MaxWrite": 9e7}]),
                        [rule], registry=reg)
    import glorfindel.detection_rules as dr
    dr._save_status({})
    p2.poll_once(rule)
    assert sent2[0]["resource_id"] == reg.assets[1].resource_id and sent2[0]["context"]["attribution"] == "asset"


def test_query_lookback_reads_every_kql_timespan_and_ignores_comments():
    """`ago(30min)` / `ago(2hours)` fell back to 10 minutes, and an ago() in a comment
    counted (third review, details)."""
    from glorfindel.detection_rules import _query_lookback_s
    assert _query_lookback_s("T | where TimeGenerated > ago(30min)") == 1800
    assert _query_lookback_s("T | where TimeGenerated > ago(2hours)") == 7200
    assert _query_lookback_s("T | where TimeGenerated > ago(1.5d)") == 129600
    assert _query_lookback_s("T | where TimeGenerated > ago(90sec)") == 90
    assert _query_lookback_s("T | where TimeGenerated > ago(5m)\n// was ago(1d)") == 300
