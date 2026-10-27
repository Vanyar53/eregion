"""IA1: the triage reads Glorfindel's rules as the watch loads them. ``analysis.triage.rules``
copies the criteria of ``glorfindel.detection_rules`` (analysis/ never imports glorfindel);
this test compares the two, on a table of layers — invalid entries of the client's layer
among them: an entry the watch skips must never replace a base rule in the triage (it would
compute ``no_rule`` for a technique the watch still watches, allow ``author_rule`` and forbid
``review_rule``). The oracle is the watch's own loader, never a copy of it."""
import json

import pytest

from analysis import triage as tg
from glorfindel import detection_rules as dr

Q = "Syslog | summarize count() by Computer"
BASE = {"rules": [
    {"name": "ssh", "ttp": "T1110.001", "query": Q},
    {"name": "disk", "ttp": "T1486", "query": Q},
    {"name": "acct", "ttp": "T1136.001", "query": Q},
    {"name": "off", "ttp": "T1041", "query": Q, "enabled": False},
]}

LAYERS = {
    "no client layer": {},
    "a valid replacement": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": Q + " // client"}]},
    "a replacement under another ttp": {"rules": [{"name": "disk", "ttp": "T1490", "query": Q}]},
    "disabled by enabled: false": {"rules": [{"name": "ssh", "enabled": False}]},
    "dropped by disable:": {"disable": ["acct", "nope", 3, ""]},
    "disabled, then given back by the client": {"disable": ["ssh"], "rules": [{"name": "ssh", "ttp": "T9", "query": Q}]},
    "a new client rule": {"rules": [{"name": "new", "ttp": "T1078", "query": Q}]},
    "a base rule enabled by the client": {"rules": [{"name": "off", "ttp": "T1041", "query": Q, "enabled": True}]},
    "twice: the last wins": {"rules": [{"name": "ssh", "ttp": "T1", "query": Q}, {"name": "ssh", "ttp": "T2", "query": Q}]},
    # Entries the watch skips — the base rule is kept.
    "no query": {"rules": [{"name": "ssh", "ttp": "T1110.001"}]},
    "an empty query": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": ""}]},
    "enabled not a boolean": {"rules": [{"name": "ssh", "query": Q, "enabled": "no"}]},
    "enabled: 0": {"rules": [{"name": "disk", "query": Q, "enabled": 0}]},
    "interval_s: 30s": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": Q, "interval_s": "30s"}]},
    "interval_s: 0": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": Q, "interval_s": 0}]},
    "interval_s: true": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": Q, "interval_s": True}]},
    "interval_s: \"45\" loads": {"rules": [{"name": "ssh", "ttp": "T5", "query": Q, "interval_s": "45"}]},
    "expected_latency_s: 1.5s": {"rules": [{"name": "disk", "query": Q, "expected_latency_s": "1.5s"}]},
    "ttp not a string": {"rules": [{"name": "ssh", "ttp": 1110, "query": Q}]},
    "query not a string": {"rules": [{"name": "ssh", "ttp": "T1110.001", "query": ["x"]}]},
    "name not a string": {"rules": [{"name": ["ssh"], "ttp": "T1110.001", "query": Q}]},
    "a blank name": {"rules": [{"name": "  ", "ttp": "T1110.001", "query": Q}]},
    "assets not a list of names": {"rules": [{"name": "ssh", "query": Q, "assets": "web"}]},
    "monitoring_backends of numbers": {"rules": [{"name": "ssh", "query": Q, "monitoring_backends": [1]}]},
    "not a dictionary": {"rules": ["ssh", None, 3]},
    "rules not a list": {"rules": {"name": "ssh", "enabled": False}},
    "disable not a list": {"disable": "ssh"},
    "an unknown key": {"rulez": [{"name": "ssh", "enabled": False}]},
    "valid and invalid together": {"disable": ["acct"], "rules": [
        {"name": "ssh"}, {"name": "disk", "ttp": "T1490", "query": Q}, {"name": "x", "query": Q, "interval_s": "1m"}]},
}


def _watch(base, client) -> list[tuple]:
    """What the watch loads: its own loader, ``load_config``, on the same two files."""
    cfg = dr.load_config(base, client_layer=client)
    return [(r.name, r.ttp, r.layer) for r in cfg.rules]


def _triage(base, client) -> list[tuple]:
    enabled, _ = tg.rules(base, client)
    return [(r["name"], str(r.get("ttp") or ""), r["layer"]) for r in enabled]


@pytest.mark.parametrize("name", list(LAYERS))
def test_the_triage_loads_the_rules_the_watch_loads(tmp_path, name):
    base, client = tmp_path / "base.yaml", tmp_path / "client_rules.yaml"
    base.write_text(json.dumps(BASE))              # JSON is YAML
    if LAYERS[name]:
        client.write_text(json.dumps(LAYERS[name]))
    assert _triage(base, client) == _watch(base, client)
    # And merge_layers, which load_config merges with: the same names, ttp and layer.
    merged, _, layer = dr.merge_layers(BASE, LAYERS[name]) if LAYERS[name] else (BASE, [], {})
    expected = [(r["name"], r.get("ttp", ""), layer.get(r["name"], "base"))
                for r in merged["rules"] if r.get("enabled", True)]
    assert _triage(base, client) == expected


def test_an_entry_the_watch_skips_keeps_its_base_rule_in_the_triage(tmp_path):
    """The case the review found: a client entry without a query (or `interval_s: 30s`) did
    replace the base rule here — the triage computed ``no_rule`` and allowed ``author_rule``."""
    base, client = tmp_path / "base.yaml", tmp_path / "client_rules.yaml"
    base.write_text(json.dumps(BASE))
    client.write_text(json.dumps({"rules": [{"name": "ssh", "enabled": "no"},
                                            {"name": "disk", "query": Q, "interval_s": "30s"}]}))
    enabled, note = tg.rules(base, client)
    assert {(r["name"], r["layer"]) for r in enabled} >= {("ssh", "base"), ("disk", "base")}
    assert "2 entrée(s) que la watch ne charge pas" in note
    from analysis import campaign_report as cr
    fact = cr.RunFact("R1", "C", 1, "T1110.001", "B", "executed", "missed")
    techniques, _ = tg.catalog()
    (item,), _ = tg.items([fact], techniques, enabled, tmp_path)
    assert "no_rule" not in item.causes
    assert item.allowed()["author_rule"] and not item.allowed()["review_rule"]
