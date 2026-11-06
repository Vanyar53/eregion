"""CAN2 (#605): the azurerm canary set aside from `nsg-change-outside-glorfindel`, in the bench's
client layer — by its group and its principal together, and nothing else.

The scheduled run of `canary-azurerm` (`infra/canary/jit-terraform/`, P-04) creates then deletes
its throwaway NSGs (`nsg-customer-<suffix>`, `nsg-glorfindel-quarantine-canary-<suffix>`) in
`rg-eregion-canary`, under its own OIDC principal: twelve cards on H0, judged right (Jonathan,
06/11). Of the shipped `source: azure_activity` rules, only `nsg-change-outside-glorfindel` reads
what the canary does (NSG write and delete; its VNet, subnet and NIC writes are no rule's
operation). The bench's copy is the shipped rule plus one exclusion: the group is
`rg-eregion-canary` (`ResourceGroup` and `_ResourceId`, without case) **and** the caller is the
canary's principal (its appid in `Claims.appid` or `Caller`, no user's name). The appid is never in
the repository: the copy declares `env_guids: [EREGION_RULE_CANARY_APPID]`, and the watch puts the
GUID of its environment in place of `${EREGION_RULE_CANARY_APPID}` at load — absent, empty or no
GUID, the copy is set aside and the shipped rule runs.

The rules run as written (`tests/unit/kql_subset.py`) on lines in AzureActivity's form, an
operation's Start, Accept and Success; through the RulePoller and the activity adapter too. Every
identifier is made up: 00000000-… GUIDs. No Azure, no model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from glorfindel.detection_rules import (
    RulePoller,
    base_rule_sha256,
    env_guid,
    load_config,
    shipped_rules_path,
)
from glorfindel.detectors import AzureActivityDetector
from glorfindel.providers.azure.monitor import AzureMonitorDetector

from . import kql_subset

ROOT = Path(__file__).resolve().parents[2]
BENCH = ROOT / "infra" / "glorfindel-host" / "client_rules.bench.yaml"
NAME = "nsg-change-outside-glorfindel"
VAR = "EREGION_RULE_CANARY_APPID"
SHIPPED = {r["name"]: r for r in yaml.safe_load(shipped_rules_path().read_text())["rules"]}
CLIENT = {r["name"]: r for r in yaml.safe_load(BENCH.read_text())["rules"]}

# Placeholders, never real ids.
SUB = "00000000-0000-0000-0000-0000000000cc"
CANARY_APP = "00000000-0000-0000-0000-00000000ca17"
CANARY_OID = "00000000-0000-0000-0000-00000000ca18"
OTHER_APP = "00000000-0000-0000-0000-0000000000ab"
OTHER_OID = "00000000-0000-0000-0000-0000000000ac"
OWN_APP = "00000000-0000-0000-0000-0000000000f1"     # Glorfindel's own identity, for the adapter
CANARY_RG = "rg-eregion-canary"
NOW = datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def _now_when_the_test_starts():
    global NOW
    NOW = datetime.now(timezone.utc)


def _nsg(name: str = "nsg-customer-gh123-1", rg: str = CANARY_RG, sub: str = SUB) -> str:
    # As AzureActivity writes it (lowercase); the rule compares without case.
    return f"/subscriptions/{sub}/resourcegroups/{rg}/providers/microsoft.network/networksecuritygroups/{name}"


def _claims(app: str, oid: str, **more) -> str:
    return json.dumps({"appid": app, "http://schemas.microsoft.com/identity/claims/objectidentifier": oid,
                       "idtyp": "app", **more})


def _operation(corr: str = "c-1", op: str = "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
               resource: str | None = None, rg: str = CANARY_RG, caller: str = CANARY_OID,
               app: str = CANARY_APP, oid: str = CANARY_OID, claims: str | None = None,
               statuses=("Start", "Accept", "Success")) -> list[dict]:
    """One ARM operation as AzureActivity writes it: one line per status, the same CorrelationId."""
    resource = _nsg(rg=rg) if resource is None else resource
    lines = []
    for i, status in enumerate(statuses):
        lines.append({"Type": "AzureActivity", "TimeGenerated": NOW - timedelta(minutes=5) + timedelta(seconds=i),
                      "OperationNameValue": op, "ActivityStatusValue": status, "Caller": caller,
                      "CallerIpAddress": "192.0.2.40", "Claims": _claims(app, oid) if claims is None else claims,
                      "_ResourceId": resource, "ResourceGroup": rg.upper() if i % 2 else rg,
                      "CorrelationId": corr})
    return lines


def _query(environ: dict) -> str:
    cfg = load_config(shipped_rules_path(), client_layer=BENCH, environ=environ)
    return next(r for r in cfg.rules if r.name == NAME).query


def _bench(rows, appid: str = CANARY_APP):
    return kql_subset.run(_query({VAR: appid}), rows, now=NOW)


def _base(rows):
    return kql_subset.run(SHIPPED[NAME]["query"], rows, now=NOW)


# ── The rules the canary makes speak ────────────────────────────────────────────────

# What infra/canary/jit-terraform/ does (main.tf, run.sh): its operations, as ARM names them.
CANARY_OPERATIONS = {
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/WRITE", "MICROSOFT.NETWORK/VIRTUALNETWORKS/DELETE",
    "MICROSOFT.NETWORK/VIRTUALNETWORKS/SUBNETS/WRITE", "MICROSOFT.NETWORK/VIRTUALNETWORKS/SUBNETS/DELETE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE", "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE",
    "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE", "MICROSOFT.NETWORK/NETWORKINTERFACES/DELETE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/JOIN/ACTION", "MICROSOFT.NETWORK/VIRTUALNETWORKS/SUBNETS/JOIN/ACTION",
}


def test_of_the_shipped_activity_rules_only_the_nsg_rule_reads_what_the_canary_does():
    """The list of the bench's copies is right: each shipped `azure_activity` rule run on every
    operation of the canary, by the canary, in its group — one makes cards."""
    speaking = set()
    for name, rule in SHIPPED.items():
        if rule.get("source") != "azure_activity":
            continue
        for i, op in enumerate(sorted(CANARY_OPERATIONS)):
            if kql_subset.run(rule["query"], _operation(corr=f"c-{i}", op=op), now=NOW):
                speaking.add(name)
    assert speaking == {NAME}


# ── The copy: the base, plus the exclusion block, nothing else ──────────────────────

_BLOCK_START = "// CAN2 (#605)"


def _without_block(query: str) -> str:
    lines = query.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.strip().startswith(_BLOCK_START))
    end = next(i for i in range(start, len(lines)) if 'Caller !contains "@")' in lines[i])
    return "".join(lines[:start] + lines[end + 1:])


def test_the_bench_rule_is_the_shipped_query_plus_the_exclusion_block_alone():
    """Drift, read in the repository: the base changes and the copy does not → this fails, in the
    pull request that changes the base. Redo the copy (the base's query, then the block)."""
    client, base = CLIENT[NAME], SHIPPED[NAME]
    assert _without_block(client["query"]) == base["query"]
    assert client["base_sha256"] == base_rule_sha256(base)
    for key in ("source", "ttp", "assets", "interval_s", "expected_latency_s", "enabled"):
        assert client[key] == base[key], key
    assert client["description"].startswith(base["description"].strip())
    assert set(client) - set(base) == {"base_sha256", "env_guids"}
    assert client["env_guids"] == [VAR]
    block = client["query"][client["query"].index(_BLOCK_START):]
    # After the operation's latest line is chosen, before `project`: the line the card shows.
    assert block.index("| where not(") < block.index("| project")
    assert client["query"].index("| summarize arg_max") < client["query"].index(_BLOCK_START)


def test_no_identifier_of_the_canary_in_the_repository():
    """The appid, the subscription, the tenant: never in the bench's layer — a placeholder only."""
    text = BENCH.read_text()
    assert "${" + VAR + "}" in CLIENT[NAME]["query"]
    import re
    guids = re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text)
    assert guids == []


def test_the_bench_layer_loads_the_copy_with_the_guid_of_the_environment():
    cfg = load_config(shipped_rules_path(), client_layer=BENCH, environ={VAR: CANARY_APP.upper()})
    rule = next(r for r in cfg.rules if r.name == NAME)
    assert rule.layer == "client" and rule.replaces_base and rule.source == "azure_activity"
    assert "${" not in rule.query and rule.query.count(CANARY_APP) == 2          # lowercase
    assert rule.query == CLIENT[NAME]["query"].replace("${" + VAR + "}", CANARY_APP)
    assert NAME in cfg.overrides and cfg.drifted == []
    assert not any(VAR in n for n in cfg.notes)


# ── The canary in its group: no card ────────────────────────────────────────────────

@pytest.mark.parametrize("op", ["MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
                                "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE",
                                "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"])
@pytest.mark.parametrize("nsg", ["nsg-customer-gh4242-3", "nsg-glorfindel-quarantine-canary-gh4242-3"])
def test_the_canary_in_its_group_makes_no_card(op, nsg):
    rows = _operation(op=op, resource=_nsg(nsg))
    assert len(_base(rows)) == 1                    # the shipped rule's card, every run
    assert _bench(rows) == []


@pytest.mark.parametrize("how", ["claims", "caller"])
def test_the_canary_is_its_appid_in_the_claims_or_as_the_caller(how):
    if how == "claims":
        rows = _operation(caller=CANARY_OID)                         # Caller: its object id
    else:
        rows = _operation(caller=CANARY_APP.upper(), claims="")      # no Claims, its appid as the caller
    assert _bench(rows) == []


def test_the_group_is_read_without_case_as_arm_does():
    rows = _operation(resource=_nsg(rg="RG-Eregion-Canary").replace("/resourcegroups/", "/resourceGroups/"),
                      rg="RG-EREGION-CANARY")
    assert _bench(rows) == []


# ── Anything else is a card ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("caller, app, oid", [
    ("someone@example.org", "00000000-0000-0000-0000-0000000000d0", OTHER_OID),   # a user
    (OTHER_OID, OTHER_APP, OTHER_OID),                                            # another principal
    # A user signed in through the canary's application: its appid in the token, not its principal.
    ("someone@example.org", CANARY_APP, OTHER_OID),
    ("", "", ""),                                                                 # no caller at all
])
def test_another_caller_in_the_group_makes_a_card(caller, app, oid):
    rows = _operation(caller=caller, app=app, oid=oid)
    assert len(_bench(rows)) == 1 == len(_base(rows))


@pytest.mark.parametrize("rg, resource", [
    ("rg-celebrimbor", _nsg(rg="rg-celebrimbor")),                                # another group
    ("rg-eregion-canary-2", _nsg(rg="rg-eregion-canary-2")),
    ("x-rg-eregion-canary", _nsg(rg="x-rg-eregion-canary")),
    # The column says the canary's group, the resource is elsewhere — or the other way round.
    (CANARY_RG, _nsg(rg="rg-celebrimbor")),
    ("rg-celebrimbor", _nsg()),
    (CANARY_RG, f"/subscriptions/{SUB}/resourcegroups/rg-celebrimbor/providers/microsoft.network/"
                "networksecuritygroups/nsg-x/resourcegroups/rg-eregion-canary/providers/x"),
    (CANARY_RG, ""),
])
def test_the_canary_elsewhere_makes_a_card(rg, resource):
    rows = _operation(rg=rg, resource=resource)
    assert len(_bench(rows)) == 1 == len(_base(rows))


def test_a_failed_operation_stays_no_card_as_with_the_shipped_rule():
    rows = _operation(caller=OTHER_OID, app=OTHER_APP, oid=OTHER_OID, statuses=("Start", "Failure"))
    assert _bench(rows) == [] == _base(rows)


# ── The variable absent or invalid: the shipped rule runs ───────────────────────────

@pytest.mark.parametrize("environ", [
    {}, {VAR: ""}, {VAR: "   "}, {VAR: "not-a-guid"}, {VAR: CANARY_APP + "0"}, {VAR: CANARY_APP[:-1]},
    # What would leave the string and widen the exclusion, if it reached the query (KQL injection).
    {VAR: '" or 1 == 1 or "'}, {VAR: CANARY_APP + '" or Caller != "'}, {VAR: CANARY_APP + "\nx"},
    {"EREGION_RULE_CANARY": CANARY_APP},
])
def test_the_variable_absent_or_invalid_sets_the_copy_aside_and_the_shipped_rule_runs(environ):
    cfg = load_config(shipped_rules_path(), client_layer=BENCH, environ=environ)
    rule = next(r for r in cfg.rules if r.name == NAME)
    assert rule.layer == "base" and rule.query == SHIPPED[NAME]["query"]
    assert NAME not in cfg.overrides
    [note] = [n for n in cfg.notes if VAR in n]
    assert "la règle livrée tourne à sa place" in note
    value = environ.get(VAR, "").strip()
    assert not value or value not in note                           # never the value
    # …so the canary makes its cards again: more cards, never fewer.
    assert len(kql_subset.run(rule.query, _operation(), now=NOW)) == 1
    # The other copy of the layer is untouched.
    assert next(r for r in cfg.rules if r.name == "sudo-privilege-escalation").layer == "client"


def test_a_guid_with_spaces_around_it_is_read():
    assert env_guid({VAR: f"  {CANARY_APP.upper()}\n"}, VAR) == CANARY_APP
    assert env_guid({VAR: f"{CANARY_APP}x"}, VAR) is None


def test_the_watch_reads_its_own_environment(monkeypatch):
    monkeypatch.setenv(VAR, CANARY_APP)
    cfg = load_config(shipped_rules_path(), client_layer=BENCH)
    assert next(r for r in cfg.rules if r.name == NAME).layer == "client"
    monkeypatch.delenv(VAR)
    cfg = load_config(shipped_rules_path(), client_layer=BENCH)
    assert next(r for r in cfg.rules if r.name == NAME).layer == "base"


# ── The mechanism, beyond the bench's rule ──────────────────────────────────────────

def _layer(tmp_path, *rules, disable=None) -> Path:
    path = tmp_path / "client_rules.yaml"
    path.write_text(yaml.safe_dump({"rules": list(rules), **({"disable": disable} if disable else {})},
                                   sort_keys=False, allow_unicode=True))
    return path


@pytest.mark.parametrize("names", [
    ["AZURE_CLIENT_ID"], ["AZURE_TENANT_ID"], ["eregion_rule_x"], [], "EREGION_RULE_X", [1], None,
    ["EREGION_RULE_"],
])
def test_only_declared_eregion_rule_variables_are_taken(tmp_path, names):
    """A rule never pulls another variable of the watch's environment into its query (SEC2):
    `env_guids` names EREGION_RULE_… variables, in a list, or the rule is skipped and said."""
    rule = {**CLIENT[NAME], "env_guids": names}
    cfg = load_config(shipped_rules_path(), client_layer=_layer(tmp_path, rule),
                      environ={"AZURE_CLIENT_ID": CANARY_APP, "AZURE_TENANT_ID": CANARY_APP,
                               "eregion_rule_x": CANARY_APP, VAR: CANARY_APP})
    loaded = next(r for r in cfg.rules if r.name == NAME)
    assert loaded.layer == "base"
    assert any("env_guids" in n and "ignorée" in n for n in cfg.notes)


def test_a_placeholder_not_declared_is_left_as_written(tmp_path):
    """Only what `env_guids` names is replaced: any other `${…}` stays as written (SEC2)."""
    rule = {**CLIENT[NAME], "query": CLIENT[NAME]["query"].replace("@\")", "@\" or Caller == \"${AZURE_CLIENT_ID}\")")}
    cfg = load_config(shipped_rules_path(), client_layer=_layer(tmp_path, rule),
                      environ={VAR: CANARY_APP, "AZURE_CLIENT_ID": OTHER_APP})
    query = next(r for r in cfg.rules if r.name == NAME).query
    assert "${AZURE_CLIENT_ID}" in query and OTHER_APP not in query and CANARY_APP in query


@pytest.mark.parametrize("off", ["disable", "no_base"])
def test_without_the_variable_and_without_a_shipped_rule_to_run_the_rule_runs_unreplaced(tmp_path, off):
    """Set aside, nothing might detect its technique: kept, its `${…}` equal to no identifier
    (the exclusion never holds), and said."""
    if off == "disable":
        rule, layer = CLIENT[NAME], _layer(tmp_path, CLIENT[NAME], disable=[NAME])
    else:
        rule = {k: v for k, v in CLIENT[NAME].items() if k != "base_sha256"} | {"name": "nsg-canary-only"}
        layer = _layer(tmp_path, rule)
    cfg = load_config(shipped_rules_path(), client_layer=layer, environ={})
    loaded = next(r for r in cfg.rules if r.name == rule["name"])
    assert loaded.layer == "client" and loaded.query == CLIENT[NAME]["query"]
    assert any("aucune règle livrée ne tournerait" in n and VAR in n for n in cfg.notes)
    assert len(kql_subset.run(loaded.query, _operation(), now=NOW)) == 1


def test_a_disabled_copy_still_disables_without_the_variable(tmp_path):
    cfg = load_config(shipped_rules_path(), client_layer=_layer(tmp_path, {**CLIENT[NAME], "enabled": False}),
                      environ={})
    assert NAME in cfg.disabled_base and not any(VAR in n for n in cfg.notes)


# ── Through the poller and the activity adapter: the canary makes no signal ─────────

@pytest.fixture()
def law(monkeypatch):
    """The workspace: the rule's query run as written on the lines of `rows`."""
    state = {"rows": []}
    monkeypatch.setattr(AzureMonitorDetector, "run_query",
                        lambda self, query, timespan=None: kql_subset.run(query, state["rows"], now=NOW))
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLORFINDEL_OWN_CALLERS", raising=False)
    return state


class _Credential:
    def get_token(self, _scope):
        import base64

        def b64(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        return SimpleNamespace(token=f"{b64({'alg': 'none'})}.{b64({'appid': OWN_APP, 'oid': OWN_APP})}.sig")


def _poll(rows, environ):
    cfg = load_config(shipped_rules_path(), client_layer=BENCH, environ=environ,
                      glorfindel_cfg=SimpleNamespace(monitoring_backends=[SimpleNamespace(
                          name="law-bench", type="azure_monitor", workspace_id="ws-test", endpoint="")]))
    rule = next(r for r in cfg.rules if r.name == NAME)
    sent: list = []
    p = RulePoller([rule], sent.append)
    det = AzureActivityDetector("ws-test", credential=_Credential())
    p._detector = lambda _rule: det
    vm = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-1"
    p._registry = SimpleNamespace(for_backend=lambda _n: [SimpleNamespace(name="vm-1", resource_id=vm)])
    p.poll_once(rule)
    return sent


def test_through_the_poller_the_canary_makes_no_signal_and_an_intruder_one(law):
    law["rows"] = (_operation(corr="c-canary", resource=_nsg("nsg-customer-gh9-1"))
                   + _operation(corr="c-canary-q", op="MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE",
                                resource=_nsg("nsg-glorfindel-quarantine-canary-gh9-1")))
    assert _poll(law["rows"], {VAR: CANARY_APP}) == []
    # Without the variable, the shipped rule: the canary's two operations, two cards.
    assert len(_poll(law["rows"], {})) == 2
    # An intruder in the canary's group, among the canary's lines: its card.
    law["rows"] += _operation(corr="c-intruder", caller="someone@example.org", app=OTHER_APP, oid=OTHER_OID,
                              resource=_nsg("nsg-customer-gh9-1"))
    [signal] = _poll(law["rows"], {VAR: CANARY_APP})
    assert signal["raw_signal"]["first_result_row"]["CorrelationId"] == "c-intruder"
