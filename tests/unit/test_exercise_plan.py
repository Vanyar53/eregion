"""Dagorlad (docs/design/console.md, §7): may a wire run, and if not, why — the shared core's
verdict, which the console gives to advise and Orodruin will give again to decide.

Pure: no Azure, no model; the targets are dicts of tags, as the reader read them.
"""
from __future__ import annotations

from eregion_core.exercise_plan import (
    FAULT_S, REFUSALS, TECHNIQUE_S, Experiment, Target, judge, load_catalog, plan)
from eregion_core.inscription import Scope
from eregion_core.orodruin import CEILING_INJECTIONS, CEILING_RUN_S

RG = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, SENTINEL, BREE = RG + "vm-celebrimbor-gondolin", RG + "vm-sentinel", RG + "vm-celebrimbor-bree"
ENROLLED = {"eregion-target": "celebrimbor"}
SCOPE = Scope(sandbox="celebrimbor")


def _target(rid, zone="bench", **tags):
    return Target(rid, rg_tags=dict(ENROLLED), tags={**ENROLLED, "eregion-zone": zone, **tags})


def _cat(*extra):
    out = {
        "T1110.001": Experiment("T1110.001", "technique", "Brute Force", "azure_vm", "implemented", False, "atomic"),
        "T1486": Experiment("T1486", "technique", "Ransomware", "azure_vm", "implemented", True, "atomic"),
        "T1070": Experiment("T1070", "technique", "Log clearing", "azure_vm", "planned", True, "atomic"),
        "T1099": Experiment("T1099", "technique", "Undeclared", "azure_vm", "implemented", None, "atomic"),
        "T1530": Experiment("T1530", "technique", "Blob read", "azure_storage", "implemented", False, "stratus"),
        "vm-shutdown": Experiment("vm-shutdown", "fault", "VM shutdown", "azure_vm", "implemented", False, "chaos-studio"),
    }
    out.update({e.id: e for e in extra})
    return out


def _judge(experiment, rid=GONDOLIN, target="default", **kw):
    if target == "default":
        target = _target(rid)
    kw.setdefault("fault_targets", {"vm-shutdown": ["vm-celebrimbor-gondolin"]})
    return judge(experiment, rid, target, catalog=_cat(), scope=SCOPE, **kw)


def test_a_wire_inside_every_rule_may_run():
    v = _judge("T1110.001")
    assert (v.status, v.code, v.zone, v.warnings) == ("ok", "", "bench", [])


def test_the_catalogue_says_what_runs():
    assert _judge("T9999").code == "unknown_experiment"
    assert _judge("T1070").code == "not_implemented"
    assert _judge("T1530").code == "wrong_target_type"


def test_the_bench_perimeter_and_the_enrollment():
    outside = "/subscriptions/s/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-x"
    assert _judge("T1110.001", outside).code == "outside_scope"
    assert _judge("T1110.001", target=None).code == "not_enrolled"           # not read among the VMs
    assert _judge("T1110.001", target=Target(BREE, rg_tags=dict(ENROLLED), tags={})).code == "not_enrolled"
    other = Target(GONDOLIN, rg_tags=dict(ENROLLED), tags={"eregion-target": "elsewhere", "eregion-zone": "bench"})
    assert _judge("T1110.001", target=other).code == "not_enrolled"
    no_zone = Target(GONDOLIN, rg_tags=dict(ENROLLED), tags=dict(ENROLLED))
    assert "zone" in _judge("T1110.001", target=no_zone).reason
    disagree = Target(GONDOLIN, rg_tags={**ENROLLED, "eregion-zone": "production"},
                      tags={**ENROLLED, "eregion-zone": "bench"})
    assert _judge("T1110.001", target=disagree).code == "not_enrolled"


def test_the_production_rule():
    """Never a fault, nor a destructive technique, nor one nobody declared non-destructive."""
    prod = _target(SENTINEL, zone="production")
    assert _judge("T1110.001", SENTINEL, prod).status == "ok"
    assert _judge("vm-shutdown", SENTINEL, prod, fault_targets={"vm-shutdown": ["vm-sentinel"]}).code == "zone_forbids"
    assert _judge("T1486", SENTINEL, prod).code == "zone_forbids"
    assert _judge("T1099", SENTINEL, prod).code == "zone_forbids"
    assert _judge("T1486", GONDOLIN, _target(GONDOLIN, zone="twin")).code == ""


def test_never_without_glorfindel():
    v = _judge("T1110.001", watch_refusal="no heartbeat for 12 min")
    assert v.code == "no_watch" and "12 min" in v.reason


def test_a_fault_runs_only_where_its_engine_aims():
    assert _judge("vm-shutdown").status == "ok"
    assert _judge("vm-shutdown", BREE, _target(BREE)).code == "no_engine"
    unknown = _judge("vm-shutdown", fault_targets={"vm-shutdown": None})
    assert unknown.status == "warn" and unknown.warnings[0]["code"] == "engine_unknown"


def test_a_fault_aimed_at_several_vms_is_refused_a_wire_takes_one():
    """DG-b review, point 2: the operator sees and types one VM per wire — a fault acting on
    others too would run wider than what was shown."""
    v = _judge("vm-shutdown", fault_targets={"vm-shutdown": ["vm-celebrimbor-gondolin", "vm-celebrimbor-bree"]})
    assert v.code == "no_engine" and "alone" in v.reason


def test_a_destructive_technique_asks_for_the_name_typed():
    v = _judge("T1486")
    assert v.status == "warn" and [w["code"] for w in v.warnings] == ["typed_name"]


def test_the_refusals_come_in_their_order():
    """A production fault with no watch: the zone first — the rule Orodruin's inscription holds."""
    prod = _target(SENTINEL, zone="production")
    assert _judge("vm-shutdown", SENTINEL, prod, watch_refusal="dead").code == "zone_forbids"
    assert REFUSALS.index("zone_forbids") < REFUSALS.index("no_watch") < REFUSALS.index("no_engine")


def test_a_plan_keeps_the_order_drawn_once_per_pair():
    targets = {GONDOLIN.lower(): _target(GONDOLIN), SENTINEL.lower(): _target(SENTINEL, zone="production")}
    wires = [("T1110.001", GONDOLIN), ("T1486", SENTINEL), ("vm-shutdown", GONDOLIN),
             ("T1110.001", GONDOLIN.upper())]
    out = plan(wires, targets, catalog=_cat(), scope=SCOPE,
               fault_targets={"vm-shutdown": ["vm-celebrimbor-gondolin"]})
    assert [(v.experiment, v.code, v.order) for v in out] == [
        ("T1110.001", "", 1), ("T1486", "zone_forbids", None), ("vm-shutdown", "", 2)]
    assert [v.estimate_s for v in out] == [TECHNIQUE_S, None, FAULT_S]


def test_past_orodruins_ceilings_a_wire_is_refused():
    cat = _cat(*[Experiment(f"T9{i:03d}", "technique", "x", "azure_vm", "implemented", False, "atomic")
                 for i in range(CEILING_INJECTIONS + 5)])
    targets = {GONDOLIN.lower(): _target(GONDOLIN)}
    out = plan([(f"T9{i:03d}", GONDOLIN) for i in range(CEILING_INJECTIONS + 5)], targets,
               catalog=cat, scope=SCOPE)
    fit = min(CEILING_INJECTIONS, CEILING_RUN_S // TECHNIQUE_S)
    assert [v.order for v in out[:fit]] == list(range(1, fit + 1))
    assert {v.code for v in out[fit:]} == {"over_cap"}
    assert sum(v.estimate_s or 0 for v in out) <= CEILING_RUN_S


def test_the_catalogue_is_read_as_shipped():
    cat = load_catalog()
    assert cat["T1110.001"].kind == "technique" and cat["T1110.001"].injector == "annatar"
    assert cat["T1486"].destructive is True
    assert cat["vm-shutdown"].kind == "fault" and cat["vm-shutdown"].injector == "gothmog"
    assert all(e.status in ("implemented", "planned") for e in cat.values())


# --- the bench's VMs, as the reader reads them (inscription.TagEnrollment.vms) -------------

class _Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code, self.ok = body, status, status < 400

    def json(self):
        return self._body


class _Cred:
    def get_token(self, scope):
        return type("T", (), {"token": "t"})()


def test_the_bench_vms_are_read_page_after_page_in_the_benchs_groups_only():
    from eregion_core.inscription import ARM, TagEnrollment
    calls = []
    vm = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
    pages = {
        f"{ARM}/subscriptions/s/resourcegroups": {
            "value": [{"name": "rg-celebrimbor", "tags": {"eregion-target": "celebrimbor"}}],
            "nextLink": f"{ARM}/next-rgs"},
        f"{ARM}/next-rgs": {"value": [{"name": "rg-prod", "tags": {}}]},
        f"{ARM}/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines": {
            "value": [{"id": vm + "vm-a", "name": "vm-a", "tags": {"eregion-zone": "bench"}}], "nextLink": f"{ARM}/next-vms"},
        f"{ARM}/next-vms": {"value": [{"id": vm + "vm-b", "name": "vm-b"}]},
    }

    def get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        return _Resp(pages[url])

    out = TagEnrollment(credential=_Cred(), get=get).vms("s")
    assert [v["name"] for v in out] == ["vm-a", "vm-b"]
    assert out[0]["rg_tags"] == {"eregion-target": "celebrimbor"} and out[1]["tags"] == {}
    assert not any("rg-prod" in c for c in calls)           # a group outside the bench: never read


def test_the_bench_vms_unreadable_raise_never_an_empty_bench():
    import pytest
    from eregion_core.inscription import TagEnrollment
    reader = TagEnrollment(credential=_Cred(), get=lambda *a, **k: _Resp({}, 403))
    with pytest.raises(RuntimeError, match="403"):
        reader.vms("s")
    with pytest.raises(ValueError, match="AZURE_SUBSCRIPTION_ID"):
        reader.vms("")


def test_a_technique_nobody_declared_non_destructive_asks_for_the_name_too():
    """A0: an unknown is never taken for harmless — refused in production (check_zone), the name
    typed on the bench; DG-b makes this a guard on Orodruin."""
    v = _judge("T1099")
    assert v.status == "warn" and [w["code"] for w in v.warnings] == ["typed_name"]
    assert "not declared" in v.warnings[0]["text"]


def test_a_zone_outside_the_three_is_refused_whatever_its_spelling():
    """Azure keeps tag values as written: « Production » or « prod » is no zone — refused."""
    for zone in ("Production", "prod", "BENCH"):
        v = _judge("T1110.001", target=_target(GONDOLIN, zone=zone))
        assert v.code == "zone_forbids", zone


def test_the_count_ceiling_holds_should_an_estimate_shrink(monkeypatch):
    """Today the time ceiling comes first; with more time, the count stops the wires past it."""
    import eregion_core.exercise_plan as ep
    monkeypatch.setattr(ep, "CEILING_RUN_S", 10 ** 7)
    cat = _cat(*[Experiment(f"T9{i:03d}", "technique", "x", "azure_vm", "implemented", False, "atomic")
                 for i in range(CEILING_INJECTIONS + 3)])
    out = ep.plan([(f"T9{i:03d}", GONDOLIN) for i in range(CEILING_INJECTIONS + 3)],
                  {GONDOLIN.lower(): _target(GONDOLIN)}, catalog=cat, scope=SCOPE)
    assert [v.order for v in out[:CEILING_INJECTIONS]] == list(range(1, CEILING_INJECTIONS + 1))
    assert {v.code for v in out[CEILING_INJECTIONS:]} == {"over_cap"}


def test_a_next_page_outside_arm_is_refused_and_never_fetched():
    """N-15's rule for the reader's token: Azure Resource Manager only."""
    import pytest
    from eregion_core.inscription import ARM, TagEnrollment
    asked = []

    def get(url, headers=None, params=None, timeout=None):
        asked.append(url)
        return _Resp({"value": [{"name": "rg-celebrimbor", "tags": {}}], "nextLink": "https://elsewhere.example/next"})

    with pytest.raises(RuntimeError, match="outside Azure Resource Manager"):
        TagEnrollment(credential=_Cred(), get=get).vms("s")
    assert all(u.startswith(ARM + "/") for u in asked)
    # A host that only begins like ARM's is another host.
    asked.clear()

    def get_lookalike(url, headers=None, params=None, timeout=None):
        asked.append(url)
        return _Resp({"value": [], "nextLink": "https://management.azure.com.evil.example/next"})

    with pytest.raises(RuntimeError, match="outside Azure Resource Manager"):
        TagEnrollment(credential=_Cred(), get=get_lookalike).vms("s")
    assert all(u.startswith(ARM + "/") for u in asked)


def test_a_destructive_fault_or_one_not_declared_asks_for_the_name_typed_too():
    """§7: « chaque fil destructif » — a fault as a technique (A0: undeclared is destructive)."""
    cat = _cat(Experiment("vm-wipe", "fault", "Disk wipe", "azure_vm", "implemented", True, "chaos-studio"),
               Experiment("vm-odd", "fault", "Undeclared", "azure_vm", "implemented", None, "chaos-studio"))
    targets = {"vm-wipe": ["vm-celebrimbor-gondolin"], "vm-odd": ["vm-celebrimbor-gondolin"],
               "vm-shutdown": ["vm-celebrimbor-gondolin"]}
    for fid in ("vm-wipe", "vm-odd"):
        v = judge(fid, GONDOLIN, _target(GONDOLIN), catalog=cat, scope=SCOPE, fault_targets=targets)
        assert [w["code"] for w in v.warnings] == ["typed_name"], fid
    v = judge("vm-shutdown", GONDOLIN, _target(GONDOLIN), catalog=cat, scope=SCOPE, fault_targets=targets)
    assert v.warnings == []
