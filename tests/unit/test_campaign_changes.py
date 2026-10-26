"""D-2 (#184): what changed since the previous campaign, computed by the code.

Campaigns on disk, in tmp: the previous one is chosen by the rule (the latest ``done``
campaign of the index that started before this one and shares a key — a technique on a
VM), never by similarity; an aborted one, a later one, and one without a shared key are not
it. The runs are joined exactly by key into typed facts; the section is rendered by the
code; a claim of a difference without its fact, or with a number no fact holds, is removed
by ``verify``. And the index of past campaigns: put in again, idempotent, never losing the
facts a report saw. A fake model (no call), an index in memory (no embedding, no download).
D2b: the runs a trend cites face each other in the order they were played, when it is known;
a campaign that came through the channel has its manifest's start checked against what H0
saw. Mutants M260–M279, M510–M519, M530–M547 and M650–M666 (scripts/mutation_check.py) are
measured here."""
import json
import os
from types import SimpleNamespace

import pytest

from analysis import campaign_changes as cc
from analysis import campaign_index as ci
from analysis import campaign_report as cr
from eregion_core.exercise_channel import PULLED

VM = "/subscriptions/s/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm-bench-01"
OTHER_VM = VM.replace("vm-bench-01", "vm-bench-02")


class _Index:
    """The ``campaign_runs`` collection in memory: ``upsert``, ``count`` and ``get`` by ids
    or by equal metadata, as chromadb answers them."""
    def __init__(self):
        self.rows = {}

    def __call__(self, path=None):
        return self

    def upsert(self, ids, documents, metadatas):
        self.rows.update(zip(ids, (dict(m) for m in metadatas)))

    def count(self):
        return len(self.rows)

    def get(self, ids=None, where=None, limit=None):
        keys = [i for i in (ids if ids is not None else self.rows) if i in self.rows]
        keys = [i for i in keys if all(self.rows[i].get(k) == v for k, v in (where or {}).items())]
        keys = keys[:limit] if limit else keys
        return {"ids": keys, "metadatas": [self.rows[i] for i in keys]}


class _Model:
    def __init__(self, claims=()):
        self.claims, self.calls = list(claims), []

    def completion(self, **kw):
        self.calls.append(kw)
        msg = SimpleNamespace(tool_calls=[SimpleNamespace(function=SimpleNamespace(
            arguments=json.dumps({"claims": self.claims})))])
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


@pytest.fixture
def index(monkeypatch):
    idx = _Index()
    monkeypatch.setattr(cr, "_collection", idx)
    return idx


def _run(seq, rid, ttp, *, vm=VM, detection="detected", latency=None, action="", confidence=None,
         escalate=None, status="executed"):
    return {"seq": seq, "ttp": ttp, "name": f"step {seq}", "target_resource_id": vm,
            "status": status, "run_id": rid, "detection": detection,
            "detection_latency_s": latency,
            "_decision": {"action": action, "confidence": confidence, "escalate": escalate}}


def _campaign(runs, cid, created, scenarios, *, state="done"):
    """A campaign as ``annatar campaign run`` leaves it: its manifest, and each run's own
    decision file beside it (a watch beside the run)."""
    cdir = runs / "campaigns" / cid
    cdir.mkdir(parents=True)
    for s in scenarios:
        dec = s.pop("_decision")
        if dec["action"]:
            (runs / f"{s['run_id']}_debug.jsonl").write_text(json.dumps(
                {"signal": {"event": "detection"}, **dec, "reasoning": "data"}) + "\n")
    manifest = {"campaign_id": cid, "state": state, "scenarios": scenarios}
    if created:
        manifest["created_at"] = created
    (cdir / "manifest.json").write_text(json.dumps(manifest))
    return cdir


def _bench(tmp_path):
    """C0 (21/10) and C1 (23/10) share T1110.001 on vm-bench-01; C0 alone played T1041 on it,
    C1 alone T1136.001 on it and T1041 on vm-bench-02. Between them, CA (aborted) and CX
    (done, nothing in common); after C1, C2 (done, the same key)."""
    runs = tmp_path / "runs"
    c0 = _campaign(runs, "C0", "2026-10-21T12:16:43Z", [
        _run(1, "P1", "T1110.001", latency=91.9, action="block_suspicious_ip", confidence=0.80, escalate=True),
        _run(2, "P2", "T1041", latency=130.1, action="isolate_vm", confidence=0.9, escalate=True)])
    ca = _campaign(runs, "CA", "2026-10-22T09:00:00Z", [
        _run(1, "A1", "T1110.001", latency=50.0, action="snapshot", confidence=0.3)], state="aborted")
    cx = _campaign(runs, "CX", "2026-10-22T10:00:00Z", [
        _run(1, "X1", "T1486", vm=OTHER_VM, latency=60.0, action="isolate_vm", confidence=0.95)])
    c1 = _campaign(runs, "C1", "2026-10-23T08:11:20Z", [
        _run(1, "R1", "T1136.001", latency=106.3, action="snapshot", confidence=0.4, escalate=True),
        _run(2, "R2", "T1110.001", latency=106.9, action="isolate_vm", confidence=0.78, escalate=True),
        _run(3, "R3", "T1041", vm=OTHER_VM, latency=101.6, action="isolate_vm", confidence=0.86),
        _run(4, "R4", "T1486", status="skipped", detection=None)])
    c2 = _campaign(runs, "C2", "2026-10-24T08:00:00Z", [
        _run(1, "Z1", "T1110.001", latency=10.0, action="snapshot", confidence=0.5)])
    return runs, {"C0": c0, "CA": ca, "CX": cx, "C1": c1, "C2": c2}


def _report(cdir, claims=(), model=None):
    return cr.build(cdir, model="fake/model", llm=model or _Model(claims), index_path=None)


def _index_all(cdirs, *names):
    for name in names:
        _report(cdirs[name])


# ── The previous campaign: chosen by a rule ──────────────────────────────────────────

def test_the_previous_campaign_is_the_latest_done_earlier_one_sharing_a_key(tmp_path, index):
    """M260–M263: CA is later than C0 and shares its key, but aborted; CX is done and later,
    but shares no key; C2 shares it, but started after C1. The previous campaign is C0."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0", "CA", "CX", "C2")
    report = _report(cdirs["C1"])
    assert report.comparison.previous == "C0"
    assert {f.run_id for f in report.prior} >= {"P1", "P2"}   # citable, by a trend too


def test_of_two_earlier_campaigns_sharing_a_key_the_latest(tmp_path, index):
    """M264: the latest of the campaigns that qualify, not the first one found."""
    runs, cdirs = _bench(tmp_path)
    cb = _campaign(runs, "CB", "2026-10-22T12:00:00Z", [
        _run(1, "B1", "T1110.001", latency=80.0, action="block_suspicious_ip", confidence=0.8)])
    _report(cb)
    _index_all(cdirs, "C0")
    assert _report(cdirs["C1"]).comparison.previous == "CB"


def test_without_a_previous_campaign_the_section_says_so(tmp_path, index):
    """M265: the first campaign, or one with nothing in common with the earlier ones — the
    section says there is none, and why."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "CA", "CX", "C2")      # aborted, no shared key, later
    report = _report(cdirs["C1"])
    assert (report.comparison.previous, report.comparison.why_none) == ("", cr.NO_PREVIOUS)
    md = cr.render(report)
    assert f"{cc.TITLE}\n\n*Aucune campagne précédente : {cr.NO_PREVIOUS}.*" in md
    assert "Campagne précédente" not in md
    assert cr._facts_message(report.facts, report.prior, report.comparison).endswith(
        f"(no previous campaign: {cr.NO_PREVIOUS})")


def test_a_campaign_whose_start_is_unknown_has_no_previous_one(tmp_path, index):
    runs, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0")
    nodate = _campaign(runs, "lab", None, [_run(1, "N1", "T1110.001", latency=5.0)])
    assert _report(nodate).comparison.why_none == cr.NO_START


def test_when_a_campaign_started(tmp_path):
    """Its first scenario's start, else its creation, else its id when it is a date."""
    runs = tmp_path / "runs"
    first = _campaign(runs, "S", "2026-10-20T00:00:00Z", [
        {**_run(1, "S1", "T1041"), "started_at": "2026-10-21T10:00:00Z"},
        {**_run(2, "S2", "T1041"), "started_at": "2026-10-21T09:00:00Z"}])
    assert cr.campaign_info(first).started == pytest.approx(1792573200.0)    # 2026-10-21T09:00Z
    assert cr.campaign_info(_campaign(runs, "D", "2026-10-21T09:00:00Z", [])).started == pytest.approx(1792573200.0)
    assert cr.campaign_info(_campaign(runs, "20261021T090000Z", None, [])).started == pytest.approx(1792573200.0)
    assert cr.campaign_info(_campaign(runs, "x", "not a date", [])).started is None


def test_rows_indexed_before_d2_are_never_chosen(tmp_path, index):
    """A row without its campaign's state and start (written before D-2) is not read: no
    guess. Putting the campaign in again (analysis/campaign_index.py) adds them."""
    _, cdirs = _bench(tmp_path)
    old = cr.collect_facts(cdirs["C0"])
    for f in old:
        f.target = ""
    cr.index_facts(old)                       # as before D-2: no campaign, no VM
    assert _report(cdirs["C1"]).comparison.previous == ""
    ci.verse(cdirs["C0"])
    assert _report(cdirs["C1"]).comparison.previous == "C0"


# ── The facts: joined exactly by key ─────────────────────────────────────────────────

def test_each_shared_key_faces_its_previous_run(tmp_path, index):
    """M266–M269: the n-th run of a technique on a VM faces the n-th of the previous
    campaign on the same VM; a key on one side only is listed as such — T1041 on another VM
    is another key. A skipped scenario played nothing: no key."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0")
    changes = {c.fact_id: c for c in _report(cdirs["C1"]).comparison.changes}
    assert [(c.ttp, c.vm.rsplit("/", 1)[-1], c.side, c.before_run, c.after_run)
            for c in changes.values()] == [
        ("T1136.001", "vm-bench-01", "after", "", "R1"),
        ("T1110.001", "vm-bench-01", "both", "P1", "R2"),
        ("T1041", "vm-bench-02", "after", "", "R3"),
        ("T1041", "vm-bench-01", "before", "P2", "")]
    brute = changes["chg-2"]
    assert (brute.detection_before, brute.detection_after) == ("detected", "detected")
    assert (brute.latency_before, brute.latency_after) == (91.9, 106.9)
    assert brute.latency_delta == pytest.approx(15.0)
    assert (brute.decision_before, brute.decision_after) == ("block_suspicious_ip", "isolate_vm")
    assert (brute.confidence_before, brute.confidence_after) == (0.80, 0.78)
    assert brute.confidence_delta == pytest.approx(-0.02)
    assert (brute.escalated_before, brute.escalated_after) == (True, True)


def test_the_vm_is_compared_without_its_case():
    before = [cr.RunFact("P1", "C0", 1, "T1110.001", "", "executed", "detected", target=VM.upper())]
    after = [cr.RunFact("R1", "C1", 1, "T1110.001", "", "executed", "missed", target=VM)]
    [c] = cc.pair(before, after, "C0")
    assert (c.side, c.detection_before, c.detection_after) == ("both", "detected", "missed")


def test_a_key_played_twice_pairs_in_order():
    """M270: the first run faces the first, the second the second — never the last with the
    first."""
    def run(rid, seq, cid, latency):
        return cr.RunFact(rid, cid, seq, "T1110.001", "", "executed", "detected",
                          latency_s=latency, target=VM)
    changes = cc.pair([run("P1", 1, "C0", 10.0), run("P2", 2, "C0", 20.0)],
                      [run("R1", 1, "C1", 11.0), run("R2", 2, "C1", 22.0), run("R3", 3, "C1", 33.0)], "C0")
    assert [(c.nth, c.before_run, c.after_run) for c in changes] == [
        (1, "P1", "R1"), (2, "P2", "R2"), (3, "", "R3")]


def test_an_unknown_decision_stays_unknown_in_the_change():
    before = [cr.RunFact("P1", "C0", 1, "T1110.001", "", "executed", "detected", target=VM,
                         decision_unknown=cr.NONE_IN_WINDOW)]
    after = [cr.RunFact("R1", "C1", 1, "T1110.001", "", "executed", "detected", target=VM,
                        decision="isolate_vm", confidence=0.78)]
    [c] = cc.pair(before, after, "C0")
    row = c.row()
    assert row["decision"] == [None, "isolate_vm"]
    assert row["decision_unknown_because"] == [cr.NONE_IN_WINDOW, None]
    md = "\n".join(cc.render_section(cc.Comparison("C0", "", [c])))
    assert f"inconnue ({cr.NONE_IN_WINDOW}) → isolate_vm" in md
    assert "ce n'est pas dire que Glorfindel n'a pas agi" in md


# ── The section, rendered by the code ────────────────────────────────────────────────

def test_the_report_renders_the_section_from_the_facts(tmp_path, index):
    """M271, M272: the section is the code's — the previous campaign, a row per shared key
    (detection, latency, action, confidence, escalation, before → after), then the keys of
    one side only; the model gets the same facts, to cite."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0")
    model = _Model()
    md = cr.render(_report(cdirs["C1"], model=model))
    assert "Campagne précédente : `C0`." in md
    assert ("| `chg-2` | T1110.001 | vm-bench-01 | detected → detected | 91,9 s → 106,9 s (+15,0 s) "
            "| block_suspicious_ip → isolate_vm | 80% → 78% (−2 pts) | escaladé → escaladé |") in md
    assert ("Seulement dans la campagne précédente (1) : `chg-4` T1041 sur vm-bench-01 (run `P2`).") in md
    assert ("Seulement dans celle-ci (2) : `chg-1` T1136.001 sur vm-bench-01 (run `R1`) ; "
            "`chg-3` T1041 sur vm-bench-02 (run `R3`).") in md
    assert md.index(cc.TITLE) < md.index("## Ce que le rapport affirme")
    sent = model.calls[0]["messages"][1]["content"]
    assert "## Changes since the previous campaign C0" in sent
    rows = [json.loads(line) for line in sent.split("## Changes since the previous campaign C0")[1].splitlines()
            if line.startswith("{")]
    assert [r["fact"] for r in rows] == ["chg-1", "chg-2", "chg-3", "chg-4"]
    assert rows[1]["decision"] == ["block_suspicious_ip", "isolate_vm"]
    assert rows[1]["latency_delta_s"] == pytest.approx(15.0)


# ── The check: a difference comes from a fact ────────────────────────────────────────

KEPT = [
    # each number is one of chg-2's
    {"kind": "change", "text": "Sur T1110.001, l'action passe de block_suspicious_ip à isolate_vm, "
                               "à 78 % au lieu de 80 %.", "runs": ["chg-2"]},
    {"kind": "change", "text": "La force brute est vue 15 s plus tard (106,9 s contre 91,9 s).",
     "runs": ["chg-2"], "value": "15"},
    {"kind": "change", "text": "La confiance baisse de 0,02.", "runs": ["chg-2"]},
    {"kind": "change", "text": "T1041 n'a pas été rejouée sur vm-bench-01.", "runs": ["chg-4"]},
    {"kind": "trend", "text": "La latence de T1110.001 passe de 91,9 s à 106,9 s.", "runs": ["R2", "P1"]},
    # review of D-2, point 3: true trends and changes, never barred (M512–M514)
    {"kind": "trend", "text": "La latence de T1110.001 augmente de 15 s.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "La confiance sur T1110.001 baisse de 2 points.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Bloquée le 21 octobre, la force brute est isolée le 23 octobre.",
     "runs": ["R2", "P1"]},
    # (on T1041, no fact holds a 2: the count alone lets it through)
    {"kind": "trend", "text": "T1041 est détectée dans les 2 campagnes.", "runs": ["R3", "P2"]},
    {"kind": "trend", "text": "Au 2ᵉ passage comme au 1er, T1110.001 est détectée.", "runs": ["R2", "P1"]},
    {"kind": "change", "text": "En 2026, T1110.001 passe du blocage à l'isolement.", "runs": ["chg-2"]},
    {"kind": "observation", "text": "Sur la force brute, la confiance baisse de 2 points.", "runs": ["chg-2"]},
    # second review of D-2: a range of dates is a date (M537), a relative change in percent a
    # fact's (M538), a true trend said « de X à Y » is never barred
    {"kind": "observation", "text": "La décision sur T1110.001 a changé entre le 21 et le 23 octobre.",
     "runs": ["chg-2"]},
    {"kind": "change", "text": "La latence augmente de 15,0 s (+16 %).", "runs": ["chg-2"]},
    {"kind": "trend", "text": "La latence de T1110.001 augmente de 16 %.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "T1110.001 passe de block_suspicious_ip à isolate_vm, de 0,8 à 0,78.",
     "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Les 2 dernières campagnes détectent T1110.001.", "runs": ["R2", "P1"]},
    # third review of D-2: a date in English (M543), a range after « du » (M544)
    {"kind": "trend", "text": "Confidence on T1110.001 dropped by 2 points since October 21.",
     "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Confidence on T1110.001 dropped by 2 points since 21 October.",
     "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Du 21 au 23 octobre, la latence de T1110.001 augmente de 15 s.",
     "runs": ["R2", "P1"]},
    # fourth review of D-2: a range after « des », « aux » (M546), « du … et du … » (M547)
    {"kind": "trend", "text": "Les campagnes des 21 et 23 octobre détectent T1110.001.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "T1110.001 est détectée aux 21 et 23 octobre.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Sur T1110.001, les runs des 21 et 23 octobre sont détectés.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "La latence de T1110.001 augmente de 15 s entre les runs du 21 et du 23 octobre.",
     "runs": ["R2", "P1"]},
    # D2b: « au … et au … » (M664), « the » after « from », « on », « between », and inside the
    # range (M546, M665), the days' st, nd, rd (M666)
    {"kind": "trend", "text": "Au 21 et au 23 octobre, T1110.001 est détectée.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "From the 21 to the 23 October, latency on T1110.001 rose by 15 s.",
     "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "On the 21st and 23rd October, T1110.001 was detected.", "runs": ["R2", "P1"]},
    {"kind": "trend", "text": "Between the 21 and the 23 October, confidence on T1110.001 dropped by 2 points.",
     "runs": ["R2", "P1"]},
]
REMOVED = [
    ({"kind": "change", "text": "La force brute est vue 40 s plus tard.", "runs": ["chg-2"]},
     "a number is not in the cited facts (40)"),
    ({"kind": "change", "text": "La force brute est vue 15 s plus tard.", "runs": ["R2", "P1"]},
     "a change claim cites no change fact"),
    ({"kind": "change", "text": "Sa latence passe de 91,9 s à 106,9 s.", "runs": ["R2", "P1"]},
     "a change claim cites no change fact"),
    ({"kind": "change", "text": "La confiance baisse de 12 points.", "runs": ["chg-2"]},
     "a number is not in the cited facts (12)"),
    ({"kind": "change", "text": "L'action devient un instantané.", "runs": ["chg-2"], "value": "snapshot"},
     "'snapshot' is not in the cited change facts"),
    ({"kind": "trend", "text": "La latence de T1110.001 passe de 91,9 s à 150 s.", "runs": ["R2", "P1"]},
     "a number is not in the cited facts (150)"),
    ({"kind": "detected", "text": "Détectée les deux fois.", "runs": ["chg-2"]},
     "a detected claim cites a change fact (only a trend, a change or an observation may)"),
    ({"kind": "change", "text": "Un fait inventé.", "runs": ["chg-9"]},
     "cites a run that is not in the facts"),
    # review of D-2: an observation citing a change fact has its numbers checked (M510)…
    ({"kind": "observation", "text": "Glorfindel voit la force brute 40 s plus tard.", "runs": ["chg-2"]},
     "a number is not in the cited facts (40)"),
    # … a count is at most the runs cited (M515), a difference of runs a true one (M512)…
    ({"kind": "trend", "text": "T1110.001 est détectée dans les 3 campagnes.", "runs": ["R2", "P1"]},
     "a number is not in the cited facts (3)"),
    ({"kind": "trend", "text": "La latence de T1110.001 augmente de 25 s.", "runs": ["R2", "P1"]},
     "a number is not in the cited facts (25)"),
    # … and a change names its facts' actions and detections, the right way round (M516–M518)
    ({"kind": "change", "text": "T1110.001 passe de detected à missed.", "runs": ["chg-2"]},
     "'missed' is not in the cited change facts"),
    ({"kind": "change", "text": "Sur T1110.001, Glorfindel passe de l'isolement au blocage.", "runs": ["chg-2"]},
     "the cited change facts hold no change from isolate_vm to block_suspicious_ip"),
    ({"kind": "change", "text": "La latence de la force brute passe de 106,9 s à 91,9 s.", "runs": ["chg-2"]},
     "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    ({"kind": "change", "text": "La confiance passe de 78 % à 80 %.", "runs": ["chg-2"]},
     "the change is said the wrong way round (78 → 80: it went from 80 to 78)"),
    # second review of D-2: « de X à Y » without a unit (M530), or with a date in brackets…
    ({"kind": "change", "text": "La confiance passe de 0,78 à 0,8.", "runs": ["chg-2"]},
     "the change is said the wrong way round (0.78 → 0.8: it went from 0.8 to 0.78)"),
    ({"kind": "change", "text": "La latence passe de 106,9 à 91,9.", "runs": ["chg-2"]},
     "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    ({"kind": "change", "text": "Elle passe de 106,9 s (23/10) à 91,9 s (21/10).", "runs": ["chg-2"]},
     "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    # … from a fact's side to a number that is not its other side (M539)…
    ({"kind": "change", "text": "La latence passe de 91,9 s à 15 s.", "runs": ["chg-2"]},
     "the cited facts hold no change from 91.9 to 15"),
    # … a number is of its unit's kind (M535), a duration converted (M536); only what is
    # counted makes a count (M534)…
    ({"kind": "change", "text": "T1110.001 est vue en 2 s.", "runs": ["chg-2"]},
     "a number is not in the cited facts (2)"),
    ({"kind": "change", "text": "La force brute est vue 15 ms plus tard.", "runs": ["chg-2"]},
     "a number is not in the cited facts (0.015)"),
    ({"kind": "change", "text": "La force brute est vue 1 heure plus tard.", "runs": ["chg-2"]},
     "a number is not in the cited facts (3600)"),
    # … a trend says the way its runs went (M531) and names their actions only (M532), an
    # observation citing a change fact its facts' (M533)
    ({"kind": "trend", "text": "La latence de T1110.001 passe de 106,9 s à 91,9 s.", "runs": ["R2", "P1"]},
     "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    ({"kind": "trend", "text": "T1110.001 passe de l'isolement au blocage.", "runs": ["R2", "P1"]},
     "the cited change facts hold no change from isolate_vm to block_suspicious_ip"),
    ({"kind": "trend", "text": "T1136.001 passe de isolate_vm à snapshot.", "runs": ["R1", "R2", "P1", "P2"]},
     "the cited change facts hold no change from isolate_vm to snapshot"),
    ({"kind": "trend", "text": "Sur T1110.001, wipe_storage cette fois.", "runs": ["R2", "P1"]},
     "'wipe_storage' is not in the cited runs"),
    ({"kind": "observation", "text": "Glorfindel a pris un wipe_storage sur T1110.001.", "runs": ["chg-2"]},
     "'wipe_storage' is not in the cited change facts"),
    # third review of D-2: a number before a date is no day of a range (M544)
    ({"kind": "change", "text": "La confiance baisse de 12, le 23 octobre.", "runs": ["chg-2"]},
     "a number is not in the cited facts (12)"),
    # fourth review of D-2: a day of a range is from 1 to 31 (M545)
    ({"kind": "change", "text": "The latency moved between 70 and 60, 23 October.", "runs": ["chg-2"]},
     "a number is not in the cited facts (70)"),
    # D2b: « au » and « the » alone open no range (M662, M663)
    ({"kind": "change", "text": "La latence tombe au 12, le 23 octobre.", "runs": ["chg-2"]},
     "a number is not in the cited facts (12)"),
    ({"kind": "change", "text": "The latency rose by the 12, 23 October.", "runs": ["chg-2"]},
     "a number is not in the cited facts (12)"),
]
CLAIMS = KEPT + [c for c, _ in REMOVED]


def test_a_difference_without_its_fact_is_removed(tmp_path, index):
    """M273–M277, M510, M512–M518, M530–M539, M543–M547: a change claim cites a change fact, and each
    number it writes is one of the cited facts' (a latency, a confidence, a difference, in
    seconds, as a fraction or in percent, a relative change in percent) — of its unit's kind,
    a duration converted to seconds; a trend too, and an observation that cites a change fact.
    A trend may write the difference of two cited runs; a count of runs, campaigns,
    techniques…, at most the runs it cites. Technique and run ids, dates (in figures, in words,
    a range), years, ordinals and VM names are not numbers. A change, a trend, and an
    observation citing a change fact name only their facts' actions and detections, and say a
    change the way it went: a trend, its earlier runs facing its runs of this campaign of the
    same technique."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0")
    report = _report(cdirs["C1"], CLAIMS)
    kept = [c.text for c in report.kept]
    assert kept == [c["text"] for c in KEPT], [(c.text, c.rejected) for c in report.rejected]
    assert [(c.text, c.rejected) for c in report.rejected] == [(c["text"], why) for c, why in REMOVED]
    md = cr.render(report)
    assert "- Sur T1110.001, l'action passe de block_suspicious_ip à isolate_vm, à 78 % au lieu de 80 %. — `chg-2`" in md
    assert "~~La force brute est vue 40 s plus tard.~~ — a number is not in the cited facts (40)" in md


def _swing(**after):
    """chg-1: T1110.001 on vm-bench-01, detected, blocked at 0.80 in 91.9 s, then ``after``."""
    run = dict(detection="detected", latency_s=106.9, decision="isolate_vm", confidence=0.78) | after
    return cc.pair([cr.RunFact("P1", "C0", 1, "T1110.001", "", "executed", "detected", latency_s=91.9,
                               decision="block_suspicious_ip", confidence=0.8, target=VM)],
                   [cr.RunFact("R2", "C1", 1, "T1110.001", "", "executed", target=VM, **run)], "C0")


@pytest.mark.parametrize("text, after, why", [
    ("Détectée puis manquée : de detected à missed.", {"detection": "missed"}, ""),
    ("De missed à detected.", {"detection": "missed"},
     "the cited change facts hold no change from missed to detected"),
    ("block_suspicious_ip → isolate_vm, 0,8 → 0,78.", {}, ""),
    ("0,78 → 0,8.", {}, "the change is said the wrong way round (0.78 → 0.8: it went from 0.8 to 0.78)"),
    ("isolate_vm → block_suspicious_ip.", {}, "the cited change facts hold no change from isolate_vm to "
                                              "block_suspicious_ip"),
    ("91,9 s → 106,9 s.", {}, ""),
    ("106,9 s → 91,9 s.", {}, "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    ("La latence reste de 91,9 s à 92 s près.", {"latency_s": 92.0}, ""),
    ("Glorfindel garde snapshot.", {}, "'snapshot' is not in the cited change facts"),
])
def test_a_change_is_said_the_way_it_went(text, after, why):
    """M516–M518: the actions and detections a change claim names are its facts'; « de X à
    Y » and « X → Y » go the way the fact went."""
    [claim] = cr.verify([cr.Claim("change", text, ["chg-1"])], [], [], _swing(**after))
    assert claim.rejected == why


@pytest.mark.parametrize("text", [
    "Le 23/10 à 08:21, T1110.001 sur vm-bench-01 (run 20261023T081719Z) : isolée à 78 %.",
    "Écart de 15,0 s sur chg-2.",
])
def test_names_are_not_numbers(text):
    [c] = cc.pair([cr.RunFact("P1", "C0", 1, "T1110.001", "", "executed", "detected", latency_s=91.9,
                              decision="block_suspicious_ip", confidence=0.8, target=VM)],
                  [cr.RunFact("R2", "C1", 1, "T1110.001", "", "executed", "detected", latency_s=106.9,
                              decision="isolate_vm", confidence=0.78, target=VM)], "C0")
    [claim] = cr.verify([cr.Claim("change", text, ["chg-1"])], [], [], [c])
    assert not claim.rejected, claim.rejected


def test_a_change_on_an_unknown_decision_says_so():
    """The rule of #167 holds on a change fact: a claim on the response of a side whose
    decision is unknown says it is unknown, and never that Glorfindel did not act."""
    [c] = cc.pair([cr.RunFact("P1", "C0", 1, "T1110.001", "", "executed", "detected", target=VM,
                              decision_unknown=cr.NO_WINDOW)],
                  [cr.RunFact("R1", "C1", 1, "T1110.001", "", "executed", "detected", target=VM,
                              decision="isolate_vm", confidence=0.78)], "C0")
    claims = cr.verify([
        cr.Claim("change", "La décision passe à isolate_vm.", ["chg-1"]),
        cr.Claim("change", "Décision inconnue avant, isolate_vm cette fois.", ["chg-1"]),
        cr.Claim("change", "Décision inconnue avant : Glorfindel n'avait pas agi.", ["chg-1"]),
    ], [], [], [c])
    assert [bool(x.rejected) for x in claims] == [True, False, True]


def test_a_change_fact_never_lets_an_unknown_decision_be_said_acted():
    """M511: « a isolé » passes on a change fact only when its other side's decision is
    known — never on a run cited directly whose decision is unknown, even beside a change
    fact, nor on a change fact unknown on both sides (#167)."""
    def run(rid, cid, **kw):
        return cr.RunFact(rid, cid, 1, "T1110.001", "", "executed", "detected", target=VM, **kw)
    p1 = run("P1", "C0", decision_unknown=cr.NO_WINDOW)
    [one] = cc.pair([p1], [run("R1", "C1", decision="isolate_vm", confidence=0.78)], "C0")
    [two] = cc.pair([p1], [run("R1", "C1", decision_unknown=cr.NONE_IN_WINDOW)], "C0")
    acted = "Décision inconnue sur un côté ; Glorfindel a isolé la VM."
    claims = cr.verify([
        cr.Claim("observation", acted, ["P1"]),
        cr.Claim("observation", acted, ["P1", "chg-1"]),
    ], [], [p1], [one])
    claims += cr.verify([
        cr.Claim("change", "Décision inconnue des deux côtés, mais Glorfindel a isolé la VM les deux fois.",
                 ["chg-1"])], [], [], [two])
    claims += cr.verify([cr.Claim("change", acted, ["chg-1"])], [], [], [one])
    assert [x.rejected.endswith("the claim says Glorfindel acted") for x in claims] == [True, True, True, False]


def test_a_run_without_its_id_is_still_played():
    """M519: a run played without a run id is on its side — never « only in the previous
    campaign » when its key was played here too."""
    def run(rid, cid, seq, ttp):
        return cr.RunFact(rid, cid, seq, ttp, "", "executed", "detected", target=VM)
    changes = cc.pair([run("P1", "C0", 1, "T1110.001")],
                      [run("", "C1", 1, "T1110.001"), run("", "C1", 2, "T1041")], "C0")
    assert [(c.ttp, c.side, c.before_run, c.after_run) for c in changes] == [
        ("T1110.001", "both", "P1", ""), ("T1041", "after", "", "")]
    md = "\n".join(cc.render_section(cc.Comparison("C0", "", changes)))
    assert "Seulement dans celle-ci (1) : `chg-2` T1041 sur vm-bench-01 (run sans identifiant)." in md
    assert "Seulement dans la campagne précédente" not in md


def test_the_actions_named_are_glorfindels():
    """The actions a change claim may name are Glorfindel's, written again for the report
    (the Annatar image has no Glorfindel package)."""
    from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED
    assert set(cc.ACTIONS) == AUTONOMOUS_ACTIONS | HUMAN_APPROVAL_REQUIRED


# ── The index of past campaigns ──────────────────────────────────────────────────────

def test_putting_a_campaign_in_keeps_the_facts_its_report_saw(tmp_path, index):
    """M278: a run already indexed keeps its facts — its window may be gone by now, and its
    decision with it; only the campaign's state and start, and the run's VM, are added."""
    runs, cdirs = _bench(tmp_path)
    old = cr.collect_facts(cdirs["C0"])
    for f in old:
        f.target = ""
    cr.index_facts(old)                                   # its report, before D-2
    for rid in ("P1", "P2"):
        (runs / f"{rid}_debug.jsonl").unlink()            # what the files say now: no decision
    result = ci.verse(cdirs["C0"])
    assert (result.kept, result.computed, result.missing) == (["P1", "P2"], [], [])
    row = index.rows["P1"]
    assert (row["campaign_state"], row["vm"]) == ("done", VM.lower())
    assert row["campaign_started"] == pytest.approx(cr.campaign_info(cdirs["C0"]).started)
    fact = cr.fact_of(row)
    assert (fact.decision, fact.confidence, fact.target) == ("block_suspicious_ip", 0.8, VM)


def test_a_run_not_yet_indexed_is_computed_from_the_files(tmp_path, index):
    _, cdirs = _bench(tmp_path)
    result = ci.verse(cdirs["C1"])
    assert (result.kept, result.computed) == ([], ["R1", "R2", "R3", "R4"])
    assert cr.fact_of(index.rows["R2"]).decision == "isolate_vm"


def test_putting_campaigns_in_is_idempotent(tmp_path, index, capsys):
    """M279: run twice, the index is the same; a campaign still running is left, and said."""
    runs, cdirs = _bench(tmp_path)
    _campaign(runs, "CR", "2026-10-25T08:00:00Z", [_run(1, "Q1", "T1041")], state="running")
    assert ci.main(["--all", str(runs / "campaigns")]) == 0
    first = json.loads(json.dumps(index.rows))
    assert ci.main(["--all", str(runs / "campaigns")]) == 0
    assert index.rows == first
    assert "Q1" not in index.rows
    out = capsys.readouterr().out
    assert "CR : laissée (état running : pas terminée)" in out
    assert "C1 (done) : 4 run(s) dans l'index — 4 gardé(s) tel(s) quel(s), 0 calculé(s)" in out
    assert _report(cdirs["C1"]).comparison.previous == "C0"


def test_the_command_says_how_to_use_it(capsys):
    assert ci.main([]) == 2
    assert ci.main([str("/nonexistent/campaign")]) == 1
    assert "manifeste illisible" in capsys.readouterr().out


def test_the_real_index_chooses_the_previous_campaign(tmp_path):
    """The same rule against chromadb itself: its ``where`` on the campaign's state, its
    float metadata."""
    pytest.importorskip("chromadb")
    _, cdirs = _bench(tmp_path)
    idx = tmp_path / "idx"
    for name in ("C0", "CA", "C2"):
        cr.build(cdirs[name], model="fake/model", llm=_Model(), index_path=idx)
    report = cr.build(cdirs["C1"], model="fake/model", llm=_Model(), index_path=idx)
    assert report.comparison.previous == "C0"
    assert [c.side for c in report.comparison.changes] == ["after", "both", "after", "before"]


# When a campaign started, as the index keeps it (D2b).
STARTED = {"Cm1": cr._timestamp("2026-10-19T08:00:00Z"), "C0": cr._timestamp("2026-10-21T12:16:43Z"),
           "C1": cr._timestamp("2026-10-23T08:11:20Z")}


def _three_campaigns(known=False):
    """T1110.001 on 19/10 (Q1, blocked at 0.85 in 120 s), 21/10 (P1, blocked at 0.80 in
    91.9 s) and 23/10 (R2, isolated at 0.78 in 106.9 s); T1041 blocked on 19/10 (Q2),
    isolated on 21/10 (P2), blocked again on 23/10 (R3). R2 and R3 are this campaign's.
    ``known``: each run carries its campaign's start, as the index keeps it (D2b); else
    which came first is not known (rows indexed before D-2, ids that are no dates)."""
    def run(rid, cid, seq, ttp, latency, decision, confidence):
        return cr.RunFact(rid, cid, seq, ttp, "", "executed", "detected", latency_s=latency,
                          decision=decision, confidence=confidence, target=VM,
                          campaign_started=STARTED[cid] if known else None)
    prior = [run("Q1", "Cm1", 1, "T1110.001", 120.0, "block_suspicious_ip", 0.85),
             run("Q2", "Cm1", 2, "T1041", 140.0, "block_suspicious_ip", 0.70),
             run("P1", "C0", 1, "T1110.001", 91.9, "block_suspicious_ip", 0.80),
             run("P2", "C0", 2, "T1041", 130.1, "isolate_vm", 0.90)]
    facts = [run("R2", "C1", 1, "T1110.001", 106.9, "isolate_vm", 0.78),
             run("R3", "C1", 2, "T1041", 101.6, "block_suspicious_ip", 0.86)]
    return facts, prior, cc.pair(prior[2:], facts, "C0")


@pytest.mark.parametrize("text, runs, why", [
    # a true trend over three campaigns is kept, cited in either order (M540, M541)
    ("Sur T1110.001, la latence passe de 120 s (19/10) à 91,9 s (21/10), puis à 106,9 s (23/10).",
     ["R2", "P1", "Q1"], ""),
    ("Sur T1110.001, la latence passe de 120 s (19/10) à 91,9 s (21/10), puis à 106,9 s (23/10).",
     ["R2", "Q1", "P1"], ""),
    ("Sur T1110.001, la latence : 120 s → 91,9 s → 106,9 s.", ["R2", "P1", "Q1"], ""),
    ("La confiance sur T1110.001 : 0,85 → 0,80 → 0,78.", ["R2", "P1", "Q1"], ""),
    ("Sur T1110.001, la confiance passe de 85 % à 80 %, puis à 78 %.", ["R2", "P1", "Q1"], ""),
    ("Sur T1041, du blocage à l'isolement (avant), puis retour au blocage.", ["R3", "P2", "Q2"], ""),
    # a way inverted between an earlier run and one of this campaign stays removed…
    ("Sur T1110.001, la latence passe de 106,9 s à 91,9 s.", ["R2", "P1", "Q1"],
     "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)"),
    ("Sur T1110.001, la latence passe de 106,9 s à 120 s.", ["R2", "P1", "Q1"],
     "the change is said the wrong way round (106.9 → 120: it went from 120 to 106.9)"),
    ("T1110.001 passe de l'isolement au blocage.", ["R2", "P1", "Q1"],
     "the cited change facts hold no change from isolate_vm to block_suspicious_ip"),
    # … and two earlier runs face each other only on the same technique (M542)
    ("T1110.001 passe de l'isolement au blocage.", ["R2", "P1", "P2"],
     "the cited change facts hold no change from isolate_vm to block_suspicious_ip"),
])
@pytest.mark.parametrize("known", [False, True], ids=["order unknown", "order known"])
def test_a_trend_over_three_campaigns(text, runs, why, known):
    """M540–M542, M651: a trend citing two earlier campaigns may say the way between them,
    cited in either order — both ways when which came first is not known, the way they went
    when it is (D2b); between an earlier run and one of this campaign, the way is still
    read."""
    facts, prior, changes = _three_campaigns(known)
    [claim] = cr.verify([cr.Claim("trend", text, runs)], facts, prior, changes)
    assert claim.rejected == why


# ── D2b: the order of the runs a trend cites, read ───────────────────────────────────

def _alibi(order):
    """T1110.001 blocked in 91.9 s (P1), then isolated in 106.9 s (Q1), on two earlier
    campaigns; isolated again in 106.9 s on this one (R2). It never went from isolating to
    blocking, nor from 106.9 s to 91.9 s. ``order``: how the earlier runs' order is known —
    ``None`` (rows indexed before D-2: not known), ``started`` (the index's start of their
    campaign), ``id`` (an id that is a date, no start), ``seq`` (both of one campaign)."""
    def run(rid, cid, seq, decision, latency, started=None):
        return cr.RunFact(rid, cid, seq, "T1110.001", "", "executed", "detected", latency_s=latency,
                          decision=decision, confidence=0.8, target=VM, campaign_started=started)
    ids = {"id": ("20261019T080000Z", "20261021T121643Z"), "seq": ("Cb", "Cb")}.get(order, ("Cb", "Cq"))
    starts = (STARTED["Cm1"], STARTED["C0"]) if order == "started" else (None, None)
    prior = [run("P1", ids[0], 1, "block_suspicious_ip", 91.9, starts[0]),
             run("Q1", ids[1], 2, "isolate_vm", 106.9, starts[1])]
    return [run("R2", "C1", 1, "isolate_vm", 106.9, STARTED["C1"])], prior


ALIBIS = [("T1110.001 passe de l'isolement au blocage.",
           "the cited change facts hold no change from isolate_vm to block_suspicious_ip"),
          ("Sur T1110.001, la latence passe de 106,9 s à 91,9 s.",
           "the change is said the wrong way round (106.9 → 91.9: it went from 91.9 to 106.9)")]


@pytest.mark.parametrize("text, why", ALIBIS)
@pytest.mark.parametrize("order", ["started", "id", "seq"])
def test_a_pair_of_earlier_runs_is_no_alibi_once_their_order_is_known(text, why, order):
    """M650, M654, M655: two earlier runs face each other the way they were played, read on
    their campaigns' starts, on their ids when they are dates, on ``seq`` within one
    campaign: « de l'isolement au blocage » or « de 106,9 s à 91,9 s » finds no pair to
    hide behind."""
    facts, prior = _alibi(order)
    [claim] = cr.verify([cr.Claim("trend", text, ["R2", "P1", "Q1"])], facts, prior)
    assert claim.rejected == why


@pytest.mark.parametrize("text, why", ALIBIS)
def test_without_their_order_two_earlier_runs_face_each_other_both_ways(text, why):
    """The limit that stays (docs/analysis.md): rows indexed before D-2, ids that are no
    dates — which came first is not known, both ways are read between two earlier runs."""
    facts, prior = _alibi(None)
    [claim] = cr.verify([cr.Claim("trend", text, ["R2", "P1", "Q1"])], facts, prior)
    assert claim.rejected == ""


def test_a_true_trend_between_two_earlier_runs_stays():
    """Isolated on 19/10 (Q1), blocked on 21/10 (P1), isolated on 23/10 (R2): « de
    l'isolement au blocage » is what happened between 19/10 and 21/10 — kept, the order
    known, as « du blocage à l'isolement (avant), puis retour au blocage » is on T1041
    (test_a_trend_over_three_campaigns)."""
    def run(rid, cid, decision):
        return cr.RunFact(rid, cid, 1, "T1110.001", "", "executed", "detected", decision=decision,
                          target=VM, campaign_started=STARTED[cid])
    facts = [run("R2", "C1", "isolate_vm")]
    prior = [run("Q1", "Cm1", "isolate_vm"), run("P1", "C0", "block_suspicious_ip")]
    [claim] = cr.verify([cr.Claim("trend", "T1110.001 passe de l'isolement au blocage.",
                                  ["R2", "P1", "Q1"])], facts, prior)
    assert claim.rejected == ""


def test_a_later_campaign_s_run_comes_after_this_one(tmp_path, index):
    """M652, M653: the report of C1 (23/10) written again once C2 (24/10) is in the index —
    C2's run is cited as an earlier one, but it was played after: « de 10 s à 106,9 s » goes
    against time, « de 106,9 s à 10 s » with it. The order is read on the start the index
    keeps beside each run, and on this campaign's own."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0", "C2")
    report = _report(cdirs["C1"], [
        {"kind": "trend", "text": "La latence de T1110.001 passe de 10 s à 106,9 s.", "runs": ["R2", "Z1"]},
        {"kind": "trend", "text": "La latence de T1110.001 passe de 106,9 s à 10 s.", "runs": ["R2", "Z1"]}])
    assert [c.rejected for c in report.claims] == [
        "the change is said the wrong way round (10 → 106.9: it went from 106.9 to 10)", ""]


def test_the_start_of_a_campaign_is_kept_beside_its_runs_not_in_their_facts(tmp_path, index):
    """One place: the row's ``campaign_started``, which putting the campaign in again
    updates — the facts' JSON, kept as indexed, never holds it."""
    _, cdirs = _bench(tmp_path)
    _index_all(cdirs, "C0")
    row = index.rows["P1"]
    assert "campaign_started" not in json.loads(row["fact"])
    assert cr.fact_of(row).campaign_started == pytest.approx(cr.campaign_info(cdirs["C0"]).started)


# ── D2b: the dates of a manifest that came through the channel, checked ─────────────────

WINDOW = "2026-10-23T08:12:00Z"           # when the first run of CH opened its window


def _window_file(runs, rid, start, *, lasts_s=3600.0):
    """A run's window as H0 holds it once pulled: its file written ten minutes after its start."""
    t = cr._timestamp(start)
    path = cr.windows_dir(runs) / f"{rid}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "run_id": rid, "injector": "annatar", "kind": "technique", "experiment": "T1110.001",
        "targets": [VM.lower()], "start": start, "end": cr._iso(t + 300),
        "expires": cr._iso(t + lasts_s)}))
    os.utime(path, (t + 600, t + 600))


def _from_channel(runs, cid, created, scenarios, *, pulled="2026-10-26T06:00:00Z", windows=()):
    """A campaign pulled from the channel: its manifest (``created``: the date it gives),
    its runs' reports, its ``.pulled`` marker, and the windows H0 holds — ``(run id, start,
    how long it lasts)``."""
    cdir = _campaign(runs, cid, created, scenarios)
    (cdir / "runs").mkdir()
    for s in scenarios:
        (cdir / "runs" / f"{s['run_id']}.json").write_text(json.dumps(
            {"run_id": s["run_id"], "metrics": {"attack_time": None}}))
    for rid, start, lasts in windows:
        _window_file(runs, rid, start, lasts_s=lasts)
    marker = cdir / PULLED
    marker.touch()
    os.utime(marker, (cr._timestamp(pulled),) * 2)
    return cdir


@pytest.mark.parametrize("created, forged, said", [
    # the date it gives: the start H0 saw, give or take — believed, nothing said
    ("2026-10-23T08:11:20Z", (), ""),
    # after C2 (24/10): unchecked, C2 would be « the previous one »
    ("2026-10-25T00:00:00Z", (), "il est postérieur à la première fenêtre d'exercice de ses runs"),
    # before C0 (21/10, 12:16), after CM (18/10): unchecked, CM would be
    ("2026-10-21T00:00:00Z", (), "il précède de plus de 1 h la première fenêtre d'exercice de ses runs"),
    # the same, with a window of its own that H-1 refuses (it lasts 3 h): it bounds nothing
    ("2026-10-18T10:00:00Z", (("HX", "2026-10-18T10:05:00Z", 3 * 3600.0),),
     "il précède de plus de 1 h la première fenêtre d'exercice de ses runs"),
])
def test_a_forged_manifest_date_does_not_change_the_previous_campaign(tmp_path, index, created, forged,
                                                                      said):
    """M656, M657, M659–M661: a campaign that came through the channel gives its start in
    its manifest, written by whoever can write in the channel. H0 bounds it by what it saw:
    the first window of its runs that H-1 believes. A date that does not fit is refused, said
    in the report, and the window's start taken: the previous campaign stays C0."""
    runs, cdirs = _bench(tmp_path)
    cm = _campaign(runs, "CM", "2026-10-18T09:00:00Z", [
        _run(1, "M1", "T1110.001", latency=70.0, action="block_suspicious_ip", confidence=0.7)])
    _report(cm)
    _index_all(cdirs, "C0", "C2")
    scenarios = [_run(1, "H1", "T1110.001", latency=106.9, action="isolate_vm", confidence=0.78)]
    scenarios += [_run(2, rid, "T1041", status="error", detection=None) for rid, *_ in forged]
    cdir = _from_channel(runs, "CH", created, scenarios, windows=(("H1", WINDOW, 3600.0), *forged))
    info = cr.campaign_info(cdir)
    report = _report(cdir)
    assert report.comparison.previous == "C0"
    refused = [s for s in report.skipped if "refusé" in s]
    if not said:
        assert (info.started, info.start_refused, refused) == (cr._timestamp(created), "", [])
        return
    assert info.started == cr._timestamp(WINDOW)
    assert refused == [info.start_refused]
    assert info.start_refused == (f"début de la campagne lu dans son manifeste ({created}) refusé : "
                                  f"{said} ({WINDOW}) ; pris : le début de sa première fenêtre ({WINDOW})")
    assert f"*Écarté des faits (1) : {info.start_refused}.*" in cr.render(report)
    assert index.rows["H1"]["campaign_started"] == cr._timestamp(WINDOW)


def test_a_channel_campaign_did_not_start_after_h0_pulled_it(tmp_path, index):
    """M658: without a window (purged a week after its end), the ``.pulled`` marker still
    bounds it: a campaign cannot have started after H0 pulled it. Refused, its start is
    unknown — never the date it gave — and putting it in the index says so."""
    runs = tmp_path / "runs"
    cdir = _from_channel(runs, "CH", "2026-10-25T00:00:00Z",
                         [_run(1, "H1", "T1110.001", latency=106.9)], pulled="2026-10-24T00:00:00Z")
    info = cr.campaign_info(cdir)
    assert (info.started, info.start_refused) == (None, (
        "début de la campagne lu dans son manifeste (2026-10-25T00:00:00Z) refusé : il est postérieur "
        "au tirage de la campagne par H0 (2026-10-24T00:00:00Z) ; début inconnu"))
    assert ci.verse(cdir).line().endswith(f" ; {info.start_refused}")
    honest = _from_channel(runs, "CK", "2026-10-23T08:00:00Z",
                           [_run(1, "K1", "T1110.001", latency=106.9)], pulled="2026-10-24T00:00:00Z")
    assert (cr.campaign_info(honest).started, cr.campaign_info(honest).start_refused) == (
        cr._timestamp("2026-10-23T08:00:00Z"), "")


def test_a_local_campaign_s_dates_are_its_own(tmp_path):
    """Only a campaign that came through the channel is checked: a local one's manifest was
    written on this host."""
    runs, cdirs = _bench(tmp_path)
    _window_file(runs, "R2", WINDOW)
    (cdirs["C1"] / "manifest.json").write_text(json.dumps(
        {"campaign_id": "C1", "state": "done", "created_at": "2026-10-25T00:00:00Z",
         "scenarios": [{"seq": 1, "ttp": "T1110.001", "run_id": "R2", "status": "executed"}]}))
    assert cr.campaign_info(cdirs["C1"]).started == cr._timestamp("2026-10-25T00:00:00Z")
