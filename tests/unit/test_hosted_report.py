"""#167, H0's side: the report of a campaign published by Orodruin writes itself where the
watch runs — once, with Glorfindel's decisions found in the watch's ``watch-*`` files by the
rule of #157 (same technique, same VM without case, between the run's attack and the end of
its window, grace included), an unknown decision said as such, and no failure of the report
ever reaching the watch. A fake model (no call), a fake index (no embedding, no download),
the container in memory (tests/unit/fake_container.py), files in tmp. Mutants M126–M129,
M131–M135, M137, M140–M148, M159–M169 and M180–M188 (scripts/mutation_check.py) are measured
here."""
import fcntl
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import eregion_core.exercise as exercise
import eregion_core.exercise_channel as channel
from analysis import campaign_report as cr
from analysis import hosted_report as hr
from tests.unit.fake_container import CRED, URL, FakeContainer

VM = "/subscriptions/s/resourceGroups/rg-bench/providers/Microsoft.Compute/virtualMachines/vm-bench-01"
OTHER_VM = VM.replace("vm-bench-01", "vm-bench-02")
T = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)   # the campaign's first window opens
ATTACK = T + timedelta(minutes=1)
END = T + timedelta(minutes=5)                           # the window closes
LAST = END + timedelta(seconds=exercise.GRACE_AFTER_S)   # last moment a detection counts


class _Index:
    """The ``campaign_runs`` collection in memory: no embedding model, no download."""
    def __init__(self):
        self.rows, self.paths = {}, []

    def __call__(self, path=None):
        self.paths.append(path)
        return self

    def upsert(self, ids, documents, metadatas):
        self.rows.update(zip(ids, metadatas))

    def count(self):
        return len(self.rows)

    def get(self, where, limit):
        rows = [m for m in self.rows.values() if all(m.get(k) == v for k, v in where.items())]
        return {"metadatas": rows[:limit]}


class _Model:
    """The analysis model, faked: its claims through the tool, or an answer without it."""
    def __init__(self, claims=(), tool=True):
        self.claims, self.tool, self.calls = list(claims), tool, []

    def completion(self, **kw):
        self.calls.append(kw)
        calls = [SimpleNamespace(function=SimpleNamespace(
            arguments=json.dumps({"claims": self.claims})))] if self.tool else None
        msg = SimpleNamespace(tool_calls=calls, content="Voici le rapport.")
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


@pytest.fixture(autouse=True)
def hermetic(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a call left the process")
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", refuse)
    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    monkeypatch.setattr(hr, "_failures", {})
    monkeypatch.setattr(hr, "_said", {})


@pytest.fixture
def index(monkeypatch):
    idx = _Index()
    monkeypatch.setattr(cr, "_collection", idx)
    return idx


def _iso(dt):
    return dt.isoformat()


def _never_raises(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except Exception as e:
        pytest.fail(f"{fn.__name__} raised {type(e).__name__}: {e}")


def _scen(seq, rid, *, status="executed", detection="detected", vm=VM, ttp="T1136.001"):
    return {"seq": seq, "ttp": ttp, "name": f"step {seq}", "target_resource_id": vm,
            "status": status, "run_id": rid, "detection": detection,
            "finished_at": _iso(END)}


def _decision(*, at, vm=VM.lower(), ttp="T1136.001", action="snapshot", confidence=0.4):
    return {"signal": {"event": "detection", "ttp": ttp, "resource_id": vm, "timestamp": _iso(at)},
            "action": action, "confidence": confidence, "escalate": True,
            "reasoning": "Un nouveau compte local avec un shell."}


def _window(rid, *, start=T, end=END, vm=VM):
    return {"run_id": rid, "injector": "annatar", "kind": "technique", "experiment": "T1136.001",
            "targets": [vm.lower()], "start": _iso(start), "end": end and _iso(end),
            "expires": _iso(start + timedelta(seconds=exercise.MAX_DURATION_S))}


def _h0(tmp_path, *, scenarios=None, watch=(), state="done", pulled=True, windows=True,
        attack=ATTACK.timestamp(), name="C1", start=T):
    """A campaign as H0 holds it once pulled: its manifest and its runs' reports under
    ``runs/campaigns/<id>/``, the runs' windows in ``runs/exercises/``, the watch's file."""
    runs = tmp_path / "h0" / "runs"
    cdir = runs / "campaigns" / name
    (cdir / "runs").mkdir(parents=True)
    scenarios = scenarios if scenarios is not None else [
        _scen(1, "R1"), _scen(2, "R2", detection="missed")]
    (cdir / "manifest.json").write_text(json.dumps({
        "campaign_id": name, "state": state, "updated_at": _iso(T + timedelta(minutes=10)),
        "scenarios": scenarios}))
    if pulled:
        (cdir / channel.PULLED).touch()
    for s in scenarios:
        if s["status"] == "executed" and channel.safe_part(s["run_id"]):
            (cdir / "runs" / f"{s['run_id']}.json").write_text(json.dumps(
                {"run_id": s["run_id"], "metrics": {"attack_time": attack}}))
            if windows:
                (runs / "exercises").mkdir(exist_ok=True)
                (runs / "exercises" / f"{s['run_id']}.json").write_text(
                    json.dumps(_window(s["run_id"], vm=s["target_resource_id"] or VM, start=start,
                                       end=END + (start - T))))
    if watch:
        (runs / "watch-account-creation-20261001T100300Z_debug.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in watch))
    return cdir, runs


def _attach(cdir, runs, scenario=None, rid="R1"):
    scenario = scenario or json.loads((cdir / "manifest.json").read_text())["scenarios"][0]
    return cr.run_decision(scenario, rid, cdir, runs, cr._watch_files(runs))


# ── The decision of a run, from the watch's files ────────────────────────────────

def test_the_decision_is_the_first_on_the_runs_technique_and_vm(tmp_path):
    """M128: a decision on another VM, or of another technique, is never the run's."""
    cdir, runs = _h0(tmp_path, watch=[
        _decision(at=T + timedelta(minutes=2), ttp="T1110.001", action="block_suspicious_ip"),
        _decision(at=T + timedelta(minutes=2, seconds=30), vm=OTHER_VM.lower(), action="isolate_vm"),
        _decision(at=T + timedelta(minutes=4), action="isolate_vm", confidence=0.9),
        _decision(at=T + timedelta(minutes=3), action="snapshot", confidence=0.4),
    ])
    dec, why, until = _attach(cdir, runs)
    assert (dec.get("action"), dec.get("confidence"), why) == ("snapshot", 0.4, "")
    assert until == LAST


def test_the_vm_is_compared_without_its_case(tmp_path):
    """M129: Log Analytics writes the resource id in lower case, Annatar in ARM's."""
    for vm in (VM.lower(), VM.upper()):
        cdir, runs = _h0(tmp_path / vm[-5:], watch=[_decision(at=T + timedelta(minutes=3), vm=vm)])
        assert _attach(cdir, runs)[0].get("action") == "snapshot"


@pytest.mark.parametrize("at, counts", [
    (ATTACK - timedelta(seconds=1), False),   # before the attack: an earlier one's
    (ATTACK, True),
    (LAST, True),                             # the window's end plus its grace, included
    (LAST + timedelta(seconds=1), False),     # after: a later exercise's, or a real one
])
def test_a_decision_counts_only_inside_the_runs_window(tmp_path, at, counts):
    """M126, M127: from the run's attack to the end of its window, grace included."""
    cdir, runs = _h0(tmp_path, watch=[_decision(at=at)])
    dec, why, _ = _attach(cdir, runs)
    assert (dec.get("action"), why) == (("snapshot", "") if counts else (None, cr.NONE_IN_WINDOW))


def test_a_detection_without_an_action_is_not_a_decision(tmp_path):
    """M137: the first detection that carries an action, as in the run's own file."""
    cdir, runs = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=2), action=""),
                                      _decision(at=T + timedelta(minutes=6), action="isolate_vm")])
    assert _attach(cdir, runs)[0].get("action") == "isolate_vm"
    cdir, runs = _h0(tmp_path / "b", watch=[_decision(at=T + timedelta(minutes=2), action="")])
    assert _attach(cdir, runs)[:2] == ({}, cr.NONE_IN_WINDOW)


@pytest.mark.parametrize("attack", [None, float("nan"), float("inf"), "1790000000"])
def test_nothing_is_attached_without_a_finite_attack_time(tmp_path, attack):
    cdir, runs = _h0(tmp_path, attack=attack, watch=[_decision(at=T + timedelta(minutes=3))])
    assert _attach(cdir, runs)[:2] == ({}, cr.NO_ATTACK_TIME)


def test_nothing_is_attached_without_a_resource(tmp_path):
    cdir, runs = _h0(tmp_path, scenarios=[_scen(1, "R1", vm="")],
                     watch=[_decision(at=T + timedelta(minutes=3))])
    assert _attach(cdir, runs)[:2] == ({}, cr.NO_RESOURCE)


@pytest.mark.parametrize("window", [None, "not json", {"run_id": "R1", "start": "x"}])
def test_nothing_is_attached_without_a_readable_window(tmp_path, window):
    cdir, runs = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    path = runs / "exercises" / "R1.json"
    if window is None:
        path.unlink()
    else:
        path.write_text(window if isinstance(window, str) else json.dumps(window))
    dec, why, until = _attach(cdir, runs)
    assert (dec, why, until) == ({}, cr.NO_WINDOW, None)


def test_the_runs_own_debug_file_comes_first(tmp_path):
    cdir, runs = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    (runs / "R1_debug.jsonl").write_text(json.dumps(
        {"signal": {"event": "detection"}, "action": "isolate_vm", "confidence": 0.9}) + "\n")
    assert _attach(cdir, runs)[:2] == ({"signal": {"event": "detection"}, "action": "isolate_vm",
                                        "confidence": 0.9}, "")


def test_collect_facts_carries_the_decision_found_in_the_watch(tmp_path):
    """R2, missed, shares R1's technique, VM and window: the decision inside it is a late
    one or R1's — a missed run takes nothing from the watch's files, and its decision is then
    unknown, not « none »."""
    cdir, runs = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    r1, r2 = cr.collect_facts(cdir)
    assert (r1.decision, r1.confidence, r1.escalated, r1.decision_unknown) == ("snapshot", 0.4, True, "")
    assert r1.excerpt == "Un nouveau compte local avec un shell."
    assert (r2.detection, r2.decision, r2.escalated, r2.decision_unknown) == ("missed", "", None,
                                                                            cr.LATE_OR_OTHER)


def test_a_missed_run_whose_window_holds_a_decision_is_unknown_not_none(tmp_path):
    """M164: Glorfindel may have detected late, and acted, inside the window and its grace:
    « did not act » is then not known — the decision is not attached, nor awaited."""
    missed = [_scen(1, "R1", detection="missed")]
    cdir, runs = _h0(tmp_path, scenarios=missed, watch=[_decision(at=LAST)])
    [r1] = cr.collect_facts(cdir)
    assert (r1.decision, r1.confidence, r1.escalated, r1.excerpt) == ("", None, None, "")
    assert r1.decision_unknown == cr.LATE_OR_OTHER
    assert cr.undecided_runs(cdir, runs) == []
    none, seen = cr.verify([cr.Claim("missed", "Manquée ; Glorfindel n'a pas agi.", ["R1"]),
                            cr.Claim("missed", "La création du compte a été manquée.", ["R1"])], [r1], [])
    assert none.rejected.startswith("the decision of a cited run is unknown") and not seen.rejected
    md = cr.render(cr.Report("C1", [r1], model="fake/model"))
    assert f"| `R1` | missed | — | inconnue — {cr.LATE_OR_OTHER} |" in md
    # no decision in its window (nor one past it): nothing to say, as before
    cdir, _ = _h0(tmp_path / "b", scenarios=missed, watch=[_decision(at=LAST + timedelta(seconds=1))])
    assert cr.collect_facts(cdir)[0].decision_unknown == ""


# ── A decision not found is an unknown, never « none » ───────────────────────────

def _five(tmp_path, **kw):
    return _h0(tmp_path, scenarios=[
        _scen(1, "R1"),                                      # detected, no decision found
        _scen(2, "R2", detection="missed"),
        _scen(3, "R3", detection="unknown"),                 # the return channel said nothing
        _scen(4, "R4", status="skipped", detection=None),
        _scen(5, "R5", vm=OTHER_VM),                         # detected, decided
    ], watch=[_decision(at=T + timedelta(minutes=3), vm=OTHER_VM.lower())], **kw)


def test_the_runs_whose_decision_is_awaited(tmp_path):
    """M145: an executed run of unknown detection is awaited like a detected one."""
    cdir, runs = _five(tmp_path)
    assert cr.undecided_runs(cdir, runs) == [("R1", cr.NONE_IN_WINDOW, LAST),
                                             ("R3", cr.NONE_IN_WINDOW, LAST)]


def test_a_run_of_unknown_detection_is_an_unknown_decision_not_none(tmp_path):
    """M145: its decision is unknown; the check removes « Glorfindel did not act »."""
    cdir, runs = _five(tmp_path)
    facts = {f.run_id: f for f in cr.collect_facts(cdir)}
    assert facts["R3"].decision_unknown == cr.NONE_IN_WINDOW
    assert (facts["R2"].decision_unknown, facts["R4"].decision_unknown, facts["R5"].decision) == ("", "", "snapshot")
    [claim] = cr.verify([cr.Claim("observation", "Glorfindel n'a pas agi sur ce run.", ["R3"])],
                        list(facts.values()), [])
    assert claim.rejected.startswith("the decision of a cited run is unknown")


UNKNOWN = cr.RunFact("R1", "C1", 1, "T1136.001", "step 1", "executed", "detected", latency_s=120.0,
                     decision_unknown=cr.NONE_IN_WINDOW)
EARLIER = cr.RunFact("P1", "C0", 1, "T1136.001", "step 1", "executed", "detected")


@pytest.mark.parametrize("kind, text, runs, value, kept", [
    ("detected", "T1136.001 a été détectée.", ["R1"], "", True),
    ("latency", "Détectée en 120 secondes.", ["R1"], "120", True),
    ("observation", "La décision de Glorfindel sur ce run est inconnue.", ["R1"], "", True),
    ("observation", "Aucune décision connue pour ce run.", ["R1"], "", True),
    ("trend", "Détectée comme avant ; la décision reste inconnue.", ["R1", "P1"], "", True),
    # The reasons given to the model, cited: they say « unknown » (M161).
    ("detected", f"Détectée ; {cr.NONE_IN_WINDOW}.", ["R1"], "", True),
    ("observation", f"Pour ce run : {cr.NONE_IN_WINDOW}.", ["R1"], "", True),
    ("observation", f"Pour ce run : {cr.LATE_OR_OTHER}.", ["R1"], "", True),
    ("observation", f"Décision inconnue : {cr.NONE_IN_WINDOW}.", ["R1"], "", True),
    ("observation", f"Décision inconnue : {cr.NO_WINDOW}.", ["R1"], "", True),
    ("observation", f"Décision inconnue : {cr.NO_ATTACK_TIME}.", ["R1"], "", True),
    ("observation", f"Décision inconnue : {cr.NO_RESOURCE}.", ["R1"], "", True),
    ("detected", f"Détectée ; décision inconnue ({cr.NO_ATTACK_TIME}, {cr.NO_WINDOW}).", ["R1"], "", True),
    # A trend or an observation on the detection alone: the response is not spoken of (M162).
    ("trend", "Latence en hausse par rapport à la campagne précédente.", ["R1", "P1"], "", True),
    ("trend", "Détectée cette fois comme la précédente.", ["R1", "P1"], "", True),
    ("observation", "La règle a vu la création du compte deux minutes après l'attaque.", ["R1"], "", True),
    # A decision claim, by its kind; a trend or an observation on the response that does not
    # say « unknown » (M147).
    ("decision", "Glorfindel a pris un snapshot.", ["R1"], "snapshot", False),
    ("decision", "Glorfindel n'a rien décidé.", ["R1"], "", False),
    ("observation", "Glorfindel a isolé la VM.", ["R1"], "", False),
    ("trend", "La décision de Glorfindel diffère de la campagne précédente.", ["R1", "P1"], "", False),
    ("observation", "La réponse de Glorfindel mérite un examen.", ["R1"], "", False),
    # « acted », of whatever kind (M163).
    ("detected", "Détectée ; Glorfindel a isolé la VM à 90 %.", ["R1"], "", False),
    ("latency", "Détectée en 120 secondes, puis escaladée.", ["R1"], "120", False),
    ("missed", "Glorfindel a bloqué l'adresse.", ["R1"], "", False),
    ("detected", "Détectée ; la décision reste inconnue, mais Glorfindel a pris un snapshot.", ["R1"], "", False),
    # The text: « did not act », in the phrasings measured by the third review.
    ("detected", "Détectée, mais Glorfindel n'a pas agi.", ["R1"], "", False),
    ("detected", "Détectée ; Glorfindel n'a rien fait.", ["R1"], "", False),
    ("detected", "Détectée ; Glorfindel n'a pris aucune mesure.", ["R1"], "", False),
    ("detected", "Détectée ; Glorfindel n'est pas intervenu.", ["R1"], "", False),
    ("detected", "Détectée ; Glorfindel est resté passif.", ["R1"], "", False),
    ("observation", "Décision inconnue : Glorfindel n'a pas agi.", ["R1"], "", False),
    # The old reason, a nothing, copied into a claim (review 5, measured): never read as an
    # unknown (M180) — nor the reason of a missed run inside « aucune … » (M184).
    ("detected", "Détectée ; Glorfindel n'a pris aucune décision dans la fenêtre.", ["R1"], "", False),
    ("observation", "Détectée ; Glorfindel n'a pris aucune décision dans la fenêtre.", ["R1"], "", False),
    ("detected", f"Détectée ; Glorfindel n'a pris auc{cr.LATE_OR_OTHER}.", ["R1"], "", False),
    ("detected", f"Détectée ; décision inconnue ({cr.LATE_OR_OTHER}).", ["R1"], "", True),
    # Containment, in its words (review 5, M182).
    ("detected", "Détectée ; Glorfindel a mis la VM en quarantaine.", ["R1"], "", False),
    ("detected", "Detected; Glorfindel put the VM in quarantine.", ["R1"], "", False),
    ("detected", "Détectée et contenue en deux minutes.", ["R1"], "", False),
    ("detected", "Detected and contained within two minutes.", ["R1"], "", False),
    ("detected", "Détectée ; Glorfindel est intervenu.", ["R1"], "", False),
    ("missed", "La menace a été neutralisée.", ["R1"], "", False),
    ("observation", "La quarantaine de la VM mérite un examen.", ["R1"], "", False),
    ("trend", "Le confinement diffère ; la quarantaine aussi.", ["R1", "P1"], "", False),
])
def test_the_check_never_keeps_an_unknown_decision_as_none(kind, text, runs, value, kept):
    """M147, M161–M163: on a run whose decision is unknown, only a claim on the detection, or
    one that says the decision is unknown, stays — and never one that says Glorfindel did not
    act, nor one that says it acted."""
    [claim] = cr.verify([cr.Claim(kind, text, runs, value)], [UNKNOWN], [EARLIER])
    assert (not claim.rejected) is kept, claim.rejected


@pytest.mark.parametrize("text", ["La quarantaine de la VM mérite un examen.",
                                  "Le confinement reste à voir : contenue ou non.",
                                  "Containment of the VM deserves a look."])
def test_containment_is_the_response(text):
    """M183: an observation on the containment speaks of the response — removed because it
    does not say the decision is unknown, before reading whether it says Glorfindel acted."""
    [claim] = cr.verify([cr.Claim("observation", text, ["R1"])], [UNKNOWN], [EARLIER])
    assert claim.rejected.endswith("the claim does not say so"), claim.rejected


def test_the_report_and_the_model_see_the_unknown(tmp_path):
    done = cr.RunFact("R2", "C1", 2, "T1110.001", "step 2", "executed", "detected",
                      decision="snapshot", confidence=0.4)
    alone = cr.RunFact("R3", "C1", 3, "T1486", "step 3", "executed", "detected",
                       decision="isolate_vm", confidence=0.9, escalated=False)
    md = cr.render(cr.Report("C1", [UNKNOWN, done, alone], model="fake/model"))
    assert "| 1 | T1136.001 step 1 | `R1` | detected | 120,0 s | inconnue — décision non retrouvée dans la fenêtre |" in md
    assert "| 2 | T1110.001 step 2 | `R2` | detected | — | snapshot (40%) |" in md
    assert "| 3 | T1486 step 3 | `R3` | detected | — | isolate_vm (90%, sans escalade) |" in md
    assert "ce n'est pas dire que Glorfindel n'a pas agi" in md
    rows = [json.loads(line) for line in cr._facts_message([UNKNOWN, done, alone], []).splitlines()
            if line.startswith("{")]
    assert (rows[0]["decision"], rows[0]["decision_unknown_because"]) == (None, cr.NONE_IN_WINDOW)
    assert rows[1]["decision"] == "snapshot" and "decision_unknown_because" not in rows[1]
    assert [r["escalated"] for r in rows] == [None, None, False]
    assert "decision isolate_vm at 0.90, not escalated" in alone.summary()
    assert f"decision unknown ({cr.NONE_IN_WINDOW})" in UNKNOWN.summary()


# ── How long a report waits for its decisions ────────────────────────────────────

def _arrived(cdir, at):
    os.utime(cdir / "manifest.json", (at.timestamp(), at.timestamp()))


def test_a_decision_is_awaited_to_the_windows_end_and_the_cycles_lag(tmp_path):
    """M146: the window bounds when the detection was seen; its decision is written later."""
    cdir, runs = _h0(tmp_path)
    _arrived(cdir, T + timedelta(minutes=11))
    deadline = LAST.timestamp() + hr.DECISION_LAG_S
    assert hr.waits_for_decisions(cdir, runs, now=LAST.timestamp() + 60, say=lambda m: None)
    assert hr.waits_for_decisions(cdir, runs, now=deadline, say=lambda m: None)
    assert not hr.waits_for_decisions(cdir, runs, now=deadline + 1, say=lambda m: None)


def test_without_a_window_the_wait_counts_from_the_campaigns_end(tmp_path):
    cdir, runs = _h0(tmp_path, windows=False)
    _arrived(cdir, T + timedelta(minutes=11))
    end = T + timedelta(minutes=10)                        # its updated_at, after every finished_at
    assert hr.campaign_end(cdir) == end.timestamp()
    deadline = end.timestamp() + hr.DECISION_WAIT_S + hr.DECISION_LAG_S
    assert hr.waits_for_decisions(cdir, runs, now=deadline, say=lambda m: None)
    assert not hr.waits_for_decisions(cdir, runs, now=deadline + 1, say=lambda m: None)


def test_no_wait_outlasts_the_cap_after_the_manifest_came(tmp_path):
    """A date gone wrong on the other host never holds a report back for longer."""
    cdir, runs = _h0(tmp_path)
    (runs / "exercises" / "R1.json").write_text(json.dumps(
        _window("R1", start=T + timedelta(days=3), end=None)))
    arrival = T + timedelta(minutes=11)
    _arrived(cdir, arrival)
    cap = arrival.timestamp() + hr.MAX_WAIT_S
    assert hr.waits_for_decisions(cdir, runs, now=cap, say=lambda m: None)
    assert not hr.waits_for_decisions(cdir, runs, now=cap + 1, say=lambda m: None)
    # and the campaign never ends after its manifest came here
    _arrived(cdir, T + timedelta(minutes=7))
    assert hr.campaign_end(cdir) == (T + timedelta(minutes=7)).timestamp()


@pytest.mark.parametrize("why, h0", [
    (cr.NO_ATTACK_TIME, {"attack": None}),
    (cr.NO_RESOURCE, {"scenarios": [_scen(1, "R1", vm="")]}),
])
def test_without_an_attack_time_or_a_resource_nothing_is_waited_for(tmp_path, why, h0):
    """M165: the run's report and the manifest are whole — no wait could attach a decision."""
    cdir, runs = _h0(tmp_path, **h0)
    _arrived(cdir, T + timedelta(minutes=11))
    said = []
    assert not hr.waits_for_decisions(cdir, runs, now=END.timestamp(), say=said.append)
    assert said == [f"C1: no decision found for R1 ({why}) — the report says it is unknown"]


def test_each_message_is_said_once_whatever_the_others(tmp_path):
    """M148: the refused run id and the wait have one line each, not one every pull."""
    cdir, runs = _h0(tmp_path, scenarios=[_scen(1, "R1"), _scen(2, "a/b")])
    _arrived(cdir, T + timedelta(minutes=11))
    said = []
    for _ in range(3):
        assert hr.due(cdir.parent, runs_dir=runs, now=LAST.timestamp(), say=said.append) == []
    assert len(said) == 2, said
    assert "run id refused" in said[0] and "waiting for Glorfindel's decision on R1" in said[1]


# ── Which campaigns are due ──────────────────────────────────────────────────────

def test_ready_takes_a_done_campaign_pulled_from_the_channel_with_its_runs(tmp_path):
    """M140, M141: never a campaign of a local run, never an aborted one."""
    def campaign(name, **kw):
        return _h0(tmp_path, name=name, **kw)[0]
    campaign("A")
    campaign("B", pulled=False)                                       # a local campaign
    campaign("C", state="aborted")
    (campaign("D") / hr.REPORT).write_text("# done\n")
    (campaign("E") / "runs" / "R1.json").unlink()                     # a run not here yet
    campaign("F", scenarios=[_scen(1, "R1"), _scen(2, "R2", status="error")])  # R2: no report
    (campaign("G") / "manifest.json").write_text("{ half")
    campaign("H")
    root = tmp_path / "h0" / "runs" / "campaigns"
    assert [p.name for p in hr.ready(root, failed={"H"}, say=lambda m: None)] == ["A", "F"]


def test_a_refused_run_id_is_not_awaited_and_said(tmp_path):
    cdir, _ = _h0(tmp_path, scenarios=[_scen(1, "R1"), _scen(2, "x..y")])
    said = []
    assert hr.ready(cdir.parent, say=said.append) == [cdir]
    assert said == ["C1: scenario 2: run id refused (not a plain name), left out"]


# ── Written once ─────────────────────────────────────────────────────────────────

CLAIMS = [{"kind": "detected", "text": "T1136.001 a été détectée.", "runs": ["R1"]},
          {"kind": "decision", "text": "Glorfindel a pris un snapshot.", "runs": ["R1"], "value": "snapshot"},
          {"kind": "missed", "text": "La seconde étape a été manquée.", "runs": ["R2"]}]


def test_the_report_is_written_once(tmp_path, index):
    """M134: a report present is never written again — not even by a pass that waited."""
    cdir, runs = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    model = _Model(CLAIMS)
    kw = {"model": "fake/model", "llm": model, "index_path": tmp_path / "idx", "say": lambda m: None}
    assert hr.write_report(cdir, **kw) == "written"
    first = (cdir / hr.REPORT).read_text()
    assert hr.write_report(cdir, **kw) == "exists"
    assert len(model.calls) == 1 and (cdir / hr.REPORT).read_text() == first
    assert index.paths and set(index.paths) == {tmp_path / "idx"}


def test_a_pass_holding_the_campaign_keeps_another_out(tmp_path, index):
    """M135: two passes never write the same report at once."""
    cdir, _ = _h0(tmp_path)
    model = _Model(CLAIMS)
    fd = os.open(cdir / hr.LOCK, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert hr.write_report(cdir, model="fake/model", llm=model, say=lambda m: None) == "busy"
    finally:
        os.close(fd)
    assert model.calls == [] and not (cdir / hr.REPORT).exists()


def _failing(monkeypatch, calls):
    def build(*a, **kw):
        calls.append(kw)
        raise RuntimeError("the index is unreachable")
    monkeypatch.setattr(cr, "build", build)


def test_a_failure_is_noted_and_tried_at_most_max_attempts(tmp_path, monkeypatch):
    """M133, M142: noted beside the manifest, never raised, then given up."""
    cdir, _ = _h0(tmp_path)
    calls, said = [], []
    _failing(monkeypatch, calls)
    for n in range(1, hr.MAX_ATTEMPTS + 1):
        assert _never_raises(hr.write_report, cdir, say=said.append) == "failed: the index is unreachable"
        assert json.loads((cdir / hr.ERROR).read_text())["attempts"] == n
    assert said[0].startswith("C1: attempt 1/3 failed (RuntimeError: the index is unreachable)")
    assert said[-1].startswith("C1: given up after 3 attempts")
    assert "make campaign-report CAMPAIGN=C1" in said[-1]
    assert hr.ready(cdir.parent, say=lambda m: None) == []
    assert calls[0]["strict"] is True


def test_the_attempts_end_even_when_report_error_cannot_be_written(tmp_path, monkeypatch):
    """M143: the thread's own count ends them (a full disk, a read-only mount)."""
    cdir, _ = _h0(tmp_path)
    (cdir / hr.ERROR).mkdir()                       # neither writable nor readable as a file
    calls = []
    _failing(monkeypatch, calls)
    for _ in range(hr.MAX_ATTEMPTS):
        assert hr.ready(cdir.parent, say=lambda m: None) == [cdir]
        hr.write_report(cdir, say=lambda m: None)
    assert hr.attempts(cdir) == hr.MAX_ATTEMPTS
    assert hr.ready(cdir.parent, say=lambda m: None) == []
    assert len(calls) == hr.MAX_ATTEMPTS


def test_an_answer_without_the_tool_is_a_failed_attempt(tmp_path, index):
    """strict: never an empty report written for good."""
    cdir, _ = _h0(tmp_path)
    out = hr.write_report(cdir, model="fake/model", llm=_Model(tool=False), say=lambda m: None)
    assert out == "failed: the analysis model answered without calling campaign_report"
    assert not (cdir / hr.REPORT).exists()
    assert json.loads((cdir / hr.ERROR).read_text())["attempts"] == 1


class _HungModel(_Model):
    """A provider that hangs: the call ends only on its bound, as LiteLLM ends it."""
    def completion(self, **kw):
        self.calls.append(kw)
        import litellm
        raise litellm.Timeout("Request timed out.", model="fake/model", llm_provider="anthropic")


def test_the_call_to_the_analysis_model_is_bounded(tmp_path, monkeypatch, index):
    """M187 (review 6): LiteLLM's own default is 6000 s an attempt — a hung provider held the
    ``campaign-report`` thread, and every report after it, for hours. The call carries its
    bound; past it, a failed attempt, counted, never raised, given up after MAX_ATTEMPTS."""
    monkeypatch.delenv(cr.TIMEOUT_ENV, raising=False)
    cdir, _ = _h0(tmp_path)
    model, said = _HungModel(CLAIMS), []
    for n in range(1, hr.MAX_ATTEMPTS + 1):
        out = _never_raises(hr.write_report, cdir, model="fake/model", llm=model, say=said.append)
        assert out.startswith("failed: ") and "Request timed out." in out
        assert json.loads((cdir / hr.ERROR).read_text())["attempts"] == n
    assert [kw.get("timeout") for kw in model.calls] == [cr.TIMEOUT_S] * hr.MAX_ATTEMPTS
    assert cr.TIMEOUT_S == 300.0
    assert said[0].startswith("C1: attempt 1/3 failed (Timeout: ")
    assert said[-1].startswith("C1: given up after 3 attempts (Timeout: ")
    assert not (cdir / hr.REPORT).exists() and hr.ready(cdir.parent, say=lambda m: None) == []
    monkeypatch.setenv(cr.TIMEOUT_ENV, "45")
    import litellm
    with pytest.raises(litellm.Timeout):            # the command line's path: bounded, it raises
        cr.write_claims([], [], "fake/model", model)
    assert model.calls[-1]["timeout"] == 45.0


def test_a_hung_report_never_stops_the_thread(tmp_path, monkeypatch, index):
    """The thread's pass over a campaign whose model hangs: it ends without raising."""
    _, h0 = _published(tmp_path, monkeypatch,
                       watch=[_decision(at=T + timedelta(minutes=3))])
    model = _HungModel(CLAIMS)
    kw = {"model": "fake/model", "llm": model, "say": lambda m: None,
          "now": (T + timedelta(minutes=40)).timestamp()}
    out = _never_raises(hr.tick, h0, **kw)
    assert list(out) == ["C1"] and out["C1"].startswith("failed: ")
    assert model.calls[0]["timeout"] == cr.TIMEOUT_S


@pytest.mark.parametrize("raw, expected", [
    ("", 300.0), (" 90 ", 90.0), ("3600", 3600.0), ("abc", 300.0), ("0", 300.0), ("-5", 300.0),
    ("inf", 300.0), ("-inf", 300.0), ("nan", 300.0), ("86400", 300.0),
])
def test_the_analysis_bound_never_unbounds_on_a_malformed_value(monkeypatch, raw, expected):
    monkeypatch.setenv(cr.TIMEOUT_ENV, raw)
    assert cr.timeout_s() == expected


def test_the_analysis_bound_reaches_the_containers():
    """M188: docker compose passes an explicit list (``x-env``); empty is the reader's 300 s."""
    import yaml
    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "docker-compose.yml")
                             .read_text(encoding="utf-8"))
    assert compose["x-env"].get(cr.TIMEOUT_ENV) == "${%s:-}" % cr.TIMEOUT_ENV
    assert cr.TIMEOUT_ENV in compose["services"]["watch"]["environment"]


def test_a_report_written_clears_its_error(tmp_path, index):
    cdir, _ = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    (cdir / hr.ERROR).write_text(json.dumps({"attempts": 1}))
    said = []
    assert hr.write_report(cdir, model="fake/model", llm=_Model(CLAIMS), say=said.append) == "written"
    assert not (cdir / hr.ERROR).exists()
    assert said == [f"{cdir / hr.REPORT} — 3 claim(s) kept, 0 rejected by the check, "
                    "1 decision(s) unknown"]                      # R2: missed, a decision in its window


def test_an_error_that_cannot_be_cleared_never_escapes(tmp_path, index):
    """M166: the report is written; a ``report.error`` that cannot be removed stays, and the
    written report wins."""
    cdir, _ = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    (cdir / hr.ERROR).mkdir()                       # unlink: IsADirectoryError, an OSError
    out = _never_raises(hr.write_report, cdir, model="fake/model", llm=_Model(CLAIMS), say=lambda m: None)
    assert out == "written" and (cdir / hr.REPORT).exists()
    assert hr.ready(cdir.parent, say=lambda m: None) == []


# ── The thread beside the watch ──────────────────────────────────────────────────

def test_the_thread_starts_only_with_the_channel(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(hr, "run", lambda runs_dir, interval: seen.append((runs_dir, interval)))
    assert hr.start(tmp_path) is None and seen == []
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    thread = hr.start(str(tmp_path), interval=5.0)
    thread.join(timeout=5)
    assert (thread.daemon, thread.name) == (True, "campaign-report")
    assert seen == [(tmp_path, 5.0)]


def test_the_watch_goes_on_when_the_reports_cannot_start(tmp_path, monkeypatch):
    """M131: a report never stops the watch — not even its thread failing to start."""
    from glorfindel import cli as gcli
    assert gcli._start_campaign_reports(tmp_path) is False          # no channel: no thread

    def boom(runs_dir):
        raise RuntimeError("cannot start a thread")
    monkeypatch.setattr(hr, "start", boom)
    assert _never_raises(gcli._start_campaign_reports, tmp_path) is False


def test_without_annatar_the_watch_says_once_that_the_reports_are_off(tmp_path, monkeypatch):
    """M870: the report reads a run's detections with Annatar's reader (a bridge, D1). On a
    Glorfindel without Annatar, with a channel, the watch says so at start, once — no thread
    that would fail every pass."""
    import importlib.util
    import sys

    from glorfindel import cli as gcli
    spec = importlib.util.spec_from_file_location(
        "component_check", Path(__file__).resolve().parents[2] / "scripts" / "component_check.py")
    cc = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "component_check", cc)
    spec.loader.exec_module(cc)
    finder = cc.Absent(("annatar",))
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])
    for name in [m for m in sys.modules if finder.blocks(m) or m == "analysis.campaign_report"]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.delattr(sys.modules["analysis"], "campaign_report", raising=False)
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    started = []
    monkeypatch.setattr(hr, "start", lambda runs_dir: started.append(runs_dir) or object())
    said = []
    monkeypatch.setattr(gcli.console, "print", lambda *a, **kw: said.append(" ".join(map(str, a))))

    assert _never_raises(gcli._start_campaign_reports, tmp_path) is False
    assert started == []
    assert [s for s in said if "Rapports de campagne désactivés" in s] == said and len(said) == 1
    assert "annatar" in said[0]


def test_a_failing_pass_never_stops_the_thread(tmp_path):
    """M132: every pass runs, whatever the one before raised."""
    passes, sleeps = [], []

    def boom(runs_dir):
        passes.append(runs_dir)
        raise RuntimeError("the model is unreachable")
    _never_raises(hr.run, tmp_path, interval=30.0, ticks=3, sleep=sleeps.append, step=boom)
    assert (len(passes), sleeps) == (3, [30.0, 30.0, 30.0])


def _published(tmp_path, monkeypatch, *, watch=()):
    """Orodruin's half: the run's window opened and closed, its report written, the campaign
    published over the channel — and H0's runs directory with the watch's file."""
    c = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(requests, "put", c.put)
    monkeypatch.setattr(requests, "get", c.get)
    oro = tmp_path / "orodruin" / "runs"
    for rid in ("R1", "R2"):
        exercise.open_window(rid, injector="annatar", kind="technique", experiment="T1136.001",
                             targets=[VM], now=T, directory=oro / "exercises")
        exercise.close_window(rid, now=END, directory=oro / "exercises")
        (oro / f"{rid}.json").write_text(json.dumps(
            {"run_id": rid, "metrics": {"attack_time": ATTACK.timestamp()}}))
    cdir = oro / "campaigns" / "C1"
    cdir.mkdir(parents=True)
    (cdir / "manifest.json").write_text(json.dumps({
        "campaign_id": "C1", "state": "done", "updated_at": _iso(T + timedelta(minutes=10)),
        "scenarios": [_scen(1, "R1"), _scen(2, "R2", detection="missed")]}))
    assert channel.publish_campaign(cdir, oro)[0] == "C1"
    h0 = tmp_path / "h0" / "runs"
    h0.mkdir(parents=True)
    if watch:
        (h0 / "watch-account-creation-20261001T100300Z_debug.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in watch))
    return c, h0


def test_tick_never_raises(tmp_path, monkeypatch, index):
    """M133: the channel, the windows, the decisions, the model — each failure stays in the
    thread, said, and the next pass tries again."""
    c, h0 = _published(tmp_path, monkeypatch)
    said = []

    def listing_fails(url, headers=None, params=None, timeout=None):
        return SimpleNamespace(ok=False, status_code=500, content=b"")
    assert hr.tick(h0, get=listing_fails, say=said.append) == {}
    assert said[-1] == "pull failed: HTTP 500 listing the channel"

    assert hr.tick(h0, get=_windows_fail(c), say=said.append) == {"C1": "waiting"}
    assert "windows not pulled" in said[-1]

    def unreadable(*a, **kw):
        raise ValueError("a decision file cannot be read")
    monkeypatch.setattr(cr, "undecided_runs", unreadable)
    _failing(monkeypatch, [])
    assert hr.tick(h0, get=c.get, say=said.append) == {"C1": "failed: the index is unreachable"}
    assert "C1: decisions not read (ValueError" in said[-2]


def _windows_fail(c):
    def get(url, headers=None, params=None, timeout=None):
        if params and "prefix" not in params:      # the windows' listing, not the campaigns'
            return SimpleNamespace(ok=False, status_code=503, content=b"")
        return c.get(url, headers, params, timeout)
    return get


def _but_runs(said):
    """What a pass says of the campaigns and the windows: the runs' reports (#193, their own
    listing, said once too) are left out — tests/unit/test_run_channel.py."""
    return lambda m: None if m.startswith("run reports not pulled") else said.append(m)


def test_a_failing_pull_is_said_once_while_it_lasts(tmp_path, monkeypatch, index):
    """M167–M169: every 30 s, a failure said each time would fill the watch's log — once
    while it lasts, and again if it comes back after a pull that went through."""
    c, h0 = _published(tmp_path, monkeypatch)
    said = []

    def listing_fails(url, headers=None, params=None, timeout=None):
        return SimpleNamespace(ok=False, status_code=500, content=b"")
    for _ in range(3):
        assert hr.tick(h0, get=listing_fails, say=_but_runs(said)) == {}
    assert said == ["pull failed: HTTP 500 listing the channel"]
    for _ in range(3):
        assert hr.tick(h0, get=_windows_fail(c), say=_but_runs(said)) == {"C1": "waiting"}
    assert len(said) == 2 and said[1].startswith("windows not pulled (")
    assert said[1].endswith(") — 1 report(s) wait for the next pull")
    hr.tick(h0, get=listing_fails, say=_but_runs(said))          # back after a pull that went through
    assert said[2:] == ["pull failed: HTTP 500 listing the channel"]

    answers = iter([set(), {"C1"}, {"C1"}, {"C1"}, set(), {"C1"}])
    monkeypatch.setattr(channel, "pull_campaigns", lambda root, **kw: (0, next(answers)))
    said.clear()
    for _ in range(6):
        hr.tick(h0, get=_windows_fail(c), say=_but_runs(said))
    assert [m for m in said if "not all pulled" in m] == [
        "C1: not all pulled — its report waits for the next pull"] * 2


def _timeout():
    """A connection that times out, as requests says it: its text names an object ``at 0x…``,
    new at every call."""
    n = iter(range(1, 1000))

    def fail(url, headers=None, params=None, timeout=None):
        raise requests.exceptions.ConnectTimeout(
            "HTTPSConnectionPool(host='channel.invalid', port=443): Max retries exceeded "
            "(Caused by ConnectTimeoutError(<urllib3.connection.HTTPSConnection object at "
            f"0x7f{next(n):010x}>, 'Connection timed out. (connect timeout=15)'))")
    return fail


def test_a_failure_whose_text_changes_is_said_once_while_it_lasts(tmp_path, monkeypatch, index):
    """M181 (review 5): the slot compares the failure's type and status, not its text — a
    timed-out connection, said every 30 s otherwise. Another failure is said."""
    c, h0 = _published(tmp_path, monkeypatch)
    said, timeout = [], _timeout()
    for _ in range(3):
        assert hr.tick(h0, get=timeout, say=_but_runs(said)) == {}
    assert len(said) == 1 and said[0].startswith("pull failed: HTTPSConnectionPool"), said

    def listing_fails(url, headers=None, params=None, timeout=None):
        return SimpleNamespace(ok=False, status_code=500, content=b"")
    hr.tick(h0, get=listing_fails, say=_but_runs(said))
    hr.tick(h0, get=timeout, say=_but_runs(said))
    assert said[1] == "pull failed: HTTP 500 listing the channel" and len(said) == 3
    assert said[2].startswith("pull failed: HTTPSConnectionPool")

    said.clear()

    def windows_time_out(url, headers=None, params=None, timeout=None):
        if params and "prefix" not in params:      # the windows' listing, not the campaigns'
            return fail(url)
        return c.get(url, headers, params, timeout)
    fail = _timeout()
    for _ in range(3):
        assert hr.tick(h0, get=windows_time_out, say=_but_runs(said)) == {"C1": "waiting"}
    assert len(said) == 1 and said[0].startswith("windows not pulled (HTTPSConnectionPool"), said


@pytest.mark.parametrize("error, key", [
    (RuntimeError("HTTP 503 listing the channel"), "builtins.RuntimeError 503"),
    (RuntimeError("another pull of the windows is still running"), "builtins.RuntimeError"),
    (requests.exceptions.HTTPError("403 at 0x7f00", response=SimpleNamespace(status_code=403)),
     "requests.exceptions.HTTPError 403"),
])
def test_the_key_of_a_failure_is_its_type_and_status(error, key):
    assert hr._error_key(error) == key


def test_a_lock_that_cannot_be_opened_is_said_once_while_it_lasts(tmp_path, index):
    """M185, M186 (review 5): ``failed: …`` at every pull, said nowhere before — said once
    while it lasts, again if it comes back after an open that went through; never the model."""
    cdir, _ = _h0(tmp_path, watch=[_decision(at=T + timedelta(minutes=3))])
    (cdir / hr.LOCK).mkdir()                       # cannot be opened as a file
    model, said = _Model(CLAIMS), []
    kw = {"model": "fake/model", "llm": model, "index_path": tmp_path / "idx", "say": said.append}
    for _ in range(3):
        assert _never_raises(hr.write_report, cdir, **kw).startswith("failed: ")
    assert len(said) == 1, said
    assert said[0].startswith("C1: report not written, its lock cannot be opened (")
    assert said[0].endswith(" — tried again at the next pull")
    assert model.calls == [] and hr.attempts(cdir) == 0
    (cdir / hr.LOCK).rmdir()
    assert hr.write_report(cdir, **kw) == "written"
    (cdir / hr.LOCK).unlink()
    (cdir / hr.LOCK).mkdir()
    assert hr.write_report(cdir, **kw).startswith("failed: ")
    assert [m for m in said if "lock cannot be opened" in m] == [said[0]] * 2


def test_a_detected_run_without_its_decision_holds_the_report_back(tmp_path, monkeypatch, index):
    """M144: written once, a report must hold the decisions — it waits for them, then says
    the one still missing is unknown."""
    _, h0 = _published(tmp_path, monkeypatch)
    model = _Model(CLAIMS[:1])
    kw = {"model": "fake/model", "llm": model, "say": lambda m: None}
    assert hr.tick(h0, now=LAST.timestamp(), **kw) == {"C1": "waiting"}
    assert model.calls == [] and not (h0 / "campaigns" / "C1" / hr.REPORT).exists()
    later = LAST.timestamp() + hr.DECISION_LAG_S + 1
    assert hr.tick(h0, now=later, **kw) == {"C1": "written"}
    md = (h0 / "campaigns" / "C1" / hr.REPORT).read_text()
    assert "| `R1` | detected | — | inconnue — décision non retrouvée dans la fenêtre |" in md


def test_end_to_end_a_campaign_from_orodruin_gets_its_report_on_h0(tmp_path, monkeypatch, index):
    """The lot's « done when », locally: published to the channel → pulled on H0 → ``done``
    → ``report.md`` written once, the decision found in the watch's ``watch-*`` file, the
    model faked, every claim checked."""
    c, h0 = _published(tmp_path, monkeypatch, watch=[
        _decision(at=T + timedelta(minutes=2), vm=OTHER_VM.lower(), action="isolate_vm"),
        _decision(at=T + timedelta(minutes=3))])
    model = _Model(CLAIMS)
    said = []
    kw = {"model": "fake/model", "llm": model, "index_path": tmp_path / "idx", "say": said.append,
          "now": (T + timedelta(minutes=40)).timestamp()}
    assert hr.tick(h0, **kw) == {"C1": "written"}
    assert sorted(os.listdir(h0 / "exercises")) == ["R1.json", "R2.json"]
    md = (h0 / "campaigns" / "C1" / hr.REPORT).read_text()
    assert "| 1 | T1136.001 step 1 | `R1` | detected | — | snapshot (40%, escaladé) |" in md
    assert f"| 2 | T1136.001 step 2 | `R2` | missed | — | inconnue — {cr.LATE_OR_OTHER} |" in md
    assert "**1 détectée(s)** · **1 manquée(s)**" in md
    assert "## Ce que le rapport affirme (3)" in md and "Écarté par la vérification" not in md
    assert "- Glorfindel a pris un snapshot. — `R1`" in md
    facts = model.calls[0]["messages"][1]["content"]
    r1 = json.loads(next(line for line in facts.splitlines() if '"run": "R1"' in line))
    assert (r1["decision"], r1["confidence"], r1["escalated"]) == ("snapshot", 0.4, True)
    assert said[-1] == (f"{h0 / 'campaigns' / 'C1' / hr.REPORT} — 3 claim(s) kept, 0 rejected by "
                        "the check, 1 decision(s) unknown")
    assert hr.tick(h0, **kw) == {}                       # once: the next pass has nothing due
    assert len(model.calls) == 1


# ── D-2 (#184): the second campaign's report on H0 faces the first ───────────────

def test_the_second_campaign_on_h0_says_what_changed_since_the_first(tmp_path, index):
    """Two campaigns pulled from the channel, the same technique on the same VM: the second
    report holds the comparison, computed by the code from the index the first one filled —
    the decision of each run found in the watch's files, each in its own window."""
    # Each campaign's id is when it started, and its windows open then (D2b: a campaign that
    # came through the channel does not start after its first window).
    first, second = "20261001T100000Z", "20261002T100000Z"
    day = timedelta(days=1)
    later = T + day + timedelta(minutes=1)
    _h0(tmp_path, name=first, scenarios=[_scen(1, "R1")], watch=[
        _decision(at=T + timedelta(minutes=3), action="block_suspicious_ip", confidence=0.8),
        _decision(at=later + timedelta(minutes=2), action="isolate_vm", confidence=0.78)])
    cdir, runs = _h0(tmp_path, name=second, scenarios=[_scen(1, "S1"), _scen(2, "S2", ttp="T1041")],
                     attack=later.timestamp(), start=T + day)
    kw = {"model": "fake/model", "llm": _Model(), "index_path": tmp_path / "idx", "say": lambda m: None}
    assert hr.write_report(runs / "campaigns" / first, **kw) == "written"
    assert "*Aucune campagne précédente : " in (runs / "campaigns" / first / hr.REPORT).read_text()
    assert hr.write_report(cdir, **kw) == "written"
    md = (cdir / hr.REPORT).read_text()
    assert f"Campagne précédente : `{first}`." in md
    assert ("| `chg-1` | T1136.001 | vm-bench-01 | detected → detected | — → — "
            "| block_suspicious_ip → isolate_vm | 80% → 78% (−2 pts) | escaladé → escaladé |") in md
    assert "Seulement dans celle-ci (1) : `chg-2` T1041 sur vm-bench-01 (run `S2`)." in md
