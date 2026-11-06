"""CI6 (#514): the release gate measures every mutant, in shards (scripts/mutation_check.py).

One runner cannot measure 2 633 mutants at 500 sequences within any bound: the gate gives each
runner a shard (`--shard K/N`), each writes what it measured (`--json`), and `--total` says
whether the shards together measured each mutant of the tree once, at the budget given, then
whether a counted mutant survived a round outside the known survivors (CI6e, #553: `--min-caught`
before). Here on mutants and results written by the test: no test suite runs, nothing is copied
but a file of the test's own.
"""
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location("mutation_check_ci6", ROOT / "scripts" / "mutation_check.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["mutation_check_ci6"] = mod
    spec.loader.exec_module(mod)
    return mod


mc = _load()
# The harness's own preparation of ChromaDB's model (CI6b), before any test below replaces it.
REAL_PREPARE = mc.prepare_embedding_model


@pytest.fixture(autouse=True)
def _no_model(monkeypatch):
    """main() never prepares ChromaDB's real model here (CI6b): no network, no 80 MB. The tests of
    the preparation put the real one back, on a fake ChromaDB."""
    monkeypatch.setattr(mc, "prepare_embedding_model", lambda say=print: None)


def _mutants(n, prefix="X"):
    return [(f"{prefix}{i:03d}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(n)]


def _tests(mutants, heavy_every=5):
    """Targets as the harness has them: a few mutants per target, some on an invariant machine."""
    out = {}
    for i, m in enumerate(mutants):
        out[m[0]] = mc.INVARIANTS if i % heavy_every == 0 else f"tests/unit/test_t{i // 3}.py"
    return out


# ── the shards ──────────────────────────────────────────────────────────────────────────────

def _durations(todo, seed=7, targets=None):
    """Durations as a gate's run measures them: most mutants a few seconds, some minutes."""
    import random
    rnd = random.Random(seed)
    return {"mutants": {m[0]: float(rnd.choice([3, 5, 8, 13, 21, 300, 900])) for m in todo},
            "targets": dict(targets or {})}


@pytest.mark.parametrize("measured", [False, True], ids=["estimated", "measured"])
@pytest.mark.parametrize("n", [1, 2, 3, 7, 10, 14])
def test_the_shards_measure_each_mutant_once(n, measured):
    todo = _mutants(97)
    tests = _tests(todo)
    durations = _durations(todo) if measured else mc.no_durations()
    shards = [mc.shard_of(todo, k, n, tests, durations) for k in range(1, n + 1)]
    ids = [m[0] for s in shards for m in s]
    assert sorted(ids) == sorted(m[0] for m in todo)          # each once, none lost
    for s in shards:
        assert s == [m for m in todo if m in s]                # in todo's order


def test_the_heavy_targets_are_spread_across_the_shards():
    """Unmeasured, a target that runs an invariant machine weighs HEAVY: they never all land in one
    shard."""
    todo = _mutants(60)
    tests = {m[0]: (f"tests/unit/test_invariants.py tests/unit/test_h{i}.py" if i < 12 else f"tests/unit/t{i}.py")
             for i, m in enumerate(todo)}
    heavy = [sum(1 for m in mc.shard_of(todo, k, 4, tests, mc.no_durations()) if mc._heavy(tests[m[0]]))
             for k in range(1, 5)]
    assert sum(heavy) == 12 and max(heavy) - min(heavy) <= 1, heavy


def test_the_same_tree_gives_the_same_shards():
    """The same mutants, targets and durations — in another order of the file's keys, on another
    runner — give the same shards."""
    todo = _mutants(50)
    tests = _tests(todo)
    durations = _durations(todo)
    shuffled = {kind: dict(reversed(list(v.items()))) for kind, v in durations.items()}
    for d1, d2 in ((mc.no_durations(), mc.no_durations()), (durations, shuffled)):
        assert ([mc.shard_of(todo, k, 5, tests, d1) for k in range(1, 6)]
                == [mc.shard_of(list(todo), k, 5, dict(tests), d2) for k in range(1, 6)])


# ── CI6d (#545): the shards cut on the durations measured ──────────────────────────────────
# The gate's first two runs (05/11): 22 to 72 min a shard, on an estimate that weighed every
# mutant alike. Here on durations the test writes: no gate, no artifact.

def _loads(todo, n, tests, durations):
    mutant, unmutated, _ = mc.costs(todo, tests, durations)
    out = []
    for mine in mc.shards_of(todo, n, tests, durations):
        targets = {tests[i] for i in mine}
        out.append(sum(mutant[i] for i in mine) + sum(unmutated[t] for t in targets))
    return out


def test_the_shards_weigh_each_mutant_by_its_measure():
    """Twenty mutants a target each, two of them measured at 15 min, the others at 5 s: the two
    long ones never share a shard, and each shard carries its share — not a count of mutants."""
    todo = _mutants(20)
    tests = {m[0]: f"tests/unit/test_{i}.py" for i, m in enumerate(todo)}
    durations = {"mutants": {m[0]: 5.0 for m in todo} | {"X003": 900.0, "X011": 900.0},
                 "targets": {t: 1.0 for t in tests.values()}}
    shards = mc.shards_of(todo, 2, tests, durations)
    assert [len({"X003", "X011"} & s) for s in shards] == [1, 1], shards
    assert [len(s) for s in shards] == [10, 10]


def test_a_measured_mutant_outweighs_the_estimate():
    """The estimate weighs every light mutant UNIT seconds: one measured at an hour goes alone,
    and its shard takes nothing else of the measured world."""
    todo = _mutants(12)
    tests = {m[0]: f"tests/unit/test_{i}.py" for i, m in enumerate(todo)}
    durations = {"mutants": {"X000": 3600.0}, "targets": {}}
    first, second = mc.shards_of(todo, 2, tests, durations)
    assert (first, len(second)) == ({"X000"}, 11)
    estimated = mc.shards_of(todo, 2, tests, mc.no_durations())
    assert sorted(len(s) for s in estimated) == [6, 6]


def test_a_target_s_unmutated_run_is_weighed_once_per_piece():
    """A target whose unmutated run takes half an hour, its one mutant a second: it weighs its
    run, and the other targets go to the other shard."""
    todo = _mutants(9)
    tests = {m[0]: f"tests/unit/test_{i}.py" for i, m in enumerate(todo)}
    durations = {"mutants": {m[0]: 1.0 for m in todo},
                 "targets": {t: 60.0 for t in tests.values()} | {"tests/unit/test_0.py": 1800.0}}
    assert mc.shards_of(todo, 2, tests, durations)[0] == {"X000"}
    assert _loads(todo, 2, tests, durations) == [1801.0, 8 * 61.0]


def test_an_unmeasured_mutant_weighs_its_target_s_median_else_the_estimate():
    todo = _mutants(5)
    tests = {"X000": "tests/unit/test_a.py", "X001": "tests/unit/test_a.py", "X002": "tests/unit/test_a.py",
             "X003": "tests/unit/test_b.py", "X004": mc.INVARIANTS}
    durations = {"mutants": {"X000": 40.0, "X001": 100.0}, "targets": {}}
    mutant, unmutated, groups = mc.costs(todo, tests, durations)
    assert mutant == {"X000": 40.0, "X001": 100.0, "X002": 70.0, "X003": mc.UNIT, "X004": mc.UNIT * mc.HEAVY}
    # unmeasured, the unmutated run: one round of its slowest mutant, never less than the estimate
    assert unmutated == {"tests/unit/test_a.py": 100.0 / mc.DURATIONS_BUDGET[1], "tests/unit/test_b.py": mc.UNIT,
                         mc.INVARIANTS: mc.UNIT * mc.HEAVY}
    assert groups["tests/unit/test_a.py"] == ["X000", "X001", "X002"]
    durations["targets"]["tests/unit/test_a.py"] = 7.0
    assert mc.costs(todo, tests, durations)[1]["tests/unit/test_a.py"] == 7.0      # measured, it is its own


def test_a_heavy_target_is_cut_by_its_weight_a_light_one_stays_whole():
    """Sixty mutants of one target, 5 s each, stay one piece: their unmutated run happens once.
    Sixty of another at 10 min each are cut, and spread over every shard."""
    light, heavy = _mutants(60, "L"), _mutants(60, "H")
    todo = light + heavy
    tests = {m[0]: "tests/unit/test_light.py" for m in light} | {m[0]: "tests/unit/test_heavy.py" for m in heavy}
    durations = {"mutants": {m[0]: 5.0 for m in light} | {m[0]: 600.0 for m in heavy},
                 "targets": {"tests/unit/test_light.py": 30.0, "tests/unit/test_heavy.py": 300.0}}
    n = 6
    shards = mc.shards_of(todo, n, tests, durations)
    owners = lambda prefix: {k for k, s in enumerate(shards) if any(i.startswith(prefix) for i in s)}  # noqa: E731
    assert len(owners("L")) == 1 and owners("H") == set(range(n))
    pieces = [p for p in mc.pieces_of(todo, n, tests, durations) if p[1] == "tests/unit/test_heavy.py"]
    assert len(pieces) > n and all(p[0] == 300.0 + 600.0 * len(p[3]) for p in pieces)
    loads = _loads(todo, n, tests, durations)
    assert max(loads) - min(loads) <= 600.0 + 300.0, loads    # within one mutant and one run


def test_the_heaviest_shard_is_near_the_share():
    """On durations spread as the gate's are, the heaviest shard stays within a tenth of the
    share — the old count-based cut left it at twice the lightest."""
    todo = _mutants(400)
    tests = {m[0]: (mc.INVARIANTS if i % 9 == 0 else f"tests/unit/test_t{i // 7}.py") for i, m in enumerate(todo)}
    durations = _durations(todo, seed=3)
    loads = _loads(todo, 14, tests, durations)
    share = sum(loads) / 14
    assert max(loads) <= 1.1 * share, (max(loads), share)


def test_the_pools_take_the_heaviest_first():
    cost = {"a": 1.0, "b": 30.0, "c": 30.0, "d": 5.0}
    assert mc.heaviest_first(["a", "b", "c", "d", "e"], cost) == ["b", "c", "d", "a", "e"]
    assert mc._wall([30.0, 20.0, 5.0, 5.0], 2) == 30.0 and mc._wall([5.0, 5.0, 20.0, 30.0], 2) == 35.0


# ── the durations' file ─────────────────────────────────────────────────────────────────────

def test_the_durations_file_absent_reads_as_nothing_measured(tmp_path):
    assert mc.load_durations(tmp_path / "none.json") == mc.no_durations()


@pytest.mark.parametrize("text", ["not json", "[]", '{"mutants": 3}', '{"mutants": [1, 2]}'])
def test_a_durations_file_that_cannot_be_read_is_said_and_the_estimate_cuts(tmp_path, text):
    path = tmp_path / "durations.json"
    path.write_text(text, encoding="utf-8")
    said: list = []
    assert mc.load_durations(path, say=lambda *a, **k: said.append(a[0])) == mc.no_durations()
    assert said and "unreadable" in said[0] and "estimate" in said[0]


def test_an_entry_that_is_not_a_duration_is_left_out(tmp_path):
    """Negative, a string, a boolean, 0 (« not measured »), past a float (10**400: OverflowError),
    not finite, or above a day (1e308): left out, the estimate weighs it, and it is said with the
    file's name — never a trace that stops the shard (CI6d, review)."""
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"mutants": {"M1": 4, "M2": -1, "M3": "9", "M4": True, "M5": 2.5, "M6": 10**400,
                                            "M7": 1e308, "M8": 0, "M9": mc.MAX_SECONDS},
                                "targets": {"t": float("inf"), "u": 0, "v": 86_400.5, "w": 30}}), encoding="utf-8")
    said: list = []
    assert mc.load_durations(path, say=lambda *a, **k: said.append(a[0])) == {
        "mutants": {"M1": 4.0, "M5": 2.5, "M9": float(mc.MAX_SECONDS)}, "targets": {"w": 30.0}}
    assert said == [f"durations.json: 6 mutants not a duration (above 0, at most {mc.MAX_SECONDS} s) — left out, "
                    "the estimate weighs them",
                    f"durations.json: 3 targets not a duration (above 0, at most {mc.MAX_SECONDS} s) — left out, "
                    "the estimate weighs them"]


def test_durations_at_zero_never_put_every_mutant_in_the_first_shard(tmp_path):
    """A file of zeros is a file of nothing measured: the estimate cuts, every shard has its share."""
    todo = _mutants(40)
    tests = {m[0]: f"tests/unit/test_{i}.py" for i, m in enumerate(todo)}
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"mutants": {m[0]: 0 for m in todo}, "targets": {t: 0 for t in tests.values()}}),
                    encoding="utf-8")
    durations = mc.load_durations(path, say=lambda *a, **k: None)
    assert sorted(len(s) for s in mc.shards_of(todo, 4, tests, durations)) == [10, 10, 10, 10]


def test_a_duration_past_any_bound_never_stops_the_cut(tmp_path):
    """Read from a file, the largest durations stay finite: the cut never meets inf, nor NaN."""
    todo = _mutants(30)
    tests = {m[0]: "tests/unit/test_one.py" for m in todo}
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"mutants": {m[0]: (10**400 if i % 2 else mc.MAX_SECONDS) for i, m in enumerate(todo)},
                                "targets": {"tests/unit/test_one.py": 1e308}}), encoding="utf-8")
    durations = mc.load_durations(path, say=lambda *a, **k: None)
    shards = [mc.shard_of(todo, k, 3, tests, durations) for k in (1, 2, 3)]
    assert sorted(m[0] for s in shards for m in s) == sorted(m[0] for m in todo)


def _shard_json(where: Path, name, seconds=None, targets=None, rows=None, examples=500, rounds=2, legacy=None):
    """A shard's --json: `legacy` {id: s} in the rows' detail only, as before CI6d."""
    rows = list(rows or [])
    rows += [[mid, "bug", "CAUGHT", f"2/2 ({s}s)"] for mid, s in (legacy or {}).items()]
    rows += [[mid, "bug", "CAUGHT", "2/2 (0s)"] for mid in (seconds or {})]
    doc = {"control": False, "shard": 1, "shards": 1, "examples": examples, "rounds": rounds, "rows": rows}
    if seconds is not None:
        doc["seconds"] = seconds
    if targets is not None:
        doc["targets"] = targets
    where.mkdir(parents=True, exist_ok=True)
    (where / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


@pytest.fixture
def tree(monkeypatch):
    """Five mutants of this tree, two targets."""
    mutants = _mutants(5, "M")
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {"M000": "tests/unit/test_a.py", "M001": "tests/unit/test_a.py"})
    return mutants


def test_the_update_takes_each_smallest_measure_of_the_runs_given(tree, tmp_path):
    """Two runs: a slower runner slows a whole shard alike, so each mutant and each unmutated run
    keeps its smallest measure. Before CI6d, the seconds were in the rows' detail: read too."""
    path = tmp_path / "durations.json"
    _shard_json(tmp_path / "run1" / "mutants-1", "mutants-1", seconds={"M000": 40.4, "M001": 9.0},
                targets={"tests/unit/test_a.py": 120.0, mc.INVARIANTS: 300.0})
    _shard_json(tmp_path / "run2" / "mutants-1", "mutants-1", seconds={"M000": 80.0, "M001": 3.0},
                targets={"tests/unit/test_a.py": 200.0})
    _shard_json(tmp_path / "run2" / "mutants-2", "mutants-2", legacy={"M002": 700, "M003": 12})
    assert mc.update_durations([tmp_path / "run1", tmp_path / "run2"], path, say=lambda *a, **k: None) == 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["mutants"] == {"M000": 40, "M001": 3, "M002": 700, "M003": 12}
    assert doc["targets"] == {mc.INVARIANTS: 300, "tests/unit/test_a.py": 120}
    assert (doc["examples"], doc["rounds"]) == mc.DURATIONS_BUDGET
    assert mc.load_durations(path)["mutants"]["M000"] == 40.0


def test_the_update_keeps_what_was_not_measured_and_drops_what_the_tree_lost(tree, tmp_path):
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"mutants": {"M000": 10, "M004": 55, "M999": 7},
                                "targets": {"tests/unit/test_gone.py": 30, "tests/unit/test_a.py": 9}}),
                    encoding="utf-8")
    _shard_json(tmp_path / "run" / "m", "m", seconds={"M000": 20.0, "M777": 5.0, "/home/someone/x": 1.0},
                targets={"/tmp/elsewhere/test_x.py": 4.0, "tests/unit/test_a.py": 11.0})
    assert mc.update_durations([tmp_path / "run"], path, say=lambda *a, **k: None) == 0
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["mutants"] == {"M000": 20, "M004": 55}                # measured anew, kept; gone, foreign out
    assert doc["targets"] == {"tests/unit/test_a.py": 11}
    assert str(tmp_path) not in path.read_text(encoding="utf-8") and "/home/" not in path.read_text(encoding="utf-8")


def test_the_update_counts_only_the_gate_s_budget(tree, tmp_path):
    path = tmp_path / "durations.json"
    _shard_json(tmp_path / "run" / "a", "a", seconds={"M000": 900.0}, examples=1000)
    _shard_json(tmp_path / "run" / "b", "b", seconds={"M001": 900.0}, rounds=3)
    _shard_json(tmp_path / "run" / "c", "c", seconds={"M002": 8.0})
    said: list = []
    assert mc.update_durations([tmp_path / "run"], path, say=lambda *a, **k: said.append(a[0])) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["mutants"] == {"M002": 8}
    assert sum("left out" in s for s in said) == 2 and any("1000 sequences" in s for s in said)


def test_the_update_leaves_out_a_measure_that_is_not_a_duration_and_says_it(tree, tmp_path):
    """A row of before CI6d with an absurd detail (400 digits: inf), a measure at 0 or past a day:
    left out, said, the file written — never `round(inf)` (CI6d, review)."""
    path = tmp_path / "durations.json"
    _shard_json(tmp_path / "run" / "m", "mutants-1", seconds={"M001": 0, "M002": 1e308, "M003": 7.0})
    _shard_json(tmp_path / "run" / "old", "mutants-2", legacy={"M000": "9" * 400, "M004": 12})
    said: list = []
    assert mc.update_durations([tmp_path / "run"], path, say=lambda *a, **k: said.append(a[0])) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["mutants"] == {"M003": 7, "M004": 12}
    assert any("mutants-2.json: 1 mutants (rows) not a duration" in s for s in said), said
    assert any("mutants-1.json: 2 mutants not a duration" in s for s in said), said


def test_an_update_with_nothing_read_changes_nothing(tree, tmp_path):
    path = tmp_path / "durations.json"
    path.write_text('{"mutants": {"M000": 10}, "targets": {}}', encoding="utf-8")
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "bad.json").write_text("not json", encoding="utf-8")
    assert mc.update_durations([tmp_path / "run"], path, say=lambda *a, **k: None) == 1
    assert path.read_text(encoding="utf-8") == '{"mutants": {"M000": 10}, "targets": {}}'


def test_the_repository_s_durations_hold_only_ids_and_relative_test_paths():
    """The versioned file: no machine's path, no identifier — mutant ids and the tree's targets."""
    text = mc.DURATIONS.read_text(encoding="utf-8")
    doc = json.loads(text)
    assert (doc["examples"], doc["rounds"]) == mc.DURATIONS_BUDGET
    assert all(re.fullmatch(r"[MC]\d+", k) and isinstance(v, int) and v >= 1 for k, v in doc["mutants"].items())
    assert all(k.startswith("tests/") and isinstance(v, int) for k, v in doc["targets"].items())
    assert "/home/" not in text and "/tmp/" not in text and "\\\\" not in text
    # The gate's runs of 05/11, at least — a mutant narrowed since (CI10a) waits for its next measure.
    assert len(doc["mutants"]) + len(mc.WHOLE) >= 2900 and not set(doc["mutants"]) & set(mc.WHOLE)
    assert len(doc["targets"]) >= 500                        # their unmutated runs too (CI10a)


def test_the_plan_says_each_shard_and_the_heaviest(capsys):
    todo = _mutants(30)
    tests = {m[0]: f"tests/unit/test_{i % 5}.py" for i, m in enumerate(todo)}
    durations = _durations(todo, targets={t: 20.0 for t in tests.values()})
    shards = mc.plan(todo, 3, 4, tests, durations)
    assert len(shards) == 3 and sum(c for c, _, _ in shards) == 30
    assert all(s > 0 for _, _, s in shards)


def test_the_repository_s_mutants_split_into_the_gate_s_shards():
    """The gate's own numbers (release-gate.yml): fourteen shards of the mutants, two of the control
    set, each one with something to measure, together the whole set."""
    for every, n in ((mc.MUTANTS, 14), (mc.CONTROL, 2)):
        shards = [mc.shard_of(every, k, n) for k in range(1, n + 1)]
        assert all(shards) and sorted(m[0] for s in shards for m in s) == sorted(m[0] for m in every)


@pytest.mark.parametrize("text, parsed", [("1/1", (1, 1)), ("3/10", (3, 10)), (" 10/10 ", (10, 10))])
def test_a_shard_is_k_of_n(text, parsed):
    assert mc.parse_shard(text) == parsed


@pytest.mark.parametrize("text", ["0/10", "11/10", "3", "3/0", "-1/2", "a/b", "1/2/3", "", "01/10"])
def test_a_shard_that_is_not_k_of_n_is_refused(text):
    with pytest.raises(ValueError):
        mc.parse_shard(text)


# ── the total ───────────────────────────────────────────────────────────────────────────────

def _result(where: Path, name: str, rows, *, control=False, shard=1, shards=1, examples=500, rounds=2):
    where.mkdir(parents=True, exist_ok=True)
    (where / f"{name}.json").write_text(json.dumps({
        "control": control, "shard": shard, "shards": shards, "examples": examples, "rounds": rounds,
        "rows": [list(r) for r in rows]}), encoding="utf-8")


def _row(m, verdict="CAUGHT"):
    return (m[0], m[1], verdict, "2/2 (3s)")


@pytest.fixture
def world(monkeypatch, tmp_path):
    """Eight mutants and four of control, measured in two shards each, every one caught."""
    mutants, control = _mutants(8, "M"), _mutants(4, "C")
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", control)
    results = tmp_path / "results"
    for k in (1, 2):
        _result(results / f"mutants-{k}", f"mutants-{k}", [_row(m) for m in mutants[k - 1::2]], shard=k, shards=2)
        _result(results / f"control-{k}", f"control-{k}", [_row(m) for m in control[k - 1::2]], control=True,
                shard=k, shards=2)
    return mutants, control, results


def _total(results, shards=2, control_shards=2, examples=500, rounds=2):
    return mc.total(results, shards, control_shards, examples, rounds)


def test_every_shard_there_every_mutant_once_none_survived(world, capsys):
    _, _, results = world
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "mutants: 8/8 caught in every round" in out and "0 survived a round outside the known survivors" in out
    assert "control: 4/4 caught in every round (said, not held)" in out and "✗" not in out


def test_the_control_set_is_said_never_held(world, capsys):
    _, control, results = world
    _result(results / "control-1", "control-1", [_row(m, "SURVIVES") for m in control[0::2]], control=True,
            shard=1, shards=2)
    assert _total(results) == 0
    assert "control: 2/4 caught" in capsys.readouterr().out


def test_a_shard_missing_is_red(world, capsys):
    _, _, results = world
    (results / "mutants-2" / "mutants-2.json").unlink()
    assert _total(results) == 1
    out = capsys.readouterr().out
    assert "✗ mutants: shard(s) 2 of 2 missing" in out and "4 never measured" in out


def test_a_control_shard_missing_is_red(world, capsys):
    _, _, results = world
    (results / "control-1" / "control-1.json").unlink()
    assert _total(results) == 1
    assert "✗ control: shard(s) 1 of 2 missing" in capsys.readouterr().out


def test_a_shard_given_twice_is_red(world, capsys):
    mutants, _, results = world
    _result(results / "again", "mutants-1-again", [_row(m) for m in mutants[0::2]], shard=1, shards=2)
    assert _total(results) == 1
    out = capsys.readouterr().out
    assert "mutants shard 1 given twice" in out and "measured twice: M000" in out


@pytest.mark.parametrize("field, value, said", [
    ("examples", 60, "measured at 60 sequences, 2 rounds — not 500, 2"),
    ("rounds", 1, "measured at 500 sequences, 1 rounds — not 500, 2"),
    ("shards", 3, "mutants shard 1 of 3, not of 2"),
])
def test_a_shard_measured_otherwise_is_red(world, capsys, field, value, said):
    mutants, _, results = world
    kw = {"shard": 1, "shards": 2, field: value}
    _result(results / "mutants-1", "mutants-1", [_row(m) for m in mutants[0::2]], **kw)
    assert _total(results) == 1
    assert said in capsys.readouterr().out


def test_a_mutant_never_measured_or_not_of_this_tree_is_red(world, capsys):
    mutants, _, results = world
    rows = [_row(m) for m in mutants[0::2]][1:] + [("M999", "elsewhere", "CAUGHT", "2/2")]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 1
    out = capsys.readouterr().out
    assert "mutants: 1 never measured: M000" in out and "mutants: 1 not of this tree: M999" in out


@pytest.mark.parametrize("text", ["not json", "[]", '{"control": false}', '{"control": false, "shard": "x", '
                                  '"shards": 2, "rows": []}'])
def test_a_result_that_cannot_be_read_is_red(world, capsys, text):
    _, _, results = world
    (results / "mutants-1" / "mutants-1.json").write_text(text, encoding="utf-8")
    assert _total(results) == 1
    assert "mutants-1.json: unreadable" in capsys.readouterr().out


def test_nothing_measured_is_red(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(mc, "MUTANTS", _mutants(3))
    monkeypatch.setattr(mc, "CONTROL", [])
    (tmp_path / "empty").mkdir()
    assert mc.total(tmp_path / "empty", 1, 1, 500, 2) == 1


def test_equivalent_multi_host_and_stale_are_not_counted(world, capsys):
    """CI6e: not counted, they stay so — never a survivor, known or not, whatever their reason."""
    mutants, _, results = world
    rows = [_row(mutants[0], "EQUIVALENT"), _row(mutants[2], "MULTI-HOST"), _row(mutants[4], "STALE"),
            _row(mutants[6])]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "mutants: 5/5 caught" in out and "0 survived a round outside" in out and "✗" not in out


# ── a shard measured, end to end: what --json writes is what --total reads ──────────────────

def test_a_shard_s_json_is_what_the_total_reads(tmp_path, monkeypatch, capsys):
    """main() as the gate runs it, its copy of the repository and its test runs replaced: a mutant
    is caught when its file holds the new text."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(6)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {m[0]: f"tests/unit/test_{m[0]}.py" for m in mutants})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "".join(m[3] for m in mutants))))
    baselines = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        if copy.name == "base":
            baselines.append(target)
            return False
        return "LINE 3" not in (copy / "code.py").read_text()   # M3 survives, the others are caught
    monkeypatch.setattr(mc, "_run", run)
    out = tmp_path / "results"
    out.mkdir()
    for k in (1, 2, 3):
        assert mc.main(["--examples", "500", "--rounds", "2", "--jobs", "2", "--shard", f"{k}/3",
                        "--json", str(out / f"m{k}.json")]) == 0
    assert sorted(baselines) == sorted(mc.TESTS.values())          # each target's unmutated run, once
    capsys.readouterr()
    total = ["--total", str(out), "--shards", "3", "--control-shards", "0", "--examples", "500", "--rounds", "2"]
    assert mc.main(total) == 1                                      # M3 survived, no reason: red
    said = capsys.readouterr().out
    assert "mutants: 5/6 caught in every round" in said and "M3  SURVIVES" in said
    assert "✗ M3  SURVIVES 0/2" in said and "bug 3" in said
    mutants[3] = (*mutants[3], "TIMING: a race its tests see at times")   # now a known survivor
    assert mc.main(total) == 0 and "✗" not in capsys.readouterr().out


def test_a_shard_s_json_says_each_mutant_s_seconds_and_each_target_s(tmp_path, monkeypatch):
    """CI6d: what the durations' file is made of, written by the shard itself — each mutant's measure
    and each target's unmutated run, in seconds; the rows as before, the total reading them alike."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(4)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {"M0": "tests/unit/test_a.py", "M1": "tests/unit/test_a.py",
                                      "M2": "tests/unit/test_b.py", "M3": "tests/unit/test_c.py"})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "".join(m[3] for m in mutants))))
    clock = iter(range(0, 10_000, 5))
    monkeypatch.setattr(mc.time, "monotonic", lambda: float(next(clock)))
    monkeypatch.setattr(mc, "_run", lambda copy, examples, show=False, target=mc.INVARIANTS: copy.name != "base")
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "1", "--jobs", "1", "--json", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(doc["seconds"]) == ["M0", "M1", "M2", "M3"] and all(s > 0 for s in doc["seconds"].values())
    assert sorted(doc["targets"]) == ["tests/unit/test_a.py", "tests/unit/test_b.py", "tests/unit/test_c.py"]
    assert all(s > 0 for s in doc["targets"].values())
    assert [r[2] for r in doc["rows"]] == ["CAUGHT"] * 4
    assert mc._result_durations(doc) == (doc["seconds"], doc["targets"])


def test_a_shard_runs_its_heaviest_first(tmp_path, monkeypatch):
    """The unmutated runs and the mutants in one pool (CI10a, L4), the heaviest first by the durations
    measured: a long run started last would make the shard's tail, and a long unmutated run no longer
    holds every worker before the first mutant."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(4)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {m[0]: f"tests/unit/test_{m[0]}.py" for m in mutants})
    monkeypatch.setattr(mc, "load_durations", lambda path=None, say=print: {
        "mutants": {"M0": 1.0, "M1": 50.0, "M2": 9.0, "M3": 400.0},
        "targets": {"tests/unit/test_M0.py": 90.0, "tests/unit/test_M1.py": 2.0, "tests/unit/test_M2.py": 30.0,
                    "tests/unit/test_M3.py": 1.0}})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "".join(m[3] for m in mutants))))
    order: list = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        order.append(("base" if copy.name == "base" else "mutant", target))
        return copy.name != "base"
    monkeypatch.setattr(mc, "_run", run)
    assert mc.main(["--rounds", "1", "--jobs", "1"]) == 0
    assert order == [("mutant", "tests/unit/test_M3.py"), ("base", "tests/unit/test_M0.py"),
                     ("mutant", "tests/unit/test_M1.py"), ("base", "tests/unit/test_M2.py"),
                     ("mutant", "tests/unit/test_M2.py"), ("base", "tests/unit/test_M1.py"),
                     ("mutant", "tests/unit/test_M0.py"), ("base", "tests/unit/test_M3.py")]


@pytest.mark.parametrize("n", ["0", "-3", "x", "1.5"])
def test_a_plan_of_no_shard_is_refused_as_a_shard_is(n, capsys):
    """`--plan 0` (or negative) refused before anything is read, as a bad `--shard` is."""
    with pytest.raises(SystemExit) as exc:
        mc.main(["--plan", n])
    assert exc.value.code == 2 and "a number of shards, 1 or more" in capsys.readouterr().err


def test_the_plan_measures_nothing(monkeypatch, capsys):
    """`--plan N`: each shard's estimate said, nothing copied, nothing run."""
    monkeypatch.setattr(mc, "MUTANTS", _mutants(20, "M"))
    monkeypatch.setattr(mc, "TESTS", {})
    monkeypatch.setattr(mc, "load_durations", lambda path=None, say=print: mc.no_durations())
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: pytest.fail("copied"))
    monkeypatch.setattr(mc, "_run", lambda *a, **k: pytest.fail("ran"))
    assert mc.main(["--plan", "3", "--jobs", "4"]) == 0
    said = capsys.readouterr().out
    assert "3 shards of 20 mutants" in said and "shard  3/3" in said and "heaviest: shard" in said


def test_an_unmutated_target_that_fails_stops_the_shard(tmp_path, monkeypatch, capsys):
    mutants = [("M1", "bug", "code.py", "a\n", "b\n")]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text("a\n")))
    monkeypatch.setattr(mc, "_run", lambda copy, examples, show=False, target=mc.INVARIANTS: copy.name == "base")
    assert mc.main(["--json", str(tmp_path / "m.json")]) == 2
    assert "fails on the UNMUTATED code" in capsys.readouterr().out and not (tmp_path / "m.json").exists()


# ── CI6b (#538): ChromaDB's model made ready once, before any run in parallel ──────────────
# At the gate's first real run (05/11), the unmutated runs, started at once on a fresh runner,
# each fetched ChromaDB's embedding model into the same ~/.cache/chroma and read one another's
# half-written file: two shards of fourteen red on the unmutated code. Here on a fake ChromaDB.

def _fake_chromadb(monkeypatch, fails: Exception | None = None) -> list:
    """A fake `chromadb.utils.embedding_functions`: its DefaultEmbeddingFunction notes each call
    (the texts it was given), and raises `fails` if given."""
    import types
    calls: list = []

    class DefaultEmbeddingFunction:
        def __call__(self, texts):
            calls.append(list(texts))
            if fails is not None:
                raise fails
            return [[0.0] * 3 for _ in texts]
    fake = types.ModuleType(mc.EMBEDDING)
    fake.DefaultEmbeddingFunction = DefaultEmbeddingFunction
    monkeypatch.setitem(sys.modules, mc.EMBEDDING, fake)
    return calls


def _harness(monkeypatch, events: list, survives=("M3",)):
    """main()'s copy of the repository and its test runs replaced, each run noted in `events`."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(6)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {m[0]: f"tests/unit/test_{m[0]}.py" for m in mutants})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "".join(m[3] for m in mutants))))

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        events.append(("run", copy.name))
        if copy.name == "base":
            return False
        return not any(f"LINE {m[1:]}" in (copy / "code.py").read_text() for m in survives)
    monkeypatch.setattr(mc, "_run", run)
    return mutants


def test_the_model_is_prepared_once_before_any_run_never_by_each(tmp_path, monkeypatch):
    """Once, in the harness's own process, before the unmutated runs (started at once) and the
    mutants' — the defect back if each run fetches it, or if the harness never does."""
    events: list = []
    monkeypatch.setattr(mc, "prepare_embedding_model", lambda say=print: events.append("prepare") or True)
    _harness(monkeypatch, events)
    assert mc.main(["--rounds", "1", "--jobs", "4", "--json", str(tmp_path / "m.json")]) == 0
    runs = [e for e in events if e != "prepare"]
    assert events.count("prepare") == 1 and events[0] == "prepare", events[:5]
    assert len(runs) == 6 + 6                                   # six unmutated targets, six mutants


def test_the_model_is_prepared_by_chromadb_s_default_embedding_function_on_one_text(monkeypatch, capsys):
    calls = _fake_chromadb(monkeypatch)
    assert REAL_PREPARE() is True
    assert len(calls) == 1 and len(calls[0]) == 1 and isinstance(calls[0][0], str)
    assert "embedding model: ready" in capsys.readouterr().out


def test_without_chromadb_nothing_is_prepared_nor_said(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, mc.EMBEDDING, None)        # import fails: not installed
    assert REAL_PREPARE() is None
    assert capsys.readouterr().out == ""


def test_chromadb_that_cannot_start_is_said_never_raised(tmp_path, monkeypatch, capsys):
    """CI6b's review: chromadb 1.5.9 raises a RuntimeError on its own import when sqlite3 is too old
    (chromadb/__init__.py). There, but unable to start: said and False, never a trace that stops
    the harness — and never None, taken for ChromaDB absent."""
    (tmp_path / "chromadb_ci6b_cannot_start.py").write_text(
        'raise RuntimeError("Your system has an unsupported version of sqlite3. Chroma requires sqlite3 >= 3.35.0.")\n')
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(mc, "EMBEDDING", "chromadb_ci6b_cannot_start")
    monkeypatch.delitem(sys.modules, "chromadb_ci6b_cannot_start", raising=False)
    assert REAL_PREPARE() is False
    said = capsys.readouterr().out
    assert "could not be prepared" in said and "RuntimeError: Your system has an unsupported version of sqlite3" in said


def test_a_preparation_that_fails_is_said_and_the_runs_go_on_as_before(tmp_path, monkeypatch, capsys):
    """Without a network, say: the error said whole, never hidden, and the runs go on — each may
    fetch the model itself; nothing about the preparation is a verdict."""
    calls = _fake_chromadb(monkeypatch, OSError("no route to the model's host"))
    monkeypatch.setattr(mc, "prepare_embedding_model", REAL_PREPARE)
    events: list = []
    _harness(monkeypatch, events)
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "1", "--jobs", "4", "--json", str(out)]) == 0
    said = capsys.readouterr().out
    assert len(calls) == 1
    assert "could not be prepared" in said and "OSError: no route to the model's host" in said
    assert sum(1 for e in events if e == ("run", "base")) == 6  # every unmutated run, as before
    rows = {r[0]: r[2] for r in json.loads(out.read_text())["rows"]}
    assert rows == {"M0": "CAUGHT", "M1": "CAUGHT", "M2": "CAUGHT", "M3": "SURVIVES", "M4": "CAUGHT",
                    "M5": "CAUGHT"}


def test_a_failed_preparation_never_catches_a_mutant(tmp_path, monkeypatch, capsys):
    """Every mutant passing its tests survives, the preparation failed or not."""
    _fake_chromadb(monkeypatch, ValueError("Downloaded file does not match expected SHA256 hash"))
    monkeypatch.setattr(mc, "prepare_embedding_model", REAL_PREPARE)
    _harness(monkeypatch, [], survives=tuple(f"M{i}" for i in range(6)))
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "2", "--jobs", "2", "--json", str(out)]) == 0   # a shard: the total holds it
    assert {r[2] for r in json.loads(out.read_text())["rows"]} == {"SURVIVES"}
    assert "could not be prepared" in capsys.readouterr().out


def test_the_runs_see_the_home_the_model_was_prepared_in(tmp_path, monkeypatch):
    """ChromaDB's place is Path.home()/.cache/chroma: each run inherits the harness's HOME, so it
    reads the model the harness made ready — never a home of its own."""
    import subprocess
    seen: list = []
    monkeypatch.setattr(mc.subprocess, "run", lambda cmd, **kw: seen.append(kw["env"]) or
                        subprocess.CompletedProcess(cmd, 0, stdout="", stderr=""))
    assert mc._run(tmp_path, 1, target="tests/unit/test_x.py") is False
    (env,) = seen
    assert env.get("HOME") == mc.os.environ.get("HOME")
    assert Path(env["HOME"]).expanduser() == Path.home()


def test_with_the_model_there_nothing_goes_out(monkeypatch):
    """chromadb itself (the locked version): its model there, the preparation never downloads."""
    pytest.importorskip("chromadb")
    import importlib
    onnx = importlib.import_module("chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2").ONNXMiniLM_L6_V2
    files = ("config.json", "model.onnx", "special_tokens_map.json", "tokenizer_config.json", "tokenizer.json",
             "vocab.txt")
    if not all((Path(onnx.DOWNLOAD_PATH) / onnx.EXTRACTED_FOLDER_NAME / f).exists() for f in files):
        pytest.skip("ChromaDB's model is not in ~/.cache/chroma here (ci.yml restores it)")

    def no_network(self, url, fname, chunk_size=1024):
        raise AssertionError(f"downloaded {url}")
    monkeypatch.setattr(onnx, "_download", no_network)
    said: list = []
    assert REAL_PREPARE(say=lambda *a, **k: said.append(a)) is True, said



# ── CI6e (#553): red as soon as a mutant survives outside the known survivors ────────────────

def _known(m, why="TIMING: a race its tests see only at times"):
    return (*m[:5], why)


@pytest.mark.parametrize("verdict", ["SURVIVES", "flaky", "FIXED-ONLY"])
def test_an_unknown_survivor_is_red_with_its_id_and_title(world, capsys, verdict):
    """A counted mutant that survived a round — none, one of two, or caught by a fixed sequence
    only — and carries no reason: red, said with its id and its title, whatever the count."""
    mutants, _, results = world
    rows = [_row(m) for m in mutants[0::2]]
    rows[1] = _row(mutants[2], verdict)
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 1
    out = capsys.readouterr().out
    assert f"✗ M002  {verdict} 2/2 (3s): bug 2 — survived a round, and is no known survivor" in out
    assert "1 survived a round outside the known survivors" in out and "✗ M000" not in out


def test_a_known_survivor_does_nothing(world, monkeypatch, capsys):
    """A survivor whose reason the harness reads (its mark, then a colon): counted, never red."""
    mutants, _, results = world
    monkeypatch.setattr(mc, "MUTANTS", [_known(m) if m[0] == "M002" else m for m in mutants])
    rows = [_row(mutants[0]), _row(mutants[2], "TIMING"), _row(mutants[4]), _row(mutants[6])]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "mutants: 7/8 caught in every round" in out and "(1 known)" in out
    assert "✗" not in out and "known survivor no more" not in out


def test_a_known_survivor_caught_is_said_to_take_off_the_list_never_red(world, monkeypatch, capsys):
    mutants, _, results = world
    monkeypatch.setattr(mc, "MUTANTS", [_known(m, "EQUIVALENT: no behaviour tells it apart")
                                        if m[0] == "M004" else m for m in mutants])
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert ("· M004  caught in every round (2/2 (3s)), a known survivor no more: take its reason "
            "(EQUIVALENT) off by hand — bug 4") in out
    assert "✗" not in out


def test_a_reason_the_harness_cannot_read_makes_no_known_survivor(world, monkeypatch, capsys):
    """Its mark unknown, no colon, nothing before it: the reason is not read — its survivor is red."""
    mutants, _, results = world
    for why in ("FLAKY: at times", "EQUIVALENT no colon", ": nothing before", None):
        assert mc.mark(_known(mutants[2], why)) == ""
    assert [mc.mark(_known(mutants[0], f"{w}: why")) for w in mc.KNOWN_MARKS] == list(mc.KNOWN_MARKS)
    monkeypatch.setattr(mc, "MUTANTS", [_known(m, "FLAKY: at times") if m[0] == "M002" else m for m in mutants])
    rows = [_row(mutants[0]), _row(mutants[2], "SURVIVES"), _row(mutants[4]), _row(mutants[6])]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 1
    assert "✗ M002  SURVIVES" in capsys.readouterr().out


def test_the_control_set_s_survivors_are_said_never_red(world, capsys):
    _, control, results = world
    _result(results / "control-2", "control-2", [_row(m, "SURVIVES") for m in control[1::2]], control=True,
            shard=2, shards=2)
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "control: 2/4 caught" in out and "✗" not in out


def test_a_run_of_its_own_is_red_on_an_unknown_survivor_a_shard_leaves_it_to_the_total(
        tmp_path, monkeypatch, capsys):
    """Without --json (a run of its own, `--only`): red, said. A shard (--json) writes and says
    it, its upload never stopped: the total holds it. The control set: never red."""
    mutants = _harness(monkeypatch, [])
    assert mc.main(["--rounds", "2", "--jobs", "2"]) == 1
    out = capsys.readouterr().out
    assert "✗ M3  SURVIVES 0/2" in out and "bug 3" in out
    assert mc.main(["--rounds", "2", "--jobs", "2", "--json", str(tmp_path / "m.json")]) == 0
    assert "✗ M3  SURVIVES" in capsys.readouterr().out
    assert {r[0]: r[2] for r in json.loads((tmp_path / "m.json").read_text())["rows"]}["M3"] == "SURVIVES"
    mutants[3] = _known(mutants[3])
    assert mc.main(["--rounds", "2", "--jobs", "2"]) == 0
    monkeypatch.setattr(mc, "CONTROL", [m[:5] for m in mutants])
    monkeypatch.setattr(mc, "MUTANTS", [])
    assert mc.main(["--control", "--rounds", "2", "--jobs", "2"]) == 0
    assert "✗" not in capsys.readouterr().out


def test_a_known_survivor_s_row_says_its_mark_an_unread_reason_its_verdict(tmp_path, monkeypatch):
    """The row of a known survivor that survived says its reason's mark; a reason not read leaves
    the verdict measured — never a mark the total would take for a reason."""
    mutants = _harness(monkeypatch, [], survives=("M3", "M4"))
    mutants[3] = _known(mutants[3], "MULTI-HOST: needs a second host")
    mutants[4] = _known(mutants[4], "FLAKY: at times")
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "1", "--jobs", "2", "--json", str(out)]) == 0
    rows = {r[0]: r[2] for r in json.loads(out.read_text())["rows"]}
    assert (rows["M3"], rows["M4"], rows["M0"]) == ("MULTI-HOST", "SURVIVES", "CAUGHT")


def test_min_caught_is_gone_never_taken_silently(capsys):
    """`--min-caught` held 14 of 2 850: gone (CI6e). The workflows and the harness come from one
    tree: a flag left would only hide that it no longer holds anything — refused, loudly."""
    with pytest.raises(SystemExit) as exc:
        mc.main(["--total", "x", "--min-caught", "14"])
    assert exc.value.code == 2 and "--min-caught" in capsys.readouterr().err


def test_a_timing_survivor_caught_in_no_round_is_said_apart_never_red(world, monkeypatch, capsys):
    """CI6e, review: a TIMING reason excuses a mutant at 0 of N as at 1 of N. Caught in no round of
    this run, it is said apart — its race test should catch it at times — and the total stays green:
    a race may just not have come. Caught at times, it is nothing."""
    mutants, _, results = world
    timing = "TIMING: tests/unit/test_race.py catches it 1 round in 2"
    monkeypatch.setattr(mc, "MUTANTS", [_known(m, timing) if m[0] in ("M002", "M004") else m for m in mutants])
    rows = [_row(mutants[0]), ("M002", "bug 2", "TIMING", "0/2 (3s)"), ("M004", "bug 4", "TIMING", "1/2 (3s)"),
            _row(mutants[6])]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "! M002  TIMING 0/2 (3s): bug 2 — a known survivor caught in no round of this run" in out
    assert "! M004" not in out and "✗" not in out
    assert [r[0] for r in mc.never_caught(rows, mc.MUTANTS)] == ["M002"]
    assert mc.never_caught([("M002", "bug 2", "CAUGHT", "2/2 (3s)"), ("M000", "bug 0", "SURVIVES", "0/2")],
                           mc.MUTANTS) == []


def test_a_run_of_its_own_says_a_timing_survivor_caught_in_no_round(monkeypatch, capsys):
    mutants = _harness(monkeypatch, [])
    mutants[3] = _known(mutants[3], "TIMING: tests/unit/test_race.py catches it at times")
    assert mc.main(["--rounds", "2", "--jobs", "2"]) == 0
    assert "! M3  TIMING 0/2" in capsys.readouterr().out


def test_every_run_of_a_copy_carries_the_harness_s_mark(tmp_path, monkeypatch):
    """CI6e, second review: each run of a copy — the unmutated one and each mutant's — has
    EREGION_MUTANT_RUN set: the tree's meta-test skips there, never a killer by construction."""
    seen = []

    def run(cmd, cwd=None, env=None, capture_output=False, text=False):
        seen.append(env)
        return type("P", (), {"returncode": 0, "stdout": "1 passed"})()
    monkeypatch.setattr(mc.subprocess, "run", run)
    monkeypatch.delenv(mc.MUTANT_RUN, raising=False)
    assert mc._run(tmp_path, 60, target="tests/unit/test_x.py") is False
    assert seen[0][mc.MUTANT_RUN] == "1" and mc.MUTANT_RUN == "EREGION_MUTANT_RUN"


# ── CI10a (#580): the levers of the CI9 study ────────────────────────────────────────────────
# L1: a mutant whose target is a heavy file whole, on the fastest tests of it that catch it
# (scripts/mutants/narrowed.json, `--narrow FILE`). L2: one round where no chance plays. L3: the
# machines' unmutated run left to the gate's invariants job (`--skip-machine-baseline`). L4: the
# unmutated runs and the mutants in one pool. `--machines`: the mutants of the machines only.

def _files(monkeypatch, tmp_path, files: dict) -> None:
    """Test files the rules read, in a tree of the test's own."""
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    monkeypatch.setattr(mc, "REPO", tmp_path)
    monkeypatch.setattr(mc, "_SOURCES", {})
    monkeypatch.setattr(mc, "_RACERS", {})


_PLAIN = "def test_x():\n    assert True\n"
_DRAWS = "from hypothesis import given\n\n" + _PLAIN
_MACHINE = ("from hypothesis.stateful import RuleBasedStateMachine\n\n"
            "class World(RuleBasedStateMachine):\n    pass\n")


def test_a_target_no_chance_moves_has_one_round(monkeypatch, tmp_path):
    """L2: a second round replays the same test on the same code — one round, whatever is asked."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_plain.py": _PLAIN, "tests/unit/test_other.py": _PLAIN})
    m = ("M1", "bug", "code.py", "a", "b")
    assert mc.rounds_of(m, "tests/unit/test_plain.py", 2) == 1
    assert mc.rounds_of(m, "tests/unit/test_plain.py::test_x tests/unit/test_other.py -k x", 3) == 1
    assert mc.rounds_of(m, "tests/unit/test_plain.py", 1) == 1


def test_a_target_that_draws_keeps_its_rounds(monkeypatch, tmp_path):
    """L2: one file importing Hypothesis in the target — the machines, a property test — and every
    round draws new seeds: the rounds asked."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_plain.py": _PLAIN, "tests/unit/test_prop.py": _DRAWS,
                                   "tests/unit/test_db.py": "import hypothesis.database\n" + _PLAIN})
    m = ("M1", "bug", "code.py", "a", "b")
    assert mc.rounds_of(m, "tests/unit/test_plain.py tests/unit/test_prop.py::test_x", 2) == 2
    assert mc.rounds_of(m, "tests/unit/test_db.py", 3) == 3
    # An unreadable file keeps the rounds: never one round guessed.
    assert mc.rounds_of(m, "tests/unit/test_gone.py", 2) == 2


def test_the_rule_on_this_tree_keeps_the_rounds_where_chance_plays():
    """L2 on the tree: the machines, the property tests, the races keep two rounds; the CD, one."""
    m = ("M1", "bug", "code.py", "a", "b")
    for drawn in ("tests/unit/test_invariants.py", "tests/unit/test_invariants_aws.py", "tests/unit/test_arm_urls.py",
                  "tests/unit/test_entries_calls.py", "tests/unit/test_unexpected_decision.py",
                  "tests/unit/test_locks.py -k concurrent", "tests/unit/test_exercise.py"):
        assert mc.rounds_of(m, drawn, 2) == 2, drawn
    for plain in ("tests/unit/test_host_cd.py", "tests/unit/test_published_image.py",
                  "tests/unit/test_correlation.py", "tests/unit/test_glorfindel.py -k drain",
                  "tests/unit/test_invariant_regressions.py::test_an_isolation_gone_under_a_bypass_is_said_gone"):
        assert mc.rounds_of(m, plain, 2) == 1, plain


def test_a_target_that_races_keeps_its_rounds(monkeypatch, tmp_path):
    """L2: the races (TIMED: real processes, real clocks) draw no seed, yet a round may not see the
    race the other does."""
    _files(monkeypatch, tmp_path, {rel: _PLAIN for rel in mc.TIMED})
    assert set(mc.TIMED) == {"tests/unit/test_locks.py", "tests/unit/test_exercise.py"}
    for rel in mc.TIMED:
        assert mc.rounds_of(("M1", "bug", "code.py", "a", "b"), f"{rel}::test_x", 2) == 2, rel


def test_a_timing_mutant_keeps_its_rounds(monkeypatch, tmp_path):
    _files(monkeypatch, tmp_path, {"tests/unit/test_plain.py": _PLAIN})
    m = ("M1", "bug", "code.py", "a", "b", "TIMING: tests/unit/test_plain.py::test_x sees it at times")
    assert mc.rounds_of(m, "tests/unit/test_plain.py", 2) == 2


def test_main_measures_a_deterministic_target_once(tmp_path, monkeypatch):
    """L2 in main(): its rounds per mutant, said in its row and in its --json."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_plain.py": _PLAIN, "tests/unit/test_prop.py": _DRAWS})
    mutants = [("M1", "bug 1", "code.py", "line 1\n", "LINE 1\n"), ("M2", "bug 2", "code.py", "line 2\n", "LINE 2\n")]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {"M1": "tests/unit/test_plain.py", "M2": "tests/unit/test_prop.py"})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "line 1\nline 2\n")))
    runs: list = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        runs.append((copy.name, target))
        return copy.name != "base"
    monkeypatch.setattr(mc, "_run", run)
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "2", "--jobs", "1", "--json", str(out)]) == 0
    assert runs.count(("M1", "tests/unit/test_plain.py")) == 1 and runs.count(("M2", "tests/unit/test_prop.py")) == 2
    doc = json.loads(out.read_text())
    assert doc["mutant_rounds"] == {"M1": 1, "M2": 2} and doc["rounds"] == 2
    assert doc["mutant_targets"] == {"M1": "tests/unit/test_plain.py", "M2": "tests/unit/test_prop.py"}
    assert [r[2] for r in doc["rows"]] == ["CAUGHT", "CAUGHT"]
    assert doc["rows"][0][3].startswith("1/1 ") and doc["rows"][1][3].startswith("2/2 ")


def test_the_machines_are_the_files_that_define_one(monkeypatch, tmp_path):
    """A machine: a file defining a RuleBasedStateMachine — on this tree, the two."""
    assert mc.machine("tests/unit/test_invariants.py") and mc.machine("tests/unit/test_invariants_aws.py")
    assert mc.machine("tests/unit/test_invariant_regressions.py tests/unit/test_invariants.py")
    assert not mc.machine("tests/unit/test_invariant_regressions.py")
    assert not mc.machine("tests/unit/test_arm_urls.py") and not mc.machine("tests/unit/test_host_cd.py")
    _files(monkeypatch, tmp_path, {"tests/unit/test_m.py": _MACHINE, "tests/unit/test_p.py": _DRAWS})
    assert mc.machine("tests/unit/test_m.py::World") and not mc.machine("tests/unit/test_p.py")


def _two_kinds(monkeypatch, tmp_path):
    """Three mutants: one on a machine alone, one on a machine and a plain file, one plain."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_m.py": _MACHINE, "tests/unit/test_plain.py": _PLAIN})
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(3)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [("C1", "control", "code.py", "line 0\n", "LINE 0\n")])
    monkeypatch.setattr(mc, "TESTS", {"M0": "tests/unit/test_m.py",
                                      "M1": "tests/unit/test_plain.py::test_x tests/unit/test_m.py",
                                      "M2": "tests/unit/test_plain.py", "C1": "tests/unit/test_plain.py"})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "line 0\nline 1\nline 2\n")))
    baselines: list = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        if copy.name == "base":
            baselines.append(target)
            return False
        return True
    monkeypatch.setattr(mc, "_run", run)
    return mutants, baselines


def test_skip_machine_baseline_leaves_the_machines_out_and_says_it(tmp_path, monkeypatch, capsys):
    """L3: the shard runs no machine unmutated — the rest of a target still runs — and says so;
    without the flag (the Monday, a local run), each target unmutated as before."""
    _mutants, baselines = _two_kinds(monkeypatch, tmp_path)
    assert mc.main(["--rounds", "1", "--jobs", "1"]) == 0
    assert sorted(baselines) == sorted(mc.TESTS[m] for m in ("M0", "M1", "M2"))
    assert "--skip-machine-baseline" not in capsys.readouterr().out
    baselines.clear()
    out = tmp_path / "m.json"
    assert mc.main(["--rounds", "1", "--jobs", "1", "--skip-machine-baseline", "--json", str(out)]) == 0
    assert sorted(baselines) == ["tests/unit/test_plain.py", "tests/unit/test_plain.py::test_x"]
    said = capsys.readouterr().out
    assert "--skip-machine-baseline: 2 target(s) run unmutated without their invariant machines (1 not at all)" in said
    doc = json.loads(out.read_text())
    assert doc["machine_baseline"] is False and set(doc["targets"]) == set(baselines)
    assert [r[2] for r in doc["rows"]] == ["CAUGHT"] * 3               # each mutant still measured


def test_a_plan_weighs_no_machine_run_left_to_the_gate(monkeypatch, tmp_path):
    """L3 in the model: with skip, a machine's unmutated run weighs nothing in its shard."""
    mutants, _ = _two_kinds(monkeypatch, tmp_path)
    durations = {"mutants": {"M0": 10.0, "M1": 10.0, "M2": 10.0},
                 "targets": {"tests/unit/test_m.py": 600.0, mc.TESTS["M1"]: 600.0,
                             "tests/unit/test_plain.py::test_x": 5.0, "tests/unit/test_plain.py": 5.0}}
    full = mc.plan(mutants, 1, 1, tests=mc.TESTS, durations=durations)
    left = mc.plan(mutants, 1, 1, tests=mc.TESTS, durations=durations, skip=True)
    assert full[0][2] == pytest.approx(30 + 600 + 600 + 5)
    assert left[0][2] == pytest.approx(30 + 5 + 5)


def test_machines_selects_the_mutants_of_the_machines(tmp_path, monkeypatch):
    """`--machines`: the mutants whose target runs a machine, in shards and --json; the control set
    keeps its own."""
    mutants, _ = _two_kinds(monkeypatch, tmp_path)
    assert [m[0] for m in mc.selected(mutants, machines=True)] == ["M0", "M1"]
    assert [m[0] for m in mc.selected(mutants)] == ["M0", "M1", "M2"]
    assert [m[0] for m in mc.selected(mc.CONTROL, control=True, machines=True)] == ["C1"]
    out = tmp_path / "res"
    out.mkdir()
    for k in (1, 2):
        assert mc.main(["--rounds", "1", "--jobs", "1", "--machines", "--shard", f"{k}/2",
                        "--json", str(out / f"m{k}.json")]) == 0
    docs = [json.loads((out / f"m{k}.json").read_text()) for k in (1, 2)]
    assert sorted(r[0] for d in docs for r in d["rows"]) == ["M0", "M1"] and all(d["machines"] for d in docs)
    assert mc.main(["--rounds", "1", "--jobs", "1", "--control", "--machines", "--json", str(tmp_path / "c.json")]) == 0
    assert [r[0] for r in json.loads((tmp_path / "c.json").read_text())["rows"]] == ["C1"]


def test_total_machines_judges_those_only(tmp_path, monkeypatch, capsys):
    """`--total DIR --machines`: the selected mutants measured once each, the others never said
    unmeasured; without it, as before, every mutant of the tree."""
    _two_kinds(monkeypatch, tmp_path)
    out = tmp_path / "res"
    out.mkdir()
    assert mc.main(["--rounds", "1", "--jobs", "1", "--machines", "--json", str(out / "m1.json")]) == 0
    assert mc.main(["--rounds", "1", "--jobs", "1", "--control", "--json", str(out / "c1.json")]) == 0
    capsys.readouterr()
    total = ["--total", str(out), "--shards", "1", "--control-shards", "1", "--rounds", "1"]
    assert mc.main([*total, "--machines"]) == 0
    said = capsys.readouterr().out
    assert "never measured" not in said and "mutants: 2/2 caught" in said and "(--machines)" in said
    assert mc.main(total) == 1
    assert "mutants: 1 never measured: M2" in capsys.readouterr().out


def test_total_machines_refuses_a_shard_measured_otherwise(tmp_path, monkeypatch, capsys):
    """A shard of every mutant read by `--total --machines`, or the reverse: no total of those."""
    _two_kinds(monkeypatch, tmp_path)
    out = tmp_path / "res"
    out.mkdir()
    assert mc.main(["--rounds", "1", "--jobs", "1", "--json", str(out / "m1.json")]) == 0
    capsys.readouterr()
    assert mc.main(["--total", str(out), "--shards", "1", "--control-shards", "0", "--rounds", "1",
                    "--machines"]) == 1
    assert "m1.json: mutants measured without --machines, not with" in capsys.readouterr().out


def test_unmutated_runs_write_nowhere_a_mutant_reads(tmp_path, monkeypatch):
    """L4: the unmutated runs share the mutants' pool, in a copy of their own — what they write (a
    Hypothesis database, a cache) never reaches a mutant's copy, made while they run."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", f"line {i}\n", f"LINE {i}\n") for i in range(3)]
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    monkeypatch.setattr(mc, "CONTROL", [])
    monkeypatch.setattr(mc, "TESTS", {m[0]: "tests/unit/test_gone.py" for m in mutants})
    monkeypatch.setattr(mc, "load_durations", lambda path=None, say=print: {
        "mutants": {"M0": 1.0, "M1": 2.0, "M2": 3.0}, "targets": {"tests/unit/test_gone.py": 100.0}})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "line 0\nline 1\nline 2\n")))
    seen: list = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        if copy.name == "base":
            (copy / ".hypothesis").mkdir(exist_ok=True)
            return False
        seen.append((copy / ".hypothesis").exists())
        return True
    monkeypatch.setattr(mc, "_run", run)
    assert mc.main(["--rounds", "1", "--jobs", "1"]) == 0
    assert seen and not any(seen)


def test_a_narrowed_entry_applies_only_while_its_lot_targets_the_whole_file():
    """L1: an entry gives its nodes to a mutant whose target is still the whole file it was
    measured on — never to one whose lot has moved it, nor to an id nobody defines."""
    entries = {"M1": {"whole": "tests/unit/test_cd.py", "tests": "tests/unit/test_cd.py::test_a"},
               "M2": {"whole": "tests/unit/test_cd.py", "tests": "tests/unit/test_cd.py::test_b"},
               "M9": {"whole": "tests/unit/test_cd.py", "tests": "tests/unit/test_cd.py::test_c"}}
    tests = {"M1": "tests/unit/test_cd.py", "M2": "tests/unit/test_cd.py::test_z"}
    assert mc.narrowed(tests, entries) == {"M1": "tests/unit/test_cd.py"}
    assert tests == {"M1": "tests/unit/test_cd.py::test_a", "M2": "tests/unit/test_cd.py::test_z"}


def test_narrowed_json_unreadable_narrows_nothing(tmp_path):
    assert mc.load_narrowed(tmp_path / "absent.json") == {}
    (tmp_path / "n.json").write_text("{not json")
    assert mc.load_narrowed(tmp_path / "n.json") == {}
    (tmp_path / "n.json").write_text(json.dumps({"mutants": {"M1": {"whole": "a.py", "tests": " "},
                                                             "M2": {"whole": "a.py", "tests": "a.py::t"}}}))
    assert mc.load_narrowed(tmp_path / "n.json") == {"M2": {"whole": "a.py", "tests": "a.py::t"}}


def test_the_tree_s_narrowed_targets_are_its_cd_mutants_nodes():
    """L1 on the tree: each narrowed target is at most NARROW nodes of the whole file it replaces;
    M1014 keeps its target."""
    assert mc.NARROW == 2
    for mid, whole in mc.WHOLE.items():
        nodes = mc.TESTS[mid].split()
        assert 1 <= len(nodes) <= mc.NARROW and all(n.startswith(whole + "::") for n in nodes), mid
    assert "M1014" not in mc.WHOLE and mc.TESTS["M1014"].startswith("tests/unit/test_host_cd.py ")


def _junit(path: Path, cases: list) -> None:
    body = "".join(
        f'<testcase classname="{c}" name="{n}" time="{t}">' + (f"<{kind} message='x'/>" if kind else "") + "</testcase>"
        for c, n, t, kind in cases)
    path.write_text(f'<?xml version="1.0"?><testsuites><testsuite>{body}</testsuite></testsuites>')


def test_failures_of_reads_failures_and_errors_fastest_first(tmp_path):
    xml = tmp_path / "r.xml"
    _junit(xml, [("tests.unit.test_cd", "test_slow", 3.0, "failure"),
                 ("tests.unit.test_cd", "test_ok", 0.1, ""),
                 ("tests.unit.test_cd", "test_setup[a b]", 0.1, "error"),          # a space: its test whole
                 ("tests.unit.test_cd", "test_setup[c d]", 0.3, "failure"),        # once, at its fastest
                 ("tests.unit.test_cd", "test_named with space", 0.01, "failure"),  # nothing to run: out
                 ("tests.unit.test_cd.TestKind", "test_in_class", 0.5, "error"),
                 ("tests.unit.test_cd", "test_fast[x-1]", 0.2, "failure"),
                 ("tests.unit.test_other", "test_elsewhere", 0.01, "failure")])
    assert mc.failures_of(xml, "tests/unit/test_cd.py") == [
        (0.1, "tests/unit/test_cd.py::test_setup"), (0.2, "tests/unit/test_cd.py::test_fast[x-1]"), (0.5, "tests/unit/test_cd.py::TestKind::test_in_class"),
        (3.0, "tests/unit/test_cd.py::test_slow")]


def _narrowing(monkeypatch, catches: dict, narrow_catches: dict):
    """narrow() on fakes: the whole file's run writes a junit report of the tests `catches` names
    for each mutant (by its copy's name), each in its seconds; `narrow_catches[mid]` says how many
    rounds of the narrowed target catch it."""
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text("a\n")))

    def pytest_(copy, examples, target, *more):
        if copy.name != "base":
            xml = Path(more[0].split("=", 1)[1])
            _junit(xml, [("tests.unit.test_cd", n, t, "failure") for n, t in catches.get(copy.name, [])])
        return type("P", (), {"returncode": 0 if copy.name == "base" else 1, "stdout": ""})()
    monkeypatch.setattr(mc, "_pytest", pytest_)
    left: dict = dict(narrow_catches)

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        left[copy.name] = left.get(copy.name, 0) - 1
        return left[copy.name] >= 0
    monkeypatch.setattr(mc, "_run", run)


def test_narrow_keeps_the_fastest_catchers_caught_in_every_round(tmp_path, monkeypatch):
    """`--narrow`: the fastest NARROW tests that catch a mutant become its target — when they catch
    it in each round; a mutant they miss once, or that no test catches, keeps the whole file."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", "a\n", "b\n") for i in range(4)]
    _narrowing(monkeypatch, {"M0": [("test_slow", 9.0), ("test_fast", 0.5), ("test_mid", 1.0)],
                             "M1": [("test_a", 1.0)], "M2": [("test_b", 1.0)]},
               {"M0": 2, "M1": 1, "M2": 2})
    path = tmp_path / "narrowed.json"
    path.write_text(json.dumps({"mutants": {"M1": {"whole": "tests/unit/test_cd.py", "tests": "x::y"},
                                            "GONE": {"whole": "a.py", "tests": "a.py::t"}}}))
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    assert mc.narrow("tests/unit/test_cd.py", mutants, 60, 2, 1, path=path, say=lambda *a, **k: None) == 0
    doc = json.loads(path.read_text())["mutants"]
    assert doc == {"M0": {"whole": "tests/unit/test_cd.py",
                          "tests": "tests/unit/test_cd.py::test_fast tests/unit/test_cd.py::test_mid"},
                   "M2": {"whole": "tests/unit/test_cd.py", "tests": "tests/unit/test_cd.py::test_b"}}


def test_update_scales_a_measure_to_today_s_rounds(tree, tmp_path, monkeypatch):
    """A measure made in two rounds, of a target that has one today (L2): half of it is what the
    gate will take; one made in today's rounds (the result says it) is taken as it is."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_a.py": _PLAIN})
    path = tmp_path / "durations.json"
    _shard_json(tmp_path / "old" / "m", "m", seconds={"M000": 40.0})                  # before CI10a: 2 rounds
    assert mc.update_durations([tmp_path / "old"], path, say=lambda *a, **k: None) == 0
    assert json.loads(path.read_text())["mutants"] == {"M000": 20}
    doc = json.loads((tmp_path / "old" / "m" / "m.json").read_text())
    doc |= {"seconds": {"M001": 9.0}, "mutant_rounds": {"M001": 1},
            "mutant_targets": {"M001": "tests/unit/test_a.py"}}
    (tmp_path / "new" / "m").mkdir(parents=True)
    (tmp_path / "new" / "m" / "m.json").write_text(json.dumps(doc))
    assert mc.update_durations([tmp_path / "new"], path, say=lambda *a, **k: None) == 0
    assert json.loads(path.read_text())["mutants"] == {"M000": 20, "M001": 9}


def test_update_drops_a_measure_on_another_target(tree, tmp_path, monkeypatch):
    """A mutant narrowed since (L1): its measure on the whole file is no measure of it — it goes,
    and the one the file kept with it; the estimate weighs it until the gate measures it."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_a.py": _PLAIN})
    monkeypatch.setitem(mc.TESTS, "M002", "tests/unit/test_a.py::test_x")
    monkeypatch.setattr(mc, "WHOLE", {"M002": "tests/unit/test_a.py"})
    path = tmp_path / "durations.json"
    path.write_text(json.dumps({"mutants": {"M002": 300, "M003": 12}, "targets": {}}))
    _shard_json(tmp_path / "old" / "m", "m", seconds={"M002": 280.0, "M003": 10.0})
    assert mc.update_durations([tmp_path / "old"], path, say=lambda *a, **k: None) == 0
    assert json.loads(path.read_text())["mutants"] == {"M003": 10}
    doc = json.loads((tmp_path / "old" / "m" / "m.json").read_text())
    doc |= {"mutant_targets": {"M002": "tests/unit/test_a.py::test_x", "M003": "tests/unit/test_gone.py"},
            "mutant_rounds": {"M002": 1}}
    (tmp_path / "new" / "m").mkdir(parents=True)
    (tmp_path / "new" / "m" / "m.json").write_text(json.dumps(doc))
    assert mc.update_durations([tmp_path / "new"], path, say=lambda *a, **k: None) == 0
    assert json.loads(path.read_text())["mutants"] == {"M002": 280}


def _jobs(workflow: str) -> dict:
    """{job id: its definition}, of a workflow of this tree."""
    import yaml
    return yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8"))["jobs"]


# CI10b (#581, review of CI10a): the gate's invariant jobs, which prove the base the shards skip.
GATE_INVARIANTS = ("invariants-azure", "invariants-rest")


def _covers(pytest_run: list[str], machine: str) -> bool:
    """Whether one pytest command runs `machine`: named, or under `tests/`, and never taken out of it
    by a `--deselect` or an `--ignore` (in either of their spellings)."""
    removed = any(a.startswith(("--ignore", "--deselect")) and machine in a
                  or a in ("--ignore", "--deselect") and i + 1 < len(pytest_run) and machine in pytest_run[i + 1]
                  for i, a in enumerate(pytest_run))
    return not removed and (machine in pytest_run or "tests/" in pytest_run
                            or any(machine.startswith(a) and a.endswith("/") for a in pytest_run))


def test_a_shard_leaves_the_machines_only_to_a_gate_that_runs_them():
    """L3 is the gate's alone: a workflow whose shards skip the machines' unmutated run
    (`--skip-machine-baseline`, sought in the whole text of every job, never the `run` of two alone)
    has its total wait for both invariant jobs (`invariants-azure`, `invariants-rest`: CI10b), each
    at 500 sequences at least, and every machine of the tree run by one of them — never taken out by
    a `--deselect` or an `--ignore` in both. The Monday measure has no such job: the flag is nowhere
    in it (review of CI10a)."""
    import yaml
    machines = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "tests").rglob("test_*.py")
                      if mc.MACHINE.search(p.read_text(encoding="utf-8")))
    assert machines == ["tests/unit/test_invariants.py", "tests/unit/test_invariants_aws.py"]
    gate = _jobs("release-gate.yml")
    if any("--skip-machine-baseline" in yaml.safe_dump(spec) for spec in gate.values()):
        needs = gate["gate"].get("needs") or []
        assert set(GATE_INVARIANTS) <= set(needs), needs
        runs = []
        for name in GATE_INVARIANTS:
            steps = [s for s in gate[name]["steps"] if "-m pytest" in str(s.get("run") or "")]
            assert steps, name
            for step in steps:
                env = {**(gate[name].get("env") or {}), **(step.get("env") or {})}
                budget = str(env.get("GLORFINDEL_INVARIANT_EXAMPLES", ""))
                assert budget.isdigit() and int(budget) >= 500, (name, budget)
                runs += [line.split() for line in str(step["run"]).splitlines() if "-m pytest" in line]
        for machine in machines:
            assert any(_covers(run, machine) for run in runs), (machine, runs)
    for spec in _jobs("mutants.yml").values():
        assert "--skip-machine-baseline" not in yaml.safe_dump(spec)


@pytest.mark.parametrize("run, machine, covered", [
    (["python", "-m", "pytest", "tests/"], "tests/unit/test_invariants.py", True),
    (["python", "-m", "pytest", "tests/", "--ignore=tests/unit/test_invariants.py"], "tests/unit/test_invariants.py",
     False),
    (["python", "-m", "pytest", "tests/", "--ignore", "tests/unit/test_invariants.py"],
     "tests/unit/test_invariants.py", False),
    (["python", "-m", "pytest", "tests/unit/test_invariants.py", "--deselect",
      "tests/unit/test_invariants.py::test_isolation_invariants"], "tests/unit/test_invariants.py", False),
    (["python", "-m", "pytest", "tests/unit/test_invariants.py"], "tests/unit/test_invariants.py", True),
    (["python", "-m", "pytest", "tests/unit/test_invariants.py"], "tests/unit/test_invariants_aws.py", False),
    (["python", "-m", "pytest", "tests/unit/"], "tests/unit/test_invariants_aws.py", True),
])
def test_what_counts_as_running_a_machine(run, machine, covered):
    assert _covers(run, machine) is covered


# ── CI10a, review: the races on real threads, the control set, narrow's own copies ───────────

_THREADS = '''import threading


def _two_at_once(f):
    ts = [threading.Thread(target=f) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]


class _Beside:
    def __init__(self):
        self.t = threading.Thread(target=lambda: None, daemon=True)


def test_plain():
    assert True


def test_threads_itself():
    t = threading.Thread(target=lambda: None)
    t.start()
    t.join()


def test_through_a_helper():
    _two_at_once(lambda: None)


def test_through_a_class():
    _Beside()
'''


def test_a_target_whose_test_starts_a_thread_keeps_its_rounds(monkeypatch, tmp_path):
    """A race on real threads draws no seed, yet a round may not see what the other does: a test
    that starts a thread or a process — itself, or through a function or a class of its file —
    keeps its rounds; the file's other tests do not. A target runs the tests it names, the file
    whole, or those whose names hold a word of its -k."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_t.py": _THREADS})
    m = ("M1", "bug", "code.py", "a", "b")
    f = "tests/unit/test_t.py"
    assert mc.racers(f) == {"test_threads_itself", "test_through_a_helper", "test_through_a_class"}
    assert mc.rounds_of(m, f"{f}::test_plain", 2) == 1
    for node in ("test_threads_itself", "test_through_a_helper", "test_through_a_class[x-1]"):
        assert mc.rounds_of(m, f"{f}::{node}", 2) == 2, node
    assert mc.rounds_of(m, f, 2) == 2                                     # the file whole
    assert mc.rounds_of(m, f"{f} -k plain", 2) == 1
    assert mc.rounds_of(m, f"{f} -k 'helper or plain'", 2) == 2


def test_the_races_on_this_tree_keep_their_rounds():
    """On the tree (the review's list): the stuck race (M1346), two isolations at once (M3550,
    M3553), the clients' eight threads, the runs channel's watchdog threads, the watch's thread
    in the action queue's tests keep their rounds. The sweep's lock (M3289) is checked by a spy
    on one thread: the same calls in the same order each time — one round."""
    m = ("M1", "bug", "code.py", "a", "b")
    for mid in ("M1346", "M3550", "M3553"):
        assert mc.rounds_of(m, mc.TESTS[mid], 2) == 2, mid
    for raced in ("tests/unit/test_glorfindel.py::test_ensure_clients_thread_safe_single_init",
                  "tests/unit/test_runs_channel.py", "tests/unit/test_action_queue_watch.py"):
        assert mc.rounds_of(m, raced, 2) == 2, raced
    assert mc.rounds_of(m, mc.TESTS["M3289"], 2) == 1


def test_the_control_set_keeps_its_rounds_whatever_its_target(tmp_path, monkeypatch):
    """The control set measures what the suite was never shaped to find: its rounds always, even
    on a target no chance moves — never because its targets happen to be machines."""
    _files(monkeypatch, tmp_path, {"tests/unit/test_plain.py": _PLAIN})
    monkeypatch.setattr(mc, "MUTANTS", [])
    monkeypatch.setattr(mc, "CONTROL", [("C1", "control", "code.py", "line 1\n", "LINE 1\n")])
    monkeypatch.setattr(mc, "TESTS", {"C1": "tests/unit/test_plain.py"})
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text(
        "line 1\n")))
    runs: list = []

    def run(copy, examples, show=False, target=mc.INVARIANTS):
        runs.append(copy.name)
        return copy.name != "base"
    monkeypatch.setattr(mc, "_run", run)
    out = tmp_path / "c.json"
    assert mc.main(["--control", "--rounds", "2", "--jobs", "1", "--json", str(out)]) == 0
    assert runs.count("C1") == 2 and json.loads(out.read_text())["mutant_rounds"] == {"C1": 2}
    assert mc.rounds_of(mc.CONTROL[0], "tests/unit/test_plain.py", 2, control=True) == 2


def test_narrow_copies_its_mutants_from_a_pristine_copy(tmp_path, monkeypatch):
    """`--narrow`: what the unmutated run wrote (a cache, a database) never reaches a mutant's
    copy — each is made of a pristine copy, as main() makes them."""
    mutants = [(f"M{i}", f"bug {i}", "code.py", "a\n", "b\n") for i in range(2)]
    monkeypatch.setattr(mc, "_copy_repo", lambda dest: (dest.mkdir(parents=True), (dest / "code.py").write_text("a\n")))
    seen: list = []

    def pytest_(copy, examples, target, *more):
        if copy.name == "base":
            (copy / ".hypothesis").mkdir()
            return type("P", (), {"returncode": 0, "stdout": ""})()
        seen.append((copy / ".hypothesis").exists())
        _junit(Path(more[0].split("=", 1)[1]), [("tests.unit.test_cd", "test_a", 1.0, "failure")])
        return type("P", (), {"returncode": 1, "stdout": ""})()
    monkeypatch.setattr(mc, "_pytest", pytest_)
    monkeypatch.setattr(mc, "_run", lambda copy, examples, show=False, target=mc.INVARIANTS: True)
    monkeypatch.setattr(mc, "MUTANTS", mutants)
    path = tmp_path / "narrowed.json"
    assert mc.narrow("tests/unit/test_cd.py", mutants, 60, 2, 1, path=path, say=lambda *a, **k: None) == 0
    assert seen == [False, False]
