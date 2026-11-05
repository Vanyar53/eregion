"""CI6 (#514): the release gate measures every mutant, in shards (scripts/mutation_check.py).

One runner cannot measure 2 633 mutants at 500 sequences within any bound: the gate gives each
runner a shard (`--shard K/N`), each writes what it measured (`--json`), and `--total` says
whether the shards together measured each mutant of the tree once, at the budget given, then
holds the count to `--min-caught`. Here on mutants and results written by the test: no test
suite runs, nothing is copied but a file of the test's own.
"""
from __future__ import annotations

import importlib.util
import json
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

@pytest.mark.parametrize("n", [1, 2, 3, 7, 10])
def test_the_shards_measure_each_mutant_once(n):
    todo = _mutants(97)
    tests = _tests(todo)
    shards = [mc.shard_of(todo, k, n, tests) for k in range(1, n + 1)]
    ids = [m[0] for s in shards for m in s]
    assert sorted(ids) == sorted(m[0] for m in todo)          # each once, none lost
    for s in shards:
        assert s == [m for m in todo if m in s]                # in todo's order


def test_a_target_s_mutants_stay_together_up_to_a_chunk():
    """A target's unmutated run happens once per piece: its mutants are cut in pieces of CHUNK at
    most, never spread one by one."""
    todo = _mutants(40)
    tests = {m[0]: mc.INVARIANTS for m in todo[:20]} | {m[0]: "tests/unit/test_a.py" for m in todo[20:]}
    n = 6
    owners: dict[str, set] = {}
    for k in range(1, n + 1):
        for m in mc.shard_of(todo, k, n, tests):
            owners.setdefault(tests[m[0]], set()).add(k)
    assert len(owners[mc.INVARIANTS]) <= -(-20 // mc.CHUNK)
    assert len(owners["tests/unit/test_a.py"]) <= -(-20 // mc.CHUNK)


def test_the_heavy_targets_are_spread_across_the_shards():
    """A target that runs an invariant machine weighs HEAVY: they never all land in one shard."""
    todo = _mutants(60)
    tests = {m[0]: (f"tests/unit/test_invariants.py tests/unit/test_h{i}.py" if i < 12 else f"tests/unit/t{i}.py")
             for i, m in enumerate(todo)}
    heavy = [sum(1 for m in mc.shard_of(todo, k, 4, tests) if mc._heavy(tests[m[0]])) for k in range(1, 5)]
    assert sum(heavy) == 12 and max(heavy) - min(heavy) <= 1, heavy


def test_the_same_tree_gives_the_same_shards():
    todo = _mutants(50)
    tests = _tests(todo)
    assert [mc.shard_of(todo, k, 5, tests) for k in range(1, 6)] == [mc.shard_of(list(todo), k, 5, dict(tests))
                                                                      for k in range(1, 6)]


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


def _total(results, min_caught=8, shards=2, control_shards=2, examples=500, rounds=2):
    return mc.total(results, shards, control_shards, examples, rounds, min_caught)


def test_every_shard_there_every_mutant_once_the_count_held(world, capsys):
    _, _, results = world
    assert _total(results) == 0
    out = capsys.readouterr().out
    assert "mutants: 8/8 caught in every round" in out and "at least 8 wanted" in out
    assert "control: 4/4 caught in every round (said, not held)" in out and "✗" not in out


def test_fewer_caught_than_wanted_is_red(world, capsys):
    mutants, _, results = world
    _result(results / "mutants-1", "mutants-1", [_row(m, "SURVIVES") for m in mutants[0::2]], shard=1, shards=2)
    assert _total(results, min_caught=5) == 1
    assert _total(results, min_caught=4) == 0
    assert "M000  SURVIVES" in capsys.readouterr().out


def test_the_control_set_is_said_never_held(world, capsys):
    _, control, results = world
    _result(results / "control-1", "control-1", [_row(m, "SURVIVES") for m in control[0::2]], control=True,
            shard=1, shards=2)
    assert _total(results) == 0
    assert "control: 2/4 caught" in capsys.readouterr().out


def test_a_shard_missing_is_red(world, capsys):
    _, _, results = world
    (results / "mutants-2" / "mutants-2.json").unlink()
    assert _total(results, min_caught=0) == 1
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
    assert _total(results, min_caught=0) == 1
    out = capsys.readouterr().out
    assert "mutants: 1 never measured: M000" in out and "mutants: 1 not of this tree: M999" in out


@pytest.mark.parametrize("text", ["not json", "[]", '{"control": false}', '{"control": false, "shard": "x", '
                                  '"shards": 2, "rows": []}'])
def test_a_result_that_cannot_be_read_is_red(world, capsys, text):
    _, _, results = world
    (results / "mutants-1" / "mutants-1.json").write_text(text, encoding="utf-8")
    assert _total(results, min_caught=0) == 1
    assert "mutants-1.json: unreadable" in capsys.readouterr().out


def test_nothing_measured_is_red(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(mc, "MUTANTS", _mutants(3))
    monkeypatch.setattr(mc, "CONTROL", [])
    (tmp_path / "empty").mkdir()
    assert mc.total(tmp_path / "empty", 1, 1, 500, 2, 0) == 1


def test_equivalent_multi_host_and_stale_are_not_counted(world, capsys):
    mutants, _, results = world
    rows = [_row(mutants[0], "EQUIVALENT"), _row(mutants[2], "MULTI-HOST"), _row(mutants[4], "STALE"),
            _row(mutants[6])]
    _result(results / "mutants-1", "mutants-1", rows, shard=1, shards=2)
    assert _total(results, min_caught=5) == 0
    assert "mutants: 5/5 caught" in capsys.readouterr().out


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
    assert mc.main(["--total", str(out), "--shards", "3", "--control-shards", "0", "--examples", "500", "--rounds", "2",
                    "--min-caught", "5"]) == 0
    said = capsys.readouterr().out
    assert "mutants: 5/6 caught in every round" in said and "M3  SURVIVES" in said
    assert mc.main(["--total", str(out), "--shards", "3", "--control-shards", "0", "--examples", "500", "--rounds", "2",
                    "--min-caught", "6"]) == 1


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
    assert mc.main(["--rounds", "2", "--jobs", "2", "--json", str(out), "--min-caught", "1"]) == 1
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
