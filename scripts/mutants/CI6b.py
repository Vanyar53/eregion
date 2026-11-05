"""CI6b (#538): ChromaDB's embedding model made ready once, by the harness, before any run in
parallel — never by each run, never not at all; a preparation that fails is said, and never stops
the runs nor catches a mutant, ChromaDB unable to start included (M3730–M3733, M3735); the gate's mutants and control set restore the
model's cache, as its invariants and ci.yml (M3734).
"""
HARNESS = "scripts/mutation_check.py"
_SH = "tests/unit/test_mutation_shards.py::"
_ONCE = f"{_SH}test_the_model_is_prepared_once_before_any_run_never_by_each"
_FAILS = f"{_SH}test_a_preparation_that_fails_is_said_and_the_runs_go_on_as_before"

MUTANTS = [
    ("M3730", "the model never prepared: the unmutated runs, at once, fetch it into one place again (CI6b, "
              "the defect back)", HARNESS,
     "        prepare_embedding_model()\n", ""),
    ("M3731", "the model prepared by each mutant's measure, in parallel, after the unmutated runs (CI6b)",
     HARNESS,
     ("        prepare_embedding_model()\n",
      "            mid, title, rel, old, new = mutant[:5]\n"),
     ("",
      "            mid, title, rel, old, new = mutant[:5]\n            prepare_embedding_model()\n")),
    ("M3732", "a preparation that fails stops the harness: no network, every shard red (CI6b)", HARNESS,
     "    except Exception as exc:          # said, never hidden, never a verdict\n",
     "    except ImportError as exc:        # said, never hidden, never a verdict\n"),
    ("M3733", "a preparation that fails says nothing: the runs' error unexplained (CI6b)", HARNESS,
     "    say(f\"ChromaDB's embedding model could not be prepared before the runs",
     "    (lambda *_, **__: None)(f\"ChromaDB's embedding model could not be prepared before the runs"),
    ("M3735", "chromadb there but unable to start (sqlite3 too old: a RuntimeError on import) crashes the "
              "harness, its failure unsaid (CI6b, review)", HARNESS,
     "    except Exception as exc:          # there, but it cannot start: chromadb 1.5.9 raises a RuntimeError\n"
     "        return _not_prepared(exc, say)   # on import when sqlite3 is too old (CI6b, review)\n", ""),
]
# The release gate's (.github/workflows/release-gate.yml): its mutants restore ChromaDB's model, as
# the invariants and ci.yml do (M3734).
GATE = ".github/workflows/release-gate.yml"
_CACHE = ("      - uses: actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25   # v5.1.0\n"
          "        with:\n          path: ~/.cache/chroma\n          key: chroma-onnx-v1\n\n")
MUTANTS += [
    ("M3734", "the gate's mutants without ChromaDB's model restored: each shard fetches it again (CI6b)", GATE,
     _CACHE + "      - name: Re-introduce each bug of the shard, run its tests\n",
     "      - name: Re-introduce each bug of the shard, run its tests\n"),
]
TESTS = {
    "M3734": "tests/unit/test_workflows.py::test_the_gate_s_test_runs_restore_chroma_s_model_as_ci_does",
    "M3730": _ONCE,
    "M3731": _ONCE,
    "M3732": f"{_FAILS} {_SH}test_a_failed_preparation_never_catches_a_mutant",
    "M3733": f"{_FAILS} {_SH}test_chromadb_that_cannot_start_is_said_never_raised",
    "M3735": f"{_SH}test_chromadb_that_cannot_start_is_said_never_raised",
}
