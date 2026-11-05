"""CI6b (#538): ChromaDB's embedding model made ready once, by the harness, before any run in
parallel — never by each run, never not at all; a preparation that fails is said, and never stops
the runs nor catches a mutant (M3730–M3733).
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
      "            mid, title, rel, old, new, *why = mutant\n"),
     ("",
      "            mid, title, rel, old, new, *why = mutant\n            prepare_embedding_model()\n")),
    ("M3732", "a preparation that fails stops the harness: no network, every shard red (CI6b)", HARNESS,
     "    except Exception as exc:          # said, never hidden, never a verdict\n",
     "    except ImportError as exc:        # said, never hidden, never a verdict\n"),
    ("M3733", "a preparation that fails says nothing: the runs' error unexplained (CI6b)", HARNESS,
     "    except Exception as exc:          # said, never hidden, never a verdict\n        say(",
     "    except Exception as exc:          # said, never hidden, never a verdict\n        (lambda *_, **__: None)("),
]
TESTS = {
    "M3730": _ONCE,
    "M3731": _ONCE,
    "M3732": f"{_FAILS} {_SH}test_a_failed_preparation_never_catches_a_mutant",
    "M3733": _FAILS,
}
