"""CI10a (#580): the release gate, on the harness's side — the CI9 study's levers. One round where
no chance plays: a target keeps its rounds when a file of it imports Hypothesis, races (TIMED) or
when its mutant is TIMING (M4170–M4174). The invariant machines are the files that define one; the
gate's shards leave their unmutated run to its invariants job, the rest of a target still run
(`--skip-machine-baseline`, M4175–M4178); `--machines` measures their mutants only, and `--total
--machines` judges those only (M4179–M4181). The CD's mutants on the fastest tests that catch them
(scripts/mutants/narrowed.json, `--narrow`, M4182–M4185, M4189); the durations taken as today's
targets and rounds run them (M4186, M4187); the unmutated runs in the mutants' pool, in a copy of
their own (M4188).
"""
HARNESS = "scripts/mutation_check.py"
ANCHORS = "scripts/mutant_anchors.py"
_SH = "tests/unit/test_mutation_shards.py::"
_MA = "tests/unit/test_mutant_anchors.py::"

MUTANTS = [
    ("M4170", "a Hypothesis test taken for a deterministic one: a property test measured in one round (CI10a)",
     HARNESS,
     'DRAWS = re.compile(r"^\\s*(?:from\\s+hypothesis[\\s.]|import\\s+hypothesis\\b)", re.M)\n',
     'DRAWS = re.compile(r"^\\s*(?:from\\s+hypothesiz[\\s.]|import\\s+hypothesiz\\b)", re.M)\n'),
    ("M4171", "the process races of test_locks.py measured in one round: a race a round misses is a verdict "
              "(CI10a)", HARNESS,
     'TIMED = ("tests/unit/test_locks.py", "tests/unit/test_exercise.py")\n',
     'TIMED = ("tests/unit/test_exercise.py",)\n'),
    ("M4172", "a TIMING mutant measured in one round: the race its reason names, one chance only (CI10a)",
     HARNESS,
     '    return rounds if mark(mutant) == "TIMING" or chance(target) else min(rounds, 1)\n',
     '    return rounds if chance(target) else min(rounds, 1)\n'),
    ("M4173", "every target in all its rounds: the second replays the same test, the gate twice as long "
              "(CI10a, the cost back)", HARNESS,
     '    return rounds if mark(mutant) == "TIMING" or chance(target) else min(rounds, 1)\n',
     '    return rounds\n'),
    ("M4174", "main() measures each mutant in the rounds asked, its rule never read (CI10a)", HARNESS,
     "            rounds = rounds_of(mutant, target, args.rounds)\n",
     "            rounds = args.rounds\n"),
    ("M4175", "no file is a machine: --machines selects nothing, the gate's shards rerun the machines (CI10a)",
     HARNESS,
     '    return any(MACHINE.search(_source(f) or "") for f in files_of(target))\n',
     "    return False\n"),
    ("M4176", "--skip-machine-baseline taken and ignored: each shard reruns the machine at 500 (CI10a)",
     HARNESS,
     "        runs = {t: baseline_of(t, skip) for t in targets}\n",
     "        runs = {t: baseline_of(t) for t in targets}\n"),
    ("M4177", "a target holding a machine run unmutated not at all: its other tests never proved unmutated "
              "(CI10a)", HARNESS,
     '    kept = [w for w in target.split() if not (w.split("::")[0].endswith(".py") and machine(w))]\n',
     "    kept = [] if machine(target) else target.split()\n"),
    ("M4178", "the plan weighs the machines' runs the gate no longer makes: its shards cut on time not spent "
              "(CI10a)", HARNESS,
     "        run = baseline_of(target, skip)\n",
     "        run = baseline_of(target)\n"),
    ("M4179", "--machines measures every mutant: the Monday at 1 000 on all 3 000 (CI10a)", HARNESS,
     "    return [m for m in mutants if machine(TESTS.get(m[0], INVARIANTS))]\n",
     "    return list(mutants)\n"),
    ("M4180", "--total --machines asks every mutant: the others said never measured, red (CI10a)", HARNESS,
     "(False, shards, selected(MUTANTS, machines=machines)), (True, control_shards",
     "(False, shards, MUTANTS), (True, control_shards"),
    ("M4181", "a shard of every mutant read by --total --machines unsaid: two measures mixed in one count "
              "(CI10a)", HARNESS,
     '        if not control and bool(doc.get("machines")) != machines:\n',
     "        if False:\n"),
    ("M4182", "a narrowed entry applied to a mutant its lot moved: measured on tests of a file it no longer "
              "targets (CI10a)", HARNESS,
     '        if tests.get(mid) == entry["whole"]:\n',
     "        if True:\n"),
    ("M4183", "--narrow keeps tests that miss a round: a mutant caught at times taken for caught (CI10a)",
     HARNESS,
     "                if caught != rounds:\n",
     "                if caught == 0:\n"),
    ("M4184", "a test that errs on the mutant never counted as catching it: a mutant caught only so keeps "
              "the whole file (CI10a)", HARNESS,
     '        if not name or not any(c.tag in ("failure", "error") for c in case):\n',
     '        if not name or not any(c.tag == "failure" for c in case):\n'),
    ("M4185", "--narrow keeps the slowest catchers: the gain lost (CI10a)", HARNESS,
     '                tests = " ".join(node for _s, node in found[:NARROW])\n',
     '                tests = " ".join(node for _s, node in found[-NARROW:])\n'),
    ("M4186", "a measure in two rounds taken for one: a deterministic mutant weighed twice what it costs "
              "(CI10a)", HARNESS,
     "        out[mid] = s * r_now / r_then if ok else s\n",
     "        out[mid] = s\n"),
    ("M4187", "a measure on the whole file taken for the narrowed target's: the CD weighed as before (CI10a)",
     HARNESS,
     "        if then != today:\n",
     "        if False:\n"),
    ("M4188", "the mutants copied from the copy the unmutated runs write in: their database in each mutant's "
              "(CI10a)", HARNESS,
     "            shutil.copytree(pristine, copy)\n",
     "            shutil.copytree(unmutated_copy, copy)\n"),
    ("M4189", "a narrowed entry that no longer applies unsaid: its stale nodes checked as if they did "
              "(CI10a)", ANCHORS,
     "        if mid not in whole:\n",
     "        if False:\n"),
]
TESTS = {
    "M4170": f"{_SH}test_a_target_that_draws_keeps_its_rounds {_SH}test_the_rule_on_this_tree_keeps_the_rounds_where_chance_plays",
    "M4171": f"{_SH}test_a_target_that_races_keeps_its_rounds",
    "M4172": f"{_SH}test_a_timing_mutant_keeps_its_rounds",
    "M4173": f"{_SH}test_a_target_no_chance_moves_has_one_round",
    "M4174": f"{_SH}test_main_measures_a_deterministic_target_once",
    "M4175": f"{_SH}test_the_machines_are_the_files_that_define_one",
    "M4176": f"{_SH}test_skip_machine_baseline_leaves_the_machines_out_and_says_it",
    "M4177": f"{_SH}test_skip_machine_baseline_leaves_the_machines_out_and_says_it",
    "M4178": f"{_SH}test_a_plan_weighs_no_machine_run_left_to_the_gate",
    "M4179": f"{_SH}test_machines_selects_the_mutants_of_the_machines",
    "M4180": f"{_SH}test_total_machines_judges_those_only",
    "M4181": f"{_SH}test_total_machines_refuses_a_shard_measured_otherwise",
    "M4182": f"{_SH}test_a_narrowed_entry_applies_only_while_its_lot_targets_the_whole_file",
    "M4183": f"{_SH}test_narrow_keeps_the_fastest_catchers_caught_in_every_round",
    "M4184": f"{_SH}test_failures_of_reads_failures_and_errors_fastest_first",
    "M4185": f"{_SH}test_narrow_keeps_the_fastest_catchers_caught_in_every_round",
    "M4186": f"{_SH}test_update_scales_a_measure_to_today_s_rounds",
    "M4187": f"{_SH}test_update_drops_a_measure_on_another_target",
    "M4188": f"{_SH}test_unmutated_runs_write_nowhere_a_mutant_reads",
    "M4189": f"{_MA}test_a_narrowed_entry_that_no_longer_applies_or_names_a_lost_test_is_a_fault",
}
