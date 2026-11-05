"""CI6d (#545): the release gate's shards cut on the durations measured — each mutant weighed by its
measure, each piece by its target's unmutated run, a heavy target cut by its weight, the estimate
only for what was never measured (M3790–M3793); a shard's --json says each mutant's seconds and each
target's (M3794, M3795); the durations' file takes each smallest measure, of this tree only, at the
gate's budget (M3796–M3798); a shard's pools take the heaviest first (M3799).
"""
HARNESS = "scripts/mutation_check.py"
_SH = "tests/unit/test_mutation_shards.py::"

MUTANTS = [
    ("M3790", "the shards cut on the estimate again: the mutants' measures never read (CI6d, the defect back)",
     HARNESS,
     '    measured, runs = durations.get("mutants") or {}, durations.get("targets") or {}\n',
     '    measured, runs = {}, durations.get("targets") or {}\n'),
    ("M3791", "a piece weighed without its target's unmutated run: a third of a shard unseen (CI6d)", HARNESS,
     "        pieces += [(unmutated[target] + load[j], target, j, parts[j]) for j in range(p)]\n",
     "        pieces += [(load[j], target, j, parts[j]) for j in range(p)]\n"),
    ("M3792", "a mutant never measured weighs nothing: a new lot's mutants all in one shard (CI6d)", HARNESS,
     "        guess = statistics.median(known) if known else estimate\n",
     "        guess = 0.0\n"),
    ("M3793", "a target never cut, whatever its weight: test_host_cd.py's quarter of the whole in one shard "
              "(CI6d)", HARNESS,
     "        p = max(1, min(len(ids), math.ceil(work / cap))) if cap > 0 else 1\n",
     "        p = 1\n"),
    ("M3794", "a shard's --json without each mutant's seconds: the durations never measured again (CI6d)",
     HARNESS,
     '            "seconds": {mid: round(seconds[mid], 1) for mid in sorted(seconds)},\n', ""),
    ("M3795", "a shard's --json without its targets' unmutated runs: their weight guessed for ever (CI6d)",
     HARNESS,
     '            "targets": {t: round(ran[t][1], 1) for t in sorted(ran)}}, indent=1)',
     '            "targets": {}}, indent=1)'),
    ("M3796", "the durations take the last run read, not the smallest measure: a slow runner's shard weighs "
              "twice (CI6d)", HARNESS,
     "                        new[kind][key] = min(s, new[kind].get(key, s))\n",
     "                        new[kind][key] = s\n"),
    ("M3797", "the durations take any key a result holds: a mutant gone, a machine's path kept (CI6d)",
     HARNESS,
     "                    if key in known:\n", "                    if True:\n"),
    ("M3798", "the durations take a result at another budget: the Monday's 1 000 sequences for the gate's "
              "500 (CI6d)", HARNESS,
     "            if budget != DURATIONS_BUDGET:\n", "            if False:\n"),
    ("M3799", "a shard's mutants measured in the list's order: a 20 min one started last makes the tail (CI6d)",
     HARNESS,
     "            measured = list(pool.map(timed, heaviest_first(todo, mutant_cost, key=lambda m: m[0])))\n",
     "            measured = list(pool.map(timed, todo))\n"),
]
TESTS = {
    "M3790": f"{_SH}test_a_measured_mutant_outweighs_the_estimate {_SH}test_the_shards_weigh_each_mutant_by_its_measure",
    "M3791": f"{_SH}test_a_target_s_unmutated_run_is_weighed_once_per_piece",
    "M3792": f"{_SH}test_an_unmeasured_mutant_weighs_its_target_s_median_else_the_estimate",
    "M3793": f"{_SH}test_a_heavy_target_is_cut_by_its_weight_a_light_one_stays_whole",
    "M3794": f"{_SH}test_a_shard_s_json_says_each_mutant_s_seconds_and_each_target_s",
    "M3795": f"{_SH}test_a_shard_s_json_says_each_mutant_s_seconds_and_each_target_s",
    "M3796": f"{_SH}test_the_update_takes_each_smallest_measure_of_the_runs_given",
    "M3797": f"{_SH}test_the_update_keeps_what_was_not_measured_and_drops_what_the_tree_lost",
    "M3798": f"{_SH}test_the_update_counts_only_the_gate_s_budget",
    "M3799": f"{_SH}test_a_shard_runs_its_heaviest_first",
}
