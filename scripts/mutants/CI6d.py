"""CI6d (#545): the release gate's shards cut on the durations measured — each mutant weighed by its
measure, each piece by its target's unmutated run, a heavy target cut by its weight, the estimate
only for what was never measured (M3790–M3793); a shard's --json says each mutant's seconds and each
target's (M3794, M3795); the durations' file takes each smallest measure, of this tree only, at the
gate's budget (M3796–M3798); a shard's pools take the heaviest first (M3799). After its review: a
duration past a float, at 0 or above a day left out and said, never a crash nor a first shard of
everything; `--plan` of no shard refused (M3805–M3809).
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
     "        p = max(1, min(len(ids), math.ceil(work / cap))) if cap > 0 and math.isfinite(work / cap) else 1\n",
     "        p = 1\n"),
    ("M3794", "a shard's --json without each mutant's seconds: the durations never measured again (CI6d)",
     HARNESS,
     '            "seconds": {mid: round(seconds[mid], 1) for mid in sorted(seconds)},\n', ""),
    ("M3795", "a shard's --json without its targets' unmutated runs: their weight guessed for ever (CI6d)",
     HARNESS,
     '            "targets": {r: round(ran[r][1], 1) for r in sorted(ran)},\n',
     '            "targets": {},\n'),
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
     "        work = heaviest_first([(\"run\", r) for r in baselines] + [(\"mutant\", m[0]) for m in todo], cost)\n",
     "        work = [(\"run\", r) for r in baselines] + [(\"mutant\", m[0]) for m in todo]\n"),
]
_ENTRY = f"{_SH}test_an_entry_that_is_not_a_duration_is_left_out"
MUTANTS += [
    ("M3805", "an integer past a float's range in the durations: OverflowError, the shard stops (CI6d, review)",
     HARNESS, "    except OverflowError:             # an integer past a float's range (10**400)\n        return None\n",
     ""),
    ("M3806", "a duration at 0 taken for a measure: every mutant in the first shard (CI6d, review)", HARNESS,
     "    return value if math.isfinite(value) and 0 < value <= MAX_SECONDS else None\n",
     "    return value if math.isfinite(value) and 0 <= value <= MAX_SECONDS else None\n"),
    ("M3807", "no ceiling on a duration: 1e308 weighs, the sums run to inf (CI6d, review)", HARNESS,
     "    return value if math.isfinite(value) and 0 < value <= MAX_SECONDS else None\n",
     "    return value if math.isfinite(value) and 0 < value else None\n"),
    ("M3808", "a duration left out says nothing: the file's fault unseen (CI6d, review)", HARNESS,
     '    if left:\n        say(f"{where}: {left} {kind} not a duration',
     '    if False:\n        say(f"{where}: {left} {kind} not a duration'),
    ("M3809", "`--plan 0` taken: a division by zero, never said as a bad count (CI6d, review)", HARNESS,
     '    ap.add_argument("--plan", type=_positive, default=0, metavar="N",',
     '    ap.add_argument("--plan", type=int, default=0, metavar="N",'),
]
TESTS = {
    "M3805": _ENTRY,
    "M3806": f"{_ENTRY} {_SH}test_durations_at_zero_never_put_every_mutant_in_the_first_shard",
    "M3807": _ENTRY,
    "M3808": _ENTRY,
    "M3809": f"{_SH}test_a_plan_of_no_shard_is_refused_as_a_shard_is",
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
