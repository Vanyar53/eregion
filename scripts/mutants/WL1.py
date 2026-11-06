"""WL1 (#595): bree's scheduled maintenance set aside from `sudo-privilege-escalation` in the bench's
client layer (infra/glorfindel-host/client_rules.bench.yaml) — one mutant per property the exclusion
holds: the command, its arguments, the account, no terminal, bree alone. Each one widens the
exclusion, and a sudo that must stay a card no longer makes one. M4265–M4269, measured by
tests/unit/test_bench_routine.py.

The drift of a copy (`base_sha256`, glorfindel/detection_rules.py `_drift`), after the review: a
stale copy set aside, the shipped rule in its place — more cards, never fewer. M4300–M4304, each
measured by the test of its property. Second review: a stale copy set aside only when the
shipped rule will load in its place; the retired field `base_query_sha256` refused. M4365–M4368."""
BENCH = "infra/glorfindel-host/client_rules.bench.yaml"
RULES = "glorfindel/detection_rules.py"
_TESTS = "tests/unit/test_bench_routine.py"

MUTANTS = [
    ("M4265", "the exclusion takes any command of one word, not the three of the cron (WL1)", BENCH,
     "|/usr/bin/journalctl --vacuum-time=14d)$",
     "|/usr/bin/journalctl --vacuum-time=14d|/\\S+)$"),
    ("M4266", "the exclusion no longer anchored at the end: `nginx -t; bash` set aside (WL1)", BENCH,
     "|/usr/bin/journalctl --vacuum-time=14d)$\")",
     "|/usr/bin/journalctl --vacuum-time=14d)\")"),
    ("M4267", "the exclusion takes any account, not celebrimbor alone (WL1)", BENCH,
     "@\"^ *celebrimbor : PWD=",
     "@\"^ *\\S+ : PWD="),
    ("M4268", "the exclusion takes a line with a terminal (TTY=) (WL1)", BENCH,
     "@\"^ *celebrimbor : PWD=",
     "@\"^ *celebrimbor : (TTY=[^ ;]+( ; | +))?PWD="),
    ("M4269", "the exclusion on every VM, not bree alone (WL1)", BENCH,
     "      | where not(Computer == \"vm-celebrimbor-bree\"\n"
     "            and _ResourceId endswith \"/resourcegroups/rg-celebrimbor/providers/microsoft.compute/"
     "virtualmachines/vm-celebrimbor-bree\"\n"
     "            and SyslogMessage matches regex",
     "      | where not(SyslogMessage matches regex"),
]
MUTANTS += [
    ("M4300", "the drift no longer read: a stale copy runs, unsaid (WL1)", RULES,
     "        elif (current := base_rule_sha256(base)) != sha:\n",
     "        elif False and (current := base_rule_sha256(base)) != sha:\n"),
    ("M4301", "a malformed fingerprint accepted: the copy loads, never compared (WL1)", RULES,
     "    if sha is not None and not _is_sha256(sha):\n", "    if False:\n"),
    ("M4302", "a stale copy said, but kept in place of the shipped rule: fewer cards (WL1)", RULES,
     "            names.append(name)          # the stale copy is not kept: the shipped rule loads\n",
     "            names.append(name)\n            kept.append(entry)\n"),
    ("M4303", "a copy whose base rule is gone dropped too: its technique no longer detected (WL1)", RULES,
     "            kept.append(entry)          # its base gone: the copy alone detects its technique\n",
     "            pass\n"),
    ("M4304", "the fingerprint of the base query alone: a change of the rule's other fields unseen (WL1)",
     RULES,
     "    canonical = json.dumps(rule, sort_keys=True,",
     "    canonical = json.dumps(rule.get(\"query\"), sort_keys=True,"),
]
MUTANTS += [
    ("M4365", "a stale copy set aside although the layer disables the shipped rule: nothing detects (WL1)",
     RULES, "            if not base.get(\"enabled\", True) or name in off:\n",
     "            if not base.get(\"enabled\", True):\n"),
    ("M4366", "a stale copy set aside although the release disables the shipped rule: nothing detects (WL1)",
     RULES, "            if not base.get(\"enabled\", True) or name in off:\n",
     "            if name in off:\n"),
    ("M4367", "a stale copy of a shipped rule that will not load dropped: nothing detects (WL1)", RULES,
     "                kept.append(entry)          # the shipped rule off: the copy alone detects its technique\n",
     "                pass\n"),
    ("M4368", "a copy with the retired base_query_sha256 loads, never compared (WL1)", RULES,
     "    if \"base_query_sha256\" in entry:\n", "    if False:\n"),
]
TESTS = {f"M{n}": _TESTS for n in range(4265, 4270)}
TESTS.update({
    "M4300": f"{_TESTS}::test_a_shipped_rule_changed_since_the_copy_sets_the_copy_aside_and_runs",
    "M4301": f"{_TESTS}::test_a_fingerprint_that_is_not_one_skips_the_copy_and_the_shipped_rule_loads",
    "M4302": f"{_TESTS}::test_a_shipped_rule_changed_since_the_copy_sets_the_copy_aside_and_runs",
    "M4303": f"{_TESTS}::test_a_base_rule_gone_since_the_copy_keeps_the_copy_and_says_it",
    "M4304": f"{_TESTS}::test_the_fingerprint_is_the_rule_not_its_layout",
    "M4365": f"{_TESTS}::test_a_stale_copy_whose_shipped_rule_would_not_load_keeps_running",
    "M4366": f"{_TESTS}::test_a_stale_copy_whose_shipped_rule_would_not_load_keeps_running",
    "M4367": f"{_TESTS}::test_a_stale_copy_whose_shipped_rule_would_not_load_keeps_running",
    "M4368": f"{_TESTS}::test_a_copy_with_the_retired_field_is_set_aside_and_the_shipped_rule_loads",
})
