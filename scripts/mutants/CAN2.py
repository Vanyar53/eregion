"""CAN2 (#605): the azurerm canary set aside from `nsg-change-outside-glorfindel` in the bench's client
layer (infra/glorfindel-host/client_rules.bench.yaml), by its group and its principal together; its
appid taken from the watch's environment (`env_guids`, glorfindel/detection_rules.py `_env_guids`),
a GUID or the shipped rule runs. One mutant per property, M4360–M4364, measured by
tests/unit/test_canary_exclusion.py; M4508–M4509, the exclusion read on the row as AL1d completes it."""
BENCH = "infra/glorfindel-host/client_rules.bench.yaml"
RULES = "glorfindel/detection_rules.py"
_TESTS = "tests/unit/test_canary_exclusion.py"

MUTANTS = [
    ("M4360", "the GUID never put in the query: the canary's runs in its group still make cards (CAN2)",
     RULES,
     "                query = query.replace(\"${\" + n + \"}\", v)\n",
     "                query = query\n"),
    ("M4361", "the exclusion takes any caller with an application, not the canary's principal alone (CAN2)",
     BENCH,
     " or Caller =~ \"${EREGION_RULE_CANARY_APPID}\")\n",
     " or Caller =~ \"${EREGION_RULE_CANARY_APPID}\" or isnotempty(CallerAppId))\n"),
    ("M4362", "the exclusion in every group, not rg-eregion-canary alone (CAN2)", BENCH,
     "      | where not(ResourceGroup =~ \"rg-eregion-canary\"\n"
     "            and _ResourceId matches regex @\"(?i)^/subscriptions/[0-9a-f-]+/resourcegroups/"
     "rg-eregion-canary/providers/\"\n"
     "            and (CallerAppId",
     "      | where not((CallerAppId"),
    ("M4363", "a variable absent put in as nothing: `=~ \"\"` sets aside a caller without appid (CAN2)",
     RULES,
     "        values = {n: env_guid(environ, n) for n in names}\n",
     "        values = {n: env_guid(environ, n) or \"\" for n in names}\n"),
    ("M4364", "any value of the variable put in the query, not a GUID alone: a KQL injection (CAN2)",
     RULES,
     "    return value.lower() if _GUID.fullmatch(value) else None\n",
     "    return value.lower() if value else None\n"),
    ("M4508", "the exclusion reads the caller any line names, not the row's: among two callers, a bare "
     "latest line set aside when one of them is the canary (CAN2, AL1d)", BENCH,
     "            and (CallerAppId =~ \"${EREGION_RULE_CANARY_APPID}\"",
     "            and (NamedCallerAppId =~ \"${EREGION_RULE_CANARY_APPID}\""),
    ("M4509", "the exclusion reads the latest line before its caller is completed: the canary's bare "
     "latest line makes a card (CAN2, AL1d)", BENCH,
     "      | extend Fill = not(Named) and Callers == 1\n",
     "      | extend Fill = false\n"),
]
TESTS = {
    "M4360": f"{_TESTS}::test_the_canary_in_its_group_makes_no_card",
    "M4361": f"{_TESTS}::test_another_caller_in_the_group_makes_a_card",
    "M4362": f"{_TESTS}::test_the_canary_elsewhere_makes_a_card",
    "M4363": f"{_TESTS}::test_the_variable_absent_or_invalid_sets_the_copy_aside_and_the_shipped_rule_runs",
    "M4364": f"{_TESTS}::test_the_variable_absent_or_invalid_sets_the_copy_aside_and_the_shipped_rule_runs",
    "M4508": f"{_TESTS}::test_a_bare_latest_line_among_two_callers_is_never_set_aside",
    "M4509": f"{_TESTS}::test_a_bare_latest_line_of_the_canary_alone_is_set_aside",
}
