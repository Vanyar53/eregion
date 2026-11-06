"""B3a (#609): a deterministic floor in the decision — a brute force the correlation saw succeed,
then a sudo to root, on the same VM, and `decide` proposes at least isolate_vm. M4375–M4379 and M4400–M4404,
measured by tests/unit/test_root_floor.py.
"""
AGENT = "glorfindel/agent.py"
_T = "tests/unit/test_root_floor.py"

MUTANTS = [
    ("M4375", "the confirming draws never floored: the draws disagree, the floored isolation held (B3a)",
     AGENT,
     "                floor=lambda x: _root_compromise_floor(x, signal, incident))",
     "                floor=None)"),
    ("M4376", "a model that already isolates told the floor raised it (B3a)", AGENT,
     '    if signal.get("event") != "detection" or d["action"] == "isolate_vm":\n'
     '        return ""\n'
     "    facts = set(confirmed_facts(signal))\n",
     '    if signal.get("event") != "detection":\n'
     '        return ""\n'
     "    facts = set(confirmed_facts(signal))\n"),
    ("M4377", "one fact enough: a brute force alone, or a sudo alone, isolates (B3a)", AGENT,
     "    if not {LOGIN_AFTER_BRUTE_FORCE, ROOT_ELEVATION} <= facts:\n",
     "    if not {LOGIN_AFTER_BRUTE_FORCE, ROOT_ELEVATION} & facts:\n"),
    ("M4378", "the incident of another VM read as this VM's (B3a)", AGENT,
     '    if incident and incident.get("resource_id", rid) == rid:\n',
     "    if incident:\n"),
    ("M4379", "failures the correlation never saw succeed counted as a login (B3a)", AGENT,
     '    if signal.get("ttp") == "T1110.001" and _is_compromise(signal):\n',
     '    if signal.get("ttp") == "T1110.001":\n'),
]
TESTS = {
    "M4375": f"{_T}::test_a_block_is_raised_to_isolate_vm_and_says_why {_T}::test_no_action_is_raised_to_isolate_vm",
    "M4376": f"{_T}::test_a_model_that_isolates_keeps_its_choice",
    "M4377": f"{_T}::test_a_brute_force_alone_keeps_the_models_choice {_T}::test_a_sudo_alone_keeps_the_models_choice",
    "M4378": f"{_T}::test_two_vms_keep_the_models_choice",
    "M4379": f"{_T}::test_neighbouring_signals_the_correlation_never_confirmed_keep_the_models_choice",
}

# The review of B3a (06/11): only a detection is floored, an action only a human approves is never
# lost, the reason fits the choice set aside, the harness's floor case is judged as an action.
SMOKE = "scripts/llm_smoke.py"
MUTANTS += [
    ("M4400", "a recovery_complete or a timeout floored: the release after a restore re-isolated (B3a)",
     AGENT,
     '    if signal.get("event") != "detection" or d["action"] == "isolate_vm":\n',
     '    if d["action"] == "isolate_vm":\n'),
    ("M4401", "the restore set aside by the floor never carded once the isolation ran (B3a)", AGENT,
     "    _record_displaced(state, source, exercise_run)\n", ""),
    ("M4402", "an action only a human approves replaced by the isolation, unsaid (B3a)", AGENT,
     "    if before in HUMAN_APPROVAL_REQUIRED:\n", "    if False:\n"),
    ("M4403", "« bloquer la source » said whatever the model chose (B3a)", AGENT,
     '    elif before == "block_suspicious_ip":\n', "    elif True:\n"),
    ("M4404", "the harness's floor case judged as a caution: the floor read as over-acting (B3a)", SMOKE,
     '    if sc["kind"] in ("act", "paired", "floor"):\n', '    if sc["kind"] in ("act", "paired"):\n'),
]
TESTS.update({
    "M4400": f"{_T}::test_only_a_detection_is_floored",
    "M4401": f"{_T}::test_an_action_only_a_human_approves_is_kept_on_a_card",
    "M4402": f"{_T}::test_an_action_only_a_human_approves_is_kept_on_a_card "
             f"{_T}::test_an_action_only_a_human_approves_is_said_when_the_cycle_escalates",
    "M4403": f"{_T}::test_the_reason_fits_the_choice_set_aside",
    "M4404": f"{_T}::test_the_harness_floor_case_passes_three_times_in_three",
})
