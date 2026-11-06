"""B3a (#609): a deterministic floor in the decision — a brute force the correlation saw succeed,
then a sudo to root, on the same VM, and `decide` proposes at least isolate_vm. M4375–M4379,
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
