"""GS1 (#520): two starting guides replayed from zero, and make doctor — what a first start needs,
checked without the cloud nor the model (scripts/doctor.py), and the anchors of the docs a
newcomer follows (scripts/doc_anchors.py). M3620–M3629.

The form of a lot's file, as scripts/mutation_check.py loads it: MUTANTS, TESTS (its own ids),
optionally TESTS_ALSO and CONTROL; its paths as plain strings.
"""
DOCTOR = "scripts/doctor.py"
ANCHORS = "scripts/doc_anchors.py"
T = "tests/unit/test_doctor.py::"

MUTANTS = [
    ("M3620", "make doctor exits 0 with a check failed: a script chaining it goes on (GS1)", DOCTOR,
     "    return 1 if any(c.status == FAIL for c in checks) else 0",
     "    return 0"),
    ("M3621", "the model's key printed when it is there (GS1)", DOCTOR,
     """    return [Check(g, f"{provider} : {', '.join(keys)}", OK)]""",
     """    return [Check(g, f"{provider} : {', '.join(env.get(k, '') for k in keys)}", OK)]"""),
    ("M3622", "a value left from .envrc.example taken as filled (GS1)", DOCTOR,
     "    return bool(_EXAMPLE.fullmatch(value.strip()))",
     "    return False"),
    ("M3623", "a principal's pair half set taken as a principal (GS1)", DOCTOR,
     "    if have == (True, True):\n",
     "    if any(have):\n"),
    ("M3624", "the example's workspace placeholder taken as a workspace (GS1)", DOCTOR,
     "    good = [w for w in workspaces if w and w != WORKSPACE_PLACEHOLDER and _GUID.match(w)]",
     "    good = [w for w in workspaces if w]"),
    ("M3625", "a state directory docker made as root taken as the operator's (GS1)", DOCTOR,
     "    if st.st_uid != uid:\n",
     "    if False:\n"),
    ("M3626", "the console's port held by another program taken as the console (GS1)", DOCTOR,
     '    if any(name.endswith("-war-room") for name in names):',
     "    if True:"),
    ("M3627", "the watch's key in orodruin.env never checked: every run would be refused (GS1)", DOCTOR,
     "        good = bool(m) and len(base64.b64decode(m.group(1))) == 32",
     "        good = True"),
    ("M3628", "an anchor never compared with the headings of its file (GS1)", ANCHORS,
     '            if anchor not in anchors(dest.read_text(encoding="utf-8")):',
     "            if False:"),
    ("M3629", "docker without its daemon said to answer: `docker info --format` exits 0 (GS1, the replay)",
     DOCTOR,
     "r.returncode == 0 and r.stdout.strip()",
     "r.returncode == 0"),
]
TESTS = {
    "M3620": T + "test_one_failure_exits_1_and_says_the_command_that_fixes_it",
    "M3621": T + "test_no_value_is_ever_printed",
    "M3622": T + "test_the_values_of_envrc_example_are_refused_as_unfilled",
    "M3623": T + "test_a_half_pair_fails_and_the_watch_needs_its_principal",
    "M3624": T + "test_the_configuration_must_be_a_file_read_as_the_watch_reads_it",
    "M3625": T + "test_a_state_directory_not_the_operators_fails_with_its_fix",
    "M3626": T + "test_the_port_free_or_held_by_the_console_passes_anything_else_fails",
    "M3627": T + "test_the_bench_says_what_would_refuse_a_run",
    "M3628": "tests/unit/test_doc_anchors.py::test_a_link_to_a_missing_anchor_or_file_is_said",
    "M3629": T + "test_docker_without_its_daemon_fails_though_the_cli_exits_0",
}
