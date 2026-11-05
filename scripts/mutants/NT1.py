"""NT1 (#583): the watch reads the never_target list (eregion_core/never_target.py) — docker-compose.yml
passes it to the watch alone, infra/glorfindel-host/host_env.py copies it into host.env and says,
writing and at `--check`, what it lacks, never refusing. M4200–M4209, measured by
tests/unit/test_glorfindel_host.py."""
COMPOSE = "docker-compose.yml"
HOST_ENV = "infra/glorfindel-host/host_env.py"
_HOST = "tests/unit/test_glorfindel_host.py::"
_ALONE = f"{_HOST}test_the_never_target_list_reaches_the_watch_alone"
_READABLE = f"{_HOST}test_host_env_carries_the_never_target_list_readable_to_the_watch"
_WRITES = f"{_HOST}test_host_env_says_a_missing_never_target_variable_and_still_writes"
_CHECK = f"{_HOST}test_check_says_a_missing_never_target_variable_without_refusing"
_TYPO = f"{_HOST}test_check_says_an_entry_that_is_no_object_id_never_its_value"

MUTANTS = [
    ("M4200", "the watch never receives the operator: on H0 its list is unreadable, every verb of an "
     "identity plan a human's step (#583, NT1)", COMPOSE,
     "      EREGION_OPERATOR_OBJECT_ID: ${EREGION_OPERATOR_OBJECT_ID:-}\n",
     ""),
    ("M4201", "the list handed to every container through x-env, the console, the bot (NT1)", COMPOSE,
     '  ORT_LOGGING_LEVEL_DEFAULT: "3"\n',
     '  ORT_LOGGING_LEVEL_DEFAULT: "3"\n  EREGION_OPERATOR_OBJECT_ID: ${EREGION_OPERATOR_OBJECT_ID:-}\n'),
    ("M4202", "the protected identities filled from another variable: Orodruin and H0 left targets (NT1)",
     COMPOSE,
     "      EREGION_PROTECTED_IDENTITIES: ${EREGION_PROTECTED_IDENTITIES:-}\n",
     "      EREGION_PROTECTED_IDENTITIES: ${EREGION_OPERATOR_OBJECT_ID:-}\n"),
    ("M4203", "the identity executor never reaches the watch's list: a plan may aim at it (NT1)", COMPOSE,
     "      EREGION_IDENTITY_EXECUTOR_CLIENT_ID: ${EREGION_IDENTITY_EXECUTOR_CLIENT_ID:-}\n",
     ""),
    ("M4204", "host_env.py never copies the list into host.env: H0's watch without it (NT1)", HOST_ENV,
     "          *NEVER_TARGET)\n",
     "          )\n"),
    ("M4205", "`--check` refuses a host.env without the list: the push of a whole watch blocked (NT1)",
     HOST_ENV,
     '        print(f"{dst}: {warning}", file=sys.stderr)\n',
     '        raise SystemExit(f"{dst}: {warning}")\n'),
    ("M4206", "an empty list never said, writing or at `--check`: every verb a human's step, unsaid (NT1)",
     HOST_ENV,
     "    return said\n",
     "    return []\n"),
    ("M4207", "an entry that is no object id not said: the watch's list unreadable, unsaid (NT1)",
     HOST_ENV,
     "        if bad:\n            said.append",
     "        if False:\n            said.append"),
    ("M4208", "the entry that is no object id printed: a secret pasted in the wrong line shown (NT1)",
     HOST_ENV,
     'said.append(f"⚠ {name} porte {len(bad)} entrée(s)',
     'said.append(f"⚠ {name} porte {bad} entrée(s)'),
    ("M4209", "`--check` reads the list with its quotes, unlike compose: a typo said that is none (NT1)",
     HOST_ENV,
     "never_target_warnings({k: model_value(env.get(k, \"\")) for k in NEVER_TARGET})",
     "never_target_warnings({k: env.get(k, \"\") for k in NEVER_TARGET})"),
]
TESTS = {
    "M4200": _ALONE,
    "M4201": _ALONE,
    "M4202": _READABLE,
    "M4203": _ALONE,
    "M4204": _READABLE,
    "M4205": _CHECK,
    "M4206": f"{_WRITES} {_CHECK}",
    "M4207": _TYPO,
    "M4208": _TYPO,
    "M4209": _CHECK,
}
