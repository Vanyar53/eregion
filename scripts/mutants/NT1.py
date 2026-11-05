"""NT1 (#583): the watch reads the never_target list (eregion_core/never_target.py) — docker-compose.yml
passes it to the watch alone, infra/glorfindel-host/host_env.py copies it into host.env and says,
writing and at `--check`, what it lacks, never refusing; no value it copies injects a line or a
quote into host.env (the review of febef45f). M4200–M4209 and M4230–M4234, measured by
tests/unit/test_glorfindel_host.py."""
COMPOSE = "docker-compose.yml"
HOST_ENV = "infra/glorfindel-host/host_env.py"
_HOST = "tests/unit/test_glorfindel_host.py::"
_ALONE = f"{_HOST}test_the_never_target_list_reaches_the_watch_alone"
_READABLE = f"{_HOST}test_host_env_carries_the_never_target_list_readable_to_the_watch"
_WRITES = f"{_HOST}test_host_env_says_a_missing_never_target_variable_and_still_writes"
_CHECK = f"{_HOST}test_check_says_a_missing_never_target_variable_without_refusing"
_TYPO = f"{_HOST}test_check_says_an_entry_that_is_no_object_id_never_its_value"
_INJECT = f"{_HOST}test_host_env_refuses_a_value_that_would_inject_into_host_env"

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
     "    return {k: model_value(env.get(k, \"\")) for k in NEVER_TARGET}\n",
     "    return {k: env.get(k, \"\") for k in NEVER_TARGET}\n"),
    # After the review of febef45f (a value injected into host.env): M4230–M4234.
    ("M4230", "a line break in a copied value written as is: a variable of its own in host.env, the "
     "signed queue switched on with a planted key (NT1 review)", HOST_ENV,
     'UNSAFE = {"\\n": "a line break", ',
     "UNSAFE = {"),
    ("M4231", "a carriage return in a copied value written as is (NT1 review)", HOST_ENV,
     '"\\r": "a carriage return", ',
     ""),
    ("M4232", "a quote in a copied value written as is: compose refuses the whole host.env, nothing "
     "starts on H0 (NT1 review)", HOST_ENV,
     ''', '"': "a quote", "'": "a quote"}\n''',
     "}\n"),
    ("M4233", "`--check` pushes a host.env whose value opens a quote it never closes (NT1 review)",
     HOST_ENV,
     "            if v[:1] in (\"\\\"\", \"'\") and v.find(v[0], 1) == -1:\n",
     "            if False:\n"),
    ("M4234", "the refusal of an injected value prints it: a secret pasted in the wrong line shown "
     "(NT1 review)", HOST_ENV,
     "raise SystemExit(f\"{k} holds {' and '.join(held)}: written",
     "raise SystemExit(f\"{k} holds {' and '.join(held)} ({v!r}): written"),
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
    "M4230": _INJECT,
    "M4231": _INJECT,
    "M4232": _INJECT,
    "M4233": f"{_HOST}test_check_refuses_a_quote_its_line_never_closes",
    "M4234": _INJECT,
}
