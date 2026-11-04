"""H1c (#518): the CD of H0 holds a release only on the checks the rule of main requires
(REQUIRED_CHECKS) and on the image it pulls (publish (glorfindel)); every other check is said,
once per tag and per check, in orange, never waited for, never a refusal. M3610–M3619.
"""
CD = "infra/glorfindel-host/cd/eregion_cd.py"
_TESTS = "tests/unit/test_host_cd.py"

MUTANTS = [
    ("M3610", "a check main does not require, red or cancelled (macOS without a runner), refuses again (H1c)", CD,
     "    red = [n for n, s in held.items() if s and s[0] in RED]\n",
     "    red = [n for n, s in {**held, **told}.items() if s and s[0] in RED]\n"),
    ("M3611", "a check main does not require, still running or queued, holds the release (H1c)", CD,
     "    running = [n for n, s in held.items() if s and not s[1]]\n",
     "    running = [n for n, s in {**held, **told}.items() if s and not s[1]]\n"),
    ("M3612", "a required check red or cancelled no longer refuses the release (H1c)", CD,
     "    if red:\n        raise Refused(f\"CI rouge sur", "    if False:\n        raise Refused(f\"CI rouge sur"),
    ("M3613", "a check named like a required one, by its start, taken for it (H1c)", CD,
     "    held = {n: _ci_state(by[n]) if n in by else None for n in BLOCKING}\n",
     "    held = {n: _ci_state([r for k, rs in by.items() if k.startswith(n[:12]) for r in rs])\n"
     "            if any(k.startswith(n[:12]) for k in by) else None for n in BLOCKING}\n"),
    ("M3614", "a check main does not require, red or cancelled, never said (H1c)", CD,
     "    if not check:\n        say_told(state, tag, commit, told)\n", ""),
    ("M3615", "a check main does not require, red, said again at every pass (H1c)", CD,
     '    new = [n for n, s in told.items() if s[0] in RED and f"ci-told {n}" not in said]\n',
     "    new = [n for n, s in told.items() if s[0] in RED]\n"),
    ("M3616", "a check main does not require, red, said with Jonathan's mention, as a refusal is (H1c)", CD,
     "publiée bloquent une release\", color=nd.ORANGE)\n",
     "publiée bloquent une release\", color=nd.ORANGE, alert=True)\n"),
    ("M3617", "a required check left out of the agent's list: red, it no longer refuses (H1c)", CD,
     'REQUIRED_CHECKS = ("lint + tests (py3.11)", "lint + tests (py3.12)", "terraform test (mock providers)",\n',
     'REQUIRED_CHECKS = ("lint + tests (py3.11)", "lint + tests (py3.12)",\n'),
    ("M3618", "a required check absent never waited for nor refused: only the image's is (H1c)", CD,
     "    for name in BLOCKING:\n        if held[name] is not None:\n",
     "    for name in (PUBLISH_CHECK,):\n        if held[name] is not None:\n"),
    ("M3619", "the dry run no longer shows what holds the release and what is only said (H1c)", CD,
     'pour que le CD la déploie.\\n{checks}", color=nd.GREEN', 'pour que le CD la déploie.", color=nd.GREEN'),
]
TESTS = {f"M{n}": _TESTS for n in range(3610, 3620)}
