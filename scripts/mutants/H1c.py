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
     "    counted = {n: _holding(by.get(n, [])) for n in BLOCKING}\n",
     "    counted = {n: _holding([r for k, rs in by.items() if k.startswith(n[:12]) for r in rs]) for n in BLOCKING}\n"),
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
    # After H1c's review (M3640–M3645): a name said as it came, a check that holds completed without
    # a green conclusion, two runs of one name, another app's runs, the second page.
    ("M3640", "a check's name said in #deploy as GitHub gave it: a link, a mention (SEC6, H1c)", CD,
     '    return re.sub(r"[^0-9A-Za-zÀ-ÿ .,()+‹›-]", "·", s)[:100]\n', "    return str(name)\n"),
    ("M3641", "a check that holds, completed without a green conclusion, taken for green: the CD fails open (H1c)",
     CD, '    if odd:\n        raise Refused(f"un check requis terminé', '    if False:\n        raise Refused(f"un check requis terminé'),
    ("M3642", "of two runs of one name, the first alone read: one still running beside it not waited for (H1c)", CD,
     '    for r in runs:\n        if r.get("status") != "completed":\n',
     '    for r in runs[:1]:\n        if r.get("status") != "completed":\n'),
    ("M3643", "another app's run, green, named as a required job, stands for it (H1c)", CD,
     "    return isinstance(app, dict) and app.get(\"slug\") == ACTIONS_APP\n", "    return True\n"),
    ("M3644", "another app's run named as a required job, red, no longer holds the release (H1c)", CD,
     '    return [r for r in runs if _by_actions(r) or not (r.get("status") == "completed"\n'
     '                                                      and r.get("conclusion") in GREEN)]\n',
     "    return [r for r in runs if _by_actions(r)]\n"),
    ("M3645", "the check runs' first page alone read: a required one red on page 2 unseen (H1c)", CD,
     "    for page in range(1, 11):\n", "    for page in range(1, 2):\n"),
]
TESTS = {f"M{n}": _TESTS for n in [*range(3610, 3620), *range(3640, 3646)]}
