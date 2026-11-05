"""RW2 (#555): the reassertion of an isolation reads what its write answered — `verified`, `bypass` —
and RW1's follow-ups: the first time's own mark of a pair written partial (`partial_unsaid`), the
card of a write the provider said partial. M4110–M4119, measured by tests/unit/test_reassert_verified.py.
Its review (M4125–M4134): a put-back that does not hold is put back once all the same, its isolation
time kept; the pair of an earlier pass has its own card and keeps its hour; an isolation left partial
says no pass reads it again."""
REASSERT = "glorfindel/reassert.py"
PERIMETERS = "glorfindel/reassert_perimeters.py"
STATE = "glorfindel/response/state.py"
_TESTS = "tests/unit/test_reassert_verified.py"

MUTANTS = [
    ("M4110", "an isolation's write read as written: AWS's `verified` False « reposée une fois » (RW2)", REASSERT,
     '    verified = put.get("verified", True)\n',
     "    verified = True\n"),
    ("M4111", "Azure's `bypass` not read: a deny behind an allow « reposée une fois », marked put back (RW2)",
     REASSERT,
     "        return f\"le fournisseur ne la relit pas entière ({named or 'non vérifiée'})\"\n    return named\n",
     "        return f\"le fournisseur ne la relit pas entière ({named or 'non vérifiée'})\"\n    return \"\"\n"),
    ("M4112", "an isolation put back that does not hold, not marked said: put back and said again every pass (RW2)",
     REASSERT,
     '    if outcome in ("partial", "failed"):\n',
     '    if outcome == "failed":\n'),
    ("M4113", "a pair written partial in an earlier pass: its VM's rules written later, in human_only too (RW2)",
     REASSERT,
     '    scopes, at = (scopes[:1], b.get("reasserted_at") or now) if later else (scopes, now)\n',
     '    scopes, at = (scopes, b.get("reasserted_at") or now) if later else (scopes, now)\n'),
    ("M4114", "the first time writes a pair partial without its own mark: the pass cut off, never said (RW2)",
     PERIMETERS,
     '                    _update_block_entry(ref, ip, partial_unsaid=short)\n', '                    pass\n'),
    ("M4115", "the second time ignores the first time's mark: the entry held by the provider's `partial` (RW2)",
     REASSERT,
     '    if pair is None and b.get("scoped") is False and b.get("partial") and b.get("partial_unsaid"):\n',
     '    if False:\n'),
    ("M4116", "the first time's mark read without the provider's `partial`: a stale reason said (RW2)", REASSERT,
     '    if pair is None and b.get("scoped") is False and b.get("partial") and b.get("partial_unsaid"):\n',
     '    if pair is None and b.get("scoped") is False and b.get("partial_unsaid"):\n'),
    ("M4117", "the first time's mark never taken off with its card (RW2)", REASSERT,
     '            _update_block_entry(ref or vm, ip, partial_unsaid=None)\n', '            pass\n'),
    ("M4118", "a block written whole keeps the first time's mark of a write it supersedes (RW2)", STATE,
     '"drift_said", "reasserted_at", "partial_unsaid"):\n',
     '"drift_said", "reasserted_at"):\n'),
    ("M4119", "a write the provider said partial, re-read whole: « une écriture a échoué » (RW2)", REASSERT,
     "_block_drift(ip, vm, after, said=True, partial=not errors)",
     "_block_drift(ip, vm, after, said=True)"),
]
_REGRESSION = "tests/unit/test_invariant_regressions.py::test_a_reassertion_says_the_deny_it_kept_before_an_allow"
MUTANTS += [
    ("M4125", "a put-back keeps Azure's new `isolated_at`: the TTL counted from the put-back (RW2, review)", REASSERT,
     '        _save_isolation_state(ref or vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),\n'
     '                                   "reasserted_at": now})\n',
     '        _save_isolation_state(ref or vm, {**state, "reasserted_at": now})\n'),
    ("M4126", "a put-back that does not hold left unmarked: put back again at every episode (RW2, review)",
     REASSERT,
     '                                   "reasserted_at": now})\n',
     '                                   **({} if _isolation_said(put) else {"reasserted_at": now})})\n'),
    ("M4127", "an isolation left partial by its put-back: its card silent on no pass reading it again (RW2, review)",
     REASSERT,
     '            "isolation entière ou une levée.") if (_load_isolation_state(ref) or {}).get("partial") else ""\n',
     '            "isolation entière ou une levée.") if False else ""\n'),
    ("M4128", "every failed put-back said « ne la relit plus », partial or not (RW2, review)", REASSERT,
     '            "isolation entière ou une levée.") if (_load_isolation_state(ref) or {}).get("partial") else ""\n',
     '            "isolation entière ou une levée.") if True else ""\n'),
    ("M4129", "a pair of an earlier pass said « ses règles réécrites une fois », nothing written now (RW2, review)",
     REASSERT,
     '("sa règle de périmètre réécrite à la passe précédente" if later else "ses règles réécrites une fois")',
     '("sa règle de périmètre réécrite à la passe précédente" if False else "ses règles réécrites une fois")'),
    ("M4130", "a pair of an earlier pass rewrites `reasserted_at`: the first time's hour lost (RW2, review)",
     REASSERT,
     '    scopes, at = (scopes[:1], b.get("reasserted_at") or now) if later else (scopes, now)\n',
     '    scopes, at = (scopes[:1], now) if later else (scopes, now)\n'),
    ("M4131", "a pair of an earlier pass taken for one of this pass: written, in human_only too (RW2, review)",
     REASSERT,
     '    later = bool((pair or {}).get("later"))\n', '    later = False\n'),
    ("M4132", "the ENIs AWS names in `bypass` left off the card (RW2, review)", REASSERT,
     '    named = ", ".join(str(x) for x in bypass) if',
     '    named = "" if'),
    ("M4133", "an unreadable read-back said « ne la relit pas entière », as if read (RW2, review)", REASSERT,
     "    if verified is None:\n        return f\"le fournisseur n'a pas pu la relire",
     "    if False:\n        return f\"le fournisseur n'a pas pu la relire"),
    ("M4134", "a put-back behind an allow silent on the deny it kept, aimed at another VM (I4B, RW2 review)",
     REASSERT,
     '"`glorfindel release {rid} --yes` si la levée est voulue, sinon ré-isoler." + who + left)\n',
     '"`glorfindel release {rid} --yes` si la levée est voulue, sinon ré-isoler." + who)\n'),
]
TESTS = {f"M{n}": _TESTS for n in (*range(4110, 4120), *range(4125, 4134))}
TESTS["M4134"] = _REGRESSION
