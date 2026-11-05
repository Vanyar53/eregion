"""RW2 (#555): the reassertion of an isolation reads what its write answered — `verified`, `bypass` —
and RW1's follow-ups: the first time's own mark of a pair written partial (`partial_unsaid`), the
card of a write the provider said partial. M4110–M4119, measured by tests/unit/test_reassert_verified.py."""
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
     '    scopes = scopes[:1] if (pair or {}).get("later") else scopes ',
     '    scopes = scopes '),
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
     '        prev.pop("partial_unsaid", None) if not partial else None', '        None'),
    ("M4119", "a write the provider said partial, re-read whole: « une écriture a échoué » (RW2)", REASSERT,
     "_block_drift(ip, vm, after, said=True, partial=not errors)",
     "_block_drift(ip, vm, after, said=True)"),
]
TESTS = {f"M{n}": _TESTS for n in range(4110, 4120)}
