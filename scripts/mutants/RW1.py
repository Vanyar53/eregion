"""RW1 (#513): the reassertion of a block reads the status its write returns — AWS's `failed`
(nothing written) is a failure, its `partial` a put-back that does not hold, said on its card.
M3925–M3929, measured by tests/unit/test_reassert_status.py."""
REASSERT = "glorfindel/reassert.py"
PERIMETERS = "glorfindel/reassert_perimeters.py"
_TESTS = "tests/unit/test_reassert_status.py"

MUTANTS = [
    ("M3925", "the first time reads AWS's `failed` as written: its pair marked put back, never tried again (RW1)",
     PERIMETERS,
     '                    err, short = (why if status == "failed" else None), (why if status == "partial" else None)\n',
     '                    err, short = None, (why if status == "partial" else None)\n'),
    ("M3926", "the second time's write: its answer not read, a `failed` taken for rules rewritten (RW1)", REASSERT,
     "        if status:\n            failed(scope, why, errors if status == \"failed\" else short)\n",
     "        if status == \"partial\":\n            failed(scope, why, short)\n"),
    ("M3927", "a write the provider said partial, re-read whole: « reposé une fois », « Glorfindel alertera » (RW1)",
     REASSERT,
     "            reposed = not short ",
     "            reposed = True "),
    ("M3928", "the pair written partial by the first time: its entry held by its own mark, no card at all (RW1)",
     REASSERT,
     '    if _held_by_an_operation({**b, "partial": False} if (pair or {}).get("partial") else b,\n',
     "    if _held_by_an_operation(b,\n"),
    ("M3929", "an entry marked partial, no longer read by any pass: its card does not say so (RW1)", REASSERT,
     '    return (" Noté partiel par le fournisseur : la réaffirmation ne le relit plus avant un nouveau blocage "\n'
     '            "entier ou un déblocage.") if b.get("partial") else ""\n',
     '    return ""\n'),
]
TESTS = {f"M{n}": _TESTS for n in range(3925, 3930)}
