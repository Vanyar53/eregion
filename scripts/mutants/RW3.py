"""RW3 (#575): the put-back of an isolation reads its effect again (`verify_isolation`), as a block's does —
a re-read that does not hold, or cannot be read, is a put-back that does not hold, said as such.
M4210–M4224, measured by tests/unit/test_reassert_reread.py."""
REASSERT = "glorfindel/reassert.py"
_TESTS = "tests/unit/test_reassert_reread.py"

MUTANTS = [
    ("M4210", "an isolation put back said from its write alone: a rule taken off at once « reposée une fois » (RW3)",
     REASSERT,
     "        reread = _reread_said(after)\n",
     '        reread = ""\n'),
    ("M4211", "a re-read that raises read as holds: « reposée une fois » of what nobody read (RW3)", REASSERT,
     "            after = connector.verify_isolation(rid)\n        except Exception as exc:\n"
     '            after = {"verified": None, "error": f"relecture impossible : {exc}"}\n',
     "            after = connector.verify_isolation(rid)\n        except Exception as exc:\n"
     '            after = {"verified": True}\n'),
    ("M4212", "a re-read that raises: its error left off the card (RW3)", REASSERT,
     "            after = connector.verify_isolation(rid)\n        except Exception as exc:\n"
     '            after = {"verified": None, "error": f"relecture impossible : {exc}"}\n',
     "            after = connector.verify_isolation(rid)\n        except Exception as exc:\n"
     '            after = {"verified": None, "error": "relecture impossible"}\n'),
    ("M4213", "an unreadable re-read (`verified` None) read as holds (RW3)", REASSERT,
     '    if verified is True:\n        return ""\n    after = after if',
     '    if verified is not False:\n        return ""\n    after = after if'),
    ("M4214", "an unreadable re-read said « ne tient pas », as if read (RW3)", REASSERT,
     "    if verified is not False:\n        named = ",
     "    if False:\n        named = "),
    ("M4215", "a bypass the re-read finds: no card of its own before the next pass (RW3)", REASSERT,
     '    if outcome == "partial" and reread:\n',
     "    if False:\n"),
    ("M4216", "the re-read's words dropped when the provider spoke (RW3)", REASSERT,
     '        short = " ; ".join(x for x in (_isolation_said(put), reread) if x)\n',
     "        short = _isolation_said(put) or reread\n"),
    ("M4217", "the provider's words dropped when the re-read spoke (RW3)", REASSERT,
     '        short = " ; ".join(x for x in (_isolation_said(put), reread) if x)\n',
     "        short = reread or _isolation_said(put)\n"),
    ("M4218", "the NICs the re-read finds without isolation left off the card (RW3)", REASSERT,
     '    parts = ["sans isolation : " + ", ".join(str(n) for n in after["uncovered_nics"])] if after.get(\n'
     '        "uncovered_nics") else []\n',
     "    parts = []\n"),
    ("M4219", "the re-read's reason (a bypass, a quarantine altered) left off the card (RW3)", REASSERT,
     "    if why:\n        parts.append(why)\n",
     "    if False:\n        parts.append(why)\n"),
    ("M4220", "the rules AWS's re-read finds altered left off the card (RW3)", REASSERT,
     '    elif after.get("missing_rules"):\n',
     "    elif False:\n"),
    ("M4221", "the NICs an unreadable re-read could not read left off the card (RW3)", REASSERT,
     '        named = ", ".join(str(n) for n in (after.get("unreadable_nics") or after.get("unknown") or []))\n',
     '        named = ""\n'),
    ("M4222", "AWS's reason for an unreadable re-read (`reason`, not `error`) left off the card (RW3)", REASSERT,
     '    why = str(after.get("error") or after.get("reason") or "").rstrip(". ")\n',
     '    why = str(after.get("error") or "").rstrip(". ")\n'),
    ("M4223", "the bypass card said from the check before the write, never from the re-read (RW3)", REASSERT,
     "        say_bypass(vm, rid, after, report, ref=ref)\n",
     "        say_bypass(vm, rid, verification, report, ref=ref)\n"),
    ("M4224", "a re-read that holds nothing it names said with empty brackets (RW3)", REASSERT,
     "    return f\"relue, elle ne tient pas ({' ; '.join(parts) or 'non vérifiée'})\"\n",
     "    return f\"relue, elle ne tient pas ({' ; '.join(parts)})\"\n"),
]
TESTS = {f"M{n}": _TESTS for n in range(4210, 4225)}
