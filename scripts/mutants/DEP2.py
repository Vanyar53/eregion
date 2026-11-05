"""DEP2 (#590): one package raised alone in the locks (`make lock UPGRADE_PACKAGE=…`), and kept there
by the next `make lock` (scripts/lock_flags.py). M4245–M4254, measured by
tests/unit/test_dependency_lock.py.
"""
_FLAGS = "scripts/lock_flags.py"
_LOCK = "tests/unit/test_dependency_lock.py::"
_STOPS = f"{_LOCK}test_make_lock_stops_at_the_lock_whose_flags_cannot_be_read"


def _line(lock: str) -> tuple[str, str]:
    """A lock's uv run whatever its flags gave: `&&` made `;`."""
    return (f"\tf=$$($(call LOCK_PKG,requirements/{lock})) && \\\n",
            f"\tf=$$($(call LOCK_PKG,requirements/{lock})); \\\n")


MUTANTS = [
    ("M4245", "a lock's own date for a package never passed again: the next make lock at the same LOCK_DATE "
              "takes oauthlib back to 4.0.0, silently (DEP2)", _FLAGS,
     "    kept = {n: d for n, d in exceptions(lock).items() if d > lock_date}\n",
     "    kept = {}\n"),
    ("M4246", "a package's date kept once LOCK_DATE has caught up: it caps the package below the day's "
              "resolution (DEP2)", _FLAGS,
     "exceptions(lock).items() if d > lock_date}\n", "exceptions(lock).items()}\n"),
    ("M4247", "the package raised in every lock: those that do not pin it get a new header, the "
              "injectors' image rebuilt for nothing (DEP2)", _FLAGS,
     "        if name not in held:\n            continue                                   # this lock is written again byte for byte\n",
     ""),
    ("M4248", "uv run when the flags of dev.txt could not be read: the lock written without its "
              "exceptions (DEP2)", "Makefile", *_line("dev.txt")),
    ("M4249", "a misspelt UPGRADE_PACKAGE accepted: every lock rewritten, nothing raised (DEP2)", "Makefile",
     "\t@python3 scripts/lock_flags.py held $(LOCKS)\n", ""),
    ("M4250", "uv run when the flags of glorfindel.txt could not be read: the image's lock written "
              "without its exceptions (DEP2, review)", "Makefile", *_line("glorfindel.txt")),
    ("M4251", "uv run when the flags of annatar.txt could not be read (DEP2, review)", "Makefile",
     *_line("annatar.txt")),
    ("M4252", "uv run when the flags of audit.txt could not be read (DEP2, review)", "Makefile",
     *_line("audit.txt")),
    ("M4253", "a header that is not uv's taken for one without exceptions: a change of uv's form, and the "
              "next make lock takes oauthlib back down (DEP2, review)", _FLAGS,
     "    if not _UV_HEADER.match(line):\n        raise SystemExit(",
     "    if not _UV_HEADER.match(line):\n        return {}\n        raise SystemExit("),
    ("M4254", "UPGRADE_PACKAGE expanded by make: a $(shell …) typed on the command line is run (DEP2, "
              "review)", "Makefile",
     "lock: export EREGION_UPGRADE_PACKAGE = $(value UPGRADE_PACKAGE)\n",
     "lock: export EREGION_UPGRADE_PACKAGE = $(UPGRADE_PACKAGE)\n"),
]
TESTS = {
    "M4245": f"{_LOCK}test_the_date_a_lock_admits_a_package_at_is_passed_again_while_it_postdates_lock_date",
    "M4246": f"{_LOCK}test_the_date_a_lock_admits_a_package_at_is_passed_again_while_it_postdates_lock_date",
    "M4247": f"{_LOCK}test_upgrade_package_raises_it_only_in_the_locks_that_pin_it",
    "M4248": _STOPS,
    "M4249": f"{_LOCK}test_make_lock_keeps_the_raised_package_and_refuses_an_unknown_one",
    "M4250": _STOPS,
    "M4251": _STOPS,
    "M4252": _STOPS,
    "M4253": f"{_LOCK}test_a_header_it_cannot_read_is_refused_never_taken_for_one_without_exceptions",
    "M4254": f"{_LOCK}test_what_the_operator_typed_is_never_run",
}
