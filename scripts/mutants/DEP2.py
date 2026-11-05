"""DEP2 (#590): one package raised alone in the locks (`make lock UPGRADE_PACKAGE=…`), and kept there
by the next `make lock` (scripts/lock_flags.py). M4245–M4249, measured by
tests/unit/test_dependency_lock.py.
"""
_FLAGS = "scripts/lock_flags.py"
_LOCK = "tests/unit/test_dependency_lock.py::"

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
    ("M4248", "uv run when the flags of its lock could not be read: the lock written without its "
              "exceptions (DEP2)", "Makefile",
     "\tf=$$($(call LOCK_PKG,requirements/dev.txt)) && \\\n",
     "\tf=$$($(call LOCK_PKG,requirements/dev.txt)); \\\n"),
    ("M4249", "a misspelt UPGRADE_PACKAGE accepted: every lock rewritten, nothing raised (DEP2)", "Makefile",
     "\t@$(if $(UPGRADE_PACKAGE),python3 scripts/lock_flags.py held $(UPGRADE_PACKAGE) $(LOCKS))\n", ""),
]
TESTS = {
    "M4245": f"{_LOCK}test_the_date_a_lock_admits_a_package_at_is_passed_again_while_it_postdates_lock_date",
    "M4246": f"{_LOCK}test_the_date_a_lock_admits_a_package_at_is_passed_again_while_it_postdates_lock_date",
    "M4247": f"{_LOCK}test_upgrade_package_raises_it_only_in_the_locks_that_pin_it",
    "M4248": f"{_LOCK}test_make_lock_stops_when_a_lock_s_flags_cannot_be_read",
    "M4249": f"{_LOCK}test_make_lock_keeps_the_raised_package_and_refuses_an_unknown_one",
}
