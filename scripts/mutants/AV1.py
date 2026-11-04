"""AV1 (#524): `annatar validate` says a failure by its exit code — one invalid scenario exits 1
with its cause, --all exits 1 as soon as one is invalid and lists them, all valid: 0; an empty
file or a YAML that is no mapping is a scenario said invalid, never a TypeError that stops --all.
M3650–M3654, measured by tests/unit/test_annatar_cli.py."""
CLI = "annatar/cli.py"
PARSER = "annatar/runner/parser.py"
_CLI_TESTS = "tests/unit/test_annatar_cli.py"

MUTANTS = [
    ("M3650", "an invalid scenario said, and validate exits 0: a CI that trusts it sees it good (AV1)", CLI,
     '        console.print(f"     {escape(err)}")\n    raise SystemExit(EXIT_SCENARIO_INVALID)\n',
     '        console.print(f"     {escape(err)}")\n'),
    ("M3651", "validate --all exits 0 with invalid scenarios (AV1)", CLI,
     '                console.print(f"  [red]FAIL[/red] {escape(rel)}")\n'
     "            raise SystemExit(EXIT_SCENARIO_INVALID)\n",
     '                console.print(f"  [red]FAIL[/red] {escape(rel)}")\n'),
    ("M3652", "validate --all fails without the list of the invalid ones (AV1)", CLI,
     "            for rel in invalid:\n"
     '                console.print(f"  [red]FAIL[/red] {escape(rel)}")\n',
     ""),
    ("M3653", "an empty scenario file a TypeError that stops validate --all before the others (AV1)",
     PARSER, "        if not isinstance(data, dict):\n", "        if False:\n"),
    ("M3654", "an invalid scenario's cause read as markup, said other than written (AV1)", CLI,
     '        console.print(f"     {escape(err)}")\n    raise SystemExit(EXIT_SCENARIO_INVALID)\n',
     '        console.print(f"     {err}")\n    raise SystemExit(EXIT_SCENARIO_INVALID)\n'),
]
TESTS = {
    "M3650": f"{_CLI_TESTS} -k test_validate_one_invalid_scenario_exits_1_and_says_why",
    "M3651": f"{_CLI_TESTS} -k test_validate_all_exits_1_when_one_is_invalid_and_lists_the_invalid_ones",
    "M3652": f"{_CLI_TESTS} -k test_validate_all_exits_1_when_one_is_invalid_and_lists_the_invalid_ones",
    "M3653": f"{_CLI_TESTS} -k test_validate_all_says_an_empty_or_list_file_and_goes_on_to_the_others",
    "M3654": f"{_CLI_TESTS} -k test_validate_says_the_cause_as_written_never_read_as_markup",
}
