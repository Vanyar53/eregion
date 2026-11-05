"""VM3b (#568): the follow-ups of VM3's second review — the catalog decides an atomic
scenario's probes (S1), T1053.003's revert waits on a probe, not on the call (S2), an
engine_args value never starts with '-' (S3), log_tamper's python3 set-aside tightened (S4).
M4100–M4109 and M4123–M4124 (review m1: the revert waits on root's crontab restored, not only
on the evil line gone), all measured by tests/unit/test_vm3b_suites.py."""
CATPY = "annatar/campaign/catalog.py"
ATOMIC = "annatar/engines/atomic.py"
ENGINE = "annatar/runner/engine.py"
RULES = "glorfindel/rules/azure/detection_rules.yaml"
CRON_SCN = "annatar/scenarios/azure/cron-persistence-atomic.yaml"
_TESTS = "tests/unit/test_vm3b_suites.py"

MUTANTS = [
    # ── S1: the catalog decides the probes ──
    ("M4100", "catalog_destructive no longer compares the probes — any verify passes as the catalog's (VM3b, S1)", CATPY,
     '        if seen is None or seen != _plain_probes(probes_of(entry.get("steady_state"))):',
     "        if seen is None:"),
    ("M4101", "probes compared by name only — a verify changed under its name passes (VM3b, S1)", CATPY,
     "    return json.dumps(probes, sort_keys=True, default=str)\n\n\ndef probes_of(",
     '    return json.dumps([p.get("name") if isinstance(p, dict) else p for p in probes])\n\n\ndef probes_of('),
    ("M4102", "the run's probes never reach the catalog — every atomic scenario unknown, R1's refused (VM3b, S1)", ENGINE,
     '                               probes=probes_of((getattr(scenario, "raw", None) or {})\n'
     '                                                 .get("steady_state")),\n',
     ""),

    # ── S2: the revert waits on a probe, not on the call ──
    ("M4103", "the revert runs once the cleanup's call passed, its probe ignored — root's crontab backup removed (VM3b, S2)", ENGINE,
     "            if not self._revert_gate(executor, probe, resolved):",
     "            if False:"),
    ("M4104", "a gate probe that raises is taken for a probe that held (VM3b, S2)", ENGINE,
     "            console.print(f\"[red]Probe {probe.get('name')} failed:[/red] {e}\")\n            return False",
     "            console.print(f\"[red]Probe {probe.get('name')} failed:[/red] {e}\")\n            return True"),
    ("M4105", "a revert step naming no probe of the scenario is no longer refused before the contract (VM3b, S2)", ENGINE,
     "            if not isinstance(gate, str) or gate not in names:",
     "            if False:"),
    ("M4106", "the adapter accepts a revert step with no requires_probe (VM3b, S2)", ATOMIC,
     "        if not isinstance(gate, str) or not gate.strip():",
     "        if False:"),
    ("M4107", "the cap no longer counts the probe each revert step waits on (VM3b, S2)", ENGINE,
     "            needed = self._atomic_calls_needed(len(probes)) + 2 * len(revert)",
     "            needed = self._atomic_calls_needed(len(probes)) + len(revert)"),
    ("M4123", "the cron revert waits on the evil line gone again — an emptied crontab loses its only copy (VM3b, m1)", CRON_SCN,
     "    requires_probe: root-crontab-restored",
     "    requires_probe: cron-entry-absent"),
    ("M4124", "the restored probe only checks a crontab is installed — an emptied one passes (VM3b, m1)", CRON_SCN,
     "crontab -l 2>/dev/null | cmp -s - /tmp/notevil;",
     "crontab -l >/dev/null 2>&1;"),

    # ── S3: no leading '-' in an engine_args value ──
    ("M4108", "an engine_args value may start with '-' — an option in an argument's place (VM3b, S3)", ATOMIC,
     '        if str(value).startswith("-"):   # VM3b: an option in an argument\'s place',
     '        if False:   # VM3b: an option in an argument\'s place'),

    # ── S4: log_tamper sets python3 aside as the interpreter only ──
    ("M4109", "log_tamper sets aside any exe that begins with /usr/bin/python3 (VM3b, S4)", RULES,
     '      | extend Python = Tamper and Exe matches regex @"^/usr/bin/python3(\\.[0-9]+)?$"',
     '      | extend Python = Tamper and Exe startswith "/usr/bin/python3"'),
]

TESTS = {m[0]: _TESTS for m in MUTANTS}
