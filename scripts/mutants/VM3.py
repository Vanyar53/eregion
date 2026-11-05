"""VM3 (#548): three attack/detection pairs on VM — T1053.003 (cron), T1059.004 (Unix shell),
T1070.002 (clear Linux logs). Each is a pinned Atomic Red Team test (red) and a shipped
detection rule (blue). M3840–M3859 and M3930–M3939, all measured by tests/unit/test_vm3_pairs.py."""
CATALOG = "technique_catalog.yaml"
CATPY = "annatar/campaign/catalog.py"
SYNTH = "annatar/campaign/synthesizer.py"
ATOMIC = "annatar/engines/atomic.py"
ENGINE = "annatar/runner/engine.py"
RULES = "glorfindel/rules/azure/detection_rules.yaml"
POLLER = "glorfindel/detection_rules.py"
AUDITD = "glorfindel/auditd.py"
PIN = "annatar/atomics/PIN"
MON = "infra/terraform/monitoring.tf"
VM3SH = "infra/terraform/scripts/vm3_auditd.sh"
_TESTS = "tests/unit/test_vm3_pairs.py"

MUTANTS = [
    # ── The catalog: three techniques turned implemented, the destructive ones contained ──
    ("M3840", "cron (T1053.003) left planned, no red side (VM3)", CATALOG,
     '      - ttp: T1053.003\n        name: "Scheduled Task/Job: Cron"\n        tactic: persistence\n        status: implemented',
     '      - ttp: T1053.003\n        name: "Scheduled Task/Job: Cron"\n        tactic: persistence\n        status: planned'),
    ("M3841", "Unix shell (T1059.004) left planned (VM3)", CATALOG,
     '      - ttp: T1059.004\n        name: "Command and Scripting Interpreter: Unix Shell"\n        tactic: execution\n        status: implemented',
     '      - ttp: T1059.004\n        name: "Command and Scripting Interpreter: Unix Shell"\n        tactic: execution\n        status: planned'),
    ("M3842", "log clearing (T1070.002) left planned (VM3)", CATALOG,
     "        tactic: defense-evasion\n        status: implemented",
     "        tactic: defense-evasion\n        status: planned"),
    ("M3843", "log clearing not marked destructive — would run in production (VM3)", CATALOG,
     "        destructive: true           # efface un journal → ne se confine PAS à un volume",
     "        destructive: false           # efface un journal → ne se confine PAS à un volume"),
    ("M3844", "log clearing destructive without containment (VM3)", CATALOG,
     "        safe_target: sandbox_disposable   # garde-fou = scope allowlist (VM Celebrimbor jetable), pas un path",
     '        safe_target: ""   # garde-fou = scope allowlist (VM Celebrimbor jetable), pas un path'),

    # ── B1: the campaign plays the catalog's engine_args; B2: the catalog decides them ──
    ("M3845", "the synthesizer drops the catalog's engine_args — a campaign pings 8.8.8.8 (VM3, B1)", SYNTH,
     '        **({"engine_args": dict(engine_args)} if engine_args else {}),\n',
     ""),
    ("M3846", "catalog_destructive no longer compares engine_args — other values pass as harmless (VM3, B2)", CATPY,
     '        if own is None or own != _plain_args(entry.get("engine_args")):',
     "        if own is None:"),

    # ── The blue side: the three detection rules ──
    ("M3847", "cron rule watches the daemon running jobs, not the crontab edit (VM3)", RULES,
     '      | where ProcessName == "crontab"',
     '      | where ProcessName == "CRON"'),
    ("M3848", "cron rule fires on any crontab line, a LIST read too (VM3)", RULES,
     '      | where SyslogMessage has "REPLACE" or SyslogMessage has "DELETE"',
     '      | where SyslogMessage has "root" or SyslogMessage has "DELETE"'),
    ("M3849", "log-tamper rule no longer sets rsyslogd's exe aside — its own writes fire (VM3, C2)", RULES,
     '      | extend Daemon = Tamper and Exe in ("/usr/sbin/rsyslogd", "/usr/lib/systemd/systemd-journald",',
     '      | extend Daemon = Tamper and Exe in ("/usr/lib/systemd/systemd-journald",'),
    ("M3850", "log-tamper rule sets a session writer aside on any file — sshd on auth.log missed (VM3, C2)", RULES,
     "      | where not(Sessions > 0 and Entries > 0 and SessionFiles == Entries)",
     "      | where not(Sessions > 0)"),
    ("M3851", "shell rule fires on a shell exec OR a /tmp arg, not both (VM3)", RULES,
     "      | where Shells > 0 and Tmp > 0",
     "      | where Shells > 0 or Tmp > 0"),
    ("M3852", "shell rule keys on /var, not world-writable /tmp — benign fires, attack missed (VM3)", RULES,
     '      | extend TmpArg = RecordType == "EXECVE" and (A1 startswith "/tmp/" or A1 startswith "/dev/shm/" or A1 startswith "/var/tmp/")',
     '      | extend TmpArg = RecordType == "EXECVE" and (A1 startswith "/var/" or A1 startswith "/dev/shm/" or A1 startswith "/var/tmp/")'),
    ("M3853", "shell rule keys on every exec but a shell — the attack is missed (VM3)", RULES,
     '      | extend ShellExec = RecordType == "SYSCALL" and Key == "shell_exec"',
     '      | extend ShellExec = RecordType == "SYSCALL" and Key != "shell_exec"'),

    # ── C1: the human-root reading stays the default for every T1059.004 rule ──
    ("M3854", "the human-root settle bound to the shipped rule's name again — a client rule loses it (VM3, C1)", POLLER,
     "        if auditd.reads(rule.name, rule.ttp):\n            try:\n                rows, audit_n = auditd.settle(",
     '        if rule.name == "auditd-sensitive-root-command":\n            try:\n                rows, audit_n = auditd.settle('),
    ("M3855", "reads() ignores EXEMPT_RULES — the shell rule's rows become unreadable cards (VM3, C1)", AUDITD,
     "    return ttp == TTP and rule_name not in EXEMPT_RULES",
     "    return ttp == TTP"),

    # ── The red side's provenance, and the proposed telemetry ──
    ("M3856", "the cron atomic's pinned sha256 is wrong — a drifted file would be run (VM3)", PIN,
     "#   4830ac00380213b101a686458ddebdbf92757f5b68b285aab09cac909cac63ab  T1053.003/T1053.003.yaml",
     "#   4830ac00380213b101a686458ddebdbf92757f5b68b285aab09cac909cac63ac  T1053.003/T1053.003.yaml"),
    ("M3857", "the cron facility is never added to the DCR, even when asked (VM3)", MON,
     '      facility_names = concat(["auth", "authpriv", "syslog", "daemon"], var.auditd_enabled ? [local.auditd_facility] : [], var.cron_logs_enabled ? ["cron"] : [])',
     '      facility_names = concat(["auth", "authpriv", "syslog", "daemon"], var.auditd_enabled ? [local.auditd_facility] : [])'),
    ("M3858", "the proposed shell_exec audit rule no longer watches a shell (VM3)", VM3SH,
     "-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/dash -k shell_exec",
     "-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/false -k shell_exec"),
    ("M3859", "the proposed log_tamper watch reads /var/log instead of watching writes (VM3)", VM3SH,
     "-w /var/log -p wa -k log_tamper",
     "-w /var/log -p ra -k log_tamper"),

    # ── B2: _resolve_args holds what reaches a shell ──
    ("M3930", "an engine_arg the test does not declare is accepted (VM3, B2)", ATOMIC,
     "        if name not in declared:\n            raise AtomicError(",
     "        if not declared:\n            raise AtomicError("),
    ("M3931", "an engine_arg value is no longer held to plain characters — `; reboot` reaches the shell (VM3, B2)", ATOMIC,
     "                or not _ARG_VALUE.fullmatch(str(value)):",
     '                or not str(value):'),
    ("M3932", "engine_args that are no mapping are no longer refused — a crash, not a refusal (VM3, B2)", ATOMIC,
     "    if not isinstance(overrides, dict):",
     "    if isinstance(overrides, str):"),

    # ── B3: T1053.003 destructive; the revert removes what its cleanup leaves ──
    ("M3933", "T1053.003 not destructive — root's crontab replaced in production (VM3, B3)", CATALOG,
     "        # crontab /tmp/persistevil) et la rétablit depuis /tmp → altère l'état système, banc seulement.\n        destructive: true",
     "        # crontab /tmp/persistevil) et la rétablit depuis /tmp → altère l'état système, banc seulement.\n        destructive: false"),
    ("M3934", "catalog_destructive no longer compares the revert — any rm passes as the catalog's (VM3)", CATPY,
     '        if mine is None or mine != _plain_revert(entry.get("revert")):',
     "        if mine is None:"),
    ("M3935", "the scenario's revert is never run — /tmp/notevil and /tmp/persistevil left (VM3)", ENGINE,
     "                checks[\"revert\"] = self._run_revert(executor, revert, resolved) \\\n",
     "                checks[\"revert\"] = \"PASS\" \\\n"),
    ("M3936", "the revert runs after a failed cleanup — root's crontab backup removed (VM3)", ENGINE,
     '                    if checks.get("cleanup") == "PASS" else "SKIPPED"',
     '                    if checks.get("cleanup") else "SKIPPED"'),
    ("M3937", "a revert path outside /tmp is accepted — rm reaches /etc (VM3)", ATOMIC,
     "                    or not path.startswith(_REVERT_DIRS) or path in _REVERT_DIRS:",
     "                    or path in _REVERT_DIRS:"),
    ("M3938", "the synthesizer drops the catalog's revert — a campaign on cron ends dirty (VM3)", SYNTH,
     '        **({"revert": [dict(r) for r in revert]} if revert else {}),\n',
     ""),
    ("M3939", "a failed revert is taken for a clean run — the next one chained over its leftovers (VM3)", ENGINE,
     '        if checks.get("revert", "PASS") != "PASS":   # VM3: never chained over its leftovers',
     "        if False:   # VM3: never chained over its leftovers"),
]

TESTS = {m[0]: _TESTS for m in MUTANTS}
