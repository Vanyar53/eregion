"""VM3 (#548): three attack/detection pairs on VM — T1053.003 (cron), T1059.004 (Unix shell),
T1070.002 (clear Linux logs). Each is a pinned Atomic Red Team test (red) and a shipped
detection rule (blue). M3840–M3859, all measured by tests/unit/test_vm3_pairs.py."""
CATALOG = "technique_catalog.yaml"
RULES = "glorfindel/rules/azure/detection_rules.yaml"
POLLER = "glorfindel/detection_rules.py"
AUDITD = "glorfindel/auditd.py"
PIN = "annatar/atomics/PIN"
MON = "infra/terraform/monitoring.tf"
VM3SH = "infra/terraform/scripts/vm3_auditd.sh"
_TESTS = "tests/unit/test_vm3_pairs.py"

MUTANTS = [
    # ── The catalog: three techniques turned implemented (red side present) ──
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
    ("M3845", "the shell atomic pings 8.8.8.8 again — an outbound dependency (VM3)", CATALOG,
     "          host: 127.0.0.1",
     "          host: 8.8.8.8"),
    ("M3846", "log clearing targets a real log, not a disposable path — state not restored (VM3)", CATALOG,
     "          log_path: /var/log/eregion-t1070-disposable.log",
     "          log_path: /var/log/secure"),

    # ── The blue side: the three detection rules ──
    ("M3847", "cron rule watches the daemon running jobs, not the crontab edit (VM3)", RULES,
     '      | where ProcessName == "crontab"',
     '      | where ProcessName == "CRON"'),
    ("M3848", "cron rule fires on any crontab line, a LIST read too (VM3)", RULES,
     '      | where SyslogMessage has "REPLACE" or SyslogMessage has "DELETE"',
     '      | where SyslogMessage has "root" or SyslogMessage has "DELETE"'),
    ("M3849", "log-tamper rule no longer excludes rsyslog — its own writes fire (VM3)", RULES,
     '      | where not(Comm in ("rsyslogd", "rsyslog", "systemd-journal", "systemd-journald",',
     '      | where not(Comm in ("systemd-journal", "systemd-journald",'),
    ("M3850", "log-tamper rule no longer excludes logrotate — rotation fires (VM3)", RULES,
     '                           "logrotate", "(logrotate)", "auditd", "systemd", "cron", "CRON",',
     '                           "auditd", "systemd", "cron", "CRON",'),
    ("M3851", "shell rule fires on a shell exec OR a /tmp arg, not both (VM3)", RULES,
     "      | where Shells > 0 and Tmp > 0",
     "      | where Shells > 0 or Tmp > 0"),
    ("M3852", "shell rule keys on /var, not world-writable /tmp — benign fires, attack missed (VM3)", RULES,
     '      | extend TmpArg = RecordType == "EXECVE" and (A1 startswith "/tmp/" or A1 startswith "/dev/shm/" or A1 startswith "/var/tmp/")',
     '      | extend TmpArg = RecordType == "EXECVE" and (A1 startswith "/var/" or A1 startswith "/dev/shm/" or A1 startswith "/var/tmp/")'),
    ("M3853", "shell rule keys on every exec but a shell — the attack is missed (VM3)", RULES,
     '      | extend ShellExec = RecordType == "SYSCALL" and Key == "shell_exec"',
     '      | extend ShellExec = RecordType == "SYSCALL" and Key != "shell_exec"'),

    # ── The poller: the human-root reading stays scoped to its one rule ──
    ("M3854", "the auditd human-root settle is applied to every T1059.004 rule again (VM3)", POLLER,
     "        if rule.name == auditd.RULE:\n            try:\n                rows, audit_n = auditd.settle(rule.ttp, rows, getattr(policy, \"sensitive_commands\", None) or ())",
     "        if rule.ttp == auditd.TTP:\n            try:\n                rows, audit_n = auditd.settle(rule.ttp, rows, getattr(policy, \"sensitive_commands\", None) or ())"),
    ("M3855", "the human-root rule name points at the shell rule — the human reading moves (VM3)", AUDITD,
     'RULE = "auditd-sensitive-root-command"',
     'RULE = "t1059-004-shell-from-world-writable"'),

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
]

TESTS = {f"M{n}": _TESTS for n in range(3840, 3860)}
