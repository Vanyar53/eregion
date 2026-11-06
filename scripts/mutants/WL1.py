"""WL1 (#595): bree's scheduled maintenance set aside from `sudo-privilege-escalation` in the bench's
client layer (infra/glorfindel-host/client_rules.bench.yaml) — one mutant per property the exclusion
holds: the command, its arguments, the account, no terminal, bree alone. Each one widens the
exclusion, and a sudo that must stay a card no longer makes one.
M4265–M4269, measured by tests/unit/test_bench_routine.py."""
BENCH = "infra/glorfindel-host/client_rules.bench.yaml"
_TESTS = "tests/unit/test_bench_routine.py"

MUTANTS = [
    ("M4265", "the exclusion takes any command of one word, not the three of the cron (WL1)", BENCH,
     "|/usr/bin/journalctl --vacuum-time=14d)$",
     "|/usr/bin/journalctl --vacuum-time=14d|/\\S+)$"),
    ("M4266", "the exclusion no longer anchored at the end: `nginx -t; bash` set aside (WL1)", BENCH,
     "|/usr/bin/journalctl --vacuum-time=14d)$\")",
     "|/usr/bin/journalctl --vacuum-time=14d)\")"),
    ("M4267", "the exclusion takes any account, not celebrimbor alone (WL1)", BENCH,
     "@\"^ *celebrimbor : PWD=",
     "@\"^ *\\S+ : PWD="),
    ("M4268", "the exclusion takes a line with a terminal (TTY=) (WL1)", BENCH,
     "@\"^ *celebrimbor : PWD=",
     "@\"^ *celebrimbor : (TTY=[^ ;]+( ; | +))?PWD="),
    ("M4269", "the exclusion on every VM, not bree alone (WL1)", BENCH,
     "      | where not(Computer == \"vm-celebrimbor-bree\"\n"
     "            and _ResourceId endswith \"/resourcegroups/rg-celebrimbor/providers/microsoft.compute/"
     "virtualmachines/vm-celebrimbor-bree\"\n"
     "            and SyslogMessage matches regex",
     "      | where not(SyslogMessage matches regex"),
]
TESTS = {f"M{n}": _TESTS for n in range(4265, 4270)}
