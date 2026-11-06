"""BRO1 (#614): the bench's read identity, for the Claude session « Banc » alone — an application and
its principal, a certificate whose private key never enters Terraform, Log Analytics Reader on the
bench's workspace alone (infra/terraform/bench_reader.tf), and the script the session signs in and
queries with (scripts/bench_reader.py): a code session refused, the Banc session's variable wanted,
a short certificate, the operator's Azure identity never mixed in. M4420–M4424, measured by
tests/unit/test_bench_reader.py (the Terraform plan itself: infra/terraform/tests/bench_reader.tftest.hcl).
"""
SCRIPT = "scripts/bench_reader.py"
READER_TF = "infra/terraform/bench_reader.tf"
_TESTS = "tests/unit/test_bench_reader.py"

MUTANTS = [
    ("M4420", "a code session (EREGION_AGENT_SESSION) signs in as the bench's reader (BRO1)", SCRIPT,
     '    if env.get("EREGION_AGENT_SESSION"):\n', "    if False:\n"),
    ("M4421", "any session outside a worktree signs in as the reader: the Banc session's variable no longer "
     "wanted (BRO1)", SCRIPT,
     '    if env.get("EREGION_BANC_SESSION") != "1":\n', "    if False:\n"),
    ("M4422", "a certificate of a year, or ten: the reader no longer short-lived (BRO1)", SCRIPT,
     "    if not 1 <= days <= DAYS_MAX:\n", "    if days < 1:\n"),
    ("M4423", "the operator's AZURE_* and ARM_* reach az: his identity mixed into the reader's (BRO1)", SCRIPT,
     '    clean = {k: v for k, v in env.items() if not k.startswith(("AZURE_", "ARM_"))}\n',
     "    clean = dict(env)\n"),
    ("M4424", "the reader's role at the bench group's scope: every resource of the bench read, not its "
     "workspace alone (BRO1)", READER_TF,
     "  scope                = azurerm_log_analytics_workspace.celebrimbor.id\n",
     "  scope                = azurerm_resource_group.celebrimbor.id\n"),
]
TESTS = {f"M{n}": _TESTS for n in range(4420, 4425)}
