"""BRO1 (#614): the bench's read identity, for the Claude session « Banc » alone — an application and
its principal, a certificate whose private key never enters Terraform, Log Analytics Reader on the
bench's workspace alone (infra/terraform/bench_reader.tf), and the script the session signs in and
queries with (scripts/bench_reader.py): a code session refused, the Banc session's variable wanted,
a short certificate whose end is posed, the operator's Azure identity never mixed in, the
certificate never shown by a failed plan. M4420–M4424, M4495–M4499, measured by
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
    ("M4495", "the Banc session without the reader's AZURE_CONFIG_DIR: a bare az in it reads the operator's "
     "~/.azure, his own sign-in (BRO1)", SCRIPT,
     "    if not cfg or Path(cfg).expanduser().resolve() != own.expanduser().resolve():\n", "    if False:\n"),
    ("M4496", "the certificate file no longer sensitive: a private key pasted beside it shown in clear by the "
     "precondition's diagnostic (BRO1)", READER_TF,
     'sensitive(try(file(pathexpand(var.bench_reader_certificate_file)), ""))',
     'try(file(pathexpand(var.bench_reader_certificate_file)), "")'),
    ("M4497", "no end_date posed: the identifier's end the API's (« typically around 2 years »), not the "
     "certificate's (BRO1)", READER_TF,
     "  end_date       = local.bench_reader_certificate_end\n", ""),
    ("M4498", "keygen writes no end: Terraform's plan stops, or poses an older one (BRO1)", SCRIPT,
     '        _write_private(d / "reader.end", f"{when}\\n".encode())\n', ""),
    ("M4499", "the Banc session launched from a shell where .envrc was sourced: its inherited secrets, ARM_* "
     "and GH_TOKEN left for a terraform, an SDK or a gh of the session (BRO1)", SCRIPT,
     "    if leaked:\n", "    if False:\n"),
]
TESTS = {**{f"M{n}": _TESTS for n in range(4420, 4425)}, **{f"M{n}": _TESTS for n in range(4495, 4500)}}
