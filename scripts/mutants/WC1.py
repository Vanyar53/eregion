"""WC1 (#523): without H0, the watch of a workstation or a team writes Orodruin's return channel —
watch_principal_ids in infra/orodruin (by default H0's alone, at the addresses it had), passed by
`make orodruin-plan WATCH_PRINCIPALS=<id>[,<id>…]`, checked, never expanded by make. M3660–M3669.

The Terraform ones are caught by the files read (tests/unit/test_orodruin.py), their behaviour by
`terraform test` (infra/orodruin/tests/watch_writers.tftest.hcl); the Makefile's by running it
against a fake terraform (tests/unit/test_makefile_bench.py).
"""
TF = "infra/orodruin/main.tf"
TFVARS = "infra/orodruin/variables.tf"
MAKE = "Makefile"
_TF_TEST = "tests/unit/test_orodruin.py -k return_channel_is_written_by_the_listed_watches_only"
_MAKE_TEST = "tests/unit/test_makefile_bench.py"

MUTANTS = [
    ("M3660", "a workstation's watch writes the exercise windows: a real attack passes for an exercise (WC1)", TF,
     'resource "azurerm_role_assignment" "channel_station_watch_reader" {\n'
     "  for_each             = local.station_watches\n"
     "  scope                = azurerm_storage_container.exercises.id\n"
     '  role_definition_name = "Storage Blob Data Reader"\n',
     'resource "azurerm_role_assignment" "channel_station_watch_reader" {\n'
     "  for_each             = local.station_watches\n"
     "  scope                = azurerm_storage_container.exercises.id\n"
     '  role_definition_name = "Storage Blob Data Contributor"\n'),
    ("M3661", "a workstation's watch writes the whole channel account, not its container (WC1)", TF,
     'resource "azurerm_role_assignment" "watch_channel_station_writer" {\n'
     "  for_each             = local.station_watches\n"
     "  scope                = azurerm_storage_container.watch.id\n",
     'resource "azurerm_role_assignment" "watch_channel_station_writer" {\n'
     "  for_each             = local.station_watches\n"
     "  scope                = azurerm_storage_account.channel.id\n"),
    ("M3662", "Orodruin's own identity listed as a watch: an injector writes what the watch says (WC1)", TF,
     "      condition     = each.value != lower(azurerm_linux_virtual_machine.host.identity[0].principal_id)\n"
     '      error_message = "watch_principal_ids nomme l\'identité d\'Orodruin : un injecteur n\'écrit jamais ce que dit la watch."\n',
     "      condition     = true\n"
     '      error_message = "watch_principal_ids nomme l\'identité d\'Orodruin : un injecteur n\'écrit jamais ce que dit la watch."\n'),
    ("M3663", "watch_principal_ids takes what is no object id: a client id, a name, a path (WC1)", TFVARS,
     'can(regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", id))',
     "true"),
    ("M3664", "WATCH_PRINCIPALS expanded by make: a $(shell …) on the command line runs (WC1)", MAKE,
     "export EREGION_WATCH_PRINCIPALS = $(value WATCH_PRINCIPALS)\n",
     "export EREGION_WATCH_PRINCIPALS = $(WATCH_PRINCIPALS)\n"),
    ("M3665", "WATCH_PRINCIPALS not read whole: a list with a space, or one id among other text, passes (WC1)", MAKE,
     "grep -Eqx '$(ORO_GUID)(,$(ORO_GUID))*'", "grep -Eq '$(ORO_GUID)'"),
    ("M3666", "WATCH_PRINCIPALS names an identity twice: the second assignment fails at the apply (WC1)", MAKE,
     "| tr , '\\n' | sort | uniq -d)\" ]", "| tr , '\\n' | sort -u | uniq -d)\" ]"),
    ("M3667", "a WATCH_PRINCIPALS that leaves H0 out takes its channel away, unsaid (WC1, SEC7)", MAKE,
     '\t@if [ -n "$$EREGION_WATCH_PRINCIPALS" ] && [ "$(NO_WATCH)" != 1 ] \\\n',
     '\t@if [ -n "$$EREGION_WATCH_PRINCIPALS" ] && false \\\n'),
    ("M3668", "WATCH_PRINCIPALS taken from the environment: a shell's leftover names the channel's writers (WC1)",
     MAKE, '\t@case "$(origin WATCH_PRINCIPALS)" in environment*)', '\t@case "$(origin WATCH_PRINCIPALS)" in nowhere*)'),
    ("M3669", "watch_principal_ids unset no longer means H0: the bench's plan takes the channel from it (WC1)", TF,
     "watch_writers       = var.watch_principal_ids == null ? compact([lower(var.watch_principal_id)])",
     "watch_writers       = var.watch_principal_ids == null ? []"),
]
TESTS = {
    **{mid: _TF_TEST for mid in ("M3660", "M3661", "M3662", "M3663", "M3669")},
    **{mid: _MAKE_TEST for mid in ("M3664", "M3665", "M3666", "M3667", "M3668")},
}
