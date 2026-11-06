"""AL2 (#598): `restorepoint-by-unexpected-caller`, the sister of the snapshot rule, Azure
Backup excluded by its public application id, and it alone. M4280–M4289, one per property, all
measured by tests/unit/test_restore_points.py (the rule run as written through the KQL subset,
then the AzureActivityDetector and the RulePoller)."""
RULES = "glorfindel/rules/azure/detection_rules.yaml"
_TESTS = "tests/unit/test_restore_points.py"

_ID = "262044b1-e2ce-469f-a196-69ab7ada62d3"
_KEEP = "      | where AzureBackupLines == 0 or OtherLines > 0\n"
_MATCH = f'      | extend AzureBackup = CallerAppId =~ "{_ID}" or Caller =~ "{_ID}"\n'
_OPS = '          "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/RESTOREPOINTS/'

MUTANTS = [
    # ── Azure Backup's lines make no card ──
    ("M4280", "Azure Backup no longer excluded — a card at every backup (AL2)", RULES,
     _KEEP, ""),
    ("M4281", "the exclusion read on the operation's latest line only — a backup whose Success line "
              "carries neither Claims nor Caller makes a card (AL2)", RULES,
     _KEEP, "      | where not(AzureBackup)\n"),
    ("M4282", "Azure Backup matched by its Caller only — its id in Claims makes a card (AL2)", RULES,
     _MATCH, f'      | extend AzureBackup = Caller =~ "{_ID}"\n'),

    # ── anyone else makes a card: the exclusion is Azure Backup alone ──
    ("M4283", "every application excluded, not Azure Backup alone — another principal's restore point "
              "makes no card (AL2)", RULES,
     _MATCH, '      | extend AzureBackup = isnotempty(CallerAppId) and Caller !has "@"\n'),
    ("M4284", "a backup's correlation id hides anyone — the SAS URLs retrieved under the backup's own id "
              "(a client chooses it) make no card (AL2)", RULES,
     _KEEP, "      | where AzureBackupLines == 0\n"),

    # ── the operations read ──
    ("M4285", "RESTOREPOINTS/WRITE no longer read — a restore point made by hand is no card (AL2)", RULES,
     _OPS + 'WRITE",\n', ""),
    ("M4286", "RETRIEVESASURIS no longer read — the SAS URLs alone are no card (AL2)", RULES,
     _OPS + 'RETRIEVESASURIS/ACTION",\n', ""),

    # ── a failure makes no card: its latest line read ──
    ("M4287", "failures kept — an operation refused makes a card (AL2)", RULES,
     _KEEP + '      | where ActivityStatusValue !in~ ("Failure", "Failed")\n', _KEEP),

    # ── the card names the operation and the resource ──
    ("M4288", "the card loses its resource — _ResourceId no longer projected (AL2)", RULES,
     "                CallerAppId, CallerObjectId, _ResourceId, ResourceGroup, CorrelationId\n\n"
     "  # Notre propre identité surveillée (SID1, #409).",
     "                CallerAppId, CallerObjectId, ResourceGroup, CorrelationId\n\n"
     "  # Notre propre identité surveillée (SID1, #409)."),

    # ── the snapshot rule does not change ──
    ("M4289", "the snapshot rule extended to restore points instead of a sister rule (AL2)", RULES,
     '          "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION")\n',
     '          "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",\n'
     '          "MICROSOFT.COMPUTE/RESTOREPOINTCOLLECTIONS/RESTOREPOINTS/WRITE")\n'),
]

TESTS = {m[0]: _TESTS for m in MUTANTS}
