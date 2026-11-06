"""AL2 (#598): `restorepoint-by-unexpected-caller`, the sister of the snapshot rule, Azure
Backup excluded by its public application id, and it alone. M4280–M4289, one per property,
then M4305–M4309 after the first review (a line that names no one decides nothing, the id
matched whole, the case of an operation's name, one row per operation, an object id alone), and
M4390–M4392 after the second (the row carries the caller that decided it), M4410 after the
third (and its address), all
measured by tests/unit/test_restore_points.py (the rule run as written through the KQL subset,
then the AzureActivityDetector and the RulePoller)."""
RULES = "glorfindel/rules/azure/detection_rules.yaml"
_TESTS = "tests/unit/test_restore_points.py"

_ID = "262044b1-e2ce-469f-a196-69ab7ada62d3"
_KEEP = "      | where OtherLines > 0\n"
_GROUP = "          by CorrelationId, OperationNameValue, _ResourceId\n" + _KEEP
_BACKUP_LINES = "            , AzureBackupLines = countif(AzureBackup)\n"
_CARRY = ("      | extend Caller = iif(OtherCaller, Caller, NamedCaller),\n"
          "               CallerAppId = iif(OtherCaller, CallerAppId, NamedAppId),\n"
          "               CallerObjectId = iif(OtherCaller, CallerObjectId, NamedObjectId),\n"
          "               CallerIpAddress = iif(OtherCaller, CallerIpAddress, NamedIp)\n")
_OTHER = ('      | extend OtherCaller = not(AzureBackup) and '
          '(isnotempty(Caller) or isnotempty(CallerAppId) or isnotempty(CallerObjectId))\n')
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
     _GROUP, _BACKUP_LINES + "          by CorrelationId, OperationNameValue, _ResourceId\n"
                             "      | where OtherLines > 0 and AzureBackupLines == 0\n"),

    # ── the operations read ──
    ("M4285", "RESTOREPOINTS/WRITE no longer read — a restore point made by hand is no card (AL2)", RULES,
     _OPS + 'WRITE",\n', ""),
    ("M4286", "RETRIEVESASURIS no longer read — the SAS URLs alone are no card (AL2)", RULES,
     _OPS + 'RETRIEVESASURIS/ACTION",\n', ""),

    # ── a failure makes no card: its latest line read ──
    # (re-anchored by AL1d, #600: an operation that succeeded is read whatever its latest line)
    ("M4287", "failures kept — an operation refused makes a card (AL2)", RULES,
     '      | where Succeeded > 0 or (ActivityStatusValue !in~ ("Failure", "Failed") '
     'and (not(AzureBackup) or OtherFailures == 0))\n',
     '      | where Succeeded > 0 or not(AzureBackup)\n'),

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

    # ── after the first review (06/11) ──
    ("M4305", "a line that names no one decides — the reviewed version: a backup whose Start line is out "
              "of the window, or not yet in, makes a card on its bare Success line (AL2)", RULES,
     _GROUP, _BACKUP_LINES + "          by CorrelationId, OperationNameValue, _ResourceId\n"
                             "      | where AzureBackupLines == 0 or OtherLines > 0\n"),
    ("M4306", "Azure Backup's id matched as a term of the Caller, not whole — a Caller that starts with it "
              "is excluded (AL2)", RULES,
     _MATCH, f'      | extend AzureBackup = CallerAppId =~ "{_ID}" or Caller has "{_ID}"\n'),
    ("M4307", "the operation's name compared case-sensitively — a name in another case is no card (AL2)",
     RULES,
     '      | where OperationNameValue in~ (\n' + _OPS + 'WRITE",\n',
     '      | where OperationNameValue in (\n' + _OPS + 'WRITE",\n'),
    ("M4308", "one row per correlation id — two operations under one id make a single card (AL2)", RULES,
     _GROUP, "          by CorrelationId\n" + _KEEP),
    ("M4309", "a caller named by its object id alone no longer someone else — no card (AL2)", RULES,
     _OTHER, '      | extend OtherCaller = not(AzureBackup) and (isnotempty(Caller) or isnotempty(CallerAppId))\n'),

    # ── after the second review (06/11): the row carries the caller that decided it ──
    ("M4390", "the caller read from the latest line only — Glorfindel's Start then a bare Success is no "
              "longer critical, a human's names no one (AL2)", RULES,
     _CARRY, ""),
    ("M4391", "the caller filled column by column, when empty — Azure Backup's latest line names the card "
              "(AL2)", RULES,
     _CARRY, "      | extend Caller = iif(isnotempty(Caller), Caller, NamedCaller),\n"
             "               CallerAppId = iif(isnotempty(CallerAppId), CallerAppId, NamedAppId),\n"
             "               CallerObjectId = iif(isnotempty(CallerObjectId), CallerObjectId, NamedObjectId),\n"
             "               CallerIpAddress = iif(isnotempty(CallerIpAddress), CallerIpAddress, NamedIp)\n"),
    ("M4392", "the named caller taken from any line, Azure Backup's too — the card may name it (AL2)", RULES,
     "            NamedCaller = take_anyif(Caller, OtherCaller and isnotempty(Caller)),\n",
     "            NamedCaller = take_anyif(Caller, isnotempty(Caller)),\n"),

    # ── after the third review (06/11): and its address ──
    ("M4410", "the caller's address read from the latest line only — the card says the human acted from "
              "Azure Backup's address (AL2)", RULES,
     "NamedObjectId),\n               CallerIpAddress = iif(OtherCaller, CallerIpAddress, NamedIp)\n",
     "NamedObjectId)\n"),
]

TESTS = {m[0]: _TESTS for m in MUTANTS}
