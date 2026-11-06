"""AL1d (#600): in the shipped rules on Azure's Activity Log, an operation that succeeded is
always read, whatever its latest line; one that only failed is not; and a latest line that
names no caller keeps the caller its operation's other lines name. M4380–M4389, measured by
tests/unit/test_activity_operation_read.py (the shipped queries run as written on forged lines,
through tests/unit/kql_subset.py, then the detector and the RulePoller). M4490–M4493, after
AL2's merge: the same reading in its sister rule on restore points, where only a success that
cannot be Azure Backup's counts — measured by tests/unit/test_restore_points.py. M4494,
M4500–M4504, after the 5.5 review: a bare latest line takes its operation's caller only when
its lines name one (a CorrelationId is the client's to choose), a backup's Success arrived last
stands for no one else, and a success under several callers is not said to have taken effect."""
RULES = "glorfindel/rules/azure/detection_rules.yaml"
AGENT = "glorfindel/agent.py"
SUBSET = "tests/unit/kql_subset.py"
_TESTS = "tests/unit/test_activity_operation_read.py"

_KEEP = '      | where Succeeded > 0 or ActivityStatusValue !in~ ("Failure", "Failed")\n'
_LATEST_ONLY = '      | where ActivityStatusValue !in~ ("Failure", "Failed")\n'
_COMMENT = ("      // A latest line that names no caller takes the caller its operation's lines name, the\n"
            "      // four columns from that caller's lines — only when they name one: a CorrelationId is\n"
            "      // the client's to choose, and two callers' ids are never mixed on one row (one of them\n"
            "      // Glorfindel's would set the other's write aside). Else the row stays as its latest\n"
            "      // line, naming no one; Callers says how many.\n")
_FILL = "      | extend Fill = not(Named) and Callers == 1\n"
_CALLER = "      | extend Caller = iif(Fill, NamedCaller, Caller),\n"
_IP = "               CallerIpAddress = iif(Fill, NamedCallerIp, CallerIpAddress),\n"
_APP = "               CallerAppId = iif(Fill, NamedCallerAppId, CallerAppId),\n"
_OID = "               CallerObjectId = iif(Fill, NamedCallerObjectId, CallerObjectId)\n"
_EXTEND = _FILL + _CALLER + _IP + _APP + _OID
# The form b48bcb21 had, column by column: the mix the 5.5 review found (M4502).
_PER_COLUMN = ("      | extend Caller = iif(isempty(Caller), NamedCaller, Caller),\n"
               "               CallerIpAddress = iif(isempty(CallerIpAddress), NamedCallerIp, CallerIpAddress),\n"
               "               CallerAppId = iif(isempty(CallerAppId), NamedCallerAppId, CallerAppId),\n"
               "               CallerObjectId = iif(isempty(CallerObjectId), NamedCallerObjectId, CallerObjectId)\n")
_UNGUARDED = _EXTEND.replace(" and Callers == 1", "")
_PROJECT = ("      | project TimeGenerated, OperationNameValue, ActivityStatusValue, Succeeded, Callers, Caller, "
            "CallerIpAddress,\n"
            "                CallerAppId, CallerObjectId, _ResourceId, ResourceGroup, CorrelationId\n\n")
_NEXT = {"nsg": "  - name: role-assignment-write\n",
         "role": "  - name: snapshot-by-unexpected-caller\n",
         "snapshot": "  # La sœur de la règle des instantanés (AL2, #598)"}
_RUN = '      | extend WatchedCaller = "glorfindel"\n'


def _tail(rule: str, keep: str = _KEEP, extend: str = _EXTEND) -> str:
    """The end of a rule's query, unique by the line that follows it."""
    return keep + _COMMENT + extend + _PROJECT + _NEXT[rule]


MUTANTS = [
    ("M4380", "nsg-change-outside-glorfindel reads an operation by its latest line only: one that "
              "succeeded is not read when its latest line failed (AL1d)", RULES,
     _tail("nsg"), _tail("nsg", keep=_LATEST_ONLY)),
    ("M4381", "role-assignment-write reads an operation by its latest line only: one that succeeded "
              "is not read when its latest line failed (AL1d)", RULES,
     _tail("role"), _tail("role", keep=_LATEST_ONLY)),
    ("M4382", "snapshot-by-unexpected-caller reads an operation by its latest line only: one that "
              "succeeded is not read when its latest line failed (AL1d)", RULES,
     _tail("snapshot"), _tail("snapshot", keep=_LATEST_ONLY)),
    ("M4383", "role-assignment-write sets no failure aside: an operation that only failed makes a "
              "card (AL1d)", RULES,
     _tail("role"), _tail("role", keep=_KEEP.replace("Succeeded > 0", "Succeeded >= 0"))),
    ("M4384", "nsg-change-outside-glorfindel: a latest line that names no caller loses it — "
              "Glorfindel's own isolation becomes a card (AL1d)", RULES,
     _tail("nsg"), _tail("nsg", extend=_FILL + "      | extend CallerIpAddress = iif(Fill, NamedCallerIp, "
                                                    "CallerIpAddress)\n")),
    ("M4385", "role-assignment-write: a latest line that names no caller loses its object id — "
              "Glorfindel's identity no longer critical (AL1d)", RULES,
     _tail("role"), _tail("role", extend=_EXTEND.replace(_APP + _OID, _APP.replace("),\n", ")\n")))),
    ("M4386", "snapshot-by-unexpected-caller: the caller taken from the latest line, named or "
              "not (AL1d)", RULES,
     _tail("snapshot"), _tail("snapshot", extend=_EXTEND.replace("not(Named)", "Named"))),
    ("M4387", "run-command-by-glorfindel-outside-isolation: a latest line that names no caller "
              "loses it — its own Run Command read as unreadable, another's as a card (AL1d)", RULES,
     _EXTEND + _RUN, _RUN),
    ("M4388", "the card of an operation whose latest line failed after one succeeded says only "
              "« Failure » (AL1d)", AGENT,
     '    elif status.lower() in ("failure", "failed") and _succeeded_lines(row) > 0:\n',
     "    elif False:\n"),
    ("M4389", "the KQL subset's take_anyif ignores its predicate: an empty caller taken for one "
              "(AL1d)", SUBSET,
     '        (f(r) for r in members if pred(r) and f(r) is not None), None),\n',
     '        (f(r) for r in members if f(r) is not None), None),\n'),
]

# ── AL2's sister rule, after the merge (relecture 4 d'AL2, 06/11): restore points ──
_RP_TESTS = "tests/unit/test_restore_points.py"
_RP_SUCCEEDED = "      | extend Succeeded = iif(BackupLines > 0, OtherSucceeded, AnySucceeded)\n"
_RP_KEEP = ('      | where Succeeded > 0 or (ActivityStatusValue !in~ ("Failure", "Failed") '
            'and not(AzureBackup))\n')
_RP_OTHER_OK = ('            OtherSucceeded = countif(OtherCaller and ActivityStatusValue in~ '
                '("Success", "Succeeded")),\n')
_RP_PROJECT = ("               CallerIpAddress = iif(OtherCaller, CallerIpAddress, NamedIp)\n"
               "      | project TimeGenerated, OperationNameValue, ActivityStatusValue, Succeeded, Callers, Caller, "
               "CallerIpAddress,\n")

MUTANTS += [
    ("M4490", "restorepoint-by-unexpected-caller reads an operation by its latest line only: one that "
              "succeeded is not read when its latest line failed (AL1d)", RULES,
     _RP_KEEP, '      | where ActivityStatusValue !in~ ("Failure", "Failed") and not(AzureBackup)\n'),
    ("M4491", "restorepoint-by-unexpected-caller counts a bare success under a backup's correlation id: "
              "the backup's Success taken for the other caller's, whose try only failed (AL1d)", RULES,
     _RP_SUCCEEDED, "      | extend Succeeded = AnySucceeded\n"),
    ("M4492", "restorepoint-by-unexpected-caller counts Azure Backup's own success for the other "
              "caller (AL1d)", RULES,
     _RP_OTHER_OK, '            OtherSucceeded = countif(ActivityStatusValue in~ ("Success", "Succeeded")),\n'),
    ("M4493", "restorepoint-by-unexpected-caller no longer projects Succeeded: the card of an operation "
              "whose latest line failed after one succeeded says only « Failure » (AL1d)", RULES,
     _RP_PROJECT, _RP_PROJECT.replace("ActivityStatusValue, Succeeded, Callers", "ActivityStatusValue, Callers")),
]

# ── after the 5.5 review of AL1d (06/11): two callers under one CorrelationId ──
MUTANTS += [
    ("M4494", "nsg-change-outside-glorfindel fills a bare latest line from any caller its operation names: "
              "another's write of Glorfindel's rule, under its CorrelationId, borrows its ids and is set "
              "aside (AL1d)", RULES,
     _tail("nsg"), _tail("nsg", extend=_UNGUARDED)),
    ("M4500", "run-command-by-glorfindel-outside-isolation fills a bare latest line from any caller: "
              "another's Run Command under Glorfindel's CorrelationId taken for its drain (AL1d)", RULES,
     _EXTEND + _RUN, _UNGUARDED + _RUN),
    ("M4501", "role-assignment-write fills a bare latest line from any caller: two callers' ids mixed "
              "on one row (AL1d)", RULES,
     _tail("role"), _tail("role", extend=_UNGUARDED)),
    ("M4502", "snapshot-by-unexpected-caller fills the caller column by column, when empty: another's "
              "Caller with Glorfindel's ids on one row (AL1d)", RULES,
     _tail("snapshot"), _tail("snapshot", extend=_PER_COLUMN)),
    ("M4503", "restorepoint-by-unexpected-caller reads Azure Backup's Success, arrived last, as the "
              "other caller's, whose try only failed — a card « (Success) » (AL1d)", RULES,
     _RP_KEEP, _KEEP),
    ("M4504", "the card of an operation whose lines name several callers says a success took effect: "
              "it may be another's (AL1d)", AGENT,
     "        if _named_callers(row) > 1:\n"
     "            what += (\" Statut lu à sa dernière ligne ; une de ses lignes a réussi, mais elle \"\n",
     "        if False:\n"
     "            what += (\" Statut lu à sa dernière ligne ; une de ses lignes a réussi, mais elle \"\n"),
]
TESTS = {**{f"M{n}": _TESTS for n in range(4380, 4390)}, **{f"M{n}": _RP_TESTS for n in range(4490, 4494)},
         **{m: _TESTS for m in ("M4494", "M4500", "M4501", "M4502", "M4504")}, "M4503": _RP_TESTS}
