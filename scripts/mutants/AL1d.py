"""AL1d (#600): in the shipped rules on Azure's Activity Log, an operation that succeeded is
always read, whatever its latest line; one that only failed is not; and a latest line that
names no caller keeps the caller its operation's other lines name. M4380–M4389, measured by
tests/unit/test_activity_operation_read.py (the shipped queries run as written on forged lines,
through tests/unit/kql_subset.py, then the detector and the RulePoller). M4490–M4493, after
AL2's merge: the same reading in its sister rule on restore points, where only a success that
cannot be Azure Backup's counts — measured by tests/unit/test_restore_points.py."""
RULES = "glorfindel/rules/azure/detection_rules.yaml"
AGENT = "glorfindel/agent.py"
SUBSET = "tests/unit/kql_subset.py"
_TESTS = "tests/unit/test_activity_operation_read.py"

_KEEP = '      | where Succeeded > 0 or ActivityStatusValue !in~ ("Failure", "Failed")\n'
_LATEST_ONLY = '      | where ActivityStatusValue !in~ ("Failure", "Failed")\n'
_CALLER = "      | extend Caller = iif(isempty(Caller), NamedCaller, Caller),\n"
_IP = "               CallerIpAddress = iif(isempty(CallerIpAddress), NamedCallerIp, CallerIpAddress),\n"
_APP = "               CallerAppId = iif(isempty(CallerAppId), NamedCallerAppId, CallerAppId),\n"
_OID = "               CallerObjectId = iif(isempty(CallerObjectId), NamedCallerObjectId, CallerObjectId)\n"
_EXTEND = ("      // A latest line that names no caller: the caller its operation's other lines name.\n"
           + _CALLER + _IP + _APP + _OID)
_PROJECT = ("      | project TimeGenerated, OperationNameValue, ActivityStatusValue, Succeeded, Caller, CallerIpAddress,\n"
            "                CallerAppId, CallerObjectId, _ResourceId, ResourceGroup, CorrelationId\n\n")
_NEXT = {"nsg": "  - name: role-assignment-write\n",
         "role": "  - name: snapshot-by-unexpected-caller\n",
         "snapshot": "  # La sœur de la règle des instantanés (AL2, #598)"}


def _tail(rule: str, keep: str = _KEEP, extend: str = _EXTEND) -> str:
    """The end of a rule's query, unique by the line that follows it."""
    return keep + extend + _PROJECT + _NEXT[rule]


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
     _tail("nsg"), _tail("nsg", extend=_EXTEND.replace(_CALLER + _IP + _APP + _OID,
                                                       "      | extend CallerIpAddress = iif(isempty(CallerIpAddress), "
                                                       "NamedCallerIp, CallerIpAddress)\n"))),
    ("M4385", "role-assignment-write: a latest line that names no caller loses its object id — "
              "Glorfindel's identity no longer critical (AL1d)", RULES,
     _tail("role"), _tail("role", extend=_EXTEND.replace(_APP + _OID, _APP.replace("),\n", ")\n")))),
    ("M4386", "snapshot-by-unexpected-caller: the caller taken from the latest line, named or "
              "not (AL1d)", RULES,
     _tail("snapshot"), _tail("snapshot", extend=_EXTEND.replace("iif(isempty(", "iif(isnotempty("))),
    ("M4387", "run-command-by-glorfindel-outside-isolation: a latest line that names no caller "
              "loses it — its own Run Command read as unreadable, another's as a card (AL1d)", RULES,
     _EXTEND + '      | extend WatchedCaller = "glorfindel"\n',
     '      | extend WatchedCaller = "glorfindel"\n'),
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
_RP_KEEP = _RP_SUCCEEDED + _KEEP
_RP_OTHER_OK = ('            OtherSucceeded = countif(OtherCaller and ActivityStatusValue in~ '
                '("Success", "Succeeded")),\n')
_RP_PROJECT = ("               CallerIpAddress = iif(OtherCaller, CallerIpAddress, NamedIp)\n"
               "      | project TimeGenerated, OperationNameValue, ActivityStatusValue, Succeeded, Caller, "
               "CallerIpAddress,\n")

MUTANTS += [
    ("M4490", "restorepoint-by-unexpected-caller reads an operation by its latest line only: one that "
              "succeeded is not read when its latest line failed (AL1d)", RULES,
     _RP_KEEP, _RP_SUCCEEDED + _LATEST_ONLY),
    ("M4491", "restorepoint-by-unexpected-caller counts a bare success under a backup's correlation id: "
              "the backup's Success taken for the other caller's, whose try only failed (AL1d)", RULES,
     _RP_SUCCEEDED, "      | extend Succeeded = AnySucceeded\n"),
    ("M4492", "restorepoint-by-unexpected-caller counts Azure Backup's own success for the other "
              "caller (AL1d)", RULES,
     _RP_OTHER_OK, '            OtherSucceeded = countif(ActivityStatusValue in~ ("Success", "Succeeded")),\n'),
    ("M4493", "restorepoint-by-unexpected-caller no longer projects Succeeded: the card of an operation "
              "whose latest line failed after one succeeded says only « Failure » (AL1d)", RULES,
     _RP_PROJECT, _RP_PROJECT.replace("ActivityStatusValue, Succeeded, Caller", "ActivityStatusValue, Caller")),
]
TESTS = {**{f"M{n}": _TESTS for n in range(4380, 4390)}, **{f"M{n}": _RP_TESTS for n in range(4490, 4494)}}
