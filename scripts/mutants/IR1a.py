"""IR1a (#552): the plan of an identity card and its check, read only. The identity verbs a closed
list, never autonomous, always a human's, never in what the model reads; the plan's ids read on
Graph or the log, never invented, never a value of the log that is no id in a command; the check
never « held » without Graph's answer; Graph read only, its answers told apart; Glorfindel's
identity and never_target turned into a human's steps; the plan on the card, escaped on the page.
M3880–M3899, measured by tests/unit/test_identity_plan.py and
tests/unit/test_console_identity_plan.py (the page: tests/unit/test_console_escaping.py)."""
POLICY = "glorfindel/response/policy.py"
AGENT = "glorfindel/agent.py"
ITEMS = "glorfindel/providers/azure/entra_items.py"
GRANTS = "glorfindel/providers/azure/entra_grants.py"
PLAN = "glorfindel/providers/azure/entra_plan.py"
CHECK = "glorfindel/providers/azure/entra_check.py"
GRAPH = "glorfindel/providers/azure/graph.py"
JS = "eregion_console/static/glorfindel.js"
_PLAN = "tests/unit/test_identity_plan.py"
_CONSOLE = "tests/unit/test_console_identity_plan.py"

MUTANTS = [
    ("M3880", "an identity verb runs alone: revoking sessions made autonomous (IR1a)", POLICY,
     '    "block_suspicious_ip",\n}\n',
     '    "block_suspicious_ip",\n    "entra_revoke_sessions",\n}\n'),
    ("M3881", "the identity verbs out of HUMAN_APPROVAL_REQUIRED (IR1a)", POLICY,
     '    "restore_from_backup",  # replaces disk content — irreversible without another backup\n} | IDENTITY_ACTIONS\n',
     '    "restore_from_backup",  # replaces disk content — irreversible without another backup\n}\n'),
    ("M3882", "the list of identity verbs open: a verb that removes a role added (IR1a)", POLICY,
     '    "entra_enable_user",\n})\n',
     '    "entra_enable_user",\n    "entra_remove_role",\n})\n'),
    ("M3883", "the model reads the identity verbs among the destructive actions: the prompt changed (IR1a)", AGENT,
     "- Destructive actions {sorted(MODEL_GATED_ACTIONS)}: ALWAYS set escalate=true.",
     "- Destructive actions {sorted(HUMAN_APPROVAL_REQUIRED)}: ALWAYS set escalate=true."),
    ("M3884", "the identity card written without its plan: nothing to verify (IR1a)", AGENT,
     '            identity_plan=state.get("identity_plan") if escalation_type == "identity_change" else None,\n',
     '            identity_plan=None,\n'),
    ("M3885", "any value of the log taken for an object id: a name reaches a command (IR1a)", ITEMS,
     '    return v if _GUID.fullmatch(v) else ""\n',
     '    return v\n'),
    ("M3886", "a permission's scope from Graph put in a command as it is: a quote breaks out (IR1a)", ITEMS,
     '    return v if _WORDS.fullmatch(v) else ""\n',
     '    return v\n'),
    ("M3887", "Graph unreadable taken for « no such object » (IR1a)", ITEMS,
     "            self.why = self.why or str(exc)\n            return UNREAD\n",
     "            self.why = self.why or str(exc)\n            return None\n"),
    ("M3888", "a parameter not read shown as read: the command says complete (IR1a)", ITEMS,
     '    return {"name": name, "value": "", "from": "", "read": False, "why": why or "non lu"}\n',
     '    return {"name": name, "value": "", "from": "", "read": True, "why": why or "non lu"}\n'),
    ("M3889", "a check Graph did not answer said held (IR1a)", CHECK,
     "    except Unreadable as exc:\n        return _r(UNREADABLE, str(exc))\n",
     "    except Unreadable as exc:\n        return _r(HELD, str(exc))\n"),
    ("M3890", "the card held while an item is unreadable (IR1a)", CHECK,
     "    elif UNREADABLE in counted or not counted:\n",
     "    elif not counted:\n"),
    ("M3891", "a plan with nothing to check said held (IR1a)", CHECK,
     "    elif UNREADABLE in counted or not counted:\n",
     "    elif UNREADABLE in counted:\n"),
    ("M3892", "a credential still on the object said removed (IR1a)", CHECK,
     'est encore sur l\'objet") if key in keys else \\\n',
     'est encore sur l\'objet") if key not in keys else \\\n'),
    ("M3893", "sessions revoked before the event said revoked (IR1a)", CHECK,
     "    if since >= after:\n",
     "    if since:\n"),
    ("M3894", "a right missing on Graph read as « no such object » (IR1a)", GRAPH,
     "        if status in (401, 403):\n            code = _code(r)\n",
     "        if status in (401, 403):\n            return None\n            code = _code(r)\n"),
    ("M3895", "a next page followed off Graph's host (IR1a)", GRAPH,
     '        if not url.startswith(GRAPH + "/"):\n',
     '        if not url.startswith("https://"):\n'),
    ("M3896", "Glorfindel's identity keeps the executor's verbs (IR1a, §3.5)", PLAN,
     '            i.update(by="human", why_human=_GLORFINDEL)\n',
     '            i.update(why_human=_GLORFINDEL)\n'),
    ("M3897", "never_target not read: a verb aimed at a protected identity (IR1a, §3.5)", PLAN,
     '        held = protected(i["target"].get("id", "")) if protected and i["target"].get("id") else ""\n',
     '        held = ""\n'),
    ("M3898", "the plan's text written raw into the page (IR1a, #254)", JS,
     "${Number(i.n)}. ${verb}${_attr(i.what)}",
     "${Number(i.n)}. ${verb}${i.what}"),
    ("M3899", "a consent outside its flow blocks the resource's principal: the whole tenant cut (IR1a)", GRANTS,
     '    client = guid(row.get("TargetId")) if op == "consent to application" else guid(row.get("ClientId"))\n',
     '    client = guid(row.get("TargetId"))\n'),
]
TESTS = {f"M{n}": _PLAN for n in range(3880, 3900)}
TESTS["M3884"] = _CONSOLE
TESTS["M3898"] = f"{_CONSOLE} tests/unit/test_console_escaping.py"
TESTS["M3899"] = f"{_PLAN} tests/unit/test_entra_detection.py"
