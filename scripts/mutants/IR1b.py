"""IR1b (#572): the identity executor's contract, read at its start — its Graph token, then its own
rights read again on Graph, read only, against a closed list; a right too many is beyond_contract, a
contract it cannot read contract_unreadable, both passive, and a passive executor refuses to start
(glorfindel/providers/azure/identity_contract.py). Its application in H0's Terraform holds exactly
the contract's two Graph permissions (infra/glorfindel-host/identity_executor.tf).
M4070–M4083 measured by tests/unit/test_identity_contract.py (a fake Graph), M4084 by
tests/unit/test_identity_executor_host.py (its plan: infra/glorfindel-host/tests/
identity_executor.tftest.hcl, `terraform test`)."""
IC = "glorfindel/providers/azure/identity_contract.py"
HOST_TF = "infra/glorfindel-host/identity_executor.tf"
_CONTRACT = "tests/unit/test_identity_contract.py"
_HOST = "tests/unit/test_identity_executor_host.py"

MUTANTS = [
    ("M4070", "a right that grants privileges admitted: the refused list read as the closed one (IR1b)", IC,
     "    if name in ADMITTED_PERMISSIONS:\n        return [], {name}\n",
     "    if name in ADMITTED_PERMISSIONS | REFUSED_PERMISSIONS:\n        return [], {name}\n"),
    ("M4071", "a right the contract does not know let through (IR1b)", IC,
     "    return [_miss(BEYOND, f\"{name or 'an unnamed permission'} ({where}): a right outside the contract\")], set()\n",
     "    return [], set()\n"),
    ("M4072", "a user's token taken for the executor's own (IR1b)", IC,
     "    if not isinstance(claims, dict) or claims.get(\"scp\"):\n",
     "    if not isinstance(claims, dict):\n"),
    ("M4073", "a token of another tenant taken for the executor's (IR1b)", IC,
     "    if guid(claims.get(\"tid\")) != decl.tenant:\n",
     "    if not guid(claims.get(\"tid\")):\n"),
    ("M4074", "the directory roles of its token never read (IR1b)", IC,
     "    for w in {str(w).lower() for w in wids} - APP_DEFAULT_WIDS:\n",
     "    for w in []:\n"),
    ("M4075", "a role known by the templateId a custom role may set (IR1b)", IC,
     "        rid = guid(a.get(\"roleDefinitionId\"))\n"
     "        rd = a.get(\"roleDefinition\") if isinstance(a.get(\"roleDefinition\"), dict) else {}\n",
     "        rd = a.get(\"roleDefinition\") if isinstance(a.get(\"roleDefinition\"), dict) else {}\n"
     "        rid = guid(rd.get(\"templateId\")) or guid(a.get(\"roleDefinitionId\"))\n"),
    ("M4076", "a role said not built in taken for the built-in one of its id (IR1b)", IC,
     "        elif rid not in ADMITTED_ROLES or rd.get(\"isBuiltIn\") is False:\n",
     "        elif rid not in ADMITTED_ROLES:\n"),
    ("M4077", "an admitted role held at any scope: User Administrator over the tenant (IR1b)", IC,
     "        elif a.get(\"appScopeId\") or not scope or scope != _admitted_scope(rid, decl):\n",
     "        elif a.get(\"appScopeId\"):\n"),
    ("M4078", "an eligible role never counted: it could activate it (IR1b)", IC,
     "    for a in eligible:\n",
     "    for a in []:\n"),
    ("M4079", "owning an identity that is never a target accepted: acting as the watch (IR1b)", IC,
     "        elif ids & never.ids:\n",
     "        elif False:\n"),
    ("M4080", "the never_target list unreadable read as « nothing protected » (IR1b)", IC,
     "        elif unreadable:\n",
     "        elif False:\n"),
    ("M4081", "its own rights not read, armed all the same (IR1b)", IC,
     "        return Verdict(PASSIVE, tuple(missing + [_miss(UNREADABLE, f\"its own rights not read: {why}\")]))\n",
     "        return Verdict(PASSIVE if missing else ARMED, tuple(missing), frozenset(token_held))\n"),
    ("M4082", "a passive executor starts all the same (IR1b)", IC,
     "    if not verdict.armed:\n        raise Passive(verdict.reasons())\n",
     "    if False:\n        raise Passive(verdict.reasons())\n"),
    ("M4083", "a permission held on its token's word or its assignment's alone (IR1b)", IC,
     "    held = (token_held & assigned) | roles\n",
     "    held = token_held | assigned | roles\n"),
    ("M4084", "the executor's application given a right that grants privileges (IR1b)", HOST_TF,
     'toset(["Application.ReadWrite.OwnedBy", "User.RevokeSessions.All"])',
     'toset(["Application.ReadWrite.OwnedBy", "User.RevokeSessions.All", "Application.ReadWrite.All"])'),
]
TESTS = {f"M{n}": _CONTRACT for n in range(4070, 4084)}
TESTS["M4084"] = _HOST
