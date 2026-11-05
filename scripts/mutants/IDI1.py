"""IDI1 (#546): an identity of Entra ID enrolled for the bench by two keys, one per plane — the
application's Graph tags and the bench group's eregion-identities — and judged as a VM is: the named
tenant, an application's principal, never a protected identity, its zone deciding, a failed read
refusing (eregion_core/inscription.py). Orodruin holds Application.Read.All in Microsoft Graph and
nothing else, its contract reading its Graph token (eregion_core/orodruin.py, infra/orodruin).
M3810–M3819 (the guard), M3860–M3864 (the contract, Terraform, make); M3900–M3906 (05/11: a
privileged identity never enrolled, the shared list of eregion_core/never_target.py).

The guard's are caught by tests/unit/test_identity_inscription.py, on a fake Graph; the contract's
and Orodruin's Terraform by tests/unit/test_orodruin.py (their plan: infra/orodruin/tests/
graph_read.tftest.hcl, `terraform test`); make's by tests/unit/test_bench_identity.py.
"""
INS = "eregion_core/inscription.py"
NT = "eregion_core/never_target.py"
ORO = "eregion_core/orodruin.py"
ORO_TF = "infra/orodruin/main.tf"
ORO_VARS = "infra/orodruin/variables.tf"
MAKE = "Makefile"
_GUARD = "tests/unit/test_identity_inscription.py"
_CONTRACT = "tests/unit/test_orodruin.py -k graph"
_MAKE = "tests/unit/test_bench_identity.py"

MUTANTS = [
    ("M3810", "the Entra key alone enrolls: any member tags an application of theirs and it is a target (IDI1)", INS,
     "    if app_oid not in named:\n", "    if False:\n"),
    ("M3811", "the reader's token of another tenant judges: the bench's tenant no longer checked (IDI1)", INS,
     '    if _guid(token.get("tid")) != tenant:\n', "    if False:\n"),
    ("M3812", "an application registered in another tenant (Microsoft's) is a target: its home tenant writes its tags (IDI1)",
     NT, '        if not tenant or guid(sp.get("appOwnerOrganizationId")) != tenant:\n', "        if False:\n"),
    ("M3813", "a managed identity's principal is a target — Glorfindel's, Orodruin's (IDI1)", NT,
     '        if str(sp.get("servicePrincipalType") or "") != APPLICATION_PRINCIPAL:\n', "        if False:\n"),
    ("M3814", "the listed identities ignored: Glorfindel's hosted watch enrolled by both keys is a target (IDI1)",
     NT, "        never = set(self.ids)\n", "        never = set()\n"),
    ("M3815", "no operator named and identities still accepted: the operator's own could not be told apart (IDI1)",
     NT, "        if not self.operators:\n", "        if False:\n"),
    ("M3816", "the two keys' zones disagree and the application's wins: production tagged by its owner (IDI1)", INS,
     '    if rg.get(ZONE_TAG, "") != zone:\n', "    if False:\n"),
    ("M3817", "a read of Graph or ARM that fails enrolls: never-enrolled-by-default lost (IDI1, A0)", INS,
     '            return GuardResult(False, f"identity unreadable: {type(e).__name__}: {e}"[:300])\n',
     '            return GuardResult(True, zone="bench")\n'),
    ("M3818", "an identity's zone no longer decides: a destructive technique on a production identity (IDI1)", INS,
     "    return check_zone(enrolled.zone, kind=kind, destructive=destructive)\n", "    return enrolled\n"),
    ("M3819", "a multi-tenant application is a target: a technique on it reaches other tenants (IDI1)", INS,
     '    if str(app.get("signInAudience") or "") != SINGLE_TENANT:\n', "    if False:\n"),
    ("M3860", "the contract arms with a write right in Microsoft Graph: Application.ReadWrite.All passes (IDI1)", ORO,
     '    unlisted = sorted({str(r) for r in claims.get("roles") or []} - GRAPH_READ_ONLY)\n', "    unlisted = []\n"),
    ("M3861", "the contract arms with a directory role: Orodruin as an Application Administrator (IDI1)", ORO,
     '    roles = sorted({str(w).lower() for w in claims.get("wids") or []} - APP_DEFAULT_WIDS)\n', "    roles = []\n"),
    ("M3862", "Orodruin's Graph read on by default: an apply without the operator's choice grants it (IDI1)", ORO_VARS,
     'Défaut false."\n  type        = bool\n  default     = false\n',
     'Défaut false."\n  type        = bool\n  default     = true\n'),
    ("M3863", "Orodruin granted Application.ReadWrite.All in Graph: it could tag an application itself (IDI1)", ORO_TF,
     'toset(["Application.Read.All", "RoleManagement.Read.Directory"])',
     'toset(["Application.ReadWrite.All", "RoleManagement.Read.Directory"])'),
    ("M3864", "make orodruin-identity ID=… expanded by make: a $(shell …) on the command line runs (IDI1)", MAKE,
     "unexport ID\n", ""),
    # 05/11 (Jonathan, in the design of IR1): a privileged identity is never enrolled; the shared list.
    ("M3900", "an identity holding a directory role is enrolled: IR1 would own a privileged identity (IDI1)", INS,
     "    if roles:\n        return (f\"it holds {len(roles)} directory role(s)",
     "    if False:\n        return (f\"it holds {len(roles)} directory role(s)"),
    ("M3901", "the eligible roles (PIM) never read: an identity one activation away from a role is enrolled (IDI1)", INS,
     '        roles += self._pages(f"{_GRAPH_V1}/roleManagement/directory/roleEligibilityScheduleInstances", g, flt)\n',
     ""),
    ("M3902", "an identity holding a write application permission in Graph is enrolled (IDI1)", INS,
     '        if not _READ_ONLY_ROLE.fullmatch(value) or "write" in value.lower():\n', "        if False:\n"),
    ("M3903", "a member of a group is enrolled: the group's role reaches whoever owns the identity (IDI1)", INS,
     '    if identity["member_of"]:\n', "    if False:\n"),
    ("M3904", "the principal of a resource (an API others call) is a target (IDI1)", NT,
     '        if sp.get("appRoles") or sp.get("oauth2PermissionScopes") or identity.get("assigned_to"):\n',
     "        if False:\n"),
    ("M3905", "the shared list unreadable and an id not listed passes: covers fails open (IDI1, IR1a)", NT,
     "        return bool(self.refusal()) or not oid or oid in self.ids\n", "        return oid in self.ids\n"),
    ("M3906", "the contract arms with RoleManagement.ReadWrite.Directory: Orodruin could give itself a role (IDI1)", ORO,
     'GRAPH_READ_ONLY = frozenset({"Application.Read.All", "RoleManagement.Read.Directory"})',
     'GRAPH_READ_ONLY = frozenset({"Application.Read.All", "RoleManagement.Read.Directory", '
     '"RoleManagement.ReadWrite.Directory"})'),
]
TESTS = {
    **{f"M{n}": _GUARD for n in range(3810, 3820)},
    **{mid: _CONTRACT for mid in ("M3860", "M3861", "M3862", "M3863")},
    "M3864": _MAKE,
    **{f"M{n}": _GUARD for n in range(3900, 3906)},
    "M3906": _CONTRACT,
}
