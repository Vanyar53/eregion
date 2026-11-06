"""IDI1p (#618): a tenant without PIM. Measured from Orodruin on the bench's tenant (06/11), Graph
answers the read of eligible role instances 400, ``AadPremiumLicenseRequired``: without Entra ID P2
or ID Governance, no eligible role can exist. That exact answer — that status, that code compared
exactly, on that one read, on its first page — is « none », said in the verdict
(``eregion_core.inscription.no_pim_license``, shared by IDI1's and IDI1b's guard and IR1b's
contract); any other refuses, and says Graph's error code, filtered (letters only, at most 64).

M4470–M4479, caught on fake Graphs by tests/unit/test_identity_inscription.py,
tests/unit/test_user_inscription.py and tests/unit/test_identity_contract.py (GraphReader's own
answers, M4474, M4478, there).
"""
INS = "eregion_core/inscription.py"
GRAPH = "glorfindel/providers/azure/graph.py"
IC = "glorfindel/providers/azure/identity_contract.py"
_GUARD = "tests/unit/test_identity_inscription.py tests/unit/test_user_inscription.py"
_CONTRACT = "tests/unit/test_identity_contract.py"
_ALL = f"{_GUARD} {_CONTRACT}"

MUTANTS = [
    ("M4470", "any code of a 400 on the eligible read is « no license »: a tenant's other refusal reads as no "
              "eligible role, an identity one activation away from a role enrolled (IDI1p)", INS,
     "status == 400 and code == NO_PIM_LICENSE", "status == 400"),
    ("M4471", "any status naming AadPremiumLicenseRequired is « no license »: a 403 or a 500 read as none (IDI1p)",
     INS, "status == 400 and code == NO_PIM_LICENSE", "code == NO_PIM_LICENSE"),
    ("M4472", "the answer read as « none » on any read: roleAssignments without a license, an active role "
              "unseen (IDI1p)", INS,
     "page == 0 and path == ELIGIBLE_ROLES_PATH and status", "page == 0 and status"),
    ("M4473", "a next page answering « no license » after a first page read: the rest of a list taken for "
              "none (IDI1p)", INS,
     "return page == 0 and path == ELIGIBLE_ROLES_PATH", "return path == ELIGIBLE_ROLES_PATH"),
    ("M4474", "Graph's reader says every page is the first: a next page's « no license » read as none (IDI1p)",
     GRAPH, "            body = self._get(str(nxt), None, deadline, page)\n",
     "            body = self._get(str(nxt), None, deadline)\n"),
    ("M4475", "IDI1's guard reads « no license » as none and does not say it: the verdict silent on what it "
              "did not read (IDI1p)", INS,
     "    return replace(enrolled, notes=read_notes(identity))\n", "    return enrolled\n"),
    ("M4476", "the executor's contract reads « no license » as none and does not say it (IDI1p)", IC,
     'frozenset(held), got["notes"])', "frozenset(held))"),
    ("M4477", "a refused read of the guard says its status only: Graph's error code, the why, lost (IDI1p)", INS,
     "        super().__init__(f\"HTTP {status}{' ' + code if code else ''} reading {what}\")\n",
     "        super().__init__(f\"HTTP {status} reading {what}\")\n"),
    ("M4478", "Graph's reader says its status only: the error code of a refusal lost (IDI1p)", GRAPH,
     "        said = f\"{status}{' ' + code if code else ''}\"\n", "        said = f\"{status}\"\n"),
    ("M4479", "Graph's error code copied raw: data from outside, a forged line or markup, in a verdict (IDI1p)",
     INS, '_GRAPH_CODE = re.compile(r"[A-Za-z]{1,64}")', '_GRAPH_CODE = re.compile(r"(?s).{1,200}")'),
]
TESTS = {
    **{f"M{n}": _ALL for n in (4470, 4471, 4472, 4473, 4479)},
    "M4474": _CONTRACT, "M4476": _CONTRACT, "M4478": _CONTRACT,
    "M4475": "tests/unit/test_identity_inscription.py", "M4477": _GUARD,
}
