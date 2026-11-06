"""A fake Microsoft Graph, in memory (IR1a): the objects a plan reads and a check reads again,
read the way Graph answers — an object, None for an absence (404), `Unreadable` for a right
missing, an error or a delay. Read only, as the real reader: it has `get` and `list`, nothing
that writes. A test changes its objects to play the human's gesture (the credential removed, the
principal disabled). Every id is a placeholder.
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.graph import Unreadable

_ID = r"([0-9a-f-]{36})"


class FakeGraph:
    def __init__(self):
        self.apps: dict[str, dict] = {}
        self.sps: dict[str, dict] = {}
        self.users: dict[str, dict] = {}
        self.grants: list[dict] = []
        self.app_roles: dict[str, list[dict]] = {}           # client principal → its assignments
        self.role_assignments: list[dict] = []
        self.eligibilities: list[dict] = []
        self.fics: dict[str, list[dict]] = {}                # application → its federated credentials
        self.roles: dict[str, str] = {}                      # role definition id → display name
        self.owned: dict[str, list[dict]] = {}               # principal → its owned objects (IR1b)
        self.member_of: dict[str, list[dict]] = {}           # principal → its groups, transitively (IR1b)
        self.assigned_to: dict[str, list[dict]] = {}         # principal → who holds an app role on it (IR1b)
        self.fail: str = ""                                  # right | error | delay | crash
        self.refuse: dict[str, Unreadable] = {}              # a list's path → Graph's answer to it (IDI1p)
        self.calls: list[tuple[str, str, dict | None]] = []

    def _fail(self):
        if self.fail == "crash":
            raise RuntimeError("a reader's bug")
        if self.fail:
            raise Unreadable({"right": "droit absent sur Graph (403 Authorization_RequestDenied)",
                              "error": "Graph a répondu 503",
                              "delay": "Graph n'a pas répondu à temps (15 s)"}[self.fail], self.fail)

    def get(self, path: str, params: dict | None = None, deadline: float | None = None):
        self.calls.append(("get", path, params))
        self._fail()
        if m := re.fullmatch(r"/applications/" + _ID, path):
            return self.apps.get(m.group(1))
        if m := re.fullmatch(r"/applications\(appId='" + _ID + r"'\)", path):
            return next((a for a in self.apps.values() if a.get("appId") == m.group(1)), None)
        if m := re.fullmatch(r"/servicePrincipals/" + _ID, path):
            return self.sps.get(m.group(1))
        if m := re.fullmatch(r"/servicePrincipals\(appId='" + _ID + r"'\)", path):
            return next((s for s in self.sps.values() if s.get("appId") == m.group(1)), None)
        if m := re.fullmatch(r"/users/" + _ID, path):
            return self.users.get(m.group(1))
        raise AssertionError(f"the fake Graph does not know {path}")

    def _principal(self, params) -> str:
        m = re.search(r"(?:principalId|clientId) eq '" + _ID + "'", (params or {}).get("$filter", ""))
        assert m, params
        return m.group(1)

    def _expanded(self, rows, params):
        p = self._principal(params)
        return [{**r, "roleDefinition": {"id": r["roleDefinitionId"],
                                         "displayName": self.roles.get(r["roleDefinitionId"], ""),
                                         **r.get("definition", {})}}
                for r in rows if r["principalId"] == p]

    def list(self, path: str, params: dict | None = None, deadline: float | None = None):
        self.calls.append(("list", path, params))
        self._fail()
        if path in self.refuse:
            raise self.refuse[path]
        if path == "/oauth2PermissionGrants":
            client = self._principal(params)
            return [g for g in self.grants if g["clientId"] == client]
        if m := re.fullmatch(r"/servicePrincipals/" + _ID + "/appRoleAssignments", path):
            return list(self.app_roles.get(m.group(1), [])) if m.group(1) in self.sps else None
        if path == "/roleManagement/directory/roleAssignments":
            return self._expanded(self.role_assignments, params)
        if path == "/roleManagement/directory/roleEligibilitySchedules":
            return self._expanded(self.eligibilities, params)
        if path == "/roleManagement/directory/roleEligibilityScheduleInstances":     # IR1b: no $expand
            p = self._principal(params)
            return [dict(r) for r in self.eligibilities if r["principalId"] == p]
        if m := re.fullmatch(r"/applications/" + _ID + "/federatedIdentityCredentials", path):
            return list(self.fics.get(m.group(1), [])) if m.group(1) in self.apps else None
        if m := re.fullmatch(r"/servicePrincipals/" + _ID + "/ownedObjects", path):
            return list(self.owned.get(m.group(1), [])) if m.group(1) in self.sps else None
        if m := re.fullmatch(r"/servicePrincipals/" + _ID + "/transitiveMemberOf", path):
            return list(self.member_of.get(m.group(1), [])) if m.group(1) in self.sps else None
        if m := re.fullmatch(r"/servicePrincipals/" + _ID + "/appRoleAssignedTo", path):
            return list(self.assigned_to.get(m.group(1), [])) if m.group(1) in self.sps else None
        raise AssertionError(f"the fake Graph does not know {path}")
