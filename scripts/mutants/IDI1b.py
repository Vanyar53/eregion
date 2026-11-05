"""IDI1b (#573): a test user of Entra ID enrolled for the bench by two halves — the bench's restricted
administrative unit holds it (pinned by its id), and the attribute Eregion.eregionTarget/eregionZone
on the user names the bench and the unit's zone — and judged as a VM is: never a protected identity,
a guest, a privileged user, a read that fails (eregion_core/inscription.py). Celebrimbor poses the
unit by Graph (infra/terraform/scripts/entra_bench_unit.py: azuread 3.10.0 cannot make it restricted),
the users, their attribute before their membership, and the executor's three roles each at its scope
(infra/terraform/entra_bench_unit.tf).

M4085–M4095 (the guard), caught by tests/unit/test_user_inscription.py on a fake Graph; M4096–M4099
(the script and the Terraform), caught by tests/unit/test_bench_users.py (their plan:
infra/terraform/tests/entra_bench_unit.tftest.hcl, `terraform test`).
"""
INS = "eregion_core/inscription.py"
SCRIPT = "infra/terraform/scripts/entra_bench_unit.py"
TF = "infra/terraform/entra_bench_unit.tf"
_GUARD = "tests/unit/test_user_inscription.py"
_BENCH = "tests/unit/test_bench_users.py"

MUTANTS = [
    ("M4085", "the attribute alone enrolls: any Attribute Assignment Administrator tags a user and it is a target (IDI1b)",
     INS, "    if uid not in {_guid(m) for m in members}:\n", "    if False:\n"),
    ("M4086", "an unrestricted unit enrolls: a tenant's administrator adds a member, untraced (IDI1b)", INS,
     '    if unit.get("isMemberManagementRestricted") is not True:\n', "    if False:\n"),
    ("M4087", "the unit is not checked to be the pinned one: another unit holding the user enrolls it (IDI1b)", INS,
     "    if _guid(unit.get(\"id\")) != scope.admin_unit_id:\n", "    if False:\n"),
    ("M4088", "the attribute's bench no longer checked: a user enrolled for another bench is this one's target (IDI1b)",
     INS, "    if target != scope.bench:\n", "    if False:\n"),
    ("M4089", "the two halves' zones disagree and the attribute wins: a user of the bench's unit tagged production (IDI1b)",
     INS, "    if zone != UNIT_ZONE:\n", "    if False:\n"),
    ("M4090", "the shared list ignored for a user: an operator or a break-glass account held by the unit is a target (IDI1b)",
     INS, "    if scope.never.covers(uid) or uid in reader:\n", "    if uid in reader:\n"),
    ("M4091", "a user holding a directory role is enrolled: the executor would manage, or take, a privileged user (IDI1b)",
     INS, "    if user[\"directory_roles\"]:\n", "    if False:\n"),
    ("M4092", "a member of a group is enrolled: the group's role reaches whoever takes the user (IDI1b)", INS,
     "    if groups:\n        return \"it is a member of a group or a directory role",
     "    if False:\n        return \"it is a member of a group or a directory role"),
    ("M4093", "a guest is enrolled: another tenant's user a target of the bench (IDI1b)", INS,
     '    if str(user.get("userType") or "") != MEMBER_USER:\n', "    if False:\n"),
    ("M4094", "a read of Graph that fails enrolls the user: never-enrolled-by-default lost (IDI1b, A0)", INS,
     '            return GuardResult(False, f"user unreadable: {type(e).__name__}: {e}"[:300])\n',
     '            return GuardResult(True, zone="bench")\n'),
    ("M4095", "a member of another administrative unit is enrolled: within another administrator's reach (IDI1b)", INS,
     "    if others:\n", "    if False:\n"),
    ("M4096", "the bench's unit created unrestricted: its members managed by any tenant administrator, for good (IDI1b)",
     SCRIPT, '"isMemberManagementRestricted": True}', '"isMemberManagementRestricted": False}'),
    ("M4097", "the membership posed before the attribute: in a restricted unit, the attribute may never be written (IDI1b)",
     TF, "\n  depends_on = [terraform_data.bench_test_user_attributes]\n", "\n"),
    ("M4098", "the bench's unit and its users on by default: an apply without the operator's choice poses them (IDI1b)",
     TF, '  type        = bool\n  default     = false\n', '  type        = bool\n  default     = true\n'),
    ("M4099", "User Administrator at the tenant's scope: the executor would manage every user, operators included (IDI1b)",
     TF, 'scope = "/administrativeUnits/${var.entra_bench_unit_id}" }', 'scope = "/" }'),
]
TESTS = {
    **{f"M{n}": _GUARD for n in range(4085, 4096)},
    **{f"M{n}": _BENCH for n in range(4096, 4100)},
}
