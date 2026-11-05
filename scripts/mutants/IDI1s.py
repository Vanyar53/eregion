"""IDI1s (#559): Orodruin's Graph guarantee strict even undeclared. The wids hypothesis measured on
05/11 (the first orodruin-check after v0.5.6, armed, no Graph note): a wids outside APP_DEFAULT_WIDS
is passive, EREGION_TENANT_ID set or not; a Graph token that cannot be had is passive declared, only
said undeclared — an Orodruin without a Graph right does not fall, and having no token is no
privilege (eregion_core/orodruin.py, assess_graph, read_graph). M4225–M4229; M3941 (IDI1), whose
code is gone, is retired with it.

Caught by tests/unit/test_orodruin.py -k graph.
"""
ORO = "eregion_core/orodruin.py"
_CONTRACT = "tests/unit/test_orodruin.py -k graph"

MUTANTS = [
    ("M4225", "an undeclared wids outside the hypothesis is only said again: a directory role arms Orodruin (IDI1s)",
     ORO, '        missing.append(_miss("graph_directory_role",\n',
     '        missing.append((_miss if declared else _note)("graph_directory_role",\n'),
    ("M4226", "undeclared, a Graph token that cannot be had is passive: every Orodruin without a Graph right "
     "falls over a Graph it never reads (IDI1s)", ORO,
     "        if declared:\n            raise\n", "        raise\n"),
    ("M4227", "declared, a Graph token that cannot be had is only said: the identity guard's read unread, armed (IDI1s)",
     ORO, "        if declared:\n            raise\n", "        if False:\n            raise\n"),
    ("M4228", "the directory roles read only once the Graph read is declared: undeclared, a role passes unsaid (IDI1s)",
     ORO, "    if roles:\n        missing.append(", "    if roles and declared:\n        missing.append("),
    ("M4229", "APP_DEFAULT_WIDS holds a built-in role's template id: Orodruin as a Global Administrator arms (IDI1s)",
     ORO, 'APP_DEFAULT_WIDS = frozenset({"0997a1d0-0d1d-4acb-b408-d5ca73121e90"})',
     'APP_DEFAULT_WIDS = frozenset({"0997a1d0-0d1d-4acb-b408-d5ca73121e90", '
     '"62e90394-69f5-4237-9190-012177145e10"})'),
]
TESTS = {f"M{n}": _CONTRACT for n in range(4225, 4230)}
