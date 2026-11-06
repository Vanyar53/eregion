"""I3K (#602): a reset Azure refuses names each rule it leaves. The machine found the oracle asking
« gardée » of a deny that holds back a turned rule for the VM's own other NIC alone (its address
given to the other): the reset lifts the VM, that rule with it; refused (403), it is named by its
error, never kept. The oracle now asks that name, and « gardée » only of a rule kept for another VM
(M1962 holds that half). M4413: the refused delete said without its rule — caught by the frozen
sequence (the machine draws a 403, a two-NIC address swap and a turned rule together too rarely)."""
_SWP = "glorfindel/providers/azure/sweep.py"
_REG = "tests/unit/test_invariant_regressions.py::"

MUTANTS = [
    ("M4413", "the reset's refused delete said without the rule it leaves: « swept_partial », the deny "
              "a turned rule waits behind unnamed (I3K)", _SWP,
     '            (failed if err else deleted).append(err or f"{nsg_rg}/{nsg_name}/{name}")\n',
     '            (failed if err else deleted).append(err.split(":", 1)[1].strip() if err\n'
     '                                                else f"{nsg_rg}/{nsg_name}/{name}")\n'),
]
TESTS = {
    "M4413": f"tests/unit/test_invariants.py {_REG}test_a_reset_refused_by_azure_names_the_rule_it_leaves",
}
