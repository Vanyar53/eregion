"""OI3 (#522): make orodruin-start brings Orodruin up to the latest release, verified — the image in
service (~/.eregion-image, :orodruin) read back, compared on the workstation to the latest tag v* by
version order then by commit in git's history (scripts/published_image.py age), the verified push
when it is older, absent or unreadable, kept when newer; make orodruin-check says it. M3630–M3639.
"""
PIM = "scripts/published_image.py"
MAKEFILE = "Makefile"
_T = "tests/unit/test_published_image.py::"
_OLDER = _T + "test_an_older_image_is_replaced_by_the_latest_release_verified"
_REPLACED = _T + "test_an_image_absent_or_unreadable_is_replaced_by_the_latest_release"
_KEPT = _T + "test_an_image_newer_than_the_latest_release_is_never_replaced"

MUTANTS = [
    ("M3630", "the latest release taken by string order: v0.5.9 after v0.5.10, the older image left (OI3)", PIM,
     'res = runner(["git", "-C", str(REPO), "tag", "-l", "v*", "--sort=-v:refname"])',
     'res = runner(["git", "-C", str(REPO), "tag", "-l", "v*", "--sort=-refname"])'),
    ("M3631", "an image newer than the release taken for older: replaced (OI3)", PIM,
     '        return {**out, "state": "newer", "said": f"{said} : plus récente"}',
     '        return {**out, "state": "older", "said": f"{said} : plus récente"}'),
    ("M3632", "an image of orodruin-push-dev taken for unreadable: replaced (OI3)", PIM,
     '        return {**out, "state": "dev",',
     '        return {**out, "state": "unreadable",'),
    ("M3633", "an image without its ~/.eregion-image taken for up to date: never pushed (OI3)", PIM,
     '        return {**out, "state": "absent",\n                "said": f"image sans ~/.eregion-image',
     '        return {**out, "state": "equal",\n                "said": f"image sans ~/.eregion-image'),
    ("M3634", "no :orodruin on Orodruin, never read: its marker naming the release, never pushed (OI3)", PIM,
     "    if not image:\n", "    if False:\n"),
    ("M3635", "an unreadable ~/.eregion-image kept as if newer: never pushed (OI3)", PIM,
     '        return {**out, "state": "unreadable", "said"',
     '        return {**out, "state": "diverged", "said"'),
    ("M3636", "a push that fails swallowed: start says up to date and exits 0 (OI3)", MAKEFILE,
     "orodruin-push REF=\"$$release\" || { echo \"✗ La mise à jour a échoué (la cause ci-dessus) : rien n'est "
     "armé\" >&2; exit 1; }; \\\n",
     "orodruin-push REF=\"$$release\" || true; \\\n"),
    ("M3637", "NO_UPDATE=1 said, yet the image read and updated (OI3)", MAKEFILE,
     "make orodruin-check la dit\"; exit 0; fi; \\\n",
     "make orodruin-check la dit\"; fi; \\\n"),
    ("M3638", "REF or NO_UPDATE from the environment taken (OI3)", MAKEFILE,
     '@case "$(origin REF) $(origin NO_UPDATE)" in *environment*)',
     '@case "$(origin REF) $(origin NO_UPDATE)" in *nowhere*)'),
    ("M3639", "orodruin-check never says the image is older (OI3)", MAKEFILE,
     '	 case "$$state" in older|absent|unreadable) echo "  ⚠ plus ancienne',
     '	 case "$$state" in never) echo "  ⚠ plus ancienne'),
]
TESTS = {
    "M3630": _OLDER,
    "M3631": _KEPT,
    "M3632": _KEPT,
    "M3633": _REPLACED,
    "M3634": _REPLACED,
    "M3635": _REPLACED,
    "M3636": _T + "test_a_failed_push_stops_nonzero_nothing_armed_the_vm_said_started",
    "M3637": _T + "test_no_update_starts_the_vm_and_says_it_reads_nothing",
    "M3638": _T + "test_values_refused_start_nothing_and_send_nothing",
    "M3639": _T + "test_the_check_says_the_image_and_the_latest_release_a_warning_never_a_refusal",
}
