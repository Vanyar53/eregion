"""OI3 (#522): make orodruin-start brings Orodruin up to the latest release, verified — the image in
service (~/.eregion-image, :orodruin) read back, compared on the workstation to the latest tag v* by
version order then by commit in git's history (scripts/published_image.py age), the verified push
when it is older, absent or unreadable, kept when newer; make orodruin-check says it. M3630–M3639,
and the review's M3685–M3693 (the update's SSH, docker down, the tag's label, what is checked before
the VM starts, the wait, the dry run).
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
     'case "$$state" in older) w="plus ancienne";;',
     'case "$$state" in older) w="";;'),
    # The review of OI3 (M3685–M3693).
    ("M3685", "the update's read of the image through a bare ssh: no pinned key, no ed25519 only (OI3)", MAKEFILE,
     '{ rc=0; $(ORO_SSH) $(ORO_IMAGE_READ) || rc=$$?;',
     '{ rc=0; ssh $(ORO_USER)@$(ORO_IP) $(ORO_IMAGE_READ) || rc=$$?;'),
    ("M3686", "orodruin-update without orodruin-known: Orodruin's host key never checked (OI3)", MAKEFILE,
     "orodruin-update: orodruin-known\n", "orodruin-update:\n"),
    ("M3687", "a docker that does not answer read as an image absent: pushed, ~/.eregion-image erased (OI3)",
     MAKEFILE, "'docker info >/dev/null 2>&1 || exit 5; ", "'"),
    ("M3688", "a verified marker trusted though its tag says another commit: never pushed (OI3)", PIM,
     "    if revision is not None and revision != commit:\n", "    if False:\n"),
    ("M3689", "ORO_SSH_FINGERPRINT checked only after the VM started (OI3)", MAKEFILE,
     '@[ "$$EREGION_NO_UPDATE" = 1 ] || case "$$EREGION_ORO_FINGERPRINT" in',
     '@true || case "$$EREGION_ORO_FINGERPRINT" in'),
    ("M3690", "ORO_CHECK_TIMEOUT checked only after the VM started (OI3)", MAKEFILE,
     "@case \"$$EREGION_CHECK_TIMEOUT\" in 0*|*[!0-9]*|'') echo \"ORO_CHECK_TIMEOUT invalide : « "
     "$$EREGION_CHECK_TIMEOUT » (des secondes, au moins 1) : rien n'est démarré\"",
     "@case \"$$EREGION_CHECK_TIMEOUT\" in x-never) echo \"ORO_CHECK_TIMEOUT invalide : « "
     "$$EREGION_CHECK_TIMEOUT » (des secondes, au moins 1) : rien n'est démarré\""),
    ("M3691", "the start never waits for the VM to answer (OI3)", MAKEFILE,
     'until ssh-keyscan -T 5 -t ed25519 "$(ORO_IP)" 2>/dev/null | grep -q .;', "until true;"),
    ("M3692", "orodruin-check never says an image absent (OI3)", MAKEFILE,
     'absent) w="absente";; ', ""),
    ("M3693", "the sub-make written $(MAKE) in the recipe: make -n starts the VM (OI3)", MAKEFILE,
     "	 $(ORO_SUBMAKE) orodruin-update ||", "	 $(MAKE) --no-print-directory orodruin-update ||"),
]
_H = "tests/unit/test_host_ssh.py::"
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
    "M3685": _H + "test_the_update_s_ssh_takes_the_pinned_key_alone",
    "M3686": _H + "test_the_update_s_ssh_takes_the_pinned_key_alone " + _H + "test_the_update_without_its_fingerprint_sends_nothing",
    "M3687": _T + "test_a_docker_that_does_not_answer_is_never_taken_for_an_absent_image",
    "M3688": _T + "test_a_verified_marker_whose_tag_says_another_commit_is_unreadable_the_release_pushed",
    "M3689": _T + "test_what_the_update_needs_is_checked_before_the_vm_starts",
    "M3690": _T + "test_what_the_update_needs_is_checked_before_the_vm_starts",
    "M3691": _T + "test_a_vm_that_never_answers_stops_nonzero_nothing_sent",
    "M3692": _T + "test_the_check_says_an_image_absent_or_unreadable_too",
    "M3693": _T + "test_a_dry_run_of_the_start_runs_nothing",
}
