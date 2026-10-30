"""The Make targets that plan and run a campaign from Orodruin (#165).

Read from the Makefile, like tests/unit/test_models.py does: no make, no ssh, no Azure.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")


def _recipe(target: str) -> list[str]:
    """The recipe lines (tab-indented) of ``target``."""
    lines = MAKEFILE.splitlines()
    start = lines.index(f"{target}:")
    recipe = []
    for line in lines[start + 1:]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return recipe


def test_campaign_targets_exist_and_are_phony():
    for target in ("orodruin-campaign-plan", "orodruin-campaign-run"):
        assert re.search(rf"^{target}:$", MAKEFILE, re.M), f"{target} missing"
        phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
        assert target in phony, f"{target} not in .PHONY"


def test_campaign_targets_run_annatar_campaign_in_the_orodruin_image():
    plan = "\n".join(_recipe("orodruin-campaign-plan"))
    run = "\n".join(_recipe("orodruin-campaign-run"))
    assert "$(ORO_RUN) annatar campaign plan" in plan
    assert '--target "$(CAMPAIGN_TARGET)"' in plan
    assert "$(ORO_RUN) annatar campaign run $(CAMPAIGN) --yes" in run


def test_campaign_targets_have_their_help_lines():
    help_ = "\n".join(_recipe("help"))
    assert "make orodruin-campaign-plan" in help_
    assert "make orodruin-campaign-run" in help_


def test_bl1_targets_check_what_reaches_the_shell():
    """BL1 (#280): the declared campaign and the containment targets, phony, with the names they
    pass checked before any ssh — a campaign id or a run id is a plain name, a declaration a path
    under the image without « .. »."""
    phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
    lines = MAKEFILE.splitlines()
    for target in ("campaign-containment", "glorfindel-host-containment"):
        start = next(i for i, ln in enumerate(lines) if ln.split(" ")[0] == f"{target}:")
        recipe = "\n".join(ln for ln in lines[start + 1:start + 4] if ln.startswith("\t"))
        assert target in phony
        assert '*[!A-Za-z0-9._,-]*) echo "CAMPAIGN ou FAULT_RUNS invalide"; exit 1' in recipe
        assert "analysis.containment runs/campaigns/$(CAMPAIGN)" in recipe
    plan = _recipe("orodruin-campaign-plan")
    check = next(i for i, ln in enumerate(plan) if "CAMPAIGN_DECLARED invalide" in ln)
    run = next(i for i, ln in enumerate(plan) if "annatar campaign plan" in ln)
    assert check < run and "*..*" in plan[check]
    assert "--declared /app/$(CAMPAIGN_DECLARED)" in plan[run]


def test_campaign_plan_does_not_echo_the_target():
    # CAMPAIGN_TARGET is a resource_id that carries the subscription: the recipe line that
    # holds it is silenced with @ (convention of orodruin-stop), and prints a neutral line.
    lines = [ln for ln in _recipe("orodruin-campaign-plan") if "$(CAMPAIGN_TARGET)" in ln]
    assert lines
    for line in lines:
        assert line.startswith("\t@"), f"echoed with the subscription: {line!r}"
    ssh_line = next(ln for ln in lines if "annatar campaign plan" in ln)
    assert ssh_line.startswith('\t@echo "'), "a neutral line is printed instead"
