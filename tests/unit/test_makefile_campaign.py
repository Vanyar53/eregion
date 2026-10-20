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


def test_campaign_plan_does_not_echo_the_target():
    # CAMPAIGN_TARGET is a resource_id that carries the subscription: the recipe line that
    # holds it is silenced with @ (convention of orodruin-stop), and prints a neutral line.
    lines = [ln for ln in _recipe("orodruin-campaign-plan") if "$(CAMPAIGN_TARGET)" in ln]
    assert lines
    for line in lines:
        assert line.startswith("\t@"), f"echoed with the subscription: {line!r}"
    ssh_line = next(ln for ln in lines if "annatar campaign plan" in ln)
    assert ssh_line.startswith('\t@echo "'), "a neutral line is printed instead"
