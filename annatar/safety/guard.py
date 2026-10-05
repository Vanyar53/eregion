from dataclasses import dataclass


REQUIRED_TAG_KEY = "annatar-test"
REQUIRED_TAG_VALUE = "true"


@dataclass
class GuardResult:
    allowed: bool
    reason: str = ""


def check_resource_group(rg_tags: dict) -> GuardResult:
    """Refuse execution if resource group is not tagged for chaos testing."""
    val = rg_tags.get(REQUIRED_TAG_KEY, "").lower()
    if val != REQUIRED_TAG_VALUE:
        return GuardResult(
            allowed=False,
            reason=(
                f"Resource group missing tag '{REQUIRED_TAG_KEY}={REQUIRED_TAG_VALUE}'. "
                "Add this tag explicitly to authorize chaos testing."
            ),
        )
    return GuardResult(allowed=True)


def check_vm(vm_tags: dict) -> GuardResult:
    """Refuse execution if VM is not tagged for chaos testing."""
    val = vm_tags.get(REQUIRED_TAG_KEY, "").lower()
    if val != REQUIRED_TAG_VALUE:
        return GuardResult(
            allowed=False,
            reason=(
                f"VM missing tag '{REQUIRED_TAG_KEY}={REQUIRED_TAG_VALUE}'. "
                "Tag this VM explicitly to authorize chaos testing."
            ),
        )
    return GuardResult(allowed=True)


def check_target(rg_tags: dict, vm_tags: dict) -> GuardResult:
    """Both gates: the resource group AND the VM must carry the chaos authorization.

    The RG tag alone authorized attacks on EVERY VM of that group — including an
    untagged production VM sharing it. `check_vm` existed but had no call site.
    """
    rg = check_resource_group(rg_tags)
    if not rg.allowed:
        return rg
    return check_vm(vm_tags)
