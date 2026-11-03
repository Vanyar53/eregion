"""An orphan rule narrowed to the addresses of the VMs Glorfindel holds (U1G, #463).

A deny of a NIC that no longer exists may cut two live VMs: one Glorfindel isolates or
blocks — its NIC recreated, that rule may be the isolation its state wants (A3's first
review) — and one it holds for nothing, given another of the deleted NIC's addresses
since. The held VM kept the whole rule: the other stayed cut by a rule nobody owns (U1;
the machine, L1Qs' seed 10 at 500). The rule now loses the addresses of the VMs held for
nothing, and keeps the others — the held VM's flows unchanged. Only our exact addresses
are narrowed: a range, `*` or a tag is not read for who it takes in — kept whole, as
before. Read-only but for `_narrow_rule`, the one write.
"""
from __future__ import annotations

import ipaddress

from glorfindel.providers.azure.sdk import _enum_text
from glorfindel.response.policy import _ERR_MAX, _first_line


def _side_list(rule, side: str) -> list[str]:
    """The rule's addresses on `side` (its single prefix, then its list), as written."""
    single = getattr(rule, f"{side}_address_prefix", None)
    return [v for v in ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
            if v]


def _narrowed(rule, side: str, free: list[dict]) -> list[str] | None:
    """The addresses the rule keeps once those of `free` (the live NICs it cuts that
    Glorfindel holds for nothing) are taken out of it, or None when it can't be narrowed:
    a value that is not one exact address (`*`, a range, a tag — who it takes in is not
    read), or nothing left (then it holds no held VM: not narrowed, judged whole)."""
    values = _side_list(rule, side)
    for v in values:
        try:
            ipaddress.ip_address(v.strip())
        except ValueError:
            return None
    out = {h.get("ip") for h in free}
    keep = [v for v in values if v.strip() not in out]
    return keep if keep and len(keep) < len(values) else None


def _freed(cut: list[dict], narrow) -> list[dict]:
    """The NICs a narrowing frees: those it cuts at an address the rule no longer keeps."""
    keep = {ip.strip() for ip in narrow or []}
    return [h for h in cut if (h.get("ip") or "").strip() not in keep] if narrow else list(cut)


def _narrow_rule(network, nsg_rg: str, nsg_name: str, name: str, side: str, listed, keep) -> str | None:
    """Write the orphan rule `name` with `keep` as its addresses on `side` — read again by
    its name first: still a deny, its addresses those the listing saw (`listed`), else it
    stays as it is, said. None on success; else why it was not narrowed."""
    try:
        rule = network.security_rules.get(nsg_rg, nsg_name, name)
    except Exception as exc:
        return f"{nsg_rg}/{nsg_name}/{name} non relue avant de la réduire ({_first_line(exc)[:_ERR_MAX]})"
    now = sorted(v.strip() for v in _side_list(rule, side))
    if _enum_text(getattr(rule, "access", "")) != "deny" or now != sorted(v.strip() for v in listed or []):
        return f"{nsg_rg}/{nsg_name}/{name} a changé depuis la liste : jugée de nouveau au prochain passage"
    setattr(rule, f"{side}_address_prefix", None)
    setattr(rule, f"{side}_address_prefixes", list(keep))
    try:
        network.security_rules.begin_create_or_update(nsg_rg, nsg_name, name, rule).result()
    except Exception as exc:
        return f"{nsg_rg}/{nsg_name}/{name}: {_first_line(exc)[:_ERR_MAX]}"
    return None

