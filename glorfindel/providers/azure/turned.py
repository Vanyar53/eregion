"""Our rules someone turned into an allow, and the denies they wait behind (I5Q, #327).

A deny of a NIC that no longer exists cuts the VM given its address since; taking it off
frees that VM — unless one of our rules, turned into an allow by someone, waits behind it on
an NSG that governs that VM: the deny is then the last thing keeping out what our block
closes. The orphan sweep (sweep.py) keeps it and says it; the release of a deleted VM
(release.py) keeps it and says `release_partial`. Read-only here.
"""
from __future__ import annotations

from glorfindel.providers.azure.sdk import _enum_text
from glorfindel.response.ids import _parse_nic_resource_id, _parse_nsg_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line


def _turned_allows(nsgs) -> list[tuple[str, set, str, str, list]]:
    """Our rules, by their names, that someone turned into an allow (I5Q, #327): for
    each, its NSG, the subnets that NSG governs, the side of the NIC it protects
    ("destination" inbound, "source" outbound), its name, its addresses on that side."""
    out = []
    for nsg in nsgs:
        subnets = {s.id.rstrip("/").lower() for s in (getattr(nsg, "subnets", None) or []) if getattr(s, "id", None)}
        for r in (getattr(nsg, "security_rules", None) or []):
            name = getattr(r, "name", "") or ""
            if (not name.lower().startswith(("glorfindel-iso-", "glorfindel-block-"))
                    or _enum_text(getattr(r, "access", "")) != "allow"):
                continue
            side = "destination" if _enum_text(getattr(r, "direction", "")) == "inbound" else "source"
            single = getattr(r, f"{side}_address_prefix", None)
            values = ([single] if single else []) + list(getattr(r, f"{side}_address_prefixes", None) or [])
            out.append((nsg.id.rstrip("/").lower(), subnets, side, name, values))
    return out


def _takes_in(values: list, ip: str) -> bool:
    """An address field that takes `ip` in: empty, `*`, the address, a prefix holding
    it — or a tag, read as taking it in (the safe side: the deny stays)."""
    import ipaddress
    for v in [v for v in values if v] or ["*"]:
        if v == "*":
            return True
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(v, strict=False):
                return True
        except ValueError:
            return True                       # a tag (VirtualNetwork…): the safe side
    return False


def _chain(nic_nsg: dict, nic_subnets: dict):
    """`governs(holder, nsg_key, nsg_subnets)`: that NSG is the holder's NIC's own, or its subnet's."""
    def governs(h: dict, nsg_key: str, subnets: set) -> bool:
        nid = (h.get("nic_id") or "").rstrip("/").lower()
        return nic_nsg.get(nid) == nsg_key or bool(nic_subnets.get(nid, set()) & subnets)
    return governs


def _turned_behind(cut: list[dict], side: str, turned: list, governs) -> tuple[str, str, str] | None:
    """The first of our rules turned into an allow (I5Q, #327) that a deny of a NIC that no
    longer exists, cutting these NICs off, holds back: on the same side, aimed at the
    address of a NIC it cuts (or at all), on an NSG that `governs` that NIC. Taking the
    deny off would let through what that allow lets pass, which our block closes
    otherwise: the attacker reached a VM given a deleted VM's address and NSG, its
    subnet's perimeter block standing behind the turned rule. (NSG, rule, address), or
    None. Prudent by design: whether a probe would get through is not evaluated — a
    turned rule on another port is enough to keep the deny, said."""
    for h in cut:
        for nsg_key, subnets, t_side, name, values in turned:
            if t_side == side and governs(h, nsg_key, subnets) and _takes_in(values, h["ip"]):
                return nsg_key, name, h["ip"]
    return None


def _turned_text(t: tuple) -> str:
    nsg_key, name, ip = t
    return (f"notre règle {name} ({nsg_key.rsplit('/', 1)[-1]}), retournée en autorisation par quelqu'un, "
            f"vise {ip} : retirer ce refus laisserait passer ce qu'elle ouvre — la remettre en refus, ou la "
            "retirer ; la watch retire alors celle-ci")


def _behind_turned(cut: list[dict], side: str, turned: list, nic_nsg: dict, nic_subnets: dict) -> str:
    """_turned_behind, said; "": none."""
    t = _turned_behind(cut, side, turned, _chain(nic_nsg, nic_subnets))
    return _turned_text(t) if t else ""


def _governed_by(cut: list[dict], nic_nsg: dict, nic_subnets: dict, nsgs: list) -> None:
    """Each NIC cut gets the NSGs that govern it now (`governed_by`): what the removal
    reads again just before its write (_turned_still)."""
    subs = {n.id.rstrip("/").lower(): {s.id.rstrip("/").lower() for s in (getattr(n, "subnets", None) or [])
                                       if getattr(s, "id", None)} for n in nsgs}
    for h in cut:
        governs = _chain(nic_nsg, nic_subnets)
        h["governed_by"] = sorted(k for k, v in subs.items() if governs(h, k, v))


def _turned_still(network, orphan: dict) -> str:
    """The I5Q guard played again just before a removal (the listing may be a pass old):
    the NSGs that govern each NIC the rule cuts, read by their id — two at most per NIC.
    A read that fails keeps the rule: nothing found is not nothing there. "": remove."""
    keys = {k for h in orphan.get("cut") or [] for k in h.get("governed_by") or []}
    nsgs = []
    for k in sorted(keys):
        try:
            nsgs.append(network.network_security_groups.get(*_parse_nsg_resource_id(k)))
        except Exception as exc:
            return f"NSG {k.rsplit('/', 1)[-1]} non relu avant le retrait ({_first_line(exc)[:_ERR_MAX]})"
    t = _turned_behind(orphan.get("cut") or [], orphan.get("side") or "destination", _turned_allows(nsgs),
                       lambda h, k, _s: k in (h.get("governed_by") or ()))
    return _turned_text(t) if t else ""


def _turned_guard(network, nsgs: list):
    """The same guard for the writes that take off a deleted VM's denies by their names
    — its release, its unblock (I7S, I5R): a deny that holds back one of our rules turned
    into an allow, for the live NIC that holds its address now, stays (I5Q). Returns
    `why(nsg, rule) -> str` ("" to take it off). The NICs are listed only when a rule
    is turned; a listing that fails raises — nothing found is not nothing there."""
    turned = _turned_allows(nsgs)
    if not turned:
        return lambda nsg, rule, own="": ""
    nic_nsg: dict[str, str] = {}
    nic_subnets: dict[str, set] = {}
    holders: dict[str, str] = {}
    for nic in network.network_interfaces.list_all():
        nid = nic.id.rstrip("/").lower()
        nic_nsg[nid] = (getattr(getattr(nic, "network_security_group", None), "id", None) or "").rstrip("/").lower()
        for cfg in (nic.ip_configurations or []):
            if ip := getattr(cfg, "private_ip_address", None):
                holders[ip] = nid
            if subnet := getattr(getattr(cfg, "subnet", None), "id", None):
                nic_subnets.setdefault(nid, set()).add(subnet.rstrip("/").lower())

    def why(nsg, rule, own: str = "") -> str:
        # `own`: the NIC the rule was written for; holding the address, nothing waits.
        if _enum_text(getattr(rule, "access", "")) != "deny":
            return ""
        side = "destination" if _enum_text(getattr(rule, "direction", "")) == "inbound" else "source"
        single = getattr(rule, f"{side}_address_prefix", None)
        ips = [v for v in ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
               if v and v != "*"]
        k = nsg.id.rstrip("/").lower()
        subnets = {s.id.rstrip("/").lower() for s in (getattr(nsg, "subnets", None) or []) if getattr(s, "id", None)}
        cut = [{"ip": ip, "nic_id": holders[ip]} for ip in ips
               if ip in holders and holders[ip] != own.rstrip("/").lower()
               and (nic_nsg.get(holders[ip]) == k or nic_subnets.get(holders[ip], set()) & subnets)]
        return _behind_turned(cut, side, turned, nic_nsg, nic_subnets)
    return why


def _held_by_turned(network, cache: dict, nsg_rg: str, nsg_name: str, name: str, nic_id: str) -> str:
    """Why a rule a release's placement names stays (I5Q): a live NIC other than its own
    holds the address it denies now (its NIC gone), and one of our rules someone turned
    into an allow waits behind it (_turned_guard). The NSGs listed once per release
    (`cache`); unreadable, the rule stays — nothing found is not nothing there. "": take
    it off."""
    try:
        if "why" not in cache:
            nsgs = list(network.network_security_groups.list_all())
            cache["nsgs"] = {tuple(x.lower() for x in _parse_nsg_resource_id(n.id)): n for n in nsgs}
            cache["why"] = _turned_guard(network, nsgs)
        nsg = cache["nsgs"].get((nsg_rg.lower(), nsg_name.lower()))
        rule = next((r for r in (getattr(nsg, "security_rules", None) or [])
                     if (getattr(r, "name", "") or "").lower() == name.lower()), None)
        why = cache["why"](nsg, rule, nic_id) if rule is not None else ""
    except Exception as exc:
        # Unread: kept only if the placement's NIC is gone, or can't be read — a live VM's
        # own placement goes as before (its own address: nothing of another VM waits).
        why = f"NSG de l'abonnement illisibles, aucune règle retournée exclue ({_first_line(exc)[:_ERR_MAX]})"
        try:
            if nic_id and network.network_interfaces.get(*_parse_nic_resource_id(nic_id)) is not None:
                why = ""
        except Exception:
            pass
    return f"{nsg_rg}/{nsg_name}/{name} gardée : {why}" if why else ""
