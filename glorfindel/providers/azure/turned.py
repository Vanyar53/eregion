"""Our rules someone turned into an allow, and the denies they wait behind (I5Q, #327).

A deny of a NIC that no longer exists cuts the VM given its address since; taking it off
frees that VM — unless one of our rules, turned into an allow by someone, waits behind it on
an NSG that governs that VM: the deny is then the last thing keeping out what our block
closes. The orphan sweep (sweep.py) keeps it and says it; the release of a deleted VM
(release.py) keeps it and says `release_partial`. Read-only here.
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _takes_in      # I4A's, one rule for both
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
    into an allow, for the live NIC that holds its address now, stays (I5Q). And since
    I4B, every removal of a rule of ours by its name — the unblock, the reset, the
    release, a live VM's too: one of our rules someone turned into an allow, that lets
    through to another live NIC what it opens, stays as well (_opens_another) — taken
    off, that VM lost those flows. Returns `why(nsg, rule, own, mates) -> str` ("" to
    take it off; `own`, `mates`: the NIC the rule was written for, and its VM's other
    NICs). The NICs are listed only when a rule is turned; a listing that fails raises
    — nothing found is not nothing there."""
    turned = _turned_allows(nsgs)
    if not turned:
        return lambda nsg, rule, own="", mates=(): ""
    holders, nic_nsg, nic_subnets = _nic_maps(network)

    def why(nsg, rule, own: str = "", mates=()) -> str:
        # `own`: the NIC the rule was written for; holding the address, nothing waits.
        if _enum_text(getattr(rule, "access", "")) != "deny":
            return _opens_another(nsg, rule, {own, *mates}, holders, nic_nsg, nic_subnets)
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


def _held_by_turned(network, cache: dict, nsg_rg: str, nsg_name: str, name: str, nic_id: str,
                    mates=()) -> str:
    """Why a rule a release's placement names stays (I5Q): a live NIC other than its own
    holds the address it denies now (its NIC gone), and one of our rules someone turned
    into an allow waits behind it (_turned_guard) — or the rule is itself one of ours
    turned into an allow that opens another live NIC (I4B). Every removal of ours by a
    rule's name asks it (I4B: the unblock, the reset, the release's sweep too). The NSGs
    listed once per operation (`cache`); unreadable, the rule stays — nothing found is
    not nothing there. `mates`: the other NICs of the rule's VM. "": take it off."""
    try:
        if "why" not in cache:
            nsgs = list(network.network_security_groups.list_all())
            cache["nsgs"] = {tuple(x.lower() for x in _parse_nsg_resource_id(n.id)): n for n in nsgs}
            cache["why"] = _turned_guard(network, nsgs)
        nsg = cache["nsgs"].get((nsg_rg.lower(), nsg_name.lower()))
        rule = next((r for r in (getattr(nsg, "security_rules", None) or [])
                     if (getattr(r, "name", "") or "").lower() == name.lower()), None)
        why = cache["why"](nsg, rule, nic_id, mates) if rule is not None else ""
    except Exception as exc:
        # Unread: kept unless the placement's NIC, alive, still holds every address the rule
        # denies — a live VM's own placement then goes as before (its own addresses: nothing
        # of another VM waits). Its NIC gone, unread, or an address moved: kept.
        why = f"NSG de l'abonnement illisibles, aucune règle retournée exclue ({_first_line(exc)[:_ERR_MAX]})"
        try:
            if nic_id and _holds_all(network, nsg_rg, nsg_name, name, nic_id):
                why = ""
        except Exception:
            pass
    return f"{nsg_rg}/{nsg_name}/{name} gardée : {why}" if why else ""


def _holds_all(network, nsg_rg: str, nsg_name: str, name: str, nic_id: str) -> bool:
    """The rule, read by its name, denies only addresses this NIC holds now (I5Q, its
    second review). Raises if either can't be read."""
    nic = network.network_interfaces.get(*_parse_nic_resource_id(nic_id))
    held = {getattr(c, "private_ip_address", None) for c in (getattr(nic, "ip_configurations", None) or [])}
    rule = network.security_rules.get(nsg_rg, nsg_name, name)
    side = "destination" if _enum_text(getattr(rule, "direction", "")) == "inbound" else "source"
    single = getattr(rule, f"{side}_address_prefix", None)
    ips = [v for v in ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
           if v and v != "*"]
    return bool(ips) and set(ips) <= held


def _side_values(rule) -> list[str]:
    """The addresses of the rule's own side: the NIC's (destination inbound, source outbound)."""
    side = "destination" if _enum_text(getattr(rule, "direction", "")) == "inbound" else "source"
    single = getattr(rule, f"{side}_address_prefix", None)
    return [v for v in ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
            if v]


def _aims_elsewhere(rule, own_ips) -> bool:
    """Whether the guard must be asked before this rule of ours goes (I4B): it names, on
    its own side, an address that is not one of `own_ips` (the NIC's, as read now). A
    deny: an exact address — `*` or a prefix holds no other NIC's address the guard can
    name (_turned_guard). Anything else (an allow someone made of it): any value, `*`, a
    range or a tag included. All its own: nothing of another VM's hangs on it."""
    own = {ip.strip().lower() for ip in own_ips or [] if ip}
    values = [v.strip().lower() for v in _side_values(rule)]
    if _enum_text(getattr(rule, "access", "")) == "deny":
        return any(v not in own and v not in ("*", "any") for v in values)
    return any(v not in own for v in values or ["*"])


def _opens_another(nsg, rule, own: set, holders: dict, nic_nsg: dict, nic_subnets: dict) -> str:
    """One of our rules someone turned into an allow (I4B, #333) lets through what it names
    to the NICs its NSG governs: taken off, a live NIC other than `own` (the rule's NIC,
    its VM's others) loses those flows — the VM given an address the rule's NIC had,
    whose flows an operation on another VM must not change (I4). It reaches that NIC
    when it names its address, or any address (`*`) on an NSG that governs it; a range or
    a tag: who it takes in is not read — kept too (A0). Why it stays, or ""."""
    import ipaddress
    mine = {o.rstrip("/").lower() for o in own if o}
    k = (getattr(nsg, "id", "") or "").rstrip("/").lower()
    subnets = {s.id.rstrip("/").lower() for s in (getattr(nsg, "subnets", None) or []) if getattr(s, "id", None)}

    def governed(nid: str) -> bool:
        return nic_nsg.get(nid) == k or bool(nic_subnets.get(nid, set()) & subnets)

    name = getattr(rule, "name", "") or ""
    for v in _side_values(rule) or ["*"]:
        low = v.strip().lower()
        if low in ("*", "any", "0.0.0.0/0"):
            others = sorted(n for n in nic_nsg if n not in mine and governed(n))
            if others:
                return _opens_text(name, v, f"toutes les cartes derrière ce NSG, dont {others[0].rsplit('/', 1)[-1]}")
            continue
        try:
            ipaddress.ip_address(low)
        except ValueError:
            return _opens_text(name, v, "inconnu (une plage ou une étiquette : qui elle prend n'est pas lu)")
        nid = holders.get(v.strip())
        if nid and nid not in mine and governed(nid):
            return _opens_text(name, v, f"l'adresse de {nid.rsplit('/', 1)[-1]} maintenant")
    return ""


def _opens_text(name: str, to: str, on: str) -> str:
    return (f"notre règle {name}, retournée en autorisation par quelqu'un, vise {to} — {on} : la retirer "
            "retirerait à cette VM ce qu'elle lui ouvre — la remettre en refus, ou la retirer à la main "
            "si elle n'est plus voulue")


def _nic_maps(network) -> tuple[dict, dict, dict]:
    """The subscription's NICs, listed: (address → NIC, NIC → its own NSG, NIC → its
    subnets), ids in lowercase. Raises if they can't be listed."""
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
    return holders, nic_nsg, nic_subnets


def _waits_for(network, cache: dict, side: str, addr: str, own: str) -> bool:
    """Whether one of our rules someone turned into an allow, ANYWHERE in the subscription,
    waits behind a deny of ours on `addr` (I4B, the lot's fourth point: one guard): on an
    NSG that governs the NIC holding `addr` now — not `own` —, on `side`, taking `addr` in
    (_takes_in). The block's rewrite (I4A) read only the NIC's own block rules, on its own
    NSGs: an isolation rule turned, or a rule on the holder's other NSG, was not seen. The
    NSGs and NICs listed once per operation (`cache`); unreadable: True — keeping our deny
    never opens anything (A0)."""
    try:
        if "world" not in cache:
            turned = _turned_allows(list(network.network_security_groups.list_all()))
            cache["world"] = (turned, *(_nic_maps(network) if turned else ({}, {}, {})))
        turned, holders, nic_nsg, nic_subnets = cache["world"]
    except Exception:
        return True
    nid = holders.get(addr)
    if not turned or not nid or nid == own.rstrip("/").lower():
        return False
    return _turned_behind([{"ip": addr, "nic_id": nid}], side, turned, _chain(nic_nsg, nic_subnets)) is not None
