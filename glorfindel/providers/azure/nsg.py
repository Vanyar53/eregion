"""Reading NSG security rules by content: what a rule covers, whether a deny isolates
or blocks, which allows are evaluated before it, rule names (moved from actions.py, A1).

Pure functions over the SDK's rule objects (read by attribute): nothing calls Azure.
"""
from __future__ import annotations

from glorfindel.providers.azure.sdk import _enum_text


def _prefix_covers(prefix: str, ip: str) -> bool:
    """Does one NSG address prefix (CIDR, IP, '*', service tag) include this IP?

    Approximations, chosen for the IPs Glorfindel reasons about: `VirtualNetwork` covers
    private addresses (a VM's own IPs are always in it), `Internet` covers public ones.
    Other service tags (Storage, AzureCloud…) name Azure public ranges, never a VM's IP.
    """
    import ipaddress
    p = (prefix or "").strip()
    low = p.lower()
    if low in ("*", "any"):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if low == "virtualnetwork":
        return addr.is_private
    if low == "internet":
        return not addr.is_private
    try:
        return addr in ipaddress.ip_network(p, strict=False)
    except ValueError:
        return False


def _side_covers(rule, side: str, ips: list[str] | None) -> bool:
    """Does the rule's `side` ('source' | 'destination') include one of `ips`?

    ips=None means "any address" (a subnet-wide block has no destination scope).
    Application security groups can't be resolved here: assume they may cover
    (conservative — flag rather than miss a bypass).
    """
    if ips is None:
        return True
    if getattr(rule, f"{side}_application_security_groups", None):
        return True
    single = getattr(rule, f"{side}_address_prefix", None)
    values = ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
    if not values:
        return True
    if ips == "public":
        # Readiness check, attacker not known yet: a rule open to ANY internet source.
        # An allow from a specific address (admin access) is a deliberate trust choice,
        # unlikely to be the attacker — not flagged.
        return any(_prefix_open_to_internet(v) for v in values)
    return any(_prefix_covers(v, ip) for v in values for ip in ips)


def _prefix_open_to_internet(prefix: str) -> bool:
    return (prefix or "").strip().lower() in ("*", "any", "internet", "0.0.0.0/0", "::/0")


def _rule_covers_port(rule, port: int) -> bool:
    """Does this rule's destination port range include `port`? (`*`, `22`, `20-30`)"""
    ranges = [getattr(rule, "destination_port_range", None)]
    ranges += list(getattr(rule, "destination_port_ranges", None) or [])
    for pr in ranges:
        pr = str(pr or "").strip()
        if not pr:
            continue
        if pr in ("*", "any", "Any"):
            return True
        try:
            if "-" in pr:
                lo, hi = (int(x) for x in pr.split("-", 1))
                if lo <= port <= hi:
                    return True
            elif int(pr) == port:
                return True
        except ValueError:
            return True       # unreadable range: assume it covers (fail closed)
    return False


def _shadowing_rules(
    rules, priority: int | dict, *, inbound_src: list[str] | None, inbound_dst: list[str] | None,
    outbound_src: list[str] | None, outbound_dst: list[str] | None, port: int | None = None,
) -> list[dict]:
    """Customer ALLOW rules evaluated before a Glorfindel deny placed at `priority`.

    NSG rules run by ascending priority and the first match wins: an allow at a lower
    number than our deny lets its traffic through, deny or not. Found on the Celebrimbor
    bench (2026-10-05): `allow-ssh` (Inbound, *, port 22) sits at priority 100, so every
    IP-scoped isolation (deny at 101+) left SSH open, and every IP block (200+) let an
    SSH brute force continue — while the presence-only verification said verified=True.

    For each direction, a rule shadows the deny when its source AND destination cover
    the deny's source and destination (None = any).

    `port` (a block whose threat port is known, e.g. 22 for an SSH brute force): every
    shadowing allow is still reported, but `threat_port_open` says whether it lets the
    THREAT through (an inbound allow covering that port) or only leaves other ports
    reachable. Without it, a web server's `allow-https` declared every SSH block
    bypassed — the alert operators learn to ignore. An OUTBOUND allow before the deny
    always lets the threat through: the VM still reaches the attacker, on any port (a
    reverse shell, exfiltration) — it was counted as mere exposure (A0). Isolation
    passes no port: any allow before the deny defeats it.

    `priority`: one number for a deny about to be placed (both directions take it), or
    {"inbound": …, "outbound": …} for denies in place — each direction's own rule.
    """
    found: list[dict] = []
    for r in rules or []:
        name = getattr(r, "name", "") or ""
        prio = getattr(r, "priority", None)
        direction = _enum_text(getattr(r, "direction", ""))
        limit = priority.get(direction) if isinstance(priority, dict) else priority
        # Glorfindel never places an allow in a customer NSG: an allow named like ours is
        # someone else's, and lets its traffic through like any other (sixth review, S2).
        if not isinstance(prio, int) or not isinstance(limit, int) or prio >= limit:
            continue
        if _enum_text(getattr(r, "access", "")) != "allow":
            continue
        if direction == "inbound":
            src, dst = inbound_src, inbound_dst
        elif direction == "outbound":
            src, dst = outbound_src, outbound_dst
        else:
            continue
        if _side_covers(r, "source", src) and _side_covers(r, "destination", dst):
            found.append({
                "rule": name, "priority": prio, "direction": _enum_text(getattr(r, "direction", "")),
                "ports": getattr(r, "destination_port_range", None)
                or ",".join(getattr(r, "destination_port_ranges", None) or []) or "*",
                "threat_port_open": (
                    port is None or direction == "outbound" or _rule_covers_port(r, port)),
            })
    return found


def _report_block_shadowing(out: dict, ip: str, shadowed: list[dict]) -> None:
    """Add a block's precedence findings to its outcome: `bypass` when an allow lets
    the threat through, `exposure` when other ports only stay reachable."""
    if not shadowed:
        return
    out["shadowed_by"] = shadowed
    bypass = [x for x in shadowed if x.get("threat_port_open", True)]
    exposure = [x for x in shadowed if not x.get("threat_port_open", True)]
    if bypass:
        out["bypass"] = (f"Blocage de {ip} contourné : " + _describe_shadowing(bypass)
                         + " passe avant le deny de Glorfindel.")
    if exposure:
        out["exposure"] = (f"Port de la menace bloqué ; {ip} atteint encore d'autres ports : "
                           + _describe_shadowing(exposure) + ".")


def _describe_shadowing(found: list[dict]) -> str:
    return ", ".join(
        f"'{f['rule']}' (priorité {f['priority']}, {f['direction']}, ports {f['ports']})" for f in found)


def _ip_scoped(target: dict) -> bool:
    """True when the deny must be addressed to the VM's own IPs.

    That is the case on any NSG that also governs other NICs: a subnet NSG, or a
    NIC-level NSG shared with other NICs. An any/any deny there would cut off every VM
    behind it. Older target dicts carry no `ip_scoped` key: fall back to the scope.
    """
    return target.get("ip_scoped", target.get("scope") == "subnet")


def _scope_to_nic(target: dict) -> bool:
    """A deny placed for one NIC addresses that NIC's IPs — on a dedicated NSG too.

    Any/any was used on an NSG governing this NIC alone, as read at that moment. A NIC
    of another VM away in quarantine (L4) doesn't show on its NSG: a "tier" NSG shared
    by two VMs read as dedicated while one was isolated, took an any/any, and the other
    VM found itself cut off when its own release put it back (L24). Addressed to the
    NIC's IPs, the deny holds the same for this VM and can't reach any other, now or
    later. Without a private IP to address, only an NSG that is not shared takes it."""
    return bool(target.get("private_ips")) or _ip_scoped(target)


def _nic_hash(nic_id: str, size: int) -> str:
    import hashlib
    return hashlib.sha1(nic_id.rstrip("/").lower().encode()).hexdigest()[:size]


def _rule_name(rule) -> str:
    return getattr(rule, "name", "") or ""


def _pair_priorities(rules, in_name: str, out_name: str, start: int, step: int,
                     taken=frozenset()) -> dict:
    """Priorities for a deny pair about to be written — {"inbound": …, "outbound": …}.

    The first number free on the NSG (our two names don't count: rewriting a rule frees
    its own place), unless one of our rules already holds an earlier one in its
    direction: it keeps it. A rewrite moves a deny up, never down. Moved down, it fell
    behind an allow it used to precede: the reassertion put a perimeter block back at
    220, under an allow at 210 — a block rule someone had turned around —, and the
    attacker reached the VM on every port (I5R, invariant machine). `taken`: numbers
    already given by this operation on the same NSG."""
    own = {in_name.lower(): "inbound", out_name.lower(): "outbound"}
    used = {r.priority for r in rules or [] if _rule_name(r).lower() not in own} | set(taken)
    first = next(p for p in range(start, 4000, step) if p not in used)
    out = {"inbound": first, "outbound": first}
    for r in rules or []:
        prio, direction = getattr(r, "priority", None), own.get(_rule_name(r).lower())
        # Ours only where Azure has it in the direction we write it: there, no other
        # rule can hold its number.
        if (direction and isinstance(prio, int) and prio < out[direction]
                and _enum_text(getattr(r, "direction", "")) == direction):
            out[direction] = prio
    return out


def _side_is_any(rule, side: str) -> bool:
    single = getattr(rule, f"{side}_address_prefix", None)
    values = ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
    return not values or any((v or "").strip().lower() in ("*", "any", "0.0.0.0/0") for v in values)


def _deny_applies(rule, ips: list[str] | None) -> bool:
    """A Glorfindel deny that applies to this NIC: its own side (destination inbound,
    source outbound) includes one of the NIC's addresses, or any address. A rule of the
    same name scoped to OTHER addresses belongs to another VM — a homonym behind the
    same NSG (L24) — and is neither this NIC's isolation nor ours to delete."""
    if _enum_text(getattr(rule, "access", "")) != "deny":
        return False
    side = "destination" if _enum_text(getattr(rule, "direction", "")) == "inbound" else "source"
    return _side_covers(rule, side, ips or None)


def _nic_owns(rule, hashed: set[str], names: set[str], ips: list[str] | None) -> bool:
    """A deny of this NIC's, to remove. Named with the NIC's hash (`hashed`, unique to
    the NIC): its own, whatever addresses it covers now — the NIC's IP may have changed
    since, and a deny left on the old address would cut off whoever gets it next (L26).
    One of the older names (`names`, shared by homonyms): only if it applies to the
    NIC's addresses (L24)."""
    name = _rule_name(rule).lower()
    if name in hashed:
        # Only Glorfindel names a rule with a NIC's hash: whatever it has been turned
        # into (an allow, by hand), it goes with the NIC's release (A0).
        return True
    return _enum_text(getattr(rule, "access", "")) == "deny" and name in names and _deny_applies(rule, ips)


def _deny_isolates(rule, direction: str, ips: list[str] | None) -> bool:
    """This deny cuts ALL of the NIC's traffic in `direction`: every protocol and port,
    any peer, each of the NIC's addresses. Presence by name was taken as proof: a
    homonym's rule, or ours narrowed by hand, read as an isolation (L24)."""
    if (_enum_text(getattr(rule, "access", "")) != "deny"
            or _enum_text(getattr(rule, "direction", "")) != direction
            or _enum_text(getattr(rule, "protocol", "*")) not in ("*", "any", "")):
        return False
    if not _covers_all_ports(rule):
        return False
    own, peer = ("destination", "source") if direction == "inbound" else ("source", "destination")
    if not _side_is_any(rule, peer):
        return False
    return all(_side_covers(rule, own, [ip]) for ip in ips) if ips else _side_is_any(rule, own)


def _prefixes(rule, side: str) -> tuple:
    single = getattr(rule, f"{side}_address_prefix", None)
    values = ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
    return tuple(sorted({(v or "").strip().lower() for v in values}))


def _rule_signature(rule) -> tuple:
    """What a security rule does, without its name: two rules of the same signature
    filter the same traffic. Checking our quarantine rules by name only let a deny
    turned into an allow, moved to priority 4000 or narrowed to one address pass
    (fourth review, Q6)."""
    ports = [getattr(rule, "destination_port_range", None)] + list(getattr(rule, "destination_port_ranges", None) or [])
    return (_enum_text(getattr(rule, "access", "")), _enum_text(getattr(rule, "direction", "")),
            getattr(rule, "priority", None), _enum_text(getattr(rule, "protocol", "")),
            _prefixes(rule, "source"), _prefixes(rule, "destination"),
            tuple(sorted({str(p).strip().lower() for p in ports if p})))


def _covers_all_ports(rule) -> bool:
    ports = [getattr(rule, "destination_port_range", None)] + list(getattr(rule, "destination_port_ranges", None) or [])
    return any(str(p or "").strip().lower() in ("*", "any", "0-65535") for p in ports)


def _deny_blocks(rule, direction: str, ip: str, ips: list[str] | None) -> bool:
    """This rule is a block of `ip` for these addresses in `direction`: a deny, every
    protocol and port, the attacker on its side, each of the NIC's addresses (any, for
    a perimeter block) on the other. Checked by name only, a block turned into an
    allow, or pointed at another address, passed (sixth review, S2)."""
    if (_enum_text(getattr(rule, "access", "")) != "deny"
            or _enum_text(getattr(rule, "direction", "")) != direction
            or _enum_text(getattr(rule, "protocol", "*")) not in ("*", "any", "")
            or not _covers_all_ports(rule)):
        return False
    attacker, own = ("source", "destination") if direction == "inbound" else ("destination", "source")
    if not _side_covers(rule, attacker, [ip]):
        return False
    return all(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)
