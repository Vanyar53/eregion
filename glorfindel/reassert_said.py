"""What a block card of the reassertion says, from Azure's reading (out of reassert.py, I3P):
what is gone, and NIC by NIC what still holds — the perimeter included — what is open,
and what couldn't be read.
"""
from __future__ import annotations


def _block_drift(ip: str, vm: str, v: dict, again: bool = False, said: bool = False) -> str:
    """What a block's verification says is gone, and what still holds (RB1). Never « n'est
    plus bloquée » of an IP our perimeter (or the quarantine) still cuts off, nor of a NIC
    whose perimeter couldn't be read: that is said as unknown. `said`: the tail of a card
    whose head is already written (after a re-application).

    No NIC open nor unknown (I3P, #366): the IP is not said « plus bloquée » of the whole VM —
    where the perimeter holds, it « reste bloquée » (its own rules gone or passed by an
    allow, said beside it); NICs that couldn't be read — or whose own rules couldn't — it is
    not known, by name."""
    gone = [str(n) for n in (v.get("missing_rules") or v.get("held_missing") or [])]
    names = f" ({', '.join(gone)})" if gone else ""
    held, open_, unsure = (v.get("held_by_perimeter") or [], v.get("open_nics") or [],
                           v.get("perimeter_unread") or [])
    unknown = v.get("nics_unknown") or []        # their own rules unread: never left unsaid (I3P, review)
    by = f" par la règle de périmètre {v.get('perimeter_rule')}" if held else ""
    twice = " une deuxième fois" if again else ""
    if v.get("verified") is True:
        where = f" sur {', '.join(held)}{by}" if held else ""
        if said:
            return (f"l'IP reste bloquée{where}, mais il manque toujours{names}." if gone else
                    "Azure le relit entier, mais une écriture a échoué : à vérifier.")
        return f"Le blocage de {ip} sur {vm} a disparu d'Azure en partie{twice}{names} — l'IP reste bloquée{where}."
    if v.get("verified") is None or (v.get("shadowed_by") and not gone):
        what = ("contourné : une règle d'autorisation d'un tiers passe avant (carte à part)"
                if v.get("shadowed_by") else f"non vérifiable ({v.get('error') or 'illisible'})")
        return (what + ".") if said else f"Le blocage de {ip} sur {vm} a disparu d'Azure{twice} — {what}."
    head = "" if said else f"Le blocage de {ip} sur {vm} a disparu d'Azure{twice}{names} — "
    if open_:
        tail = f"l'IP n'est plus bloquée sur {', '.join(open_)}"
    elif unsure or unknown:
        tail = f"on ne sait pas si l'IP est encore bloquée sur {', '.join(unsure + unknown)}"
        unsure, unknown = [], []
    elif held:
        tail = f"l'IP reste bloquée sur {', '.join(held)}{by}" + (
            ", ses propres règles contournées (carte à part)" if v.get("shadowed_by") else "")
        held = []
    elif v.get("nics_unread"):
        tail = f"on ne sait pas si l'IP est encore bloquée : cartes illisibles ({v['nics_unread']})"
    else:
        tail = "l'IP n'est plus bloquée"
    tail += f" ; elle l'est encore sur {', '.join(held)}{by}" if held else ""
    tail += (f" ; sur {', '.join(unsure)}, son blocage ne tient plus et la règle de périmètre n'a pas pu être lue"
             if unsure else "")
    tail += f" ; sur {', '.join(unknown)}, ses règles n'ont pas pu être lues" if unknown else ""
    return head + tail + (f"{names}." if said else ".")


def _situation(v: dict) -> dict:
    """What a block card said (RB1, 4th review): the rules gone, the NICs still held, open,
    unknown, whether the IP stayed blocked — kept in the entry to tell a worse one."""
    return {"gone": sorted({str(n) for n in (v.get("missing_rules") or []) + (v.get("held_missing") or [])}),
            "held": sorted(v.get("held_by_perimeter") or []), "open": sorted(v.get("open_nics") or []),
            "unsure": sorted((v.get("perimeter_unread") or []) + (v.get("nics_unknown") or [])),
            "blocked": v.get("verified") is True, "rules": dict(v.get("rules_seen") or {})}


def _read_both(said: dict, now: dict) -> list[tuple]:
    """(as the card's check read it, as now) for each rule both checks read: its signature, None
    when absent (`rules_seen`, L1G). No record — an older entry, a provider that doesn't say: none."""
    before, after = said.get("rules") or {}, now.get("rules") or {}
    return [(before[k], after[k]) for k in sorted(before.keys() & after.keys())]


def _worse(said, now: dict) -> bool:
    """Worse than what the card said: blocked no more, a rule more gone, a NIC more open or
    unknown. Better or the same: nothing said again. No record (an older entry): as before.
    A rule more gone by what Azure holds, not by its name alone (L1G, #461): one the card read
    there — turned, or aimed at an address its NIC no longer has, and named « gone » for it — now
    deleted; said gone by name both times, its deletion went unsaid."""
    if not isinstance(said, dict):
        return False
    return bool((said.get("blocked") and not now["blocked"])
                or set(now["gone"]) - set(said.get("gone") or [])
                or set(now["open"]) - set(said.get("open") or [])
                or set(now["unsure"]) - set(said.get("unsure") or []) - set(said.get("open") or [])
                or any(was is not None and is_ is None for was, is_ in _read_both(said, now)))


def _pair_keys(b: dict) -> set[str]:
    """The keys (`rules_seen`) of the entry's perimeter pair — the one rule pair another entry writes
    too: one per IP and subnet, every entry of that IP and subnet names it. None for a VM block
    (`scoped` not False), nor for an entry that doesn't say where its pair is."""
    if b.get("scoped") is not False or not b.get("rule") or "/" not in (b.get("nsg") or ""):
        return set()
    return {f"{b['nsg']}/{b['rule']}{x}".lower() for x in ("", "-out")}


def _back(said, now: dict, pair: set[str] = frozenset()) -> bool:
    """A rule the card's check read absent is on Azure again (L1G): someone wrote it under our
    name since — Glorfindel itself, mostly: one VM's perimeter block writes the pair every entry
    of that IP and subnet names. And a rule of the perimeter pair (`pair`, its keys) the card said
    gone though it read it there — turned —, holding now in another form (L1H, #483): another
    entry's perimeter block wrote the pair over the turned one, the card had read it on Azure, and
    presence alone read nothing back. A VM's own rules are written by its own block alone, which
    ends the episode on its own (L1Q): turned, then set right in place, still nothing (RB1)."""
    if not isinstance(said, dict):
        return False
    before, after = said.get("rules") or {}, now.get("rules") or {}
    gone_then = {str(n).lower() for n in said.get("gone") or []}
    gone_now = {str(n).lower() for n in now.get("gone") or []}
    for k in sorted(before.keys() & after.keys()):
        was, is_ = before[k], after[k]
        if was is None and is_ is not None:
            return True
        # The pair's rules are judged by what they do alone (no address of a NIC): said gone while
        # read there, holding now, it was written again in another form.
        if k in pair and k.rsplit("/", 1)[-1] in gone_then - gone_now:
            return True
    return False


def _acknowledged(sid: str) -> bool:
    """The latest card of this alert (`sid`, exact) was closed by the operator — Glorfindel's own
    closures carry a note."""
    from glorfindel.reassert_cards import _history, same_sid
    last = next((e for e in reversed(_history()) if same_sid(e.get("signal_id"), sid)), None)
    return last is not None and last.get("status") == "resolved" and not last.get("resolution")


def still_said(b: dict, key: str, ip: str, sid: str, baseline, now: dict) -> bool:
    """A block's disappearance already said, nothing to write nor to say: its mark, its card pending
    or acknowledged (`drift_said`), no worse than the baseline — and, acknowledged, no rule of it
    written again since (L1G, #461). The operator acknowledged what the card said; another VM's
    perimeter block wrote the pair both entries name, the VM's own rules still gone: read « better,
    not worse », the disappearance stayed unsaid. A rule written again ends the episode, as a block
    written again does (L1Q): what is still gone is said anew — the pair the card read turned too,
    holding again (L1H, #483). A VM's own rule set right by hand, without being deleted, still says
    nothing (RB1); under a pending card, what came back narrows the baseline (L1Q), as before."""
    from glorfindel.reassert_cards import drift_said
    return (bool(b.get("drift_alerted_at")) and not _worse(baseline, now)
            and not (_back(baseline, now, _pair_keys(b)) and _acknowledged(sid)) and drift_said(key, ip, sid))
