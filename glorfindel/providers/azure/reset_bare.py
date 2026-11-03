"""`glorfindel reset --from-azure`'s bare NICs: a NIC left with no NSG after our quarantine NSG
was taken off it — its original found (state first, then our tag), its rules swept on it, then
put back (moved from sweep.py, I3V).
"""
from __future__ import annotations

from glorfindel.response.ids import _same_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import _held_in_quarantine, _recorded_original, _UNKNOWN, StateUnreadable


class ResetBareMixin:
    """_reset_bare_nics, _reset_put_back_bare (part of AzureConnector)."""

    def _reset_bare_nics(self, targets: list[dict], rg: str, views: list[dict], failed_early: list[str]) -> dict:
        """The reset's bare NICs: NIC id → (its original, the quarantine NSG whose tag names
        it); each original's view added to `views`, what can't be settled to `failed_early`."""
        # A NIC left bare after our NSG was taken off it: its original comes back below
        # (state first, then our tag — as the release does, L27/L28). Its rules are swept
        # too: an older version's isolation there stayed, and the VM, "swept", was still
        # cut off (A0). From the tag only, a lost tag made the reset skip the NIC, say
        # `swept` and clear the state that knew it (A0, seed 3).
        bare: dict = {}
        for t0 in targets:
            if t0.get("quarantine") or t0.get("own_nsg_id"):
                continue
            try:
                recorded = _recorded_original(t0["nic_id"])
            except StateUnreadable as exc:
                # A state that can't be read may record it: bare by design or not is
                # unknown — nothing put back, nothing cleared (SEC4b).
                failed_early.append(f'{t0["nic_short"]}: carte sans NSG, {_first_line(exc)[:_ERR_MAX]}')
                continue
            try:
                original, q_bare = self._bare_nic_original(t0, rg)
            except Exception as exc:
                # Unread, our tag may name the NSG the NIC got since the state said
                # "none" (another host's isolation, I8S): never "none" on a guess.
                if recorded is _UNKNOWN or recorded is None:
                    failed_early.append(f'{t0["nic_short"]}: tag d\'origine illisible ({_first_line(exc)[:_ERR_MAX]})')
                    continue
                original, q_bare = _UNKNOWN, None
            if recorded is None and q_bare is not None:
                recorded = original              # our tag over the state's "none" (I8S)
            if recorded is not _UNKNOWN:
                original = recorded
            elif q_bare is None:
                if recorded is _UNKNOWN and _held_in_quarantine(t0["nic_id"]):
                    # In quarantine for our state, its original unknown there and no tag:
                    # skipped, the reset said `swept` and cleared the state — the NIC
                    # left bare, an old isolation on its own NSG unrecorded (I8F).
                    failed_early.append(f'{t0["nic_short"]}: carte sans NSG, NSG d\'origine inconnu '
                                        "(ni l'état local ni le tag ne le disent) : la remettre à la main")
                continue
            bare[t0["nic_id"]] = (original, q_bare)
            if original:
                views.append(self._original_view(t0, original))
        return bare

    def _reset_put_back_bare(self, targets: list[dict], bare: dict, dry_run: bool, deleted: list[str],
                             failed: list[str]) -> None:
        """The reset's bare NICs given their original back (_reset_bare_nics): said in
        `deleted`, or in `failed`."""
        for t0 in targets:
            # A NIC left bare after our NSG was taken off it: our tag says what it
            # carried (seventh review, U2) — or the state (see above).
            if t0["nic_id"] not in bare:
                continue
            original, q_bare = bare[t0["nic_id"]]
            label = (f'{t0["nic_short"]}: carte sans NSG'
                     + (f', remettre {original.rstrip("/").split("/")[-1]}' if original else ""))
            if dry_run:
                deleted.append(label)
                continue
            try:
                if original:
                    try:
                        self._set_nic_nsg(t0["nic_id"], original)
                    except Exception as exc:
                        raise self._original_gone(q_bare, t0["nic_id"], original, exc)
                    if not _same_id(self._nic_nsg_id(t0["nic_id"]) or "", original):
                        raise RuntimeError("NSG d'origine non remis")
                if q_bare is not None:
                    self._forget_original(q_bare, t0["nic_id"])
                deleted.append(label)
            except Exception as exc:
                failed.append(f"{label} : {_first_line(exc)[:_ERR_MAX]}")
