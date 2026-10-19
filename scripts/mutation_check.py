"""Measure the invariant suite by mutation (sixth review, L26).

Each mutant re-introduces a bug Glorfindel actually had — the classes the reviews
found — or, for a lot of the eighth pass, a bug its specification names, as an exact
text replacement in a throwaway copy of the repository, then runs its tests on it:
tests/unit/test_invariants.py, or the tests named for it in TESTS. A mutant the suite fails on is CAUGHT; one it
passes on SURVIVES. A mutant whose text no longer matches the code is STALE (fix the
mutant, the code moved) — never counted as caught.

    python scripts/mutation_check.py                       # push budget (60), 3 rounds
    python scripts/mutation_check.py --examples 1000 --rounds 2
    python scripts/mutation_check.py --only M04,M13

Each round draws new seeds. The table says, per mutant, how many rounds caught it.
A mutant the invariants can't see by construction says why: EQUIVALENT (no behaviour
of the fake world tells it apart), MULTI-HOST (needs a second host writing between two of
our calls — the locks are per host; a unit test covers it).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
A = "glorfindel/actions.py"
R = "glorfindel/reassert.py"
C = "glorfindel/config.py"
INS = "eregion_core/inscription.py"
ENG = "annatar/runner/engine.py"
INVARIANTS = "tests/unit/test_invariants.py"
INSCRIPTION_TESTS = "tests/unit/test_inscription.py tests/unit/test_engine.py"
DOCS_TESTS = "tests/unit/test_docs_budget.py"
# A mutant whose "old" text is RENAME renames its file to "new" instead of editing it.
RENAME = object()

# (id, bug class, file, text in the code today, text that re-introduces the bug[, why
# the invariants can't see it])
MUTANTS = [
    ("M01", "rule name without the NIC hash (homonyms share a name)", A,
     'base = f"{prefix}-{vm_name}-{nic_short}-{_nic_hash(nic_id, 6)}"',
     'base = f"{prefix}-{vm_name}-{nic_short}"'),
    ("M02", "deny any/any on a shared NIC NSG", A,
     "        return len(nics) > 1 or len(subnets) > 0",
     "        return False"),
    ("M03", "deny scoped to the NIC's first IP only", A,
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips)',
     'self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src="*", dsts=ips[:1])'),
    ("M04", "outbound allows ignored by the precedence check", A,
     '        elif direction == "outbound":\n            src, dst = outbound_src, outbound_dst',
     '        elif direction == "outbound":\n            continue'),
    ("M05", "verify_release ignores a quarantine NSG still attached", A,
     "                  for t0 in targets if t0.get(\"quarantine\")]",
     "                  for t0 in targets if False]"),
    ("M06", "state deleted right after it is written (C1's effect)", A,
     "    _atomic_write_text(target, json.dumps(payload))\n",
     "    _atomic_write_text(target, json.dumps(payload))\n    if name != name.lower():\n        target.unlink()\n"),
    ("M07", "release sweeps the NICs only when there is no state", A,
     "        failed += self._sweep_isolation(rg, vm_name, remaining)",
     "        failed += [] if state.get(\"placements\") else self._sweep_isolation(rg, vm_name, remaining)"),
    ("M08", "fallback deny any/any on an NSG that only looks dedicated", A,
     '    return bool(target.get("private_ips")) or _ip_scoped(target)',
     "    return _ip_scoped(target)"),
    ("M09", "a missing original tag read as 'no NSG' (Q7)", A,
     "        if not value:\n            raise OriginalUnknown(",
     "        if not value:\n            return None\n            raise OriginalUnknown("),
    ("M10", "an unreadable subnet read as 'no subnet NSG'", A,
     "                subnet_nsg, subnet_unreadable = None, True",
     "                subnet_nsg, subnet_unreadable = None, False"),
    ("M11", "_is_not_found by substring", A,
     "    # No substring guess:",
     "    if \"not found\" in str(exc).lower():\n        return True\n    # No substring guess:",
     "EQUIVALENT: no call site sees a non-404 'not found' since the release re-reads the NIC"),
    ("M12", "isolation verified by rule name, not content", A,
     '                    and _deny_isolates(r_in, "inbound", ips) and _deny_isolates(r_out, "outbound", ips)):',
     "                    ):"),
    ("M13", "reassertion ignores a release that has started", "glorfindel/reassert.py",
     "    return bool(state.get(\"partial\") or state.get(failed_key) or state.get(running_key))",
     "    return bool(state.get(\"partial\") or state.get(failed_key))"),
    ("M14", "release does not read the NIC back", A,
     "            if not _same_id(now or \"\", original or \"\"):",
     "            if False:"),
    ("M15", "an unreadable config falls back to the defaults (S1)", A,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except Exception:\n            return True, \"\"\n"),
    ("M16", "blocks verified by rule name, not content (S2)", A,
     "        altered = [n for n, r, d in zip(names, found, (\"inbound\", \"outbound\")) if not _deny_blocks(r, d, ip, ips)]",
     "        altered = []"),
    ("M17", "per-VM lock inoperative", A,
     "        with _vm_lock(rid.rstrip(\"/\").rsplit(\"/\", 1)[-1]):\n            return method(self, *args, **kwargs)",
     "        return method(self, *args, **kwargs)"),
    # Found by L26 itself (the world moving): kept so they stay found.
    ("M18", "a NIC's old-IP rule recognised by content only (L26)", A,
     "    if name in hashed:\n        # Only Glorfindel names a rule with a NIC's hash",
     "    if name in hashed and _deny_applies(rule, ips):\n        # Only Glorfindel names a rule with a NIC's hash"),
    ("M19", "a block verified against the IPs recorded at block time (L26)", A,
     "                now = current.get(nic) if current is not None and isinstance(nic, str) else None",
     "                now = None"),
    ("M20", "release asks for the original of a NIC no longer in quarantine (L26)", A,
     "                        if now and not _same_id(now, p[\"nsg_id\"]):",
     "                        if False:"),
    ("M21", "a block counted on an NSG that no longer governs the NIC (L26)", A,
     '                    off = [p for p in ps if (p["nsg_rg"].lower(), p["nsg_name"].lower()) not in governing]',
     "                    off = []"),
    ("M22", "a partial release's flat fields read as a legacy state (L26)", A,
     '        elif "placements" not in state and state.get("nsg_name") and not _is_quarantine_nsg(state["nsg_name"]):',
     '        elif state.get("nsg_name"):'),
    ("M23", "an unblock doesn't look behind the quarantine (L27)", A,
     "            views = self._nic_nsg_views(t0)\n            if t0.get(\"quarantine\"):",
     "            views = self._nic_nsg_views(t0)\n            if False:"),
    ("M24", "reset --from-azure reads the original from the tag only (L27)", A,
     "                original = _recorded_original(t0[\"nic_id\"])\n                if original is _UNKNOWN:\n"
     "                    original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])\n"
     "                originals[t0[\"nic_id\"]] = original",
     "                originals[t0[\"nic_id\"]] = original = self._original_from_tags(t0[\"quarantine\"], t0[\"nic_id\"])"),
    ("M25", "a partial reset leaves the state unmarked (L27)", A,
     "        elif not dry_run:\n            # Part of it is gone from Azure",
     "        elif False:\n            # Part of it is gone from Azure",
     "EQUIVALENT: since A0 the reset records its intent (releasing_at / unblocking_at) before "
     "touching Azure — a partial reset's state is held by that marker either way; the failure "
     "mark only changes the operator's wording"),
    ("M26", "a NIC left without an NSG: the release moves on (L28, U2)", A,
     "                        if now is None:\n                            # Detached from our NSG",
     "                        if False:\n                            # Detached from our NSG"),
    ("M27", "an unreadable config hides an emptied quarantine NSG (L28, U4)", A,
     "            wanted = self._quarantine_wanted(with_forensic=False)\n            forensic_known = False",
     "            raise\n            forensic_known = False"),
    ("M28", "orphan rules not reported (L28, U1)", A,
     "                if len(mark) not in (6, 8) or any(c not in \"0123456789abcdef\" for c in mark) or mark in marks:",
     "                if True:"),
    ("M29", "a bare NIC isolated again records 'none' over its original (L28, U2)", A,
     "            if original is None:\n                # A bare NIC may have been in our quarantine before",
     "            if False:\n                # A bare NIC may have been in our quarantine before"),
    ("M30", "the quarantine swap is not read back (A0)", A,
     '            if not _same_id(now or "", q["nsg_id"]):',
     "            if False:"),
    ("M31", "one deny's priority used for both directions (A0)", A,
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": out if isinstance(out, int) else prio},',
     '        found = _shadowing_rules(rules, {"inbound": prio, "outbound": prio},'),
    ("M32", "an outbound allow before a block counted as exposure (A0)", A,
     '                    port is None or direction == "outbound" or _rule_covers_port(r, port)),',
     '                    port is None or (direction == "inbound" and _rule_covers_port(r, port))),'),
    ("M33", "an unowned old fixed-name rule on a non-dedicated NSG ignored (A0)", A,
     '        if not (t.get("sharing_unknown") or _ip_scoped(t)):\n            return []',
     '        if True:\n            return []'),
    ("M34", "verify_release ignores the old single-NSG state (A0)", A,
     "            rules = self._list_rules(cache, l_rg, l_name)\n            names =",
     "            rules = []\n            names ="),
    ("M35", "reset --from-azure records no intent (A0)", A,
     '            if state:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})',
     '            if False:\n                _save_isolation_state(resource_id, {**state, "releasing_at": now})'),
    ("M36", "the old state file removed after the new one is written (A0)", A,
     "    if olds and not target.exists():",
     "    if False:"),
    ("M37", "reassertion alerts keyed by the VM's name (A0, L1)", "glorfindel/reassert.py",
     '    return f"reassert-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")',
     '    return f"reassert-{vm}" + (f"-{ip}" if ip else "")'),
    ("M38", "a block gone behind the quarantine not reported (A0, L1)", A,
     "                                    held_missing += names",
     "                                    pass"),
    ("M39", "reset reads a bare NIC's original from the tag only (A0)", A,
     "            if recorded is not _UNKNOWN:\n                original = recorded\n            elif q_bare is None:",
     "            if False:\n                original = recorded\n            elif q_bare is None:"),
    ("M40", "a deleted NSG's listing read as unreadable (A0, L1)", A,
     "                cache[key] = [] if _is_not_found(exc) else None",
     "                cache[key] = None"),
    ("M41", "reset doesn't sweep the original it puts back on a bare NIC (A0)", A,
     '            bare[t0["nic_id"]] = (original, q_bare)\n            if original:\n                views.append(self._original_view(t0, original))',
     '            bare[t0["nic_id"]] = (original, q_bare)'),
    # O0 (eighth pass): the six bugs the inscription's specification names.
    ("M42", "the execution-time inscription check removed (O0)", ENG,
     '        if not guard.allowed:\n            console.print(f"[red]Safety check failed:[/red] {guard.reason}")',
     '        if False:\n            console.print(f"[red]Safety check failed:[/red] {guard.reason}")'),
    ("M43", "an empty bench id accepted (O0)", INS,
     "    if not bench or not bench.strip():\n        return GuardResult(False, \"empty bench id",
     "    if False:\n        return GuardResult(False, \"empty bench id"),
    ("M44", "a resource outside the bench's resource groups accepted (O0)", INS,
     "        if not (rg_ok or sandbox_ok):",
     "        if False:"),
    ("M45", "the tag value read without its case (O0)", INS,
     "        if value != bench:",
     "        if value.lower() != bench.lower():"),
    ("M46", "a destructive technique or a fault accepted in production (O0)", INS,
     '    if zone == "production":\n        if kind != "technique":',
     '    if False:\n        if kind != "technique":'),
    ("M47", "a missing zone read as the bench (O0)", INS,
     '    zone = target.zone or ("bench" if target.legacy else "")',
     '    zone = target.zone or "bench"'),
    # DX1: the two bugs its specification names.
    ("M48", "CLAUDE.md grows by 10 KB (DX1)", "CLAUDE.md",
     "## Ce qu'on ne fait PAS\n",
     "## Ce qu'on ne fait PAS\n\n" + "<!-- padding -->\n" * 640),
    ("M49", "a docs/ file the index points to is renamed (DX1)", "docs/azure.md",
     RENAME, "docs/azure-renamed.md"),
    # Sixth review, S8: the drain spared every session with the forensic host.
    ("M50", "the drain spares any session with a forensic source (S8)", A,
     'flt = flt[:-1] + f"and not ( dst {cidr} and ( {local} ) ) )"',
     'flt = flt[:-1] + f"and not dst {cidr} )"'),
    # Sixth review, S9: a verification that raised left the graph (cycle_failed, no Revert).
    ("M51", "a verification that raises leaves the graph (S9)", "glorfindel/agent.py",
     "    except Exception as exc:\n        first = str(exc).strip().splitlines()[0]",
     "    except Exception as exc:\n        raise\n        first = str(exc).strip().splitlines()[0]"),
    # Sixth review, S7: a quarantine refused at execution, unknown to the readiness gate.
    ("M52", "a quarantine refused at execution is not remembered (S7)", A,
     "        _remember_quarantine_outcome(resource_id, refused, placements)\n",
     "        pass\n"),
    ("M53", "the readiness gate ignores a remembered refusal (S7)", "glorfindel/readiness.py",
     "    refusal = quarantine_refusal(resource_id) if quarantine_nsg else None",
     "    refusal = None"),
    # H0: the hosted Glorfindel stays an observer.
    ("M54", "the pushed host config keeps the local autonomy (H0)", "infra/glorfindel-host/host_config.py",
     '    out["autonomy"] = {"default": "human_only"}\n', ""),
    ("M55", "the host gets a write role on the bench (H0)", "infra/glorfindel-host/main.tf",
     'role_definition_name = "Reader"', 'role_definition_name = "Contributor"'),
    ("M56", "empty service-principal vars stay set (H0: managed identity unreachable)", "glorfindel/cli.py",
     "    for k in dropped:\n        del environ[k]\n", ""),
    # B2 (storage side): an exercise window labels only what it names, for a bounded time.
    ("M57", "a window labels every VM, not its targets (B2)", "eregion_core/exercise.py",
     "    if resource_id.lower() not in (window.get(\"targets\") or []):\n        return False\n", ""),
    ("M58", "a window never closed never lapses (B2)", "eregion_core/exercise.py",
     "    end = _parse(window.get(\"end\")) or expires\n    # A window closed late still lapses at its expiry.\n"
     "    last = min(end, expires) + timedelta(seconds=GRACE_AFTER_S)\n",
     "    end = _parse(window.get(\"end\")) or when\n    last = end + timedelta(seconds=GRACE_AFTER_S)\n"),
    ("M59", "the observation report counts exercise cards (B2)", "glorfindel/escalations.py",
     "            exercises += 1\n            continue\n", "            exercises += 1\n"),
    ("M60", "an exercise card absorbs a real detection (B2)", "glorfindel/escalations.py",
     "                and (e.get(\"source\") or \"real\") == (source or \"real\")\n", ""),
    ("M61", "an Annatar run never closes its window (B2)", "annatar/runner/engine.py",
     "        try:\n            return self._run_enrolled(scenario, executor, run_id)\n        finally:\n            close_window(run_id)\n",
     "        return self._run_enrolled(scenario, executor, run_id)\n"),
    # #105: the boot batch's sub-second gaps set the step again (blind 10 min after a boot).
    ("M62", "the ransomware step reads the boot batch (#105)", "glorfindel/rules/azure/detection_rules.yaml",
     "summarize Step = minif(Gap, Gap >= 1s) by Vm, InstanceName", "summarize Step = min(Gap) by Vm, InstanceName"),
    # IA0: the check keeps a claim the cited runs contradict (« all detected » on a missed run).
    ("M63", "the report keeps a detected/missed claim the runs contradict (IA0)", "analysis/campaign_report.py",
     '        elif c.kind in ("detected", "missed") and any(x.detection != c.kind for x in cited):\n            c.rejected = f"a cited run was not {c.kind}"\n',
     ""),
]

# Mutants measured by other tests than the invariants (their lot's own).
TESTS = {mid: INSCRIPTION_TESTS for mid in ("M42", "M43", "M44", "M45", "M46", "M47")}
TESTS.update({mid: DOCS_TESTS for mid in ("M48", "M49")})
TESTS["M50"] = "tests/unit/test_glorfindel.py -k drain"
TESTS["M51"] = "tests/unit/test_agent_nodes.py -k raises"
TESTS["M52"] = "tests/unit/test_glorfindel.py -k remembered"
TESTS["M53"] = "tests/unit/test_readiness.py -k refused"
TESTS.update({mid: "tests/unit/test_glorfindel_host.py" for mid in ("M54", "M55", "M56")})
TESTS.update({mid: "tests/unit/test_exercise.py" for mid in ("M57", "M58", "M59", "M60", "M61")})
TESTS["M62"] = "tests/unit/test_detection_rules.py -k sampling_step"
TESTS["M63"] = "tests/unit/test_campaign_report.py"


# The auditor's control set (seventh review): plausible bugs the generation was never
# shaped on. They only MEASURE whether the invariants generalise — never tailor a
# composite rule or a world event to one of them. Run with --control.
CONTROL = [
    ("C01", "unreadable config => quarantine off", A,
     "        from glorfindel.config import load_glorfindel_config\n        iso = load_glorfindel_config().isolation\n",
     "        from glorfindel.config import load_glorfindel_config, ConfigError\n        try:\n            iso = load_glorfindel_config().isolation\n"
     "        except ConfigError:\n            return False, \"\"\n"),
    ("C02", "unreadable ownership tag => not ours", A,
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return True",
     "            return tags.get(\"managed-by\") == \"glorfindel\"\n        except Exception:\n            return False"),
    ("C03", "isolation deny without the peer-side check", A,
     "    if not _side_is_any(rule, peer):\n        return False\n",
     ""),
    ("C04", "quarantine content without the DNS/IMDS denies", A,
     "        for rule_name, priority, tag in QUARANTINE_PLATFORM_RULES:",
     "        for rule_name, priority, tag in ():"),
    ("C05", "a stale forensic allow never purged", A,
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current):",
     "            if low not in {w.lower() for w in wanted} and _opens_quarantine(current) and low != QUARANTINE_FORENSIC_RULE:"),
    ("C06", "block: one address of the NIC is enough", A,
     "    return all(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)",
     "    return any(_side_covers(rule, own, [a]) for a in ips) if ips else _side_is_any(rule, own)"),
    ("C07", "stateless release doesn't re-read the NICs", A,
     "        if restored:\n",
     "        if False:\n"),
    ("C08", "no foreign rule counts as an alteration", A,
     "                 if low not in {w.lower() for w in wanted} and _opens_quarantine(r)]",
     "                 if False]"),
    ("C09", "the release doesn't write its marker", A,
     "            _save_isolation_state(resource_id, {**state, \"releasing_at\": datetime.now(timezone.utc).isoformat()})",
     "            pass"),
    ("C10", "the reassertion never puts a missing block back", R,
     "    if b.get(\"reasserted_at\") or _mode(autonomy, vm, ref) == \"human_only\":",
     "    if True:"),
    ("C11", "a block doesn't check the access (an allow passes)", A,
     "    if (_enum_text(getattr(rule, \"access\", \"\")) != \"deny\"\n            or _enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own",
     "    if (_enum_text(getattr(rule, \"direction\", \"\")) != direction\n"
     "            or _enum_text(getattr(rule, \"protocol\", \"*\")) not in (\"*\", \"any\", \"\")\n            or not _covers_all_ports(rule)):\n        return False\n    attacker, own"),
    ("C12", "forensic exception dropped from the quarantine-as-block", A,
     "            if any(addr in ipaddress.ip_network(s, strict=False) for s in self._forensic_sources()):",
     "            if False:"),
    ("C13", "a /16 forensic source accepted", C,
     "_FORENSIC_MAX_ADDRESSES = 256",
     "_FORENSIC_MAX_ADDRESSES = 65536"),
    ("C14", "subscription guard removed from the release", A,
     "for _name in (\"isolate_vm\", \"release_isolation\", \"verify_isolation\", \"verify_release\",",
     "for _name in (\"isolate_vm\", \"verify_isolation\", \"verify_release\","),
    ("C15", "reassertion over a stale marker", R,
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\"):\n        return",
     "    if _held_by_an_operation(iso, \"release_failed\", \"releasing_at\") and not _stale(iso.get(\"releasing_at\")):\n        return"),
    ("C16", "precedence ignores glorfindel-* allows", A,
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if direction == \"inbound\":",
     "        if _enum_text(getattr(r, \"access\", \"\")) != \"allow\":\n            continue\n        if name.startswith(\"glorfindel-\"):\n            continue\n"
     "        if direction == \"inbound\":"),
]


def _copy_repo(dest: Path) -> None:
    files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    for rel in files:
        src = REPO / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)


def _run(copy: Path, examples: int, show: bool = False, target: str = INVARIANTS) -> bool:
    """True if `target` (test paths, space-separated) FAILS on this copy (the mutant is caught)."""
    env = {**os.environ, "GLORFINDEL_INVARIANT_EXAMPLES": str(examples), "GLORFINDEL_INVARIANT_NO_SHRINK": "1",
           "PYTHONPATH": str(copy), "PYTHONDONTWRITEBYTECODE": "1"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *target.split(), "-q", "-x", "-p", "no:cacheprovider"],
        cwd=copy, env=env, capture_output=True, text=True)
    if "glorfindel" in proc.stdout and "ModuleNotFoundError" in proc.stdout:
        raise RuntimeError(proc.stdout[-2000:])
    if show and proc.returncode != 0:
        print("\n".join(line for line in proc.stdout.splitlines() if line.startswith("E ")) or proc.stdout[-3000:])
    return proc.returncode != 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--examples", type=int, default=60)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--only", default="")
    ap.add_argument("--control", action="store_true",
                    help="measure the control set (never used to shape the generation) instead")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2),
                    help="mutants measured at once")
    ap.add_argument("--min-caught", type=int, default=0,
                    help="exit 1 if fewer mutants (equivalent and multi-host aside) are caught in every round")
    args = ap.parse_args()
    only = {m.strip() for m in args.only.split(",") if m.strip()}

    with tempfile.TemporaryDirectory(prefix="glorfindel-mutants-") as tmp:
        base = Path(tmp) / "base"
        _copy_repo(base)
        todo = [m for m in (CONTROL if args.control else MUTANTS) if not only or m[0] in only]
        # The unmutated copy must pass, or nothing below means anything.
        for target in sorted({TESTS.get(m[0], INVARIANTS) for m in todo}):
            if _run(base, args.examples, show=True, target=target):
                print(f"{target} fails on the UNMUTATED code — fix that first")
                return 2
        def measure(mutant):
            mid, title, rel, old, new, *why = mutant
            copy = Path(tmp) / mid
            shutil.copytree(base, copy)
            target = copy / rel
            if old is RENAME:
                if not target.exists():
                    return mid, title, "STALE", "file to rename is gone"
                target.rename(copy / new)
            else:
                text = target.read_text()
                if text.count(old) != 1:
                    return mid, title, "STALE", f"{text.count(old)} matches"
                target.write_text(text.replace(old, new))
            started = time.monotonic()
            target = TESTS.get(mid, INVARIANTS)
            caught = sum(_run(copy, args.examples, target=target) for _ in range(args.rounds))
            # Caught by a fixed sequence only (tests/unit/test_invariant_regressions.py)?
            fixed = (caught == 0 and target == INVARIANTS
                     and _run(copy, 0, target="tests/unit/test_invariant_regressions.py"))
            shutil.rmtree(copy, ignore_errors=True)
            verdict = "CAUGHT" if caught == args.rounds else ("flaky" if caught else ("FIXED-ONLY" if fixed else "SURVIVES"))
            if why and verdict != "CAUGHT":
                verdict = why[0].split(":")[0]
            row = (mid, title, verdict, f"{caught}/{args.rounds} ({time.monotonic() - started:.0f}s)")
            print(f"{mid} {verdict:8} {row[3]:14} {title}", flush=True)
            return row

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = sorted(pool.map(measure, todo))
    print(f"\nbudget {args.examples} sequences, {args.rounds} rounds:")
    for mid, title, verdict, detail in rows:
        print(f"  {mid}  {verdict:8}  {detail:16}  {title}")
    counted = [r for r in rows if r[2] not in ("EQUIVALENT", "MULTI-HOST", "STALE")]
    caught = sum(1 for r in counted if r[2] == "CAUGHT")
    print(f"\n{caught}/{len(counted)} caught in every round (equivalent and multi-host mutants aside)")
    return 1 if caught < args.min_caught else 0


if __name__ == "__main__":
    sys.exit(main())
