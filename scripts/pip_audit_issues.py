#!/usr/bin/env python3
"""pip_audit_issues — the advisories of the locked dependencies, one issue per advisory (CI2, #268).

  pip_audit_issues.py issues LOCK...   in GitHub Actions (pip-audit.yml): weekly and by hand
  pip_audit_issues.py report LOCK...   make lock, make audit: says what it finds, exit 0

Each lock (requirements/dev.txt, glorfindel.txt, annatar.txt) is read by pip-audit as it is:
`--require-hashes --disable-pip`, so nothing is resolved — the versions are the lock's, and only
the advisory service is asked (pypi.org). An advisory is a package and its identifiers (its id
and its aliases: PYSEC, GHSA, CVE); the same advisory seen twice, in one lock or in several, is
one advisory.

`issues`, through `gh` (GH_TOKEN, GH_REPO: the workflow's GITHUB_TOKEN, nothing else):
- an advisory with no issue opens one, label `security`: the package, the version of each lock
  it touches, the fixed versions, the identifiers. The issue keeps a key in its body (the
  package, every identifier seen, the locks): an issue whose key names the package and shares
  one identifier is that advisory's, open or closed, whatever its title or labels became — the
  same advisory never gets a second issue;
- its issue open: its body rewritten when what it says changed (a lock, a version, a fix, an
  alias); closed as done (`completed`) while the advisory is still there: reopened, with a
  comment; closed as not planned (or a duplicate): a human's decision, left alone;
- an open issue whose advisory is no longer found, in locks all audited this run: one comment
  (the bump was made?), never closed by the workflow — a human closes it;
- never a pull request: a bump goes through `make lock`, then the harness
  (`make llm-compare … ATTEST=1`, Jonathan) — docs/operations.md, « Verrou des dépendances ».

Exit 1 when a human has something new to see — an issue opened or reopened, an advisory back —
or when an audit failed: a red scheduled run is announced in #ci (notify.yml); an issue the
workflow's token opens triggers no workflow. Exit 0 otherwise.

Text from outside (an advisory's identifiers, a package's name, a version) is checked against
its shape before it reaches an issue: anything else is dropped; an advisory's description never
is written. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

LABEL = "security"
MARKER = re.compile(r"<!-- eregion-pip-audit: (\{[^<>]*\}) -->")
ID = re.compile(r"^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PACKAGE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,98}[a-z0-9])?$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,63}$")
LOCK = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")
PREFERRED = ("GHSA-", "CVE-", "PYSEC-")


@dataclass
class Advisory:
    package: str
    ids: set[str]
    fixes: list[str] = field(default_factory=list)
    locks: dict[str, set[str]] = field(default_factory=dict)   # lock → versions locked there

    @property
    def primary(self) -> str:
        return primary(self.ids)


@dataclass
class Issue:
    number: int
    title: str
    body: str
    state: str          # open, closed
    reason: str         # completed, not_planned, duplicate, reopened, ""
    key: dict


def primary(ids) -> str:
    for prefix in PREFERRED:
        if found := sorted(i for i in ids if i.startswith(prefix)):
            return found[0]
    return sorted(ids)[0]


def canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


# ── pip-audit ──────────────────────────────────────────────────────────────────────────

def audit(pip_audit: str, lock: str) -> tuple[list | None, str]:
    """(dependencies, "") — what pip-audit says of `lock`, read as is; (None, why) on failure."""
    cmd = [pip_audit, "-r", lock, "--require-hashes", "--disable-pip",
           "--format", "json", "--progress-spinner", "off"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except (OSError, subprocess.SubprocessError) as e:
        return None, type(e).__name__
    try:                                     # exit 1 also means « vulnerabilities found »
        deps = json.loads(res.stdout)["dependencies"]
        if not isinstance(deps, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        tail = (res.stderr or res.stdout or "").strip().splitlines()[-1:] or [f"exit {res.returncode}"]
        return None, tail[0][:300]
    return deps, ""


def advisories(reports: dict[str, list]) -> list[Advisory]:
    """One Advisory per package and advisory, whatever the lock or the duplicates: entries of a
    package sharing an identifier (its id or an alias) are merged."""
    out: list[Advisory] = []
    for lock, deps in reports.items():
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            package, version = canonical(dep.get("name", "")), str(dep.get("version", ""))
            if not PACKAGE.match(package):
                continue
            version = version if VERSION.match(version) else "?"
            for v in dep.get("vulns") or []:
                if not isinstance(v, dict):
                    continue
                ids = {i for i in [v.get("id"), *(v.get("aliases") or [])] if isinstance(i, str) and ID.match(i)}
                if not ids:
                    print(f"pip-audit: an advisory of {package} without a readable identifier, skipped",
                          file=sys.stderr)
                    continue
                fixes = [f for f in v.get("fix_versions") or [] if isinstance(f, str) and VERSION.match(f)]
                same = [a for a in out if a.package == package and a.ids & ids]
                adv = Advisory(package, set(ids), [], {})
                for a in same:
                    out.remove(a)
                    adv.ids |= a.ids
                    adv.fixes += [f for f in a.fixes if f not in adv.fixes]
                    for k, vs in a.locks.items():
                        adv.locks.setdefault(k, set()).update(vs)
                adv.fixes += [f for f in fixes if f not in adv.fixes]
                adv.locks.setdefault(lock, set()).add(version)
                out.append(adv)
    return sorted(out, key=lambda a: (a.package, a.primary))


# ── the issue ──────────────────────────────────────────────────────────────────────────

def _link(i: str) -> str:
    if i.startswith("GHSA-"):
        return f"[{i}](https://github.com/advisories/{i})"
    return f"[{i}](https://osv.dev/vulnerability/{i})"


def title(adv: Advisory) -> str:
    return f"pip-audit · {adv.package} · {adv.primary}"


def key(adv: Advisory, present: bool = True) -> dict:
    return {"package": adv.package, "ids": sorted(adv.ids), "locks": sorted(adv.locks), "present": present}


def body(adv: Advisory, present: bool = True) -> str:
    others = sorted(adv.ids - {adv.primary})
    rows = "\n".join(f"| `{lock}` | {', '.join(sorted(vs))} |" for lock, vs in sorted(adv.locks.items()))
    fixes = ", ".join(adv.fixes) if adv.fixes else "aucune encore"
    return (
        f"**{adv.package}** — avis {_link(adv.primary)}"
        + (f" ({', '.join(_link(i) for i in others)})" if others else "") + "\n\n"
        "| Verrou | Version verrouillée |\n|---|---|\n" + rows + "\n\n"
        f"**Version corrigée** : {fixes}.\n\n"
        "Trouvé par `pip-audit` sur les verrous, tels quels (`--require-hashes --disable-pip`), par "
        "`.github/workflows/pip-audit.yml` (CI2).\n\n"
        "**Pas de PR de montée automatique.** La montée : `make lock` (la version dans `pyproject.toml` "
        "si elle y est épinglée, ou `make lock UPGRADE=1`), une PR, puis le harnais "
        "(`make llm-compare … ATTEST=1`, Jonathan) — `docs/operations.md`, « Verrou des dépendances ». "
        "Le workflow ne ferme jamais cette issue : quand l'avis n'est plus trouvé, il le dit ici ; "
        "un humain la ferme.\n\n"
        f"<!-- eregion-pip-audit: {json.dumps(key(adv, present), separators=(',', ':'))} -->\n")


def with_present(text: str, present: bool) -> str:
    """The same body, its key's « present » set (the rest of what it said kept)."""
    def sub(m):
        k = json.loads(m.group(1))
        k["present"] = present
        return f"<!-- eregion-pip-audit: {json.dumps(k, separators=(',', ':'))} -->"
    return MARKER.sub(sub, text, count=1)


def parse_key(text: str) -> dict | None:
    m = MARKER.search(text or "")
    if not m:
        return None
    try:
        k = json.loads(m.group(1))
    except ValueError:
        return None
    if not (isinstance(k, dict) and isinstance(k.get("package"), str) and isinstance(k.get("ids"), list)):
        return None
    k["ids"] = {i for i in k["ids"] if isinstance(i, str)}
    k["locks"] = {x for x in k.get("locks") or [] if isinstance(x, str)}
    k["present"] = k.get("present", True) is not False
    return k


# ── gh ─────────────────────────────────────────────────────────────────────────────────

def gh(*args: str, stdin: str | None = None) -> str:
    res = subprocess.run([os.environ.get("EREGION_GH", "gh"), *args], input=stdin,
                         capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        raise RuntimeError(f"gh {args[0]} {args[1] if len(args) > 1 else ''}: "
                           f"{(res.stderr or res.stdout).strip()[:300]}")
    return res.stdout


def load_issues() -> list[Issue]:
    """Every issue of the repository, open or closed, that carries a key — by its body, whatever
    its labels (one removed must not make a second issue)."""
    out = gh("api", "--paginate", "repos/{owner}/{repo}/issues?state=all&per_page=100",
             "--jq", ".[] | select(.pull_request | not) | {number, title, body, state, state_reason}")
    issues = []
    for line in out.splitlines():
        if not line.strip():
            continue
        it = json.loads(line)
        if k := parse_key(it.get("body") or ""):
            issues.append(Issue(int(it["number"]), it.get("title") or "", it.get("body") or "",
                                it.get("state") or "", it.get("state_reason") or "", k))
    return sorted(issues, key=lambda i: i.number)


def _same(text: str) -> str:
    return text.replace("\r\n", "\n").strip()


def reconcile(advs: list[Advisory], audited: set[str], issues: list[Issue]) -> tuple[list[str], bool]:
    """Open, update, reopen, say gone. (what was done, a human has something new to see)."""
    done, new, matched = [], False, set()
    for adv in advs:
        mine = [i for i in issues if i.key["package"] == adv.package and i.key["ids"] & adv.ids]
        if mine and mine[0].number in matched:           # two advisories now, one issue's key: said once
            done.append(f"#{mine[0].number} : {adv.primary} aussi")
            continue
        if not mine:
            url = gh("issue", "create", "--title", title(adv), "--label", LABEL, "--body-file", "-",
                     stdin=body(adv)).strip()
            done.append(f"ouverte : {title(adv)} {url}")
            new = True
            continue
        issue = mine[0]
        matched.update(i.number for i in mine)
        adv.ids |= issue.key["ids"]                      # the key only grows: an alias seen once stays
        text = body(adv)
        if issue.state == "closed":
            if issue.reason in ("not_planned", "duplicate"):   # a human's decision
                done.append(f"#{issue.number} fermée (non prévue) : laissée")
                continue
            gh("issue", "reopen", str(issue.number))
            gh("issue", "comment", str(issue.number), "--body-file", "-",
               stdin=f"L'avis est toujours là, dans {', '.join(f'`{x}`' for x in sorted(adv.locks))} : "
                     "issue rouverte (CI2).")
            gh("issue", "edit", str(issue.number), "--body-file", "-", stdin=text)
            done.append(f"#{issue.number} rouverte")
            new = True
            continue
        if not issue.key["present"]:
            gh("issue", "comment", str(issue.number), "--body-file", "-",
               stdin=f"L'avis est de nouveau trouvé, dans {', '.join(f'`{x}`' for x in sorted(adv.locks))} (CI2).")
            new = True
        if not issue.key["locks"] <= audited:          # a lock of its own not read this run:
            if not issue.key["present"]:                # what it says is kept, back said once
                gh("issue", "edit", str(issue.number), "--body-file", "-", stdin=with_present(issue.body, True))
            done.append(f"#{issue.number} : laissée (verrou non lu)")
            continue
        if _same(issue.body) != _same(text):
            gh("issue", "edit", str(issue.number), "--body-file", "-", stdin=text)
            done.append(f"#{issue.number} mise à jour")
    for issue in issues:
        if issue.number in matched or issue.state != "open" or not issue.key["present"]:
            continue
        if not issue.key["locks"] or not issue.key["locks"] <= audited:
            continue                                     # a lock not read this run: nothing known
        gh("issue", "comment", str(issue.number), "--body-file", "-",
           stdin="L'avis n'est plus trouvé dans "
                 f"{', '.join(f'`{x}`' for x in sorted(issue.key['locks']))} : la montée est faite ? "
                 "Le workflow ne ferme pas l'issue : à fermer par un humain, une fois vérifié (CI2).")
        gh("issue", "edit", str(issue.number), "--body-file", "-", stdin=with_present(issue.body, False))
        done.append(f"#{issue.number} : l'avis n'est plus trouvé (commentaire)")
    return done, new


# ── main ───────────────────────────────────────────────────────────────────────────────

def summary(advs: list[Advisory]) -> str:
    if not advs:
        return "pip-audit : aucun avis connu."
    lines = [f"pip-audit : {len(advs)} avis."]
    for a in advs:
        where = "; ".join(f"{lock} {', '.join(sorted(vs))}" for lock, vs in sorted(a.locks.items()))
        others = sorted(a.ids - {a.primary})
        lines.append(f"- {a.package} · {a.primary}" + (f" ({', '.join(others)})" if others else "")
                     + f" — {where} — corrigée : {', '.join(a.fixes) or 'aucune encore'}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("issues", "report"))
    ap.add_argument("locks", nargs="+")
    ap.add_argument("--pip-audit", default="pip-audit")
    args = ap.parse_args(argv)
    if bad := [lock for lock in args.locks if not LOCK.match(lock)]:
        ap.error(f"not a lock path: {bad[0]!r}")

    reports, failed = {}, []
    for lock in args.locks:
        deps, why = audit(args.pip_audit, lock)
        if deps is None:
            failed.append(lock)
            print(f"pip-audit {lock} : échec ({why})", file=sys.stderr)
        else:
            reports[lock] = deps
    advs = advisories(reports)
    print(summary(advs))
    if args.mode == "report":
        return 0
    try:
        done, new = reconcile(advs, set(reports), load_issues())
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
        print(f"GitHub : {e}", file=sys.stderr)
        return 2
    print("\n".join(done) or "Rien à changer dans les issues.")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as f:
            f.write(summary(advs) + "\n\n" + ("\n".join(f"- {d}" for d in done) or "Rien à changer.") + "\n")
    return 1 if failed or new else 0


if __name__ == "__main__":
    sys.exit(main())
