#!/usr/bin/env python3
"""review_verdict — the Opus 5.5 review, traced on the pull request before the merge (SEC12, #418;
docs/sessions.md, « Relecture et fusion »).

  review_verdict.py body --lot ID --verdict ok|changes|blocking --head SHA [--report FILE]
      the comment to post (gh pr comment N --body-file -): the verdict, the commit it read, the
      report, and a key the check reads back
  gh pr view N --json headRefOid,comments | review_verdict.py check --author LOGIN [--author …]
      exit 0 when the last verdict that one of these authors posted for the pull request's head
      commit is « ok »; else exit 1, and why

A verdict holds for the commit it read: a push after it is not reviewed (the check fails, the
merge waits for another review) — and the merge itself is tied to that commit
(`gh pr merge N --squash --match-head-commit SHA`). Anyone can comment on a public pull request:
only the authors named (the sessions' GitHub App, the maintainer) are read, and a report's own
text can never carry a key (it is neutralised in `body`). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

VERDICTS = ("ok", "changes", "blocking")
MARKER = re.compile(r"<!-- eregion-review: (\{[^<>]*\}) -->")
SHA = re.compile(r"[0-9a-f]{40}")
LOT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
MODEL = "claude-opus-5-5"


def body(lot: str, verdict: str, head: str, report: str = "") -> str:
    if not LOT.fullmatch(lot):
        raise ValueError(f"lot illisible : {lot!r}")
    if verdict not in VERDICTS:
        raise ValueError(f"verdict : {' | '.join(VERDICTS)}")
    if not SHA.fullmatch(head):
        raise ValueError("--head : le commit complet (40 caractères hexadécimaux) que la relecture a lu")
    # The report is the reviewer's text: it never carries a key of its own.
    report = (report or "").replace("<!--", "&lt;!--").strip()
    key = json.dumps({"lot": lot, "verdict": verdict, "head": head, "model": MODEL}, separators=(",", ":"))
    return (f"### Relecture Opus 5.5 — {verdict}\n\n"
            f"Lot {lot}, commit `{head[:12]}` : la relecture vaut pour ce commit ; un push après elle "
            "demande une autre relecture.\n\n"
            + (f"{report}\n\n" if report else "")
            + f"<!-- eregion-review: {key} -->\n")


def _login(author) -> str:
    login = author.get("login") if isinstance(author, dict) else author
    return str(login or "").lower().removesuffix("[bot]")


def check(pr: dict, authors: list[str]) -> tuple[bool, str]:
    """(merge allowed, why) for `gh pr view --json headRefOid,comments`."""
    head = pr.get("headRefOid") if isinstance(pr, dict) else None
    if not isinstance(head, str) or not SHA.fullmatch(head):
        return False, "la PR ne dit pas son commit de tête (headRefOid)"
    allowed = {_login(a) for a in authors if _login(a)}
    if not allowed:
        return False, "aucun auteur de relecture nommé (--author)"
    last, elsewhere = None, None
    for c in pr.get("comments") or []:
        if not isinstance(c, dict) or _login(c.get("author")) not in allowed:
            continue
        for raw in MARKER.findall(str(c.get("body") or "")):
            try:
                key = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(key, dict) or key.get("verdict") not in VERDICTS:
                continue
            if key.get("head") == head:
                last = key
            else:
                elsewhere = key
    if last is None:
        if elsewhere is not None:
            return False, (f"la dernière relecture porte sur {str(elsewhere.get('head'))[:12]}, pas sur la tête "
                           f"{head[:12]} : un push après elle — une autre relecture")
        return False, f"aucun verdict de relecture publié pour {head[:12]}"
    if last["verdict"] != "ok":
        return False, f"le verdict publié pour {head[:12]} est « {last['verdict']} »"
    return True, f"relecture « ok » publiée pour {head[:12]} (lot {last.get('lot')})"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("body")
    b.add_argument("--lot", required=True)
    b.add_argument("--verdict", required=True)
    b.add_argument("--head", required=True)
    b.add_argument("--report", default="")
    c = sub.add_parser("check")
    c.add_argument("--author", action="append", default=[])
    args = ap.parse_args(argv)
    if args.cmd == "body":
        try:
            report = open(args.report, encoding="utf-8").read() if args.report else ""
            sys.stdout.write(body(args.lot, args.verdict, args.head, report))
        except (OSError, ValueError) as e:
            print(f"review_verdict : {e}", file=sys.stderr)
            return 2
        return 0
    try:
        pr = json.load(sys.stdin)
    except ValueError:
        print("review_verdict : la sortie de gh pr view --json headRefOid,comments est attendue", file=sys.stderr)
        return 2
    ok, why = check(pr, args.author)
    print(why, file=sys.stdout if ok else sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
