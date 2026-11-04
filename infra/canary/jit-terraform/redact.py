"""The canary's filter: what a failed terraform or az said, cut to its end and stripped of what
is real, before it reaches a public log (CAN1, #501).

    python3 -I redact.py --label "terraform apply failed (exit 1)" --tail 30 --verdict < out

Reads the command's output on stdin and prints, on stdout: the label, the last --tail lines
(all of them without it), each after "   | " — so no line from Azure ever starts a workflow
command (::add-mask::, ::stop-commands::…) —, and with --verdict, whether the error is one
Azure calls transient. Exits 3 when --verdict is given and the error is transient, 0 otherwise.
It prints only once the whole text is filtered: if it fails, nothing raw has gone out.

What it takes out, wherever it is, before anything is printed: the subscription, tenant and
client identifiers the canary runs with (read from its environment), every resource id
(/subscriptions/…, URL-encoded too), every GUID (a NIC's resourceGuid, a correlation or request
id, an object id), a token (JWT), an e-mail address, and every IPv4 or IPv6 address.

A filter, not ::add-mask::. A mask hides only a value known before it is printed: the canary
knows its three identifiers — GitHub masks them already, as the environment's secrets —, never
the GUIDs, resource ids and addresses an Azure error carries. A mask works in Actions only, not
in `make canary-jit` pasted into an issue; and it cannot be tested offline. The filter replaces
each form by its placeholder, by pattern, wherever it runs, and a test runs it on a loaded
sample (tests/unit/test_workflows.py, test_can1_*).
"""
from __future__ import annotations

import argparse
import os
import re
import sys

# The canary's own identifiers, by name: replaced as they are, whatever their form.
_OWN = {"ARM_SUBSCRIPTION_ID": "<subscription>", "AZURE_SUBSCRIPTION_ID": "<subscription>",
        "ARM_TENANT_ID": "<tenant>", "AZURE_TENANT_ID": "<tenant>",
        "ARM_CLIENT_ID": "<client>", "AZURE_CLIENT_ID": "<client>"}
# Shorter values are not identifiers (a test's "sub"): replacing them would eat words.
_OWN_MIN = 8

_FORMS = [
    # A resource id, to its end: what follows /subscriptions/ names the subscription, the group,
    # the resource; a URL's query goes with it. URL-encoded in a request's URL too.
    (re.compile(r"(?:/|%2F)subscriptions(?:/|%2F)[^\s\"'`,;()\[\]{}<>|]*", re.I), "<resource-id>"),
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]*"), "<token>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<guid>"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "<email>"),
    # IPv4, with its prefix length if it has one; a version (4.81.0) has three parts, not four.
    (re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?!\d|\.\d)"), "<ip>"),
]
# IPv6: hex groups and colons — a clock (12:03:04) or a MAC has neither « :: » nor eight groups.
_IPV6 = re.compile(r"(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:/\d{1,3})?(?![\w:])", re.I)

# What Azure, or the provider, says when the same request would pass a moment later.
TRANSIENT = [
    ("429", re.compile(r"\b429\b")),
    ("TooManyRequests", re.compile(r"TooManyRequests|Too Many Requests", re.I)),
    ("AnotherOperationInProgress", re.compile(r"AnotherOperationInProgress", re.I)),
    ("RetryableError", re.compile(r"RetryableError", re.I)),
    ("ReferencedResourceNotProvisioned", re.compile(r"ReferencedResourceNotProvisioned", re.I)),
]
_LINE_MAX = 400


def _ipv6(m: re.Match) -> str:
    s = m.group(0)
    addr = s.split("/", 1)[0]
    # A digit, too: « ::add-mask:: » is a workflow command (said after "   | "), not an address.
    if any(c.isdigit() for c in addr) and ("::" in addr or addr.count(":") == 7):
        return "<ip>"
    return s


def redact(text: str, env: dict[str, str] | None = None) -> str:
    """The text, each real form replaced by its placeholder."""
    env = os.environ if env is None else env
    # A resource id first, whole: once its subscription is replaced, its end would be left.
    (rid, rid_mark), *forms = _FORMS
    text = rid.sub(rid_mark, text)
    own = sorted(((env.get(k) or "", v) for k, v in _OWN.items()), key=lambda p: -len(p[0]))
    for value, mark in own:
        if len(value) >= _OWN_MIN:
            text = re.sub(re.escape(value), mark, text, flags=re.I)
    for pattern, mark in forms:
        text = pattern.sub(mark, text)
    return _IPV6.sub(_ipv6, text)


def transient(text: str) -> str | None:
    """The first transient error the (filtered) text names, or None."""
    return next((name for name, p in TRANSIENT if p.search(text)), None)


def report(raw: str, label: str, tail: int | None = None, verdict: bool = False,
           env: dict[str, str] | None = None) -> tuple[str, int]:
    """What the canary prints for a command's output, and the filter's exit."""
    text, label = redact(raw, env), redact(label, env)
    lines = [ln.rstrip() for ln in text.splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    if tail is not None:
        lines = lines[-tail:] if tail > 0 else []
    lines = [ln if len(ln) <= _LINE_MAX else ln[:_LINE_MAX] + " …" for ln in lines]
    out = [f"   {label}; its end, ids, GUIDs and addresses masked:" if lines else f"   {label}; it said nothing"]
    out += [f"   | {ln}" for ln in lines]
    code = 0
    if verdict:
        name = transient(text)
        if name:
            out.append(f"   transient ({name}): Azure said to retry — re-run this line before reading a change")
            code = 3
        else:
            out.append("   not a known transient error (" + ", ".join(n for n, _ in TRANSIENT) + ")")
    return "\n".join(out) + "\n", code


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--label", required=True)
    ap.add_argument("--tail", type=int)
    ap.add_argument("--verdict", action="store_true")
    args = ap.parse_args(argv)
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    out, code = report(raw, args.label, args.tail, args.verdict)
    sys.stdout.write(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
