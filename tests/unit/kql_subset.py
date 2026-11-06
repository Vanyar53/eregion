"""A KQL subset, evaluated in Python over rows in memory — the shipped Syslog rules run
as written, on lines the test writes (SEC2). No Log Analytics, no Azure.

Only what the Syslog rules use: a table, then `where`, `extend`, `summarize` (`arg_max(col, *)`
alone or followed by named aggregations — AL2 —, or `name = count()`, `countif(p)`, `min(col)`,
`max(col)`, `take_any(col)`, `take_anyif(col, p)`, `make_set_if(col, p, n)` — AUD1 —, several of
them), `project`, `order by`, `limit`; predicates `==`, `!=`, `=~`, `<`, `<=`, `>`, `>=`, `has`,
`!has`, `in (…)`, `in~ (…)`, `!in~ (…)`, `matches regex`, `startswith`, `endswith` (both
case-insensitive, as in KQL — WL1), `and`, `or`, `not(…)`; functions `ago()`, `extract()`,
`iif()` (or `iff()`), `isnotempty()`, `isnotnull()`, `toint()`, `tolong()`, `tostring()`,
`parse_json()` with a member (`.appid`) or an index (`["…"]`) — the Activity Log's `Claims`, AL2.
Anything
else raises NotImplementedError: a rule this reader cannot follow fails its test, never
passes it by accident. `has` is KQL's term match (case-insensitive, at term boundaries);
regexes are read by Python's `re` in ASCII mode (`\\d` is 0–9 only, as in RE2: AUD1's review —
`²` is a digit to Python's default `re`, not to Log Analytics). `$` also matches before a final
line break in Python, never in RE2: an exclusion anchored by `$` reads here as wider than in Log
Analytics, never narrower (WL1).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*)
  | (?P<vstr>@"[^"]*"|@'[^']*')
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<span>\d+(?:\.\d+)?(?:d|h|m|s|ms|min|days?|hours?|minutes?|seconds?)\b)
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|=~|!in~|in~|!has\b|!contains\b|[|(),=<>*.\[\]])
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
""", re.VERBOSE)

_UNITS = {"d": 86400, "day": 86400, "days": 86400, "h": 3600, "hour": 3600, "hours": 3600,
          "m": 60, "min": 60, "minute": 60, "minutes": 60, "s": 1, "second": 1, "seconds": 1,
          "ms": 0.001}


def _tokens(query: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(query):
        m = _TOKEN.match(query, pos)
        if not m:
            raise NotImplementedError(f"KQL subset: cannot read {query[pos:pos + 30]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind in ("ws", "comment"):
            continue
        text = m.group()
        if kind == "vstr":
            out.append(("str", text[2:-1]))
        elif kind == "str":
            out.append(("str", bytes(text[1:-1], "utf-8").decode("unicode_escape")))
        else:
            out.append((kind, text))
    return out


def _stages(tokens):
    stages, cur, depth = [], [], 0
    for tok in tokens:
        if tok == ("op", "("):
            depth += 1
        elif tok == ("op", ")"):
            depth -= 1
        if tok == ("op", "|") and depth == 0:
            stages.append(cur)
            cur = []
        else:
            cur.append(tok)
    stages.append(cur)
    return stages


def _has(hay, needle) -> bool:
    # A term boundary where the needle starts or ends with a term's character only: the
    # needle `new user: name=` ends on a separator, and the account's name follows it
    # (SEC4c, the T1136 rule — live on the bench, so Log Analytics reads it so).
    needle = str(needle)
    head = r"(?<![A-Za-z0-9])" if needle[:1].isalnum() else ""
    tail = r"(?![A-Za-z0-9])" if needle[-1:].isalnum() else ""
    return re.search(head + re.escape(needle) + tail, str(hay or ""), re.IGNORECASE) is not None


def _or(a, b):
    return lambda r: bool(a(r)) or bool(b(r))


def _and(a, b):
    return lambda r: bool(a(r)) and bool(b(r))


class _Parser:
    def __init__(self, tokens, now):
        self.t, self.i, self.now = tokens, 0, now

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else ("eof", "")

    def take(self, kind=None, text=None):
        tok = self.peek()
        if (kind and tok[0] != kind) or (text and tok[1] != text):
            raise NotImplementedError(f"KQL subset: expected {text or kind}, got {tok}")
        self.i += 1
        return tok

    def at(self, text):
        return self.peek()[1] == text and self.peek()[0] in ("op", "ident")

    def done(self):
        return self.i >= len(self.t)

    # expr := and ("or" and)*
    def expr(self):
        left = self.conj()
        while self.at("or"):
            self.take()
            a, b = left, self.conj()
            left = _or(a, b)
        return left

    def conj(self):
        left = self.cmp()
        while self.at("and"):
            self.take()
            a, b = left, self.cmp()
            left = _and(a, b)
        return left

    def cmp(self):
        left = self.primary()
        tok = self.peek()
        op = tok[1]
        if op in ("==", "!=", "=~", ">=", "<=", ">", "<") and tok[0] == "op":
            self.take()
            right = self.primary()
            ops = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b,
                   # KQL's case-insensitive equality, on strings (COR2: a resource id).
                   "=~": lambda a, b: isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower(),
                   ">=": lambda a, b: a is not None and a >= b, "<=": lambda a, b: a is not None and a <= b,
                   ">": lambda a, b: a is not None and a > b, "<": lambda a, b: a is not None and a < b}
            f = ops[op]
            return lambda r: f(left(r), right(r))
        if op in ("has", "!has"):
            self.take()
            right = self.primary()
            neg = op == "!has"
            return lambda r: _has(left(r), right(r)) != neg
        if op == "startswith" and tok[0] == "ident":
            self.take()
            right = self.primary()
            return lambda r: str(left(r) or "").lower().startswith(str(right(r)).lower())
        if op == "endswith" and tok[0] == "ident":
            self.take()
            right = self.primary()
            return lambda r: str(left(r) or "").lower().endswith(str(right(r)).lower())
        if op == "in" and tok[0] == "ident":
            self.take()
            self.take("op", "(")
            items = [self.primary()]
            while self.at(","):
                self.take()
                items.append(self.primary())
            self.take("op", ")")
            return lambda r: left(r) in [f(r) for f in items]
        if op in ("in~", "!in~") and tok[0] == "op":
            # KQL's case-insensitive membership, on strings (AL2: an operation's name, a status).
            self.take()
            self.take("op", "(")
            items = [self.primary()]
            while self.at(","):
                self.take()
                items.append(self.primary())
            self.take("op", ")")
            neg = op == "!in~"

            def within(r):
                v = left(r)
                return isinstance(v, str) and v.lower() in [str(f(r)).lower() for f in items]
            return lambda r: within(r) != neg
        if op == "matches" and tok[0] == "ident":
            self.take()
            self.take("ident", "regex")
            pattern = re.compile(self.take("str")[1], re.ASCII)
            return lambda r: pattern.search(str(left(r) or "")) is not None
        return left

    def primary(self):
        kind, text = self.peek()
        if kind == "str":
            self.take()
            return lambda r, v=text: v
        if kind == "num":
            self.take()
            v = float(text) if "." in text else int(text)
            return lambda r, v=v: v
        if (kind, text) == ("op", "("):
            self.take()
            inner = self.expr()
            self.take("op", ")")
            return inner
        if kind == "ident":
            self.take()
            if self.at("("):
                return self.access(self.call(text))
            return lambda r, c=text: r.get(c)
        raise NotImplementedError(f"KQL subset: unexpected {text!r}")

    def access(self, f):
        """`.member` and `["key"]` after a call (`parse_json(Claims).appid`): None when absent."""
        while self.at(".") or self.at("["):
            if self.take()[1] == ".":
                key = self.take("ident")[1]
            else:
                key = self.take("str")[1]
                self.take("op", "]")
            f = (lambda g, k: lambda r: g(r).get(k) if isinstance(g(r), dict) else None)(f, key)
        return f

    def args(self):
        self.take("op", "(")
        out = []
        while not self.at(")"):
            if self.peek()[0] == "span":
                n, unit = re.match(r"(\d+(?:\.\d+)?)(\w+)", self.take()[1]).groups()
                out.append(("span", float(n) * _UNITS[unit]))
            else:
                out.append(("expr", self.expr()))
            if self.at(","):
                self.take()
        self.take("op", ")")
        return out

    def call(self, name):
        args = self.args()
        if name == "ago":
            (_, seconds), = args
            t = self.now - timedelta(seconds=seconds)
            return lambda r: t
        if name == "not":
            (_, f), = args
            return lambda r: not f(r)
        if name == "isnotempty":
            (_, f), = args
            return lambda r: f(r) not in (None, "")
        if name in ("iif", "iff"):
            # KQL's conditional (AL2: the row names the caller that decided it).
            (_, cond), (_, then), (_, other) = args
            return lambda r: then(r) if cond(r) else other(r)
        if name == "isnotnull":
            (_, f), = args
            return lambda r: f(r) is not None
        if name == "extract":
            (_, pat), (_, grp), (_, src) = args

            def extract(r):
                m = re.search(pat(r), str(src(r) or ""), re.ASCII)
                return (m.group(grp(r)) or "") if m else ""
            return extract
        if name in ("toint", "tolong"):
            (_, f), = args

            def toint(r):
                try:
                    return int(f(r))
                except (TypeError, ValueError):
                    return None
            return toint
        if name == "parse_json":
            (_, f), = args

            def parse_json(r):
                v = f(r)
                if isinstance(v, str):
                    try:
                        return json.loads(v)
                    except ValueError:
                        return None
                return v
            return parse_json
        if name == "tostring":
            (_, f), = args
            return lambda r: "" if f(r) is None else str(f(r))
        raise NotImplementedError(f"KQL subset: function {name}()")


def run(query: str, rows: list[dict], now: datetime | None = None) -> list[dict]:
    """The rows `query` returns over `rows` (dicts; TimeGenerated a datetime)."""
    now = now or datetime.now(timezone.utc)
    stages = _stages(_tokens(query))
    table = stages[0]
    if len(table) != 1 or table[0][0] != "ident":
        raise NotImplementedError(f"KQL subset: a table first, not {table}")
    out = [dict(r) for r in rows if r.get("Type", table[0][1]) == table[0][1]]
    for stage in stages[1:]:
        p = _Parser(stage, now)
        verb = p.take("ident")[1]
        if verb == "where":
            pred = p.expr()
            out = [r for r in out if pred(r)]
        elif verb == "extend":
            while True:
                col = p.take("ident")[1]
                p.take("op", "=")
                f = p.expr()
                out = [{**r, col: f(r)} for r in out]
                if not p.at(","):
                    break
                p.take()
        elif verb == "project":
            cols = [p.take("ident")[1]]
            while p.at(","):
                p.take()
                cols.append(p.take("ident")[1])
            out = [{c: r.get(c) for c in cols} for r in out]
        elif verb in ("limit", "take"):
            out = out[:int(p.take("num")[1])]
        elif verb == "summarize":
            out = _summarize(p, out)
        elif verb == "order":
            p.take("ident", "by")
            col = p.take("ident")[1]
            desc = True                     # KQL's default
            if p.at("asc") or p.at("desc"):
                desc = p.take()[1] == "desc"
            out = sorted(out, key=lambda r: (r.get(col) is not None, r.get(col)), reverse=desc)
        else:
            raise NotImplementedError(f"KQL subset: operator {verb}")
        if not p.done():
            raise NotImplementedError(f"KQL subset: left unread in `{verb}`: {p.t[p.i:]}")
    return out


def _summarize(p: _Parser, rows: list[dict]) -> list[dict]:
    arg_max, aggs = None, []
    if p.peek()[1] == "arg_max":
        p.take()
        p.take("op", "(")
        arg_max = p.take("ident")[1]
        p.take("op", ",")
        p.take("op", "*")
        p.take("op", ")")
    if arg_max is None or p.at(","):
        if arg_max is not None:
            p.take()
        while True:
            name = p.take("ident")[1]
            p.take("op", "=")
            fn = p.take("ident")[1]
            if fn not in _AGGREGATES:
                raise NotImplementedError(f"KQL subset: aggregation {fn}()")
            aggs.append((name, fn, [f for _, f in p.args()]))
            if not p.at(","):
                break
            p.take()
    p.take("ident", "by")
    by = [p.take("ident")[1]]
    while p.at(","):
        p.take()
        by.append(p.take("ident")[1])
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault(tuple(r.get(c) for c in by), []).append(r)
    out = []
    for k, members in groups.items():
        best = max(members, key=lambda r: r.get(arg_max)) if arg_max is not None else {}
        out.append({**best, **dict(zip(by, k)),
                    **{name: _AGGREGATES[fn](members, *fs) for name, fn, fs in aggs}})
    return out


def _min(members, f):
    vals = [v for v in (f(r) for r in members) if v is not None]
    return min(vals) if vals else None


def _max(members, f):
    vals = [v for v in (f(r) for r in members) if v is not None]
    return max(vals) if vals else None


def _make_set_if(members, f, pred, n):
    """KQL's make_set_if: the distinct values (nulls left out) of the rows the predicate keeps,
    at most n (AUD1)."""
    out = []
    for r in members:
        v = f(r)
        if pred(r) and v is not None and v not in out and len(out) < n(r):
            out.append(v)
    return out


_AGGREGATES = {
    "count": lambda members: len(members),
    "countif": lambda members, pred: sum(1 for r in members if pred(r)),
    "min": _min,
    "max": _max,
    "take_any": lambda members, f: next((f(r) for r in members if f(r) is not None), None),
    "make_set_if": _make_set_if,
    # Log Analytics picks any row the predicate keeps (no order): this reader takes the first.
    # A rule that reads it holds for any choice — its predicate keeps only what may be taken
    # (AL2). Nulls left out, as take_any.
    "take_anyif": lambda members, f, pred: next(
        (f(r) for r in members if pred(r) and f(r) is not None), None),
}
