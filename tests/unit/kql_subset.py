"""A KQL subset, evaluated in Python over rows in memory — the shipped Syslog rules run
as written, on lines the test writes (SEC2). No Log Analytics, no Azure.

Only what the Syslog rules use: a table, then `where`, `extend`, `summarize` (`count()`,
`arg_max(col, *)`), `project`, `order by`; predicates `==`, `!=`, `<`, `<=`, `>`, `>=`,
`has`, `!has`, `in (…)`, `matches regex`, `startswith`, `and`, `or`, `not(…)`; functions
`ago()`, `extract()`, `isnotempty()`, `isnotnull()`, `toint()`, `tostring()`. Anything
else raises NotImplementedError: a rule this reader cannot follow fails its test, never
passes it by accident. `has` is KQL's term match (case-insensitive, at term boundaries);
regexes are read by Python's `re` (the patterns of the rules mean the same in RE2).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<comment>//[^\n]*)
  | (?P<vstr>@"[^"]*"|@'[^']*')
  | (?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<span>\d+(?:\.\d+)?(?:d|h|m|s|ms|min|days?|hours?|minutes?|seconds?)\b)
  | (?P<num>\d+(?:\.\d+)?)
  | (?P<op>==|!=|>=|<=|=~|!has\b|!contains\b|[|(),=<>*])
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
    return re.search(r"(?<![A-Za-z0-9])" + re.escape(str(needle)) + r"(?![A-Za-z0-9])",
                     str(hay or ""), re.IGNORECASE) is not None


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
        if op in ("==", "!=", ">=", "<=", ">", "<") and tok[0] == "op":
            self.take()
            right = self.primary()
            ops = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b,
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
        if op == "in" and tok[0] == "ident":
            self.take()
            self.take("op", "(")
            items = [self.primary()]
            while self.at(","):
                self.take()
                items.append(self.primary())
            self.take("op", ")")
            return lambda r: left(r) in [f(r) for f in items]
        if op == "matches" and tok[0] == "ident":
            self.take()
            self.take("ident", "regex")
            pattern = re.compile(self.take("str")[1])
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
                return self.call(text)
            return lambda r, c=text: r.get(c)
        raise NotImplementedError(f"KQL subset: unexpected {text!r}")

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
        if name == "isnotnull":
            (_, f), = args
            return lambda r: f(r) is not None
        if name == "extract":
            (_, pat), (_, grp), (_, src) = args

            def extract(r):
                m = re.search(pat(r), str(src(r) or ""))
                return (m.group(grp(r)) or "") if m else ""
            return extract
        if name == "toint":
            (_, f), = args

            def toint(r):
                try:
                    return int(f(r))
                except (TypeError, ValueError):
                    return None
            return toint
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
    if p.peek()[1] == "arg_max":
        p.take()
        p.take("op", "(")
        key = p.take("ident")[1]
        p.take("op", ",")
        p.take("op", "*")
        p.take("op", ")")
        agg = ("arg_max", key, None)
    else:
        name = p.take("ident")[1]
        p.take("op", "=")
        p.take("ident", "count")
        p.take("op", "(")
        p.take("op", ")")
        agg = ("count", None, name)
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
        if agg[0] == "count":
            out.append({**dict(zip(by, k)), agg[2]: len(members)})
        else:
            best = max(members, key=lambda r: r.get(agg[1]))
            out.append({**best, **dict(zip(by, k))})
    return out
