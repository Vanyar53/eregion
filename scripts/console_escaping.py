"""What the console writes into its pages from the outside goes through an escape (#254).

    python scripts/console_escaping.py          # the raw writes: where, what, where it comes from

The console builds its pages with template literals given to innerHTML. A field of a card, a
rule, a feed entry or an error — a resource's or an Entra application's name from Azure, a
step from the model, a rule's query, a message — written raw there runs in the operator's
console, and can call its routes (#250 found one; the CSP of #222 has no `script-src`: the
inline handlers would break).

This reader follows what can reach the page. It reads the scripts of each page (the inline
ones and console.js, exercises.js), and checks every `${…}` of an HTML template and every
value given to innerHTML: what each one can hold, through the branches of a ternary, `||`,
`+`, `.map(…).join(…)`, a variable to its declaration and its assignments, a page function
to its returns, a parameter to the arguments of its calls. A value is clean when it is a
literal, a number, a page table, or escaped (`esc`, `_attr`, `encodeURIComponent`; `_js` in
an `on…` attribute, where the browser decodes `&#39;` before the handler runs). Anything
else is raw: a field of what the server sent, a callback's argument, an error, the address
bar. ALLOWED names the few values the reader cannot follow and the page built, with why.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "eregion_console" / "static"
PAGES = ("glorfindel.html", "overview.html", "injector.html")

# The page's escapes, by where the value lands (_context): the page's text or a double-quoted
# attribute; the JavaScript of an on… attribute (`_js` makes a string of it); the start of a
# URL (an escaped `javascript:` is still one). An unquoted attribute takes none.
ESCAPES = {
    "html": {"esc", "_attr", "_js", "Console.esc", "encodeURIComponent"},
    "js": {"_js"},
    "url": {"encodeURIComponent"},
    "unquoted": set(),
}
_WHERE = {"js": "an on… attribute (the browser decodes it before the handler runs)",
          "url": "the start of a URL (a javascript: URL survives HTML escaping)",
          "unquoted": "an attribute not in double quotes (write it in double quotes)"}

# What the reader cannot follow, and the page built: (file, expression as written) → why.
ALLOWED: dict[tuple[str, str], str] = {}

_SAFE_GLOBALS = {"undefined", "NaN", "Infinity"}
# Calls whose result is a number, a boolean or a date's digits, whatever they are given.
_SAFE_CALLS = {"Number", "parseInt", "parseFloat", "isNaN", "isFinite", "Boolean", "Date.now",
               "Array.isArray"}
_SAFE_METHODS = {"toFixed", "toPrecision", "getTime", "toISOString", "toUTCString",
                 "toLocaleTimeString", "toLocaleDateString", "indexOf", "lastIndexOf",
                 "findIndex", "includes", "has", "some", "every", "test", "startsWith",
                 "endsWith", "localeCompare", "getUTCHours", "getUTCMinutes", "getUTCSeconds",
                 "getUTCDate", "getUTCMonth", "getUTCFullYear", "getHours", "getMinutes",
                 "getSeconds", "getDate", "getMonth", "getFullYear", "getDay", "valueOf"}
# Methods whose result is made of their receiver (and of their arguments, for some).
_SAME_METHODS = {"toUpperCase", "toLowerCase", "trim", "trimStart", "trimEnd", "slice",
                 "substring", "substr", "split", "toString", "at", "charAt", "repeat",
                 "normalize", "filter", "sort", "reverse", "flat", "find", "pop", "shift", "match",
                 "get", "values", "keys", "entries", "toLocaleString"}
_WITH_ARGS_METHODS = {"concat", "padStart", "padEnd", "join", "replace", "replaceAll"}
_CALLBACK_METHODS = {"map", "flatMap"}
# Methods that call a function with each item of their receiver (reduce: its second parameter).
_FEEDS = {"map", "flatMap", "forEach", "filter", "find", "findIndex", "some", "every", "sort", "reduce"}
# Methods that store nothing of their arguments in their receiver.
_PURE = {"has", "get", "includes", "indexOf", "lastIndexOf", "find", "findIndex", "some", "every",
         "map", "flatMap", "filter", "forEach", "join", "slice", "concat", "keys", "values",
         "entries", "toString", "startsWith", "endsWith", "test", "match", "matchAll", "replace",
         "replaceAll", "split", "trim", "toUpperCase", "toLowerCase", "at", "charAt", "reduce",
         "flat", "localeCompare", "padStart", "padEnd", "toFixed", "getTime", "toISOString",
         "getElementById", "querySelector", "querySelectorAll", "closest", "contains",
         "getAttribute", "then", "catch", "finally", "json", "text", "stopPropagation",
         "preventDefault", "remove", "focus", "scrollIntoView", "toggle"}
_SAME_OF_ARGS = {"String", "JSON.stringify", "Object.keys", "Object.values", "Object.entries",
                 "Array.from"}
_BROWSER = {"window", "document", "location", "navigator", "localStorage", "sessionStorage",
            "history", "event", "this"}

_KW_BEFORE_REGEX = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
                    "throw", "case", "do", "else", "yield", "await"}
_KEYWORDS = _KW_BEFORE_REGEX | {"if", "for", "while", "switch", "catch", "try", "finally",
                                "function", "const", "let", "var", "async", "break", "continue",
                                "default", "class", "this", "true", "false", "null"}
_PUNCT = sorted(""">>>= ... === !== **= <<= >>= >>> &&= ||= ??= => == != <= >= && || ?? ?.
                ++ -- += -= *= /= %= &= |= ^= ** << >>""".split(), key=len, reverse=True)
_ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "&&=", "||=", "??=", "**=", "<<=", ">>=",
           ">>>=", "&=", "|=", "^="}


# --- reading: tokens -------------------------------------------------------------------

@dataclass
class Tok:
    kind: str           # name, num, str, tpl, regex, punct
    text: str
    pos: int            # offset in the page's unit (Unit.where)
    quasis: list[str] = field(default_factory=list)      # tpl: the text between the ${…}
    exprs: list[list["Tok"]] = field(default_factory=list)  # tpl: the tokens of each ${…}
    ends: list[int] = field(default_factory=list)        # tpl: where each ${…} closes


def tokenize(src: str, base: int = 0, i: int = 0, stop_at_brace: bool = False):
    """The tokens of `src` from `i`; with `stop_at_brace`, up to the `}` closing a `${`.
    Returns (tokens, index after the end)."""
    toks: list[Tok] = []
    depth = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            i = src.index("*/", i) + 2
        elif c in "'\"":
            j = i + 1
            while src[j] != c:
                j += 2 if src[j] == "\\" else 1
            toks.append(Tok("str", src[i:j + 1], base + i))
            i = j + 1
        elif c == "`":
            tok, i = _template(src, base, i)
            toks.append(tok)
        elif c == "/" and not _after_value(toks):
            j, cls = i + 1, False
            while True:
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "\n":
                    raise SyntaxError(f"unterminated regex at {base + i}")
                if ch == "[":
                    cls = True
                elif ch == "]":
                    cls = False
                elif ch == "/" and not cls:
                    break
                j += 1
            j += 1
            while j < n and src[j].isalpha():
                j += 1
            toks.append(Tok("regex", src[i:j], base + i))
            i = j
        elif c.isalpha() or c in "_$":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(Tok("name", src[i:j], base + i))
            i = j
        elif c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = re.compile(r"0[xXbBoO][\da-fA-F_]+|(\d[\d_]*)?\.?\d*([eE][+-]?\d+)?").match(src, i)
            toks.append(Tok("num", m.group(0), base + i))
            i = m.end()
        else:
            if c == "{":
                depth += 1
            elif c == "}":
                if depth == 0 and stop_at_brace:
                    return toks, i
                depth -= 1
            op = next((p for p in _PUNCT if src.startswith(p, i)), c)
            if op == "?." and i + 2 < n and src[i + 2].isdigit():
                op = "?"
            toks.append(Tok("punct", op, base + i))
            i += len(op)
    if stop_at_brace:
        raise SyntaxError(f"unterminated ${{ at {base + i}")
    return toks, i


def _after_value(toks: list[Tok]) -> bool:
    if not toks:
        return False
    t = toks[-1]
    if t.kind == "name":
        return t.text not in _KW_BEFORE_REGEX
    return t.kind in ("num", "str", "tpl", "regex") or t.text in (")", "]", "}")


def _template(src: str, base: int, i: int):
    tok = Tok("tpl", "", base + i)
    j, part = i + 1, []
    while True:
        ch = src[j]
        if ch == "\\":
            part.append(src[j:j + 2])
            j += 2
        elif ch == "`":
            tok.quasis.append("".join(part))
            tok.text = src[i:j + 1]
            return tok, j + 1
        elif src.startswith("${", j):
            tok.quasis.append("".join(part))
            part = []
            inner, end = tokenize(src, base, j + 2, stop_at_brace=True)
            tok.exprs.append(inner)
            tok.ends.append(base + end)
            j = end + 1
        else:
            part.append(ch)
            j += 1


# --- reading: expressions --------------------------------------------------------------

@dataclass(eq=False)
class Node:
    kind: str
    pos: int
    end: int                    # offset just after the node (for its source text)
    kids: list = field(default_factory=list)
    text: str = ""              # name, operator, property, literal
    tok: Tok | None = None      # tpl: its token
    span: tuple = ()            # function with a block: (tokens, first, last)
    keys: list = field(default_factory=list)    # object: each value's key (None: computed, spread)


_BINARY = {"??": 4, "||": 4, "&&": 5, "|": 6, "^": 7, "&": 8, "==": 9, "!=": 9, "===": 9,
           "!==": 9, "<": 10, ">": 10, "<=": 10, ">=": 10, "instanceof": 10, "in": 10,
           "<<": 11, ">>": 11, ">>>": 11, "+": 12, "-": 12, "*": 13, "/": 13, "%": 13, "**": 14}


class Parser:
    """A Pratt parser for the expressions of the console's scripts."""

    def __init__(self, toks: list[Tok], end_pos: int):
        self.t = toks
        self.end_pos = end_pos
        self.close = _matching(toks)
        self.open = {b: a for a, b in self.close.items()}

    def peek(self, i: int, text: str) -> bool:
        return i < len(self.t) and self.t[i].text == text and self.t[i].kind in ("punct", "name")

    def _end(self, i: int) -> int:
        return self.t[i].pos if i < len(self.t) else self.end_pos

    def expr(self, i: int, rbp: int = 0):
        """The expression starting at token i, without the comma operator: (node, next i)."""
        left, i = self.prefix(i)
        while i < len(self.t):
            t = self.t[i]
            if t.kind == "tpl":     # a tagged template
                left = Node("call", left.pos, self._end(i + 1), [left, self._tpl(t)])
                i += 1
                continue
            if t.kind not in ("punct", "name"):
                break
            op = t.text
            if op in (".", "?.") and i + 1 < len(self.t) and self.t[i + 1].kind == "name":
                left = Node("member", left.pos, self._end(i + 2), [left], self.t[i + 1].text)
                i += 2
            elif op == "?." and self.peek(i + 1, "("):
                i += 1
                continue
            elif op == "?." and self.peek(i + 1, "["):
                i += 1
                continue
            elif op == "[" and t.kind == "punct":
                key, j = self.seq(i + 1)
                left = Node("index", left.pos, self._end(j + 1), [left, key])
                i = j + 1
            elif op == "(" and t.kind == "punct":
                args, j = self.items(i + 1, ")")
                left = Node("call", left.pos, self._end(j + 1), [left, *args])
                i = j + 1
            elif op in ("++", "--") and t.kind == "punct":
                left = Node("unary", left.pos, self._end(i + 1), [left], op)
                i += 1
            elif op == "?" and rbp < 3:
                a, j = self.expr(i + 1, 2)
                assert self.t[j].text == ":", f"ternary at {t.pos}"
                b, j = self.expr(j + 1, 2)
                left = Node("cond", left.pos, self._end(j), [left, a, b])
                i = j
            elif op in _ASSIGN and t.kind == "punct" and rbp < 2:
                right, j = self.expr(i + 1, 1)
                left = Node("assign", left.pos, self._end(j), [left, right], op)
                i = j
            elif op in _BINARY and _BINARY[op] > rbp:
                bp = _BINARY[op]
                right, j = self.expr(i + 1, bp - 1 if op == "**" else bp)
                left = Node("binary", left.pos, self._end(j), [left, right], op)
                i = j
            else:
                break
        return left, i

    def prefix(self, i: int):
        t = self.t[i]
        nxt = self._end(i + 1)
        if t.kind in ("num", "str", "regex"):
            return Node("lit", t.pos, nxt, text=t.text), i + 1
        if t.kind == "tpl":
            return self._tpl(t), i + 1
        if t.kind == "name":
            if t.text == "async" and i + 1 < len(self.t) and (
                    self.peek(i + 1, "(") or self.peek(i + 2, "=>") or self.peek(i + 1, "function")):
                return self.prefix(i + 1)
            if self.peek(i + 1, "=>"):
                return self._arrow(i, i + 1)
            if t.text == "function":
                j = i + 1
                if self.t[j].kind == "name":
                    j += 1
                close = self.close[j]
                body = close + 1
                return Node("function", t.pos, self._end(self.close[body] + 1),
                            span=(self.t, body, self.close[body])), self.close[body] + 1
            if t.text in ("typeof", "void", "delete", "await", "new"):
                arg, j = self.expr(i + 1, 15 if t.text != "new" else 16)
                if t.text == "new" and self.peek(j, "("):
                    args, k = self.items(j + 1, ")")
                    arg = Node("call", arg.pos, self._end(k + 1), [arg, *args])
                    j = k + 1
                return Node("unary", t.pos, self._end(j), [arg], t.text), j
            if t.text in ("true", "false", "null"):
                return Node("lit", t.pos, nxt, text=t.text), i + 1
            return Node("name", t.pos, nxt, text=t.text), i + 1
        op = t.text
        if op == "(":
            close = self.close[i]
            if self.peek(close + 1, "=>"):
                return self._arrow(i, close + 1)
            inner, j = self.seq(i + 1)
            return Node("paren", t.pos, self._end(j + 1), [inner]), j + 1
        if op == "[":
            items, j = self.items(i + 1, "]")
            return Node("array", t.pos, self._end(j + 1), items), j + 1
        if op == "{":
            return self._object(i)
        if op == "...":
            arg, j = self.expr(i + 1, 1)
            return Node("spread", t.pos, self._end(j), [arg]), j
        if op in ("!", "-", "+", "~", "++", "--"):
            arg, j = self.expr(i + 1, 15)
            return Node("unary", t.pos, self._end(j), [arg], op), j
        raise SyntaxError(f"unexpected {op!r} at {t.pos}")

    def seq(self, i: int):
        node, i = self.expr(i)
        while self.peek(i, ","):
            node, i = self.expr(i + 1)
        return node, i

    def items(self, i: int, closer: str):
        out = []
        while not self.peek(i, closer):
            if self.peek(i, ","):
                i += 1
                continue
            node, i = self.expr(i)
            out.append(node)
        return out, i

    def _tpl(self, t: Tok) -> Node:
        kids = [Parser(e, end).seq(0)[0] if e else Node("lit", end, end) for e, end in zip(t.exprs, t.ends)]
        return Node("tpl", t.pos, t.pos + len(t.text), kids, tok=t)

    def _arrow(self, start: int, arrow: int):
        """An arrow function: its parameters from `start`, its `=>` at `arrow`."""
        body = arrow + 1
        if self.peek(body, "{"):
            last = self.close[body]
            return Node("function", self.t[start].pos, self._end(last + 1), span=(self.t, body, last)), last + 1
        expr, j = self.expr(body, 1)
        return Node("function", self.t[start].pos, self._end(j), [expr]), j

    def _object(self, i: int):
        close = self.close[i]
        j, kids, keys = i + 1, [], []
        while j < close:
            t = self.t[j]
            if t.text == ",":
                j += 1
                continue
            if t.text == "...":
                node, j = self.expr(j + 1, 1)
                kids.append(node)
                keys.append(None)
                continue
            key = None if t.text == "[" else t.text
            if t.text == "[":            # [computed]: value
                j = self.close[j] + 1
            elif t.text in ("get", "set", "async") and j + 1 < close and self.t[j + 1].text not in (",", ":", "("):
                key = self.t[j + 1].text
                j += 2
            else:
                j += 1
            keys.append(key)
            if self.peek(j, ":"):
                node, j = self.expr(j + 1, 1)
                kids.append(node)
            elif self.peek(j, "("):            # a method
                body = self.close[j] + 1
                kids.append(Node("function", self.t[j].pos, self._end(self.close[body] + 1),
                                 span=(self.t, body, self.close[body])))
                j = self.close[body] + 1
            else:                              # shorthand
                kids.append(Node("name", t.pos, self._end(j), text=t.text))
        return Node("object", self.t[i].pos, self._end(close + 1), kids, keys=keys), close + 1


def _matching(toks: list[Tok]) -> dict[int, int]:
    pairs, stack = {}, []
    for k, t in enumerate(toks):
        if t.kind != "punct":
            continue
        if t.text in "([{":
            stack.append(k)
        elif t.text in ")]}":
            pairs[stack.pop()] = k
    return pairs


# --- the page: its scripts read as one ---------------------------------------------------

@dataclass(eq=False)
class Fn:
    body: Node                      # a "function" node: an expression ([expr]) or a block (span)
    named: bool = False             # declared, or a const's value: its calls are seen
    calls: list[list[Node]] = field(default_factory=list)
    escapes: bool = False           # passed as a value, or named in an on… attribute
    feeds: list[tuple[int, Node]] = field(default_factory=list)    # .map(fn) and kin: (param, the array)


@dataclass(eq=False)
class Decl:
    name: str
    pos: int
    scope: tuple[int, int]
    kind: str                       # var, function, param, element, caught
    init: Node | None = None        # var: its value; element: what it is taken from
    fn: Fn | None = None            # function: itself; param: the function it belongs to
    index: int = 0                  # param: its place
    assigns: list[Node] = field(default_factory=list)   # what is assigned to it, or to its fields


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    sink: str                       # the ${…} or the value given to innerHTML
    origin: str                     # what is raw in it, where it comes from
    why: str

    def __str__(self):
        return f"{self.file}:{self.line}: {self.sink} — {self.why}: {self.origin}"


_STRIDE = 10_000_000                # a file's offsets in the unit: its index × _STRIDE


class Unit:
    """A page: its inline scripts and the scripts it loads, read as one."""

    def __init__(self, page: str, static: Path = STATIC):
        self.files: list[tuple[str, str]] = []
        self.decls: dict[str, list[Decl]] = {}
        self.fns: dict[int, Fn] = {}
        self.templates: list[tuple[Node, str]] = []    # every HTML template, nested ones too,
        self._html: set[int] = set()                    # and where it lands (_context)
        self.sinks: list[Node] = []         # every value given to innerHTML
        self._uses: list = []
        self._calls: list = []
        self._refs: list = []
        self._feeds: list = []
        self._mcalls: list = []
        self._parsers: dict[int, Parser] = {}
        self._memo: dict = {}
        self._busy: set = set()
        self._cycles = 0
        html = (static / page).read_text(encoding="utf-8")
        for m in re.finditer(r"<script(?:\s+src=\"/static/([\w.]+)\")?[^>]*>(.*?)</script>", html, re.S):
            if m.group(1):
                self._read(m.group(1), (static / m.group(1)).read_text(encoding="utf-8"), 0, None)
            else:
                self._read(page, html, m.start(2), m.end(2))
        self._link()

    def _read(self, name: str, text: str, start: int, stop: int | None):
        base = len(self.files) * _STRIDE
        self.files.append((name, text))
        end = base + (len(text) if stop is None else stop)
        toks, _ = tokenize(text if stop is None else text[:stop], base, start)
        self._scan(toks, (0, end), everywhere=True)
        # A function named in an on… attribute is called by the page with what it wrote there.
        for attr in re.finditer(r"\bon[a-z]+\s*=\s*\"([^\"]*)\"", text):
            self._refs.extend((n, -1) for n in re.findall(r"([A-Za-z_$][\w$]*)\s*\(", attr.group(1)))

    def where(self, pos: int) -> tuple[str, int]:
        name, text = self.files[pos // _STRIDE]
        return name, text.count("\n", 0, pos % _STRIDE) + 1

    def source(self, node: Node) -> str:
        text = self.files[node.pos // _STRIDE][1]
        return " ".join(text[node.pos % _STRIDE:node.end % _STRIDE].split())

    def parser(self, toks: list[Tok], end: int) -> Parser:
        p = self._parsers.get(id(toks))
        if p is None:
            p = self._parsers[id(toks)] = Parser(toks, end)
        return p

    # --- the scan: declarations, then uses ---------------------------------------------

    def _scan(self, toks: list[Tok], outer: tuple[int, int], everywhere: bool = False, ctx: str = "html"):
        """`everywhere`: a script's top level, seen by the page's other scripts. `ctx`: where
        the ${…} these tokens are lands (_context)."""
        if not toks:
            return
        p = self.parser(toks, outer[1])
        if everywhere:
            outer = (0, sys.maxsize)
        blocks = [(toks[a].pos, toks[b].pos) for a, b in p.close.items() if toks[a].text == "{"]

        def scope_at(k: int) -> tuple[int, int]:
            inside = [b for b in blocks if b[0] < toks[k].pos <= b[1]]
            return min(inside, key=lambda b: b[1] - b[0]) if inside else outer

        def declare(k: int, kind: str, scope, **kw) -> Decl:
            d = Decl(toks[k].text, toks[k].pos, scope, kind, **kw)
            self.decls.setdefault(d.name, []).append(d)
            return d

        def params(fn: Fn, first: int, last: int, scope):
            depth, index, k = 0, 0, first
            while k < last:
                t = toks[k]
                if t.kind == "punct" and t.text in "([{":
                    depth += 1
                elif t.kind == "punct" and t.text in ")]}":
                    depth -= 1
                elif t.text == "," and depth == 0:
                    index += 1
                elif t.text == "=" and t.kind == "punct":     # a default value
                    k = _skip_expr(toks, k + 1, last)
                    continue
                elif t.kind == "name" and t.text != "async" and toks[k + 1].text != ":":
                    if depth:       # destructured: a field of what the function is given
                        declare(k, "element", scope)
                    else:
                        declare(k, "param", scope, fn=fn, index=index)
                k += 1

        for k, t in enumerate(toks):
            prev = toks[k - 1] if k else None
            if t.kind == "tpl":
                if _is_html(t):
                    self.templates.append((p._tpl(t), ctx))
                    self._html.add(t.pos)
                for i, (e, end) in enumerate(zip(t.exprs, t.ends)):
                    self._scan(e, (e[0].pos if e else end, end), ctx=_context(t, i, ctx))
            elif t.kind == "name" and t.text in ("const", "let", "var"):
                self._declarators(p, toks, k + 1, scope_at(k), declare)
            elif t.kind == "name" and t.text == "function":
                j = k + 1 + (toks[k + 1].kind == "name")
                body = p.close[j] + 1
                node = Node("function", t.pos, toks[p.close[body]].pos + 1, span=(toks, body, p.close[body]))
                declared = toks[k + 1].kind == "name" and (prev is None or prev.text in (";", "{", "}", "async"))
                fn = self._fn(node, named=declared)
                if declared:
                    declare(k + 1, "function", scope_at(k), fn=fn)
                params(fn, j + 1, p.close[j], (toks[j].pos, toks[p.close[body]].pos))
            elif t.kind == "punct" and t.text == "=>":
                if prev.text == ")":
                    start = p.open[k - 1]
                    first, last = start + 1, k - 1
                else:
                    start, first, last = k - 1, k - 1, k
                node, _ = p._arrow(start, k)
                fn = self._fn(node, named=False)
                params(fn, first, last, (toks[start].pos, node.end))
            elif t.kind == "name" and t.text == "catch" and prev.text != "." and toks[k + 1].text == "(" \
                    and toks[k + 3].text == ")":
                declare(k + 2, "caught", (t.pos, toks[p.close[p.close[k + 1] + 1]].pos))

        for k, t in enumerate(toks):
            if t.kind == "punct" and t.text == "(" and k >= 3 and toks[k - 2].text in (".", "?.") \
                    and toks[k - 1].text in _FEEDS:
                self._feed(p, toks, k)
            if t.kind == "punct" and t.text == "." and toks[k + 1].text in ("innerHTML", "outerHTML") \
                    and toks[k + 2].text in ("=", "+="):
                self.sinks.append(p.expr(k + 3, 1)[0])
            if t.kind == "name" and t.text == "insertAdjacentHTML" and toks[k + 1].text == "(":
                self.sinks.extend(p.items(k + 2, ")")[0][1:2])
            prev = toks[k - 1] if k else None
            if t.kind != "name" or t.text in _KEYWORDS or (
                    prev is not None and prev.text in (".", "?.", "const", "let", "var", "function")):
                continue
            # The name, then its fields and calls: what goes into it (x.f = v, x[k] = v, x.push(v),
            # x.get(k).push(v), any method not known to leave it as it is).
            j, keys, calls = k + 1, [], []
            if j < len(toks) and toks[j].kind == "punct" and toks[j].text == "(":
                self._calls.append((t.text, t.pos, p.items(j + 1, ")")[0]))
                continue
            while j < len(toks):
                if toks[j].text in (".", "?.") and j + 1 < len(toks) and toks[j + 1].kind == "name":
                    j += 2
                elif toks[j].text == "?.":
                    j += 1
                elif toks[j].kind == "punct" and toks[j].text == "[":
                    keys.append(p.seq(j + 1)[0])
                    j = p.close[j] + 1
                elif toks[j].kind == "punct" and toks[j].text == "(":
                    calls.append((toks[j - 1].text, p.items(j + 1, ")")[0], j == k + 3))
                    j = p.close[j] + 1
                else:
                    break
            nxt = toks[j] if j < len(toks) else None
            for method, args, first in calls:
                if first:
                    self._mcalls.append((t, method, args))
                if method not in _PURE:
                    self._uses.extend((t.text, t.pos, a) for a in args)
            if t.text == "Object" and calls and calls[0][0] == "assign" and calls[0][1] and calls[0][1][0].kind == "name":
                target = calls[0][1][0]
                self._uses.extend((target.text, target.pos, a) for a in calls[0][1][1:])
            if nxt is not None and nxt.kind == "punct" and nxt.text in _ASSIGN:
                # x[key] = v: the key too, for Object.keys(x) and for…in
                self._uses.extend((t.text, t.pos, v) for v in (*keys, p.expr(j + 1, 1)[0]))
            elif j == k + 1 and not (prev is not None and prev.text in ("{", ",") and nxt is not None
                                     and nxt.text in (",", "}")):     # not a page object's method
                self._refs.append((t.text, t.pos))

    def _declarators(self, p: Parser, toks, j, scope, declare):
        while True:
            if toks[j].kind == "punct" and toks[j].text in "{[":
                close = p.close[j]
                names, pattern = list(_pattern_names(toks, j, close)), True
                j = close + 1
            else:
                names, pattern = [j], False
                j += 1
            how, init = toks[j].text if j < len(toks) else None, None
            if how in ("=", "of", "in"):
                init, j = p.expr(j + 1, 1)
            for x in names:
                if how == "=" and not pattern and init.kind == "function":
                    declare(x, "function", scope, fn=self._fn(init, named=True), init=init)
                elif how in ("=", None) and not pattern:
                    declare(x, "var", scope, init=init)
                else:           # destructured, or the item of a for…of / for…in: made of init
                    declare(x, "element", scope, init=init)
            if j < len(toks) and toks[j].text == ",":
                j += 1
                continue
            return

    def _feed(self, p: Parser, toks: list[Tok], k: int):
        """`array.map(fn)` and kin, the `(` at k: fn's item parameter holds the array's items."""
        start = k - 3
        while True:
            t = toks[start]
            if t.kind == "punct" and t.text in ")]":
                start = p.open[start]
                if start and (toks[start - 1].kind in ("name", "tpl", "str") and toks[start - 1].text not in _KEYWORDS
                              or toks[start - 1].text in (")", "]")):
                    start -= 1
                    continue
                break
            if start >= 2 and toks[start - 1].text in (".", "?."):
                start -= 2
                continue
            break
        node, _ = p.expr(start, 16)
        while node.kind in ("call", "member", "index"):
            callee = node.kids[0]
            if node.kind == "call" and callee.kind == "member" and callee.end == toks[k].pos:
                if len(node.kids) > 1:
                    fn, feeds = node.kids[1], [(0, callee.kids[0])]
                    if callee.text == "reduce":     # (accumulator, item): the start value, then what fn returns
                        start = node.kids[2] if len(node.kids) > 2 else Node("name", node.pos, node.pos, text="undefined")
                        feeds = [(1, callee.kids[0]), (0, Node("reduced", start.pos, start.end, [start, fn]))]
                    for index, array in feeds:
                        if fn.kind == "function":
                            self._fn(fn, named=False).feeds.append((index, array))
                        elif fn.kind == "name":
                            self._feeds.append((fn.text, fn.pos, index, array))
                return
            node = callee

    def _fn(self, node: Node, named: bool) -> Fn:
        fn = self.fns.get(node.pos)
        if fn is None:
            fn = self.fns[node.pos] = Fn(node)
        fn.named = fn.named or named
        return fn

    def _link(self):
        for name, pos, rhs in self._uses:
            d = self.resolve(name, pos)
            if d is not None:
                d.assigns.append(rhs)
        for name, pos, args in self._calls:
            d = self.resolve(name, pos)
            if d is not None and d.kind == "function":
                d.fn.calls.append(args)
        for t, method, args in self._mcalls:            # Console.setJudgeCount(n)
            if fn := self._method(Node("name", t.pos, t.pos + len(t.text), text=t.text), method):
                fn.calls.append(args)
        # What a function puts into its parameter goes into what its callers gave it.
        for ds in list(self.decls.values()):
            for d in ds:
                if d.kind == "param" and d.assigns:
                    for args in d.fn.calls:
                        if d.index < len(args) and args[d.index].kind == "name":
                            if (to := self.resolve(args[d.index].text, args[d.index].pos)) is not None:
                                to.assigns.extend(d.assigns)
        fed = set()
        for name, pos, index, array in self._feeds:
            d = self.resolve(name, pos)
            if d is not None and d.kind == "function":
                d.fn.feeds.append((index, array))
                fed.add(pos)
        for name, pos in self._refs:
            if pos in fed:
                continue
            for d in (self.decls.get(name, ()) if pos < 0 else [self.resolve(name, pos)]):
                if d is not None and d.kind == "function" and d.pos != pos:
                    d.fn.escapes = True

    def resolve(self, name: str, pos: int) -> Decl | None:
        seen = [d for d in self.decls.get(name, ()) if d.scope[0] <= pos <= d.scope[1]]
        if not seen:
            return None
        before = [d for d in seen if d.pos <= pos or d.kind == "function"] or seen
        return min(before, key=lambda d: (d.scope[1] - d.scope[0], -d.pos))

    # --- what a value can hold ------------------------------------------------------------

    def raw(self, node: Node, ctx: str = "html") -> list[tuple[Node, str]]:
        """What in `node`'s value reaches the page unescaped: [(where it comes from, why)].
        `ctx`: where the value lands (see _context)."""
        k, kids = node.kind, node.kids
        if k in ("lit", "function"):
            return []
        if k == "tpl":      # an HTML template is checked on its own
            if node.pos in self._html:
                return []
            return [r for i, e in enumerate(kids) for r in self.raw(e, _context(node.tok, i, ctx))]
        if k == "name":
            if node.text in _SAFE_GLOBALS:
                return []
            d = self.resolve(node.text, node.pos)
            if d is None:
                return [(node, "from the browser" if node.text in _BROWSER else "not declared in the page")]
            return self._decl(d, ctx)
        if k == "member":
            return [] if node.text in ("length", "size") else self._field(kids[0], node.text, ctx)
        if k in ("index", "paren", "spread", "assign"):
            return self.raw(kids[-1] if k == "assign" else kids[0], ctx)
        if k == "cond":
            return self.raw(kids[1], ctx) + self.raw(kids[2], ctx)
        if k == "binary":
            if node.text in ("||", "??", "+"):
                return self.raw(kids[0], ctx) + self.raw(kids[1], ctx)
            return self.raw(kids[1], ctx) if node.text == "&&" else []   # a falsy field is no markup
        if k == "unary":
            if node.text == "await":
                return self.raw(kids[0], ctx)
            if node.text == "new":
                call = kids[0]
                ctor = _dotted(call.kids[0]) if call.kind == "call" else _dotted(call)
                if ctor == "Date":
                    return []
                return [r for a in (call.kids[1:] if call.kind == "call" else []) for r in self.raw(a, ctx)]
            return []
        if k in ("array", "object"):
            return [r for e in kids for r in self.raw(e, ctx)]
        if k == "call":
            return self._call(node, ctx)
        if k == "reduced":      # a reduce's accumulator
            return self.raw(kids[0], ctx) + self._callback(kids[1:], ctx)
        return [(node, f"a {k} the reader does not follow")]

    def _escape(self, callee: Node) -> str | None:
        """The escape a callee is — by its declaration, not only its name: a local `esc` (a card)
        is no escape. encodeURIComponent is the browser's; `const esc = Console.esc` an alias."""
        name = _dotted(callee)
        if name == "encodeURIComponent" or name == "Console.esc":
            return name if callee.kind != "name" or self.resolve(name, callee.pos) is None else None
        if callee.kind != "name" or not any(name in names for names in ESCAPES.values()):
            return None
        d = self.resolve(name, callee.pos)
        if d is None:
            return None
        if d.kind == "function" and d.init is None:
            return name
        if d.kind == "var" and d.init is not None and not d.assigns and _dotted(d.init) == "Console.esc":
            return name
        return None

    def _field(self, obj: Node, prop: str, ctx: str) -> list:
        """What `obj.prop` can hold: the values of that key, where `obj` is an object the page
        wrote (`response(w).cls` is a literal, its `.text` is not); all of `obj` otherwise."""
        k = obj.kind
        if k == "object":
            return [r for key, v in zip(obj.keys, obj.kids) if key in (prop, None)
                    for r in (self.raw(v, ctx) if key == prop else self._field(v, prop, ctx))]
        if k == "paren":
            return self._field(obj.kids[0], prop, ctx)
        if k == "cond":
            return self._field(obj.kids[1], prop, ctx) + self._field(obj.kids[2], prop, ctx)
        if k == "binary" and obj.text in ("||", "??", "&&"):
            return (self._field(obj.kids[0], prop, ctx) if obj.text != "&&" else []) + self._field(obj.kids[1], prop, ctx)
        if k == "name" and (d := self.resolve(obj.text, obj.pos)) is not None and d.kind == "var" and d.init:
            return self._once(("field", id(d), prop, ctx), lambda: self._field(d.init, prop, ctx)
                              + [r for a in d.assigns for r in self.raw(a, ctx)])
        if k == "call" and obj.kids[0].kind == "name" and (d := self.resolve(obj.kids[0].text, obj.pos)) \
                and d.kind == "function":
            return self._once(("ret-field", d.fn.body.pos, prop, ctx),
                              lambda: [r for e in _returned(self, d.fn) for r in self._field(e, prop, ctx)])
        return self.raw(obj, ctx)

    def _call(self, node: Node, ctx: str) -> list:
        callee, args = node.kids[0], node.kids[1:]
        while callee.kind == "paren":
            callee = callee.kids[0]
        name = _dotted(callee)
        escape = self._escape(callee)
        if escape in ESCAPES[ctx]:
            return []
        if escape:
            return [(node, f"{escape} does not escape for {_WHERE[ctx]}")]
        if name in _SAFE_CALLS or (name or "").startswith("Math."):
            return []
        if name in _SAME_OF_ARGS:
            return [r for a in args for r in self.raw(a, ctx)]
        if callee.kind == "function":                       # (() => …)()
            return self._returns(self._fn(callee, named=False), ctx)
        if name in ("fetch", "JSON.parse"):
            return [(node, "what the server sent")]
        if callee.kind == "name":
            d = self.resolve(callee.text, callee.pos)
            if d is not None and d.kind == "function":
                return self._returns(d.fn, ctx)
            if d is not None and d.kind == "var" and d.init is not None and not d.assigns:
                if d.init.kind == "member" and (fn := self._method(d.init.kids[0], d.init.text)):
                    return self._returns(fn, ctx)
            return [(node, "a call the reader does not follow")]
        if callee.kind == "member":
            method, recv = callee.text, callee.kids[0]
            if method in ("json", "text"):
                return [(node, "what the server sent")]
            if fn := self._method(recv, method):
                return self._returns(fn, ctx)
            if method in _SAFE_METHODS:
                return []
            if method in _SAME_METHODS:
                return self.raw(recv, ctx)
            if method in ("replace", "replaceAll"):
                if _keeps_only_safe(args):      # key.replace(/[^A-Za-z0-9._-]/g, '_')
                    return []
                return self.raw(recv, ctx) + self._callback(args[1:2], ctx)
            if method in _WITH_ARGS_METHODS:
                return self.raw(recv, ctx) + [r for a in args for r in self.raw(a, ctx)]
            if method in _CALLBACK_METHODS:
                return self._callback(args[:1], ctx)
            if method == "reduce":
                return self._callback(args[:1], ctx) + [r for a in args[1:] for r in self.raw(a, ctx)]
        return [(node, "a call the reader does not follow")]

    def _method(self, recv: Node, name: str) -> Fn | None:
        """A page object's function: `Console.hms` → console.js's hms."""
        for obj in self._objects(recv):
            for key, value in zip(obj.keys, obj.kids):
                if key != name:
                    continue
                if value.kind == "function":
                    return self._fn(value, named=False)
                if value.kind == "name" and (d := self.resolve(value.text, value.pos)) and d.kind == "function":
                    return d.fn
        return None

    def _objects(self, node: Node, seen=None) -> list[Node]:
        """The object literals a value can be: itself, a const's, what a function returns."""
        seen = set() if seen is None else seen
        if node.pos in seen:
            return []
        seen.add(node.pos)
        if node.kind == "object":
            return [node]
        if node.kind == "paren":
            return self._objects(node.kids[0], seen)
        if node.kind == "name" and (d := self.resolve(node.text, node.pos)) and d.kind == "var" and d.init:
            return self._objects(d.init, seen)
        if node.kind == "call" and node.kids[0].kind in ("function", "paren"):
            callee = node.kids[0].kids[0] if node.kids[0].kind == "paren" else node.kids[0]
            if callee.kind == "function":
                return [o for e in _returned(self, self._fn(callee, named=False)) for o in self._objects(e, seen)]
        return []

    def _callback(self, args: list[Node], ctx: str) -> list:
        """What a function given as an argument returns (a value: itself)."""
        out = []
        for a in args:
            if a.kind == "function":
                out += self._returns(self._fn(a, named=False), ctx)
            elif a.kind == "name" and (d := self.resolve(a.text, a.pos)) is not None and d.kind == "function":
                out += self._returns(d.fn, ctx)
            else:
                out += self.raw(a, ctx)
        return out

    def _returns(self, fn: Fn, ctx: str) -> list:
        return self._once(("fn", fn.body.pos, ctx), lambda: [r for e in _returned(self, fn) for r in self.raw(e, ctx)])

    def _decl(self, d: Decl, ctx: str) -> list:
        def compute():
            out = [r for a in d.assigns for r in self.raw(a, ctx)]
            here = Node("name", d.pos, d.pos + len(d.name), text=d.name)
            if d.kind == "function":
                return out
            if d.kind == "caught":
                return out + [(here, "an error caught")]
            if d.kind == "param":
                fn = d.fn
                if fn.escapes or not (fn.named or fn.feeds):
                    out += [(here, "what the function is given (a callback, or called from the page)")]
                out += [r for index, array in fn.feeds if index == d.index for r in self.raw(array, ctx)]
                return out + [r for args in fn.calls if d.index < len(args) for r in self.raw(args[d.index], ctx)]
            if d.init is not None:
                return out + self.raw(d.init, ctx)
            return out + ([(here, "a field of what the function is given")] if d.kind == "element" else [])
        return self._once(("decl", id(d), ctx), compute)

    def _once(self, key, compute):
        if key in self._memo:
            return self._memo[key]
        if key in self._busy:
            self._cycles += 1
            return []
        self._busy.add(key)
        cycles = self._cycles
        try:
            out = compute()
        finally:
            self._busy.discard(key)
        if self._cycles == cycles:      # complete: no value left out by a cycle
            self._memo[key] = out
        return out

    # --- the check ----------------------------------------------------------------------

    def findings(self) -> list[Finding]:
        """One per ${…} (or value given to innerHTML) with something raw in it — an HTML
        template inside is checked on its own."""
        out: dict[int, Finding] = {}
        checks = [(e, _context(t.tok, i, ctx)) for t, ctx in self.templates for i, e in enumerate(t.kids)]
        checks += [(s, "html") for s in self.sinks if s.pos not in self._html]
        for expr, ctx in checks:
            file, line = self.where(expr.pos)
            sink = self.source(expr)
            if (file, sink) in ALLOWED or expr.pos in out:
                continue
            raws = self.raw(expr, ctx)
            if raws:
                origin, why = raws[0]
                ofile, oline = self.where(origin.pos)
                at = f"{self.source(origin)}" + (f" ({ofile}:{oline})" if (ofile, oline) != (file, line) else "")
                out[expr.pos] = Finding(file, line, sink, at, why)
        return list(out.values())


def _returned(unit: Unit, fn: Fn) -> list[Node]:
    """The expressions a function returns (not those of the functions inside it)."""
    if not fn.body.span:
        return fn.body.kids[:1]
    toks, first, last = fn.body.span
    p = unit.parser(toks, toks[last].pos)
    out, k = [], first + 1
    while k < last:
        t = toks[k]
        if t.kind == "name" and t.text == "function":
            j = k + 1 + (toks[k + 1].kind == "name")
            k = p.close[p.close[j] + 1] + 1
            continue
        if t.kind == "punct" and t.text == "=>" and toks[k + 1].text == "{":
            k = p.close[k + 1] + 1
            continue
        if t.kind == "name" and t.text == "return" and toks[k + 1].text not in (";", "}"):
            node, k = p.seq(k + 1)
            out.append(node)
            continue
        k += 1
    return out


def _keeps_only_safe(args: list[Node]) -> bool:
    """`.replace(/[^…]/g, '…')`: whatever is not in the class is replaced — safe when the class
    and the replacement hold nothing HTML or JavaScript gives a meaning to."""
    if len(args) != 2 or args[0].kind != "lit" or args[1].kind != "lit":
        return False
    m = re.fullmatch(r"/\[\^([^\]]*)\]\+?/[a-z]*g[a-z]*", args[0].text)
    return bool(m) and not re.search(r"[<>&\"'`\\]", m.group(1) + args[1].text[1:-1])


def _dotted(node: Node) -> str | None:
    if node.kind == "name":
        return node.text
    if node.kind == "member" and (base := _dotted(node.kids[0])):
        return f"{base}.{node.text}"
    return None


def _skip_expr(toks, k, last):
    depth = 0
    while k < last:
        t = toks[k]
        if t.kind == "punct" and t.text in "([{":
            depth += 1
        elif t.kind == "punct" and t.text in ")]}":
            depth -= 1
        elif t.text == "," and depth == 0:
            return k
        k += 1
    return k


def _pattern_names(toks, first, last):
    """The names a destructuring pattern binds (their indexes), defaults skipped."""
    k = first + 1
    while k < last:
        t = toks[k]
        if t.kind == "punct" and t.text == "=":
            k = _skip_expr(toks, k + 1, last)
            continue
        if t.kind == "name" and toks[k + 1].text != ":":
            yield k
        k += 1


def _is_html(t: Tok) -> bool:
    return bool(re.search(r"<[a-zA-Z/!]|[\w-]=[\"']", "".join(t.quasis)))


def _context(t: Tok, i: int, inherited: str) -> str:
    """Where the i-th ${…} of a template lands: "js" in an on… attribute, "url" at the start of
    an href/src/action, "unquoted" in an attribute without double quotes, "html" otherwise. A
    template inside a ${…} inherits that ${…}'s place, unless its own text opens a quote."""
    text = "\x00".join(t.quasis[:i + 1])
    opened = list(re.finditer(r"\b([\w-]+)\s*=\s*\"", text))
    if opened and '"' not in text[opened[-1].end():]:     # inside a double-quoted value
        last = opened[-1]
        name = last.group(1).lower()
        if name.startswith("on"):
            return "js"
        if name in ("href", "src", "action", "formaction") and last.end() == len(text):
            return "url"
        return "html"
    if re.search(r"<[^>]*\b[\w-]+\s*=\s*'?[^\s\"'>]*$", text):   # a value in single quotes, or none
        return "unquoted"
    return inherited if '"' not in text else "html"


def check(static: Path = STATIC) -> list[Finding]:
    found: set[Finding] = set()
    for page in PAGES:
        found.update(Unit(page, static).findings())
    return sorted(found, key=lambda f: (f.file, f.line, f.sink))


def main() -> int:
    found = check()
    for f in found:
        print(f)
    print(f"{len(found)} raw write(s) into the console's pages", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
