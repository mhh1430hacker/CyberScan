"""A pure-Python reader for YARA rules, for the phone engine.

yara-python is a compiled C library, so it can't run inside Pyodide. This module
is packed into the phone's engine.zip as ``yara`` and offers the small part of
its API that core/yara_engine.py uses:

    rules = yara.compile(filepaths={"name": "rules.yar"})   # or source= / filepath=
    for m in rules.match(data=b"...", timeout=10):
        m.rule, m.tags, m.meta, m.strings                   # strings: (offset, "$id", bytes)

Supported: text strings (nocase, ascii, wide, fullword, private), hex strings
(?? wildcards, nibbles, [n-m] jumps, (a|b) alternatives), regular expressions
(/…/is), and conditions with and / or / not, parentheses, $a, #a, @a[i], !a[i],
$a at N, $a in (a..b), "N of (…)", any/all/none of them, $prefix* sets,
filesize, KB/MB, uint8/16/32 (+be) and int8/16/32, arithmetic and comparisons.
Rules that use a module (pe., math., …) are skipped rather than guessed.
"""
from __future__ import annotations

import re
import struct
import time
from pathlib import Path
from typing import Any

__all__ = ["compile", "Error", "SyntaxError", "TimeoutError", "Rules", "Match", "__version__"]
__version__ = "lite-1.0"
MAX_MATCHES_PER_STRING = 1000


class Error(Exception):
    pass


class SyntaxError(Error):  # noqa: A001 - same name as yara-python
    pass


class TimeoutError(Error):  # noqa: A001
    pass


class Unsupported(Error):
    pass


# ------------------------------------------------------------------ lexer
_TOKEN = re.compile(r"""
    (?P<ws>\s+|//[^\n]*|/\*.*?\*/)
  | (?P<str>"(?:\\.|[^"\\])*")
  | (?P<hex>0x[0-9a-fA-F]+)
  | (?P<num>\d+(?:KB|MB)?)
  | (?P<sid>\$[A-Za-z0-9_]*\*?|[#@!][A-Za-z0-9_]+)
  | (?P<id>[A-Za-z_][A-Za-z0-9_.]*)
  | (?P<op>\.\.|==|!=|<=|>=|<<|>>|[{}()\[\]:=,<>+\-*\\%&|^~])
""", re.S | re.X)


def _number(text: str) -> int:
    if text.startswith("0x"):
        return int(text, 16)
    if text.endswith("KB"):
        return int(text[:-2]) * 1024
    if text.endswith("MB"):
        return int(text[:-2]) * 1048576
    return int(text)


def _unescape(body: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            n = body[i + 1]
            if n == "x" and i + 3 < len(body):
                out.append(int(body[i + 2:i + 4], 16))
                i += 4
                continue
            out += {"n": b"\n", "t": b"\t", "r": b"\r", '"': b'"', "\\": b"\\"}.get(n, ("\\" + n).encode())
            i += 2
            continue
        out += c.encode("utf-8")
        i += 1
    return bytes(out)


# ------------------------------------------------------------------ strings
def _hex_regex(body: str) -> bytes:
    """Hex string → bytes regular expression."""
    body = re.sub(r"//[^\n]*|/\*.*?\*/", " ", body, flags=re.S)
    out: list[bytes] = []
    i, s = 0, body
    while i < len(s):
        c = s[i]
        if c.isspace():
            i += 1
        elif c == "[":
            j = s.index("]", i)
            spec = s[i + 1:j].replace(" ", "")
            if "-" in spec:
                lo, hi = spec.split("-", 1)
                out.append(b".{%d,%s}" % (int(lo or 0), hi.encode() if hi else b""))
            else:
                out.append(b".{%d}" % int(spec))
            i = j + 1
        elif c in "(|)":
            out.append({"(": b"(?:", "|": b"|", ")": b")"}[c])
            i += 1
        else:
            pair = s[i:i + 2]
            if len(pair) < 2:
                raise SyntaxError(f"bad hex string near {s[i:]!r}")
            hi, lo = pair
            if pair == "??":
                out.append(b".")
            elif hi == "?":
                v = int(lo, 16)
                out.append(b"[" + b"".join(re.escape(bytes([n << 4 | v])) for n in range(16)) + b"]")
            elif lo == "?":
                v = int(hi, 16) << 4
                out.append(b"[" + re.escape(bytes([v])) + b"-" + re.escape(bytes([v | 15])) + b"]")
            else:
                out.append(re.escape(bytes([int(pair, 16)])))
            i += 2
    return b"".join(out)


class _String:
    def __init__(self, ident: str, kind: str, body: Any, mods: set[str]):
        self.ident, self.kind, self.mods = ident, kind, mods
        self.private = "private" in mods
        flags = re.S
        if kind == "text":
            raw: bytes = body
            variants = []
            if "wide" in mods:
                variants.append(b"".join(re.escape(bytes([b])) + b"\x00" for b in raw))
            if "ascii" in mods or "wide" not in mods:
                variants.append(re.escape(raw))
            pattern = b"(?:" + b"|".join(variants) + b")"
            if "nocase" in mods:
                flags |= re.I
            if "fullword" in mods:
                pattern = rb"(?<![A-Za-z0-9])" + pattern + rb"(?![A-Za-z0-9])"
        elif kind == "hex":
            pattern = _hex_regex(body)
        else:  # regex
            text, rflags = body
            pattern = text.encode("utf-8")
            if "i" in rflags or "nocase" in mods:
                flags |= re.I
            if "wide" in mods:
                raise Unsupported("wide regular expressions")
        try:
            self.regex = re.compile(pattern, flags)
        except re.error as exc:
            raise SyntaxError(f"{ident}: {exc}") from exc

    def find(self, data: bytes, deadline: float) -> list[tuple[int, bytes]]:
        hits = []
        for m in self.regex.finditer(data):
            hits.append((m.start(), m.group(0)))
            if len(hits) >= MAX_MATCHES_PER_STRING or time.monotonic() > deadline:
                break
        if time.monotonic() > deadline:
            raise TimeoutError("YARA scan took too long")
        return hits


# ------------------------------------------------------------------ condition
class _Cond:
    """Pratt parser that turns a condition into a Python closure over a scan context."""

    BIN = {"or": 1, "and": 2, "==": 4, "!=": 4, "<": 5, "<=": 5, ">": 5, ">=": 5,
           "|": 6, "^": 7, "&": 8, "<<": 9, ">>": 9, "+": 10, "-": 10, "*": 11, "\\": 11, "%": 11}

    def __init__(self, tokens: list[tuple[str, str]], idents: list[str]):
        self.toks, self.i, self.idents = tokens, 0, idents

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok is None or (value is not None and tok[1] != value):
            raise SyntaxError(f"expected {value!r} in condition, got {tok[1] if tok else 'end'!r}")
        self.i += 1
        return tok

    def parse(self):
        fn = self.expr(0)
        if self.peek() is not None:
            raise SyntaxError(f"unexpected {self.peek()[1]!r} in condition")
        return fn

    def expr(self, power: int):
        left = self.prefix()
        while True:
            tok = self.peek()
            if tok is None or tok[1] not in self.BIN or self.BIN[tok[1]] <= power:
                return left
            op = self.take()[1]
            right = self.expr(self.BIN[op])
            left = self.binary(op, left, right)

    @staticmethod
    def binary(op, a, b):
        import operator as o
        table = {"or": lambda c: bool(a(c)) or bool(b(c)), "and": lambda c: bool(a(c)) and bool(b(c))}
        if op in table:
            return table[op]
        fn = {"==": o.eq, "!=": o.ne, "<": o.lt, "<=": o.le, ">": o.gt, ">=": o.ge, "|": o.or_, "^": o.xor,
              "&": o.and_, "<<": o.lshift, ">>": o.rshift, "+": o.add, "-": o.sub, "*": o.mul,
              "\\": lambda x, y: x // y if y else 0, "%": lambda x, y: x % y if y else 0}[op]
        return lambda c: fn(a(c), b(c))

    def string_set(self) -> list[str]:
        tok = self.take()
        if tok[1] == "them":
            return list(self.idents)
        if tok[1] != "(":
            raise SyntaxError("expected a string set")
        names: list[str] = []
        while True:
            sid = self.take()[1]
            if sid.endswith("*"):
                names += [n for n in self.idents if n.startswith(sid[:-1])]
            elif sid in self.idents:
                names.append(sid)
            else:
                raise SyntaxError(f"unknown string {sid}")
            if self.take()[1] == ")":
                return names
            # otherwise it was a comma

    def prefix(self):
        kind, val = self.take()
        if val == "(":
            inner = self.expr(0)
            self.take(")")
            return inner
        if val == "not":
            inner = self.expr(3)
            return lambda c: not inner(c)
        if val == "-":
            inner = self.expr(12)
            return lambda c: -inner(c)
        if val == "~":
            inner = self.expr(12)
            return lambda c: ~inner(c)
        if val in ("true", "false"):
            return (lambda c: True) if val == "true" else (lambda c: False)
        if val == "filesize":
            return lambda c: len(c["data"])
        if kind in ("num", "hex"):
            n = _number(val)
            return self.quantified(lambda c, n=n: n) if self.at_of() else (lambda c: n)
        if val in ("any", "all", "none"):
            return self.quantified(val)
        if kind == "id" and re.fullmatch(r"u?int(8|16|32)(be)?", val):
            self.take("(")
            where = self.expr(0)
            self.take(")")
            signed, bits = not val.startswith("u"), int(re.search(r"\d+", val).group())
            fmt = {8: "b", 16: "h", 32: "i"}[bits]
            fmt = (">" if val.endswith("be") else "<") + (fmt if signed else fmt.upper())

            def read(c, where=where, fmt=fmt, size=bits // 8):
                off = where(c)
                chunk = c["data"][off:off + size]
                if len(chunk) < size or off < 0:
                    raise _Undefined
                return struct.unpack(fmt, chunk)[0]
            return read
        if kind == "sid":
            return self.string_ref(val)
        if kind == "id" and "." in val:
            raise Unsupported(f"module field {val}")
        if kind == "id" and val not in ("of", "at", "in", "them", "and", "or"):
            return lambda c, val=val: bool(c["rules"].get(val, False))   # another rule's result
        raise SyntaxError(f"unexpected {val!r} in condition")

    def at_of(self) -> bool:
        tok = self.peek()
        return tok is not None and tok[1] == "of"

    def quantified(self, how):
        self.take("of")
        names = self.string_set()

        def check(c, how=how, names=names):
            hits = sum(1 for n in names if c["hits"][n])
            if how == "any":
                return hits >= 1
            if how == "all":
                return hits == len(names)
            if how == "none":
                return hits == 0
            return hits >= how(c)
        return check

    def string_ref(self, sid: str):
        sigil, name = sid[0], "$" + sid[1:]
        if sid[1:] == "" and sigil == "$":
            raise Unsupported("anonymous string reference outside a loop")
        if name not in self.idents:
            raise SyntaxError(f"unknown string {sid}")
        if sigil == "#":
            return lambda c: len(c["hits"][name])
        if sigil in "@!":
            index = lambda c: 1  # noqa: E731
            if self.peek() and self.peek()[1] == "[":
                self.take("[")
                index = self.expr(0)
                self.take("]")
            slot = 0 if sigil == "@" else 1

            def pick(c, index=index, slot=slot):
                hits, k = c["hits"][name], index(c) - 1
                if not 0 <= k < len(hits):
                    raise _Undefined
                return hits[k][0] if slot == 0 else len(hits[k][1])
            return pick
        tok = self.peek()
        if tok and tok[1] == "at":
            self.take()
            where = self.expr(9)
            return lambda c: any(off == where(c) for off, _ in c["hits"][name])
        if tok and tok[1] == "in":
            self.take()
            self.take("(")
            lo = self.expr(0)
            self.take("..")
            hi = self.expr(0)
            self.take(")")
            return lambda c: any(lo(c) <= off <= hi(c) for off, _ in c["hits"][name])
        return lambda c: bool(c["hits"][name])


class _Undefined(Exception):
    """A value YARA treats as undefined (reading past the end of the file): the rule doesn't match."""


# ------------------------------------------------------------------ rules
class Match:
    def __init__(self, rule: str, namespace: str, tags: list[str], meta: dict, strings: list[tuple[int, str, bytes]]):
        self.rule, self.namespace, self.tags, self.meta, self.strings = rule, namespace, tags, meta, strings

    def __repr__(self) -> str:
        return self.rule


class _Rule:
    def __init__(self, name, namespace, tags, meta, strings, cond, private):
        self.name, self.namespace, self.tags, self.meta = name, namespace, tags, meta
        self.strings, self.cond, self.private = strings, cond, private


class Rules:
    def __init__(self, rules: list[_Rule], skipped: list[str]):
        self._rules, self.skipped = rules, skipped

    def __iter__(self):
        return iter(self._rules)

    def match(self, filepath: str | None = None, data: bytes | None = None, timeout: float = 60, **_: Any) -> list[Match]:
        if data is None:
            if filepath is None:
                raise Error("match() needs data= or filepath=")
            data = Path(filepath).read_bytes()
        data = bytes(data)
        deadline = time.monotonic() + float(timeout or 60)
        cache: dict[int, list[tuple[int, bytes]]] = {}
        out, results = [], {}
        for rule in self._rules:
            hits = {}
            for s in rule.strings:
                if id(s) not in cache:
                    cache[id(s)] = s.find(data, deadline)
                hits[s.ident] = cache[id(s)]
            try:
                ok = bool(rule.cond({"data": data, "hits": hits, "rules": results}))
            except _Undefined:
                ok = False
            results[rule.name] = ok
            if ok and not rule.private:
                found = sorted((off, s.ident, blob) for s in rule.strings if not s.private for off, blob in hits[s.ident])
                out.append(Match(rule.name, rule.namespace, rule.tags, rule.meta, found))
        return out


def _parse(source: str, namespace: str) -> tuple[list[_Rule], list[str]]:
    rules, skipped = [], []
    pos = 0
    head = re.compile(r"((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)\s*(?::\s*([\w\s]+?))?\s*\{", re.S)
    source = re.sub(r"^\s*(import|include)\s+\"[^\"]*\"", "", source, flags=re.M)
    while True:
        m = head.search(source, pos)
        if not m:
            break
        body_start = m.end()
        end = _rule_end(source, body_start)
        body = source[body_start:end]
        pos = end + 1
        name = m.group(2)
        try:
            rules.append(_rule(name, namespace, (m.group(3) or "").split(), "private" in m.group(1), body))
        except Unsupported as exc:
            skipped.append(f"{name}: {exc}")
    return rules, skipped


def _rule_end(src: str, i: int) -> int:
    """Index of the brace closing a rule, skipping strings, regexes, hex strings and comments."""
    depth, n = 1, len(src)
    while i < n:
        c = src[i]
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                i += 2 if src[i] == "\\" else 1
        elif src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            i = src.find("*/", i) + 1
        elif c == "/" and re.search(r"=\s*$", src[max(0, i - 40):i]):
            i += 1
            while i < n and src[i] != "/":
                i += 2 if src[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise SyntaxError("a rule is missing its closing brace")


def _rule(name: str, namespace: str, tags: list[str], private: bool, body: str) -> _Rule:
    parts = re.split(r"(?:^|(?<=\s))(meta|strings|condition)\s*:", body)
    sections = {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}
    if "condition" not in sections:
        raise SyntaxError(f"rule {name} has no condition")
    meta: dict[str, Any] = {}
    for mm in re.finditer(r"(\w+)\s*=\s*(\"(?:\\.|[^\"\\])*\"|-?\d+|true|false)", sections.get("meta", "")):
        v = mm.group(2)
        meta[mm.group(1)] = _unescape(v[1:-1]).decode("utf-8", "replace") if v.startswith('"') else (v == "true" if v in ("true", "false") else int(v))
    strings: list[_String] = []
    text = sections.get("strings", "")
    for sm in re.finditer(r"(\$\w*)\s*=\s*(\"(?:\\.|[^\"\\])*\"|\{[^}]*\}|/(?:\\.|[^/\\])+/[is]*)([^\n$]*)", text):
        ident, value, mods = sm.group(1), sm.group(2), set(sm.group(3).split())
        for bad in ("xor", "base64", "base64wide"):
            if any(x.startswith(bad) for x in mods):
                raise Unsupported(f"{bad} strings")
        if value.startswith('"'):
            s = _String(ident, "text", _unescape(value[1:-1]), mods)
        elif value.startswith("{"):
            s = _String(ident, "hex", value[1:-1], mods)
        else:
            close = value.rindex("/")
            s = _String(ident, "regex", (value[1:close], value[close + 1:]), mods)
        strings.append(s)
    tokens = []
    for tm in _TOKEN.finditer(sections["condition"].strip()):
        kind = tm.lastgroup
        if kind != "ws":
            tokens.append((kind, tm.group(kind)))
    cond = _Cond(tokens, [s.ident for s in strings]).parse()
    return _Rule(name, namespace, tags, meta, strings, cond, private)


def compile(filepath: str | None = None, source: str | None = None, filepaths: dict | None = None,  # noqa: A001
            sources: dict | None = None, **_: Any) -> Rules:
    texts: dict[str, str] = {}
    if filepath:
        texts["default"] = Path(filepath).read_text(encoding="utf-8", errors="replace")
    if source:
        texts["default"] = source
    for ns, path in (filepaths or {}).items():
        texts[ns] = Path(path).read_text(encoding="utf-8", errors="replace")
    for ns, src in (sources or {}).items():
        texts[ns] = src
    rules, skipped = [], []
    for ns, src in texts.items():
        r, s = _parse(src, ns)
        rules += r
        skipped += s
    return Rules(rules, skipped)
