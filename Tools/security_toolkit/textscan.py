"""A small rule engine for line-oriented pattern checks, plus language helpers.

A ``Rule`` is a compiled pattern with its finding text. ``apply_rules`` reports each rule once per
location (file:line) with a sanitized excerpt, so secrets in matched lines never reach the output.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator

from security_toolkit.core import Context, line_of, sanitize

LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript", ".vue": "javascript", ".php": "php",
    ".phtml": "php", ".java": "java", ".kt": "java", ".scala": "java", ".go": "go", ".c": "c", ".h": "c",
    ".cc": "c", ".cpp": "c", ".hpp": "c", ".cs": "csharp", ".rb": "ruby", ".html": "html", ".htm": "html",
    ".jinja": "template", ".jinja2": "template", ".j2": "template", ".twig": "template", ".erb": "ruby",
    ".ejs": "template", ".hbs": "template", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
}


def language_of(path: str, text: str = "") -> str:
    lower = path.lower()
    for suffix, language in LANGUAGE_BY_SUFFIX.items():
        if lower.endswith(suffix):
            return language
    if text.startswith("#!") and "python" in text.splitlines()[0]:
        return "python"
    if text.startswith("<?php"):
        return "php"
    return "unknown"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    description: str
    recommendation: str | None = None
    assurance: str = "heuristic"
    languages: tuple[str, ...] = ()           # empty: any language
    exclude: re.Pattern[str] | None = None    # a match on the same line cancels the finding
    weight: int | None = None
    references: tuple[str, ...] = ()


def rule(rule_id: str, title: str, severity: str, pattern: str, description: str, recommendation: str | None = None,
         *, flags: int = re.IGNORECASE, languages: Iterable[str] = (), exclude: str | None = None,
         assurance: str = "heuristic", weight: int | None = None, references: Iterable[str] = ()) -> Rule:
    return Rule(rule_id, title, severity, re.compile(pattern, flags), description, recommendation, assurance,
                tuple(languages), re.compile(exclude, flags) if exclude else None, weight, tuple(references))


_COMMENT_PREFIX = {
    "python": ("#",), "shell": ("#",), "ruby": ("#",), "powershell": ("#",), "yaml": ("#",),
    "javascript": ("//", "*", "/*"), "java": ("//", "*", "/*"), "go": ("//", "*", "/*"), "c": ("//", "*", "/*"),
    "csharp": ("//", "*", "/*"), "php": ("//", "#", "*", "/*"),
}


def is_comment(line: str, language: str) -> bool:
    stripped = line.lstrip()
    return any(stripped.startswith(prefix) for prefix in _COMMENT_PREFIX.get(language, ()))


def apply_rules(ctx: Context, text: str, rules: Iterable[Rule], *, path: str = "input", language: str = "unknown",
                skip_comments: bool = True, per_rule_limit: int = 20) -> int:
    """Run rules line by line. Returns the number of findings added."""
    added = 0
    lines = text.splitlines()
    counts: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        if number % 500 == 0:
            ctx.check()
        if len(line) > 4000:
            line = line[:4000]
        if skip_comments and is_comment(line, language):
            continue
        for r in rules:
            if r.languages and language not in r.languages:
                continue
            if counts.get(r.rule_id, 0) >= per_rule_limit:
                continue
            match = r.pattern.search(line)
            if not match:
                continue
            if r.exclude:
                # exclusions apply to the statement that contains the match, so a sanitized call elsewhere on the
                # same line does not hide an unsanitized one
                start = line.rfind(";", 0, match.start()) + 1
                end = line.find(";", match.end())
                if r.exclude.search(line[start:end if end != -1 else len(line)]):
                    continue
            location = f"{path}:{number}"
            if ctx.finding(r.rule_id, r.title, r.severity, r.description, assurance=r.assurance, weight=r.weight,
                           location=location, recommendation=r.recommendation, references=list(r.references),
                           evidence=line.strip()):
                counts[r.rule_id] = counts.get(r.rule_id, 0) + 1
                added += 1
    return added


def apply_rules_multiline(ctx: Context, text: str, rules: Iterable[Rule], *, path: str = "input") -> int:
    """Rules whose patterns may span lines; location is the line where the match starts."""
    added = 0
    for r in rules:
        for match in r.pattern.finditer(text):
            if r.exclude and r.exclude.search(match.group(0)):
                continue
            location = f"{path}:{line_of(text, match.start())}"
            if ctx.finding(r.rule_id, r.title, r.severity, r.description, assurance=r.assurance, weight=r.weight,
                           location=location, recommendation=r.recommendation, references=list(r.references),
                           evidence=match.group(0)[:300]):
                added += 1
    return added


# ---- Python AST helpers ---------------------------------------------------------------------------

def parse_python(text: str) -> ast.AST | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def dotted_name(node: ast.AST) -> str:
    """``a.b.c`` for Name/Attribute chains; ``""`` otherwise."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names to the fully qualified names they were imported as."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def call_name(call: ast.Call, aliases: dict[str, str]) -> str:
    """Resolve a call's function to its imported, fully qualified name where possible."""
    name = dotted_name(call.func)
    if not name:
        return ""
    head, _, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + ("." + rest if rest else "")
    return name


def keyword(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_constant_string(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_dynamic_string(node: ast.AST | None) -> bool:
    """An f-string with placeholders, %-formatting, .format() or + concatenation involving non-literals."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return is_constant_string(node.left) or is_dynamic_string(node.left)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        sides = (node.left, node.right)
        return any(is_constant_string(s) or is_dynamic_string(s) for s in sides) and not all(is_constant_string(s) for s in sides)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return is_constant_string(node.func.value)
    return False


def string_parts(node: ast.AST) -> str:
    """Literal text inside a (possibly dynamic) string expression, for keyword checks."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
    if isinstance(node, ast.BinOp):
        return string_parts(node.left) + " " + string_parts(node.right)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return string_parts(node.func.value)
    return ""


USER_INPUT_SOURCES = re.compile(
    r"\b(?:request\.(?:args|form|values|json|data|GET|POST|cookies|headers|query_params|body|files|stream|get_data|get_json|FILES|META)|"
    r"flask\.request|sys\.argv|input\(|os\.environ|self\.request|params\[|req\.(?:query|body|params|cookies|headers))"
)


def function_sources(tree: ast.AST, text: str) -> dict[int, bool]:
    """For each function's line range, whether it reads obvious user input (request.*, sys.argv, input())."""
    ranges: dict[int, bool] = {}
    lines = text.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            body = "\n".join(lines[node.lineno - 1:end])
            tainted = bool(USER_INPUT_SOURCES.search(body))
            for line in range(node.lineno, end + 1):
                ranges[line] = ranges.get(line, False) or tainted
    return ranges


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def excerpt(text: str, line: int) -> str:
    lines = text.splitlines()
    return sanitize(lines[line - 1].strip(), 200) if 0 < line <= len(lines) else ""


Visitor = Callable[[ast.Call, str], None]
