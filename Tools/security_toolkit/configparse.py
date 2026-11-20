"""Parsers for configuration exports: Windows .reg files, key=value files and YAML/JSON documents.

All parsers are read-only, bounded and never evaluate content (YAML uses SafeLoader; CloudFormation
short-form tags such as !Ref are kept as plain values instead of being rejected).
"""
from __future__ import annotations

import json
import re
from typing import Any

from security_toolkit.core import ToolInputError, Unavailable

HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER", "HKCR": "HKEY_CLASSES_ROOT", "HKU": "HKEY_USERS",
         "HKCC": "HKEY_CURRENT_CONFIG"}


def normalize_key(key: str) -> str:
    key = key.strip().strip("[]").replace("/", "\\")
    head, _, rest = key.partition("\\")
    head = HIVES.get(head.upper(), head.upper())
    return f"{head}\\{rest}".rstrip("\\").lower()


def _decode_hex(text: str) -> bytes:
    return bytes(int(b, 16) for b in re.findall(r"[0-9a-fA-F]{2}", text))


def parse_reg(text: str) -> dict[str, dict[str, Any]]:
    """Parse a regedit export (REGEDIT4 or Windows Registry Editor 5.00).

    Returns ``{normalized key: {value name lower-case ("" for default): value}}`` where value is str
    (REG_SZ / EXPAND_SZ / MULTI_SZ joined with '\\n'), int (dword/qword) or bytes (other hex).
    """
    keys: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        while line.endswith("\\") and i + 1 < len(lines):  # hex continuation lines
            i += 1
            line = line[:-1] + lines[i].strip()
        i += 1
        if not line or line.startswith(";") or line.lower().startswith(("regedit4", "windows registry editor")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if line.startswith("[-"):
                current = None
                continue
            current = keys.setdefault(normalize_key(line), {})
            continue
        if current is None:
            continue
        match = re.match(r'^(@|"((?:[^"\\]|\\.)*)")\s*=\s*(.*)$', line)
        if not match:
            continue
        name = "" if match.group(1) == "@" else match.group(2).replace('\\"', '"').replace("\\\\", "\\")
        raw = match.group(3).strip()
        value: Any
        if raw.startswith('"'):
            value = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\") if raw.endswith('"') else raw[1:]
        elif raw.lower().startswith("dword:"):
            value = int(raw[6:], 16)
        elif raw.lower().startswith("hex(b):"):
            value = int.from_bytes(_decode_hex(raw[7:]), "little")
        elif raw.lower().startswith(("hex(2):", "hex(7):")):
            decoded = _decode_hex(raw[7:]).decode("utf-16-le", errors="replace").rstrip("\x00")
            value = decoded.replace("\x00", "\n") if raw.lower().startswith("hex(7)") else decoded
        elif raw.lower().startswith("hex"):
            value = _decode_hex(raw.split(":", 1)[1] if ":" in raw else "")
        elif raw == "-":
            continue
        else:
            value = raw
        current[name.lower()] = value
    return keys


def reg_value(keys: dict[str, dict[str, Any]], key: str, name: str) -> Any:
    return keys.get(normalize_key(key), {}).get(name.lower())


def parse_kv(text: str, *, separators: str = "=:", comment: str = "#;") -> dict[str, tuple[str, int]]:
    """``key = value`` lines (first occurrence wins) with their line numbers."""
    out: dict[str, tuple[str, int]] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped[0] in comment:
            continue
        match = re.match(rf"^([^{re.escape(separators)}\s]+)\s*[{re.escape(separators)}]\s*(.*)$", stripped)
        if match and match.group(1).lower() not in out:
            out[match.group(1).lower()] = (match.group(2).strip().strip('"').strip("'"), number)
    return out


class HclError(ValueError):
    pass


def parse_hcl(text: str) -> list[dict[str, Any]]:
    """Minimal, non-evaluating HCL2 reader for Terraform security checks.

    Returns top-level blocks as ``{"type": "resource", "labels": [...], "body": {...}, "line": n}``. Attribute
    values become str/int/float/bool/list/dict; nested blocks become lists under their name (``body["ingress"]``);
    expressions that are not literals (references, function calls) are kept as their source text, and heredocs
    as strings. Comments (#, //, /* */) are ignored. Nothing is ever evaluated.
    """
    pos, n = 0, len(text)
    line_starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

    def line_at(index):
        import bisect
        return bisect.bisect_right(line_starts, index)

    def skip_ws(newlines=True):
        nonlocal pos
        while pos < n:
            c = text[pos]
            if c in " \t\r" or (newlines and c == "\n"):
                pos += 1
            elif c == "#" or text.startswith("//", pos):
                while pos < n and text[pos] != "\n":
                    pos += 1
            elif text.startswith("/*", pos):
                end = text.find("*/", pos + 2)
                pos = n if end == -1 else end + 2
            else:
                break

    def read_string():
        nonlocal pos
        pos += 1
        out, depth = [], 0
        while pos < n:
            c = text[pos]
            if c == "\\" and pos + 1 < n:
                out.append(text[pos:pos + 2])
                pos += 2
                continue
            if text.startswith("${", pos):
                depth += 1
            elif c == "}" and depth:
                depth -= 1
            elif c == '"' and not depth:
                pos += 1
                return "".join(out).replace('\\"', '"').replace("\\\\", "\\").replace("\\n", "\n")
            out.append(c)
            pos += 1
        raise HclError("unterminated string")

    def read_heredoc():
        nonlocal pos
        match = re.match(r"<<-?([A-Za-z_][\w]*)\r?\n", text[pos:])
        if not match:
            raise HclError("bad heredoc")
        marker = match.group(1)
        pos += match.end()
        end = re.compile(rf"^\s*{marker}\s*$", re.M).search(text, pos)
        if not end:
            raise HclError("unterminated heredoc")
        value = text[pos:end.start()]
        pos = end.end()
        return value

    def read_expression():
        """A literal value, or the raw source text of a non-literal expression up to the end of the line."""
        nonlocal pos
        skip_ws(newlines=False)
        if pos >= n:
            raise HclError("missing value")
        c = text[pos]
        if c == '"':
            value = read_string()
            return value
        if text.startswith("<<", pos):
            return read_heredoc()
        if c == "[":
            pos += 1
            items = []
            while True:
                skip_ws()
                if pos < n and text[pos] == "]":
                    pos += 1
                    return items
                items.append(read_expression())
                skip_ws()
                if pos < n and text[pos] == ",":
                    pos += 1
        if c == "{":
            pos += 1
            obj = {}
            while True:
                skip_ws()
                if pos < n and text[pos] == "}":
                    pos += 1
                    return obj
                key = read_string() if text[pos] == '"' else read_identifier()
                skip_ws(newlines=False)
                if pos < n and text[pos] in "=:":
                    pos += 1
                obj[key] = read_expression()
                skip_ws()
                if pos < n and text[pos] == ",":
                    pos += 1
        start, depth = pos, 0
        while pos < n:
            ch = text[pos]
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == '"':
                read_string()
                continue
            elif ch in ",\n" and depth == 0:
                break
            pos += 1
        raw = text[start:pos].strip()
        if raw in ("true", "false"):
            return raw == "true"
        if re.fullmatch(r"-?\d+", raw):
            return int(raw)
        if re.fullmatch(r"-?\d+\.\d+", raw):
            return float(raw)
        if raw == "null":
            return None
        return {"__expr__": raw}

    def read_identifier():
        nonlocal pos
        match = re.match(r"[A-Za-z_][\w.-]*", text[pos:])
        if not match:
            raise HclError(f"unexpected character {text[pos]!r} on line {line_at(pos)}")
        pos += match.end()
        return match.group(0)

    def read_body():
        nonlocal pos
        body: dict[str, Any] = {}
        while True:
            skip_ws()
            if pos >= n:
                raise HclError("unterminated block")
            if text[pos] == "}":
                pos += 1
                return body
            name = read_identifier()
            skip_ws(newlines=False)
            if pos < n and text[pos] == "=":
                pos += 1
                body[name] = read_expression()
                continue
            labels = []
            while pos < n and text[pos] == '"':
                labels.append(read_string())
                skip_ws(newlines=False)
            if pos < n and text[pos] == "{":
                pos += 1
                child = read_body()
                if labels:
                    child = {"__labels__": labels, **child}
                body.setdefault(name, []).append(child)
            else:
                raise HclError(f"expected '=' or '{{' after {name} on line {line_at(pos)}")

    blocks = []
    while True:
        skip_ws()
        if pos >= n:
            return blocks
        start = pos
        kind = read_identifier()
        labels = []
        skip_ws(newlines=False)
        while pos < n and text[pos] == '"':
            labels.append(read_string())
            skip_ws(newlines=False)
        if pos < n and text[pos] == "=":  # top-level attribute (e.g. in .tfvars)
            pos += 1
            blocks.append({"type": "attribute", "labels": [kind], "body": {kind: read_expression()}, "line": line_at(start)})
            continue
        if pos >= n or text[pos] != "{":
            raise HclError(f"expected '{{' after {kind} on line {line_at(pos)}")
        pos += 1
        blocks.append({"type": kind, "labels": labels, "body": read_body(), "line": line_at(start)})


def _yaml_module():
    try:
        import yaml
    except ImportError as exc:
        raise Unavailable("PyYAML is required to read YAML documents (pip install pyyaml).") from exc
    return yaml


def _loader(yaml):
    class TaggedSafeLoader(yaml.SafeLoader):
        """SafeLoader that keeps unknown tags (CloudFormation !Ref, !Sub, GitLab !reference) as plain values."""

    def keep(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return {f"!{suffix}": loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {f"!{suffix}": loader.construct_sequence(node, deep=True)}
        return {f"!{suffix}": loader.construct_mapping(node, deep=True)}

    TaggedSafeLoader.add_multi_constructor("!", keep)
    return TaggedSafeLoader


def load_documents(text: str, *, path: str = "input") -> list[Any]:
    """JSON or YAML (multi-document) without executing anything."""
    stripped = text.lstrip()
    if stripped[:1] in "[{":
        try:
            return [json.loads(text)]
        except ValueError:
            pass  # YAML flow style is a superset; fall through
    yaml = _yaml_module()
    try:
        docs = list(yaml.load_all(text, Loader=_loader(yaml)))
    except yaml.YAMLError as exc:
        raise ToolInputError(f"{path} is not valid YAML or JSON ({type(exc).__name__}).") from exc
    return [d for d in docs if d is not None]
