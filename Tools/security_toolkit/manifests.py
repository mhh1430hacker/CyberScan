"""Dependency manifest and lockfile parsing shared by tools 082, 084, 085 and 086.

Supported: requirements*.txt, Pipfile.lock, poetry.lock, package-lock.json (v1-v3), yarn.lock (v1),
package.json, go.mod, go.sum, Gemfile.lock, composer.lock, Cargo.lock, pom.xml. Parsing never executes
anything (no setup.py, no npm scripts). Versions are compared per ecosystem for OSV advisory matching.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from security_toolkit.core import ToolInputError


@dataclass
class Package:
    ecosystem: str            # OSV ecosystem name: PyPI, npm, Go, RubyGems, Packagist, crates.io, Maven
    name: str
    version: str | None       # exact resolved version, or None if only a range is declared
    spec: str = ""            # declared range / constraint
    source_file: str = ""
    line: int = 0
    resolved: str = ""        # download URL from the lockfile
    integrity: list[str] = field(default_factory=list)
    license: str = ""
    dev: bool = False
    direct: bool = True

    @property
    def purl(self) -> str:
        return purl(self.ecosystem, self.name, self.version)

    def as_dict(self) -> dict[str, Any]:
        return {"ecosystem": self.ecosystem, "name": self.name, "version": self.version, "spec": self.spec,
                "file": self.source_file, "line": self.line, "license": self.license, "dev": self.dev, "purl": self.purl}


PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "RubyGems": "gem", "Packagist": "composer", "crates.io": "cargo", "Maven": "maven"}


def purl(ecosystem: str, name: str, version: str | None) -> str:
    kind = PURL_TYPES.get(ecosystem, "generic")
    if kind == "npm" and name.startswith("@"):
        scope, _, base = name.partition("/")
        path = f"{urllib.parse.quote(scope)}/{urllib.parse.quote(base)}"
    elif kind == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        path = f"{urllib.parse.quote(group)}/{urllib.parse.quote(artifact)}"
    else:
        path = "/".join(urllib.parse.quote(part) for part in name.split("/"))
    return f"pkg:{kind}/{path}" + (f"@{urllib.parse.quote(version)}" if version else "")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---- parsers ------------------------------------------------------------------------------------

REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*((?:===|==|~=|!=|<=|>=|<|>)[^;#\s\\]*(?:\s*,\s*(?:===|==|~=|!=|<=|>=|<|>)[^;#\s\\]*)*)?")


def parse_requirements(text: str, path: str) -> tuple[list[Package], dict[str, Any]]:
    packages, options = [], {"index_urls": [], "extra_index_urls": [], "hashes_seen": False, "editable": [], "urls": []}
    logical = re.sub(r"\\\r?\n", " ", text)
    for number, raw in enumerate(logical.splitlines(), start=1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("--index-url", "-i ")):
            options["index_urls"].append(line.split(None, 1)[-1].replace("--index-url=", "").strip())
            continue
        if line.startswith("--extra-index-url"):
            options["extra_index_urls"].append(line.split(None, 1)[-1].replace("--extra-index-url=", "").strip())
            continue
        if line.startswith(("-e ", "--editable")):
            options["editable"].append(line)
            continue
        if line.startswith(("-r", "-c", "--requirement", "--constraint", "--find-links", "-f ", "--trusted-host", "--pre", "--no-binary", "--only-binary")):
            continue
        if re.match(r"^(?:https?|git\+\w+|file)://", line) or " @ " in line:
            options["urls"].append(line)
        match = REQ_LINE.match(line)
        if not match:
            continue
        spec = (match.group(3) or "").replace(" ", "")
        exact = re.fullmatch(r"===?([^,;]+)", spec)
        hashes = re.findall(r"--hash=([a-z0-9]+:[0-9a-fA-F]+)", raw)
        options["hashes_seen"] = options["hashes_seen"] or bool(hashes)
        packages.append(Package("PyPI", pep503(match.group(1)), exact.group(1) if exact else None, spec, path, number, integrity=hashes,
                                resolved=line.split(" @ ", 1)[1].split(";")[0].strip() if " @ " in line else ""))
    return packages, options


def parse_pipfile_lock(text: str, path: str) -> list[Package]:
    data = _json(text, path)
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, info in (data.get(section) or {}).items():
            if isinstance(info, dict):
                version = str(info.get("version", "")).lstrip("=") or None
                out.append(Package("PyPI", pep503(name), version, str(info.get("version", "")), path, integrity=list(info.get("hashes") or []), dev=dev))
    return out


def _toml(text: str, path: str) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError as exc:  # Python < 3.11
        raise ToolInputError(f"{path}: reading TOML lockfiles needs Python 3.11+ (tomllib).") from exc
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ToolInputError(f"{path} is not valid TOML.") from exc


def parse_poetry_lock(text: str, path: str) -> list[Package]:
    data = _toml(text, path)
    out = []
    for item in data.get("package") or []:
        hashes = [f.get("hash", "") for f in item.get("files") or [] if isinstance(f, dict)]
        source = item.get("source") or {}
        out.append(Package("PyPI", pep503(item.get("name", "")), str(item.get("version")), "", path, integrity=hashes,
                           resolved=str(source.get("url", "")), dev=item.get("category") == "dev", direct=False))
    return out


def parse_package_lock(text: str, path: str) -> list[Package]:
    data = _json(text, path)
    out = []
    if isinstance(data.get("packages"), dict):  # lockfileVersion 2/3
        root = data["packages"].get("", {})
        direct = set((root.get("dependencies") or {}) | (root.get("devDependencies") or {}))
        for key, info in data["packages"].items():
            if not key or not isinstance(info, dict) or info.get("link"):
                continue
            name = info.get("name") or key.split("node_modules/")[-1]
            integrity = [info["integrity"]] if info.get("integrity") else []
            out.append(Package("npm", name, info.get("version"), "", path, resolved=str(info.get("resolved", "")), integrity=integrity,
                               license=str(info.get("license", "")), dev=bool(info.get("dev")), direct=name in direct and key.count("node_modules/") == 1))
    else:  # lockfileVersion 1
        def walk(deps, depth):
            for name, info in (deps or {}).items():
                if isinstance(info, dict):
                    out.append(Package("npm", name, info.get("version"), "", path, resolved=str(info.get("resolved", "")),
                                       integrity=[info["integrity"]] if info.get("integrity") else [], dev=bool(info.get("dev")), direct=depth == 0))
                    walk(info.get("dependencies"), depth + 1)
        walk(data.get("dependencies"), 0)
    return out


def parse_yarn_lock(text: str, path: str) -> list[Package]:
    out, current = [], None
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            first = line.rstrip(":").split(",")[0].strip().strip('"')
            name = first[: first.rfind("@")] if first.rfind("@") > 0 else first
            current = Package("npm", name, None, first[len(name) + 1:], path, number, direct=False)
            out.append(current)
        elif current is not None:
            match = re.match(r'^\s+(version|resolved|integrity)\s+"?([^"]+)"?', line)
            if match:
                key, value = match.groups()
                if key == "version":
                    current.version = value
                elif key == "resolved":
                    current.resolved = value
                else:
                    current.integrity.append(value)
    return out


def parse_package_json(text: str, path: str) -> list[Package]:
    data = _json(text, path)
    out = []
    for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for name, spec in (data.get(section) or {}).items():
            exact = re.fullmatch(r"=?v?(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)", str(spec))
            out.append(Package("npm", name, exact.group(1) if exact else None, str(spec), path, dev=dev))
    return out


def parse_go_mod(text: str, path: str) -> list[Package]:
    out, in_block = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.split("//", 1)[0].strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        match = re.match(r"^(?:require\s+)?(\S+)\s+(v\S+)", stripped) if (in_block or stripped.startswith("require ")) else None
        if match:
            out.append(Package("Go", match.group(1), match.group(2), "", path, number, direct="// indirect" not in line))
    return out


def parse_go_sum(text: str, path: str) -> list[Package]:
    out = {}
    for number, line in enumerate(text.splitlines(), start=1):
        parts = line.split()
        if len(parts) == 3 and not parts[1].endswith("/go.mod"):
            out[(parts[0], parts[1])] = Package("Go", parts[0], parts[1], "", path, number, integrity=[parts[2]], direct=False)
    return list(out.values())


def parse_gemfile_lock(text: str, path: str) -> list[Package]:
    out, in_specs = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and not line.startswith("  "):
            in_specs = False
        match = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line) if in_specs else None
        if match:
            out.append(Package("RubyGems", match.group(1), match.group(2).split("-")[0], "", path, number, direct=False))
    return out


def parse_composer_lock(text: str, path: str) -> list[Package]:
    data = _json(text, path)
    out = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for item in data.get(section) or []:
            dist = item.get("dist") or {}
            license_value = item.get("license") or []
            out.append(Package("Packagist", item.get("name", ""), str(item.get("version", "")).lstrip("v"), "", path,
                               resolved=str(dist.get("url", "")), integrity=[dist["shasum"]] if dist.get("shasum") else [],
                               license=" OR ".join(license_value) if isinstance(license_value, list) else str(license_value), dev=dev))
    return out


def parse_cargo_lock(text: str, path: str) -> list[Package]:
    data = _toml(text, path)
    return [Package("crates.io", p.get("name", ""), p.get("version"), "", path, resolved=str(p.get("source", "")),
                    integrity=[p["checksum"]] if p.get("checksum") else [], direct=False)
            for p in data.get("package") or [] if str(p.get("source", "")).startswith("registry+")]


def parse_pom(text: str, path: str) -> list[Package]:
    if re.search(r"<!DOCTYPE|<!ENTITY", text, re.I):
        raise ToolInputError(f"{path}: DOCTYPE/ENTITY declarations are refused.")
    props = dict(re.findall(r"<([\w.-]+)>([^<]{1,200})</\1>", re.search(r"<properties>(.*?)</properties>", text, re.S).group(1)) if "<properties>" in text else [])
    out = []
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        get = lambda tag: (re.search(rf"<{tag}>\s*([^<]+?)\s*</{tag}>", block) or [None, ""])[1]
        version = get("version")
        version = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), version)
        out.append(Package("Maven", f"{get('groupId')}:{get('artifactId')}", version if version and "${" not in version else None, version, path,
                           dev=get("scope") == "test"))
    return out


PARSERS = [
    (re.compile(r"(?:^|/)(?:requirements[^/]*\.txt|constraints[^/]*\.txt)$", re.I), "requirements"),
    (re.compile(r"(?:^|/)Pipfile\.lock$"), "pipfile_lock"), (re.compile(r"(?:^|/)poetry\.lock$"), "poetry_lock"),
    (re.compile(r"(?:^|/)(?:package-lock|npm-shrinkwrap)\.json$"), "package_lock"), (re.compile(r"(?:^|/)yarn\.lock$"), "yarn_lock"),
    (re.compile(r"(?:^|/)package\.json$"), "package_json"), (re.compile(r"(?:^|/)go\.mod$"), "go_mod"), (re.compile(r"(?:^|/)go\.sum$"), "go_sum"),
    (re.compile(r"(?:^|/)Gemfile\.lock$"), "gemfile_lock"), (re.compile(r"(?:^|/)composer\.lock$"), "composer_lock"),
    (re.compile(r"(?:^|/)Cargo\.lock$"), "cargo_lock"), (re.compile(r"(?:^|/)pom\.xml$"), "pom"),
]


def kind_of(path: str) -> str | None:
    for pattern, kind in PARSERS:
        if pattern.search(path.replace("\\", "/")):
            return kind
    return None


def parse(path: str, text: str) -> tuple[str | None, list[Package], dict[str, Any]]:
    kind = kind_of(path)
    if kind is None:
        return None, [], {}
    if kind == "requirements":
        packages, options = parse_requirements(text, path)
        return kind, packages, options
    function = globals()[f"parse_{kind}"]
    return kind, function(text, path), {}


def _json(text: str, path: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise ToolInputError(f"{path} is not valid JSON.") from exc
    if not isinstance(data, dict):
        raise ToolInputError(f"{path} must contain a JSON object.")
    return data


# ---- version ordering for advisory matching --------------------------------------------------------

def version_key(ecosystem: str, version: str):
    """A sortable key; None if the version cannot be ordered."""
    version = str(version).strip().lstrip("v=")
    if ecosystem == "PyPI":
        try:
            from packaging.version import InvalidVersion, Version
        except ImportError:
            pass
        else:
            try:
                return (0, Version(version))
            except InvalidVersion:
                return None
    version = version.split("+", 1)[0]  # semver build metadata never affects ordering
    match = re.match(r"^(\d+(?:\.\d+)*)(?:[-.]?([0-9A-Za-z][0-9A-Za-z.-]*))?$", version)
    if not match:
        return None
    numbers = tuple(int(p) for p in match.group(1).split("."))
    numbers = numbers + (0,) * (4 - len(numbers)) if len(numbers) < 4 else numbers
    pre = match.group(2)
    if not pre:
        return (1, numbers, (1,))  # a release sorts after all of its pre-releases
    identifiers = tuple((0, int(x), "") if x.isdigit() else (1, 0, x) for x in pre.split("."))
    return (1, numbers, (0, identifiers))


def affected(advisory: dict[str, Any], package: Package) -> bool:
    """OSV semantics: listed versions, or ECOSYSTEM/SEMVER range events (introduced / fixed / last_affected)."""
    if not package.version:
        return False
    for entry in advisory.get("affected") or []:
        pkg = entry.get("package") or {}
        if pkg.get("ecosystem") != package.ecosystem:
            continue
        name = pkg.get("name", "")
        if (pep503(name) if package.ecosystem == "PyPI" else name) != package.name:
            continue
        if package.version in (entry.get("versions") or []):
            return True
        current = version_key(package.ecosystem, package.version)
        if current is None:
            continue
        for range_ in entry.get("ranges") or []:
            if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            status = False
            events = sorted(range_.get("events") or [], key=lambda e: version_key(package.ecosystem, next(iter(e.values()))) or (0,))
            for event in events:
                (kind, value), = event.items()
                bound = (0,) if value == "0" else version_key(package.ecosystem, value)
                if bound is None:
                    continue
                if kind == "introduced" and current >= bound:
                    status = True
                elif kind == "fixed" and current >= bound:
                    status = False
                elif kind == "last_affected" and current > bound:
                    status = False
            if status:
                return True
    return False
