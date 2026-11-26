"""EMBER2024 (EMBER feature version 3) feature vector, 2568 floats, for any file.

Derived from ``thrember/features.py`` of the EMBER2024 project
(https://github.com/FutureComputing4AI/EMBER2024, commit 0ef753e8), Copyright the EMBER2024
authors, licensed under the Apache License 2.0 (see NOTICE). The feature definitions, their
order and their arithmetic are kept; what changed, and why:

* ``sklearn.feature_extraction.FeatureHasher`` is replaced by :func:`hash_features`, a
  pure-Python copy of its semantics (MurmurHash3 x86-32 seed 0 on the UTF-8 name, index
  ``abs(h) % n`` with scikit-learn's special case for -2**31, ``alternate_sign``, zero values
  skipped, ``name=value`` for string values), so the website (Lambda) and the phone (Pyodide)
  need no scikit-learn/SciPy. Tests check it against scikit-learn.
* the Authenticode group reads the signature with :mod:`core.authenticode_der` instead of
  ``signify`` (checked equal to signify 0.7.1 on 1,141 signed Windows files).
* faster, equivalent arithmetic for large inputs: the whole-file and overlay entropy use
  ``numpy.bincount`` instead of ``collections.Counter`` (same terms, possibly summed in a
  different order: differences of ~1e-16, invisible after the float32 cast); the byte/entropy
  histogram computes each 2,048-byte window from two 1,024-byte halves and falls back to the
  original float32 computation whenever a window's entropy lies within 1e-3 of a bin edge;
  the string regexes run once over all strings joined by newlines (no regex can cross one)
  and count the strings that contain a match, which is what the original per-string loop counts.
* robustness: any exception while parsing the PE gives ``pe=None`` (the original only caught
  ``PEFormatError``/``AttributeError``), and a feature group that fails on a malformed file
  becomes zeros and is named in ``degraded`` instead of stopping the scan (the original
  would raise). Unknown pefile warnings are ignored silently instead of printed.

Static only: the bytes are read, never executed.
"""
from __future__ import annotations

import math
import re
import struct
from bisect import bisect_right
from collections import OrderedDict
from pathlib import Path

import numpy as np

try:
    import pefile
except ImportError:  # pragma: no cover - every CyberScan edition ships pefile
    pefile = None

from core.authenticode_der import signature_features

WARNINGS_FILE = Path(__file__).resolve().parents[1] / "intel" / "data" / "ml" / "pefile_warnings.txt"
FEATURE_VERSION = 3
DIM = 2568


# ------------------------------------------------------------------ FeatureHasher, without scikit-learn
_M32 = 0xFFFFFFFF


def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, signed (scikit-learn's ``murmurhash3_32(..., positive=False)``)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & _M32
    length = len(data)
    nblocks = length // 4
    for (k,) in struct.iter_unpack("<I", data[:nblocks * 4]):
        k = (k * c1) & _M32
        k = ((k << 15) | (k >> 17)) & _M32
        k = (k * c2) & _M32
        h ^= k
        h = ((h << 13) | (h >> 19)) & _M32
        h = (h * 5 + 0xE6546B64) & _M32
    tail = data[nblocks * 4:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if tail:
        k ^= tail[0]
        k = (k * c1) & _M32
        k = ((k << 15) | (k >> 17)) & _M32
        k = (k * c2) & _M32
        h ^= k
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & _M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & _M32
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def hash_features(items, n_features: int, input_type: str = "string", alternate_sign: bool = True) -> np.ndarray:
    """``FeatureHasher(n_features, input_type=..., alternate_sign=...).transform([items]).toarray()[0]``."""
    out = np.zeros(n_features, dtype=np.float64)
    pairs = ((name, 1) for name in items) if input_type == "string" else items
    for name, value in pairs:
        if isinstance(value, str):
            name, value = f"{name}={value}", 1
        if value == 0:
            continue
        if isinstance(name, str):
            name = name.encode("utf-8")
        elif not isinstance(name, bytes):
            raise TypeError(f"feature names must be strings, not {type(name).__name__}")
        h = murmurhash3_32(name, 0)
        index = (2147483647 - (n_features - 1)) % n_features if h == -2147483648 else abs(h) % n_features
        if alternate_sign:
            value = value * ((h >= 0) * 2 - 1)
        out[index] += value
    return out


def _entropy_bits(counts: np.ndarray, total: int) -> float:
    """Shannon entropy (bits) as pefile's entropy_H computes it, from byte counts."""
    entropy = 0.0
    for x in counts[counts > 0].tolist():
        p_x = float(x) / total
        entropy -= p_x * math.log(p_x, 2)
    return entropy


# ------------------------------------------------------------------ feature groups
class FeatureType:
    name: str = ""
    dim: int = 0

    def raw_features(self, bytez: bytes, pe=None):
        raise NotImplementedError

    def process_raw_features(self, raw_obj):
        raise NotImplementedError


class GeneralFileInfo(FeatureType):
    name = "general"
    dim = 3 + 4

    def raw_features(self, bytez, pe=None):
        size = len(bytez)
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return {
            "size": size,
            "entropy": _entropy_bits(counts, size),
            "is_pe": 0 if pe is None else 1,
            "start_bytes": [int(bytez[0]), int(bytez[1]) if size >= 2 else 0,
                            int(bytez[2]) if size >= 3 else 0, int(bytez[3]) if size >= 4 else 0],
        }

    def process_raw_features(self, raw_obj):
        return np.hstack([raw_obj["size"], raw_obj["entropy"], raw_obj["is_pe"], raw_obj["start_bytes"]],
                         dtype=np.float32)


class ByteHistogram(FeatureType):
    name = "histogram"
    dim = 256

    def raw_features(self, bytez, pe):
        return np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256).tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / counts.sum()


class ByteEntropyHistogram(FeatureType):
    """2-D byte/entropy histogram (Saxe and Berlin, 2015), 2,048-byte windows every 1,024 bytes."""

    name = "byteentropy"
    dim = 256

    def __init__(self, step=1024, window=2048):
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        return self._bin_of_counts(c), c

    def _bin_of_counts(self, c):
        """The original float32 arithmetic, from a window's 16 nibble counts."""
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)
        return 15 if Hbin == 16 else Hbin

    def raw_features(self, bytez, pe):
        output = np.zeros((16, 16), dtype=np.int64)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
            return output.flatten().tolist()
        blocks = (a.shape[0] - self.window) // self.step + 1
        if self.window != 2 * self.step:   # only the 2x layout has the fast form
            for start in range(0, blocks * self.step, self.step):
                Hbin, c = self._entropy_bin_counts(a[start:start + self.window])
                output[Hbin, :] += c
            return output.flatten().tolist()
        halves = blocks + 1
        nibbles = a[:halves * self.step] >> 4
        half_counts = np.empty((halves, 16), dtype=np.int64)
        batch = 4096
        for first in range(0, halves, batch):
            part = nibbles[first * self.step:(first + batch) * self.step].reshape(-1, self.step).astype(np.int64)
            rows = part.shape[0]
            index = (np.arange(rows, dtype=np.int64)[:, None] * 16 + part).ravel()
            half_counts[first:first + rows] = np.bincount(index, minlength=rows * 16).reshape(rows, 16)
        counts = half_counts[:-1] + half_counts[1:]
        p = counts / float(self.window)
        with np.errstate(divide="ignore", invalid="ignore"):
            terms = np.where(counts > 0, -p * np.log2(np.where(counts > 0, p, 1.0)), 0.0)
        doubled = terms.sum(axis=1) * 4.0          # H * 2, with H already doubled for the 4-bit reduction
        bins = np.floor(doubled).astype(np.int64)
        near = np.abs(doubled - np.round(doubled)) < 1e-3
        for row in np.nonzero(near)[0].tolist():
            bins[row] = self._bin_of_counts(counts[row])
        bins = np.minimum(bins, 15)
        np.add.at(output, bins, counts)
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        return counts / counts.sum()


class StringExtractor(FeatureType):
    name = "strings"
    dim = 5 + 96 + 76

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")
        # The regexes of thrember, unchanged (including its names and its quirks).
        self._regexes = {
            "url": re.compile("\\b(?:http|https|ftp):\\/\\/[a-zA-Z0-9-._~:?#[\\]@!$&'()*+,;=]+"),
            "ipv4_addr": re.compile("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"),
            "ipv6_addr": re.compile("\\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\\b|\\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\\b|\\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\\b"),
            "mac_addr": re.compile("\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b"),
            "email_addr": re.compile("\\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\\b"),
            "btc_wallet": re.compile("[13][a-km-zA-HJ-NP-Z1-9]{25,34}"),
            "file_path": re.compile("\\bC:/"),
            "dos_msg": re.compile("!This program "),
            "registry_key": re.compile("\\b(?:KHEY_|KHLM|HKCU)"),
            "/dev/": re.compile("/dev/"),
            "/proc/": re.compile("/proc/"),
            "/bin/": re.compile("/bin/"),
            "/usr/": re.compile("/usr/"),
            "/tmp/": re.compile("/tmp/"),
            "/URI": re.compile("/URI"),
            "/FlateDecode": re.compile("/FlateDecode"),
            "/EmbeddedFile": re.compile("/EmbeddedFile"),
            "html": re.compile("html", re.IGNORECASE),
            "javascript": re.compile("javascript", re.IGNORECASE),
            "<script": re.compile("<script", re.IGNORECASE),
            ".click(": re.compile(".click", re.IGNORECASE),
            "onlick": re.compile("onclick", re.IGNORECASE),
            "powershell": re.compile("powershell", re.IGNORECASE),
            "Invoke-Expression": re.compile("Invoke-Expression"),
            "Invoke-Command": re.compile("Invoke-Command"),
            "Start-process": re.compile("Start-process"),
            "get": re.compile("GET /", re.IGNORECASE),
            "post": re.compile("POST /", re.IGNORECASE),
            "http": re.compile("HTTP/", re.IGNORECASE),
            "http://": re.compile("http://", re.IGNORECASE),
            "https://": re.compile("https://", re.IGNORECASE),
            "ftp": re.compile("ftp:", re.IGNORECASE),
            "useragent": re.compile("User-Agent", re.IGNORECASE),
            "cookie": re.compile("cookie", re.IGNORECASE),
            "internet": re.compile("internet", re.IGNORECASE),
            "download": re.compile("download", re.IGNORECASE),
            "connect": re.compile("connect", re.IGNORECASE),
            "base64": re.compile("base64", re.IGNORECASE),
            "base64string": re.compile("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
            "crypt": re.compile("crypt"),
            "encode": re.compile("encode", re.IGNORECASE),
            "decode": re.compile("decode", re.IGNORECASE),
            "cache": re.compile("cache", re.IGNORECASE),
            "certificate": re.compile("certificate", re.IGNORECASE),
            "clipboard": re.compile("clipboard", re.IGNORECASE),
            "command": re.compile("command", re.IGNORECASE),
            "create": re.compile("create", re.IGNORECASE),
            "debug": re.compile("debug", re.IGNORECASE),
            "delete": re.compile("delete", re.IGNORECASE),
            "desktop": re.compile("desktop", re.IGNORECASE),
            "directory": re.compile("directory", re.IGNORECASE),
            "disk": re.compile("disk", re.IGNORECASE),
            "environment": re.compile("environment", re.IGNORECASE),
            "enum": re.compile("enum", re.IGNORECASE),
            "exit": re.compile("exit", re.IGNORECASE),
            "file": re.compile("file", re.IGNORECASE),
            "hostname": re.compile("hostname", re.IGNORECASE),
            "install": re.compile("install", re.IGNORECASE),
            "hidden": re.compile("hidden", re.IGNORECASE),
            "keyboard": re.compile("keyboard", re.IGNORECASE),
            "memory": re.compile("memory", re.IGNORECASE),
            "module": re.compile("module", re.IGNORECASE),
            "mutex": re.compile("mutex", re.IGNORECASE),
            "password": re.compile("password", re.IGNORECASE),
            "privilege": re.compile("privilege", re.IGNORECASE),
            "process": re.compile("process", re.IGNORECASE),
            "remote": re.compile("remote", re.IGNORECASE),
            "resource": re.compile("resource", re.IGNORECASE),
            "security": re.compile("security", re.IGNORECASE),
            "service": re.compile("service", re.IGNORECASE),
            "shell": re.compile("shell", re.IGNORECASE),
            "snapshot": re.compile("snapshot", re.IGNORECASE),
            "system": re.compile("system", re.IGNORECASE),
            "thread": re.compile("thread", re.IGNORECASE),
            "token": re.compile("token", re.IGNORECASE),
            "wallet": re.compile("wallet", re.IGNORECASE),
            "window": re.compile("window", re.IGNORECASE),
        }
        self.regex_idxs = {k: v for v, k in enumerate(sorted(self._regexes))}

    def raw_features(self, bytez, pe):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            joined = b"".join(allstrings)
            avlength = len(joined) / len(allstrings)
            c = np.bincount(np.frombuffer(joined, dtype=np.uint8) - 0x20, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh]))
        else:
            avlength, c, H, csum = 0, np.zeros((96,), dtype=np.float32), 0, 0

        string_counts = {}
        if allstrings:
            text = "\n".join(s.decode() for s in allstrings)
            starts, position = [], 0
            for s in allstrings:
                starts.append(position)
                position += len(s) + 1
            for key, regex in self._regexes.items():
                seen = {bisect_right(starts, m.start()) - 1 for m in regex.finditer(text)}
                if seen:
                    string_counts[key] = len(seen)
        string_counts = OrderedDict(sorted(string_counts.items()))
        return {"numstrings": len(allstrings), "avlength": avlength, "printabledist": c.tolist(),
                "printables": int(csum), "entropy": float(H), "string_counts": string_counts}

    def process_raw_features(self, raw_obj):
        hist_divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        string_counts = np.zeros(len(self.regex_idxs), dtype=np.float32)
        for regex, count in raw_obj["string_counts"].items():
            string_counts[self.regex_idxs[regex]] = count
        return np.hstack([raw_obj["numstrings"], raw_obj["avlength"], raw_obj["printables"],
                          np.asarray(raw_obj["printabledist"]) / hist_divisor, raw_obj["entropy"],
                          string_counts]).astype(np.float32)


class SectionInfo(FeatureType):
    name = "section"
    dim = 11 + 50 + 50 + 50 + 50 + 10 + 3

    def raw_features(self, bytez, pe):
        if pe is None:
            return {}
        entry_section = ""
        aoep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for section in pe.sections:
            if section.contains_rva(aoep):
                entry_section = section.Name.strip(b"\x00").decode(errors="ignore").lower()
        isection = 0
        while entry_section == "" and isection < len(pe.sections):
            if pe.sections[isection].Characteristics & 0x20000000 > 0:
                entry_section = pe.sections[isection].Name.strip(b"\x00").decode(errors="ignore").lower()
            isection += 1
        raw_obj = {"entry": entry_section}
        raw_obj["sections"] = [
            {
                "name": section.Name.strip(b"\x00").decode(errors="ignore").lower(),
                "size": section.SizeOfRawData,
                "entropy": section.get_entropy(),
                "vsize": section.Misc_VirtualSize,
                "size_ratio": section.SizeOfRawData / len(bytez),
                "vsize_ratio": section.SizeOfRawData / max(section.Misc_VirtualSize, 1),
                "props": [sc[10:] for sc, _ in pefile.section_characteristics if section.__dict__[sc]],
            }
            for section in pe.sections
        ]
        raw_obj["overlay"] = {"size": 0, "size_ratio": 0, "entropy": 0}
        overlay = pe.get_overlay()
        if overlay is not None:
            counts = np.bincount(np.frombuffer(overlay, dtype=np.uint8), minlength=256)
            raw_obj["overlay"] = {"size": len(overlay), "size_ratio": len(overlay) / len(bytez),
                                  "entropy": _entropy_bits(counts, len(overlay))}
        return raw_obj

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        sections = raw_obj["sections"]
        entropies = [s["entropy"] for s in sections] + [raw_obj["overlay"]["entropy"]] + [0]
        size_ratios = [s["size_ratio"] for s in sections] + [raw_obj["overlay"]["size_ratio"]] + [0]
        vsize_ratios = [s["vsize_ratio"] for s in sections] + [0]
        general = [
            len(sections),
            sum(1 for s in sections if s["size"] == 0),
            sum(1 for s in sections if s["name"] == ""),
            sum(1 for s in sections if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),
            max(entropies), min(entropies), max(size_ratios), min(size_ratios), max(vsize_ratios), min(vsize_ratios),
        ]
        return np.hstack([
            general,
            hash_features([(s["name"], s["size"]) for s in sections], 50, "pair"),
            hash_features([(s["name"], s["vsize"]) for s in sections], 50, "pair"),
            hash_features([(s["name"], s["entropy"]) for s in sections], 50, "pair"),
            hash_features([f"{s['name']}:{p}" for s in sections for p in s["props"]], 50, "string"),
            hash_features([raw_obj["entry"]], 10, "string"),
            raw_obj["overlay"]["size"], raw_obj["overlay"]["size_ratio"], raw_obj["overlay"]["entropy"],
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    name = "imports"
    dim = 2 + 256 + 1024

    def raw_features(self, bytez, pe):
        imports = {}
        if pe is None or "DIRECTORY_ENTRY_IMPORT" not in pe.__dict__.keys():
            return imports
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode()
            imports[dll_name] = []
            for lib in entry.imports:
                if lib.name is not None and len(lib.name):
                    imports[dll_name].append(lib.name.decode()[:10000])
                elif lib.ordinal is not None:
                    imports[dll_name].append(f"{dll_name}:ordinal{lib.ordinal}")
        return imports

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        libraries = list(set([lib.lower() for lib in raw_obj.keys()]))
        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        return np.hstack([[len(imports), len(libraries)],
                          hash_features(libraries, 256, "string", alternate_sign=False),
                          hash_features(imports, 1024, "string", alternate_sign=False)]).astype(np.float32)


class ExportsInfo(FeatureType):
    name = "exports"
    dim = 1 + 128

    def raw_features(self, bytez, pe):
        if pe is None:
            return []
        clipped_exports = []
        if "DIRECTORY_ENTRY_EXPORT" in pe.__dict__.keys():
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None and len(exp.name):
                    clipped_exports.append(exp.name.decode()[:10000])
                elif exp.ordinal is not None:
                    clipped_exports.append(f"ordinal{exp.ordinal}")
        return clipped_exports

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        exports_hashed = hash_features(raw_obj, 128, "string")
        # thrember stores len(exports_hashed) (always 128) here, not the number of exports; kept.
        return np.hstack([np.array([len(exports_hashed)]), exports_hashed.astype(np.float32)])


class HeaderFileInfo(FeatureType):
    name = "header"
    dim = 74

    _machine_types = [
        "IMAGE_FILE_MACHINE_UNKNOWN", "IMAGE_FILE_MACHINE_I386", "IMAGE_FILE_MACHINE_R3000",
        "IMAGE_FILE_MACHINE_R4000", "IMAGE_FILE_MACHINE_R10000", "IMAGE_FILE_MACHINE_WCEMIPSV2",
        "IMAGE_FILE_MACHINE_ALPHA", "IMAGE_FILE_MACHINE_SH3", "IMAGE_FILE_MACHINE_SH3DSP",
        "IMAGE_FILE_MACHINE_SH3E", "IMAGE_FILE_MACHINE_SH4", "IMAGE_FILE_MACHINE_SH5",
        "IMAGE_FILE_MACHINE_ARM", "IMAGE_FILE_MACHINE_THUMB", "IMAGE_FILE_MACHINE_ARMNT",
        "IMAGE_FILE_MACHINE_AM33", "IMAGE_FILE_MACHINE_POWERPC", "IMAGE_FILE_MACHINE_POWERPCFP",
        "IMAGE_FILE_MACHINE_IA64", "IMAGE_FILE_MACHINE_MIPS16", "IMAGE_FILE_MACHINE_ALPHA64",
        "IMAGE_FILE_MACHINE_AXP64", "IMAGE_FILE_MACHINE_MIPSFPU", "IMAGE_FILE_MACHINE_MIPSFPU16",
        "IMAGE_FILE_MACHINE_TRICORE", "IMAGE_FILE_MACHINE_CEF", "IMAGE_FILE_MACHINE_EBC",
        "IMAGE_FILE_MACHINE_RISCV32", "IMAGE_FILE_MACHINE_RISCV64", "IMAGE_FILE_MACHINE_RISCV128",
        "IMAGE_FILE_MACHINE_LOONGARCH32", "IMAGE_FILE_MACHINE_LOONGARCH64", "IMAGE_FILE_MACHINE_AMD64",
        "IMAGE_FILE_MACHINE_M32R", "IMAGE_FILE_MACHINE_ARM64", "IMAGE_FILE_MACHINE_CEE",
    ]
    _subsystem_types = [
        "IMAGE_SUBSYSTEM_UNKNOWN", "IMAGE_SUBSYSTEM_NATIVE", "IMAGE_SUBSYSTEM_WINDOWS_GUI",
        "IMAGE_SUBSYSTEM_WINDOWS_CUI", "IMAGE_SUBSYSTEM_OS2_CUI", "IMAGE_SUBSYSTEM_POSIX_CUI",
        "IMAGE_SUBSYSTEM_NATIVE_WINDOWS", "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", "IMAGE_SUBSYSTEM_EFI_APPLICATION",
        "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", "IMAGE_SUBSYSTEM_EFI_ROM",
        "IMAGE_SUBSYSTEM_XBOX", "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
    ]
    _image_characteristics = [
        "RELOCS_STRIPPED", "EXECUTABLE_IMAGE", "LINE_NUMS_STRIPPED", "LOCAL_SYMS_STRIPPED", "AGGRESIVE_WS_TRIM",
        "LARGE_ADDRESS_AWARE", "16BIT_MACHINE", "BYTES_REVERSED_LO", "32BIT_MACHINE", "DEBUG_STRIPPED",
        "REMOVABLE_RUN_FROM_SWAP", "NET_RUN_FROM_SWAP", "SYSTEM", "DLL", "UP_SYSTEM_ONLY", "BYTES_REVERSED_HI",
    ]
    _dll_characteristics = [
        "HIGH_ENTROPY_VA", "DYNAMIC_BASE", "FORCE_INTEGRITY", "NX_COMPAT", "NO_ISOLATION", "NO_SEH",
        "NO_BIND", "APPCONTAINER", "WDM_DRIVER", "GUARD_CF", "TERMINAL_SERVER_AWARE",
    ]
    _dos_members = [
        "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss", "e_sp",
        "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno", "e_oemid", "e_oeminfo", "e_lfanew",
    ]

    def __init__(self):
        self._machine_types_dict = {mt: i for i, mt in enumerate(self._machine_types)}
        self._subsystem_types_dict = {st: i for i, st in enumerate(self._subsystem_types)}

    def raw_features(self, bytez, pe):
        if pe is None:
            return {}
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        raw_obj = {
            "coff": {
                "timestamp": fh.TimeDateStamp,
                "machine": pefile.MACHINE_TYPE.get(fh.Machine, "IMAGE_FILE_MACHINE_UNKNOWN"),
                "number_of_sections": fh.NumberOfSections,
                "number_of_symbols": fh.NumberOfSymbols,
                "sizeof_optional_header": fh.SizeOfOptionalHeader,
                "pointer_to_symbol_table": fh.PointerToSymbolTable,
                "characteristics": [k[11:] for k, v in fh.__dict__.items() if k.startswith("IMAGE_FILE_") and v],
            },
            "optional": {
                "magic": oh.Magic,
                "subsystem": pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, "IMAGE_SUBSYSTEM_UNKNOWN"),
                "major_image_version": oh.MajorImageVersion,
                "minor_image_version": oh.MinorImageVersion,
                "major_linker_version": oh.MajorLinkerVersion,
                "minor_linker_version": oh.MinorLinkerVersion,
                "major_operating_system_version": oh.MajorOperatingSystemVersion,
                "minor_operating_system_version": oh.MinorOperatingSystemVersion,
                "major_subsystem_version": oh.MajorSubsystemVersion,
                "minor_subsystem_version": oh.MinorSubsystemVersion,
                "sizeof_code": oh.SizeOfCode,
                "sizeof_headers": oh.SizeOfHeaders,
                "sizeof_image": oh.SizeOfImage,
                "sizeof_initialized_data": oh.SizeOfInitializedData,
                "sizeof_uninitialized_data": oh.SizeOfUninitializedData,
                "sizeof_stack_reserve": oh.SizeOfStackReserve,
                "sizeof_stack_commit": oh.SizeOfStackCommit,
                "sizeof_heap_reserve": oh.SizeOfHeapReserve,
                "sizeof_heap_commit": oh.SizeOfHeapCommit,
                "address_of_entrypoint": oh.AddressOfEntryPoint,
                "base_of_code": oh.BaseOfCode,
                "base_of_data": 0,
                "image_base": oh.ImageBase,
                "section_alignment": oh.SectionAlignment,
                "checksum": oh.CheckSum,
                "number_of_rvas_and_sizes": oh.NumberOfRvaAndSizes,
                "dll_characteristics": [k[25:] for k, v in oh.__dict__.items()
                                        if k.startswith("IMAGE_DLLCHARACTERISTICS_") and v],
            },
            "dos": {member: 0 for member in self._dos_members},
        }
        dos_dict = pe.DOS_HEADER.dump_dict()
        for member in self._dos_members:
            if dos_dict[member].get("Value") is not None:
                raw_obj["dos"][member] = dos_dict[member]["Value"]
        return raw_obj

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        coff, opt = raw_obj["coff"], raw_obj["optional"]
        return np.hstack([
            coff["timestamp"], coff["number_of_sections"], coff["number_of_symbols"],
            coff["sizeof_optional_header"], coff["pointer_to_symbol_table"],
            self._machine_types_dict.get(coff["machine"], 0),
            self._subsystem_types_dict.get(opt["subsystem"], 0),
            opt["major_image_version"], opt["minor_image_version"], opt["major_linker_version"],
            opt["minor_linker_version"], opt["major_operating_system_version"], opt["minor_operating_system_version"],
            opt["major_subsystem_version"], opt["minor_subsystem_version"], opt["sizeof_code"], opt["sizeof_headers"],
            opt["sizeof_image"], opt["sizeof_initialized_data"], opt["sizeof_uninitialized_data"],
            opt["sizeof_stack_reserve"], opt["sizeof_stack_commit"], opt["sizeof_heap_reserve"],
            opt["sizeof_heap_commit"], opt["address_of_entrypoint"], opt["base_of_code"], opt["image_base"],
            opt["section_alignment"], opt["checksum"], opt["number_of_rvas_and_sizes"],
            [ch in coff["characteristics"] for ch in self._image_characteristics],
            [ch in opt["dll_characteristics"] for ch in self._dll_characteristics],
            [raw_obj["dos"][member] for member in self._dos_members],
        ]).astype(np.float32)


class DataDirectories(FeatureType):
    name = "datadirectories"
    dim = 16 * 2 + 2
    _name_order = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "COPYRIGHT",
                   "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]

    def raw_features(self, bytez, pe):
        if pe is None:
            return []
        output = [{"has_relocs": int(pe.has_relocs()), "has_dynamic_relocs": int(pe.has_dynamic_relocs())}]
        for data_directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            output.append({"name": str(data_directory.name).replace("IMAGE_DIRECTORY_ENTRY_", ""),
                           "size": data_directory.Size, "virtual_address": data_directory.VirtualAddress})
        return output

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        features = np.zeros(2 * len(self._name_order) + 2, dtype=np.float32)
        for i in range(1, len(raw_obj) - 1):          # as thrember: the last directory is not used
            idx = self._name_order.index(raw_obj[i]["name"])
            features[2 * idx] = raw_obj[i]["size"]
            features[2 * idx + 1] = raw_obj[i]["virtual_address"]
        features[-2] = raw_obj[0]["has_relocs"]
        features[-1] = raw_obj[0]["has_dynamic_relocs"]
        return features


class RichHeader(FeatureType):
    name = "richheader"
    dim = 1 + 32

    def raw_features(self, bytez, pe):
        if pe is not None and pe.RICH_HEADER is not None:
            return pe.RICH_HEADER.values
        return []

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        pairs = [(str(raw_obj[i]), raw_obj[i + 1]) for i in range(0, len(raw_obj) - 1, 2)]
        return np.hstack([int(len(raw_obj) / 2), hash_features(pairs, 32, "pair")]).astype(np.float32)


class AuthenticodeSignature(FeatureType):
    name = "authenticode"
    dim = 8

    def raw_features(self, bytez, pe):
        if pe is None:
            return {}
        return signature_features(bytez, pe.FILE_HEADER.TimeDateStamp)

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        return np.hstack([raw_obj["num_certs"], raw_obj["self_signed"], raw_obj["empty_program_name"],
                          raw_obj["no_countersigner"], raw_obj["parse_error"], raw_obj["chain_max_depth"],
                          raw_obj["latest_signing_time"], raw_obj["signing_time_diff"]]).astype(np.float32)


class PEFormatWarnings(FeatureType):
    name = "pefilewarnings"
    dim = 87 + 1

    def __init__(self, warnings_file: Path = WARNINGS_FILE):
        self.warning_prefixes, self.warning_suffixes, self.warning_ids = set(), set(), {}
        if warnings_file.exists():
            for i, line in enumerate(warnings_file.read_text(encoding="utf-8").splitlines()):
                line = line.strip()
                if line.startswith("..."):
                    self.warning_suffixes.add(line[3:])
                else:
                    self.warning_prefixes.add(line[:-3])
                self.warning_ids[line] = i

    def raw_features(self, bytez, pe):
        if pe is None:
            return []
        warnings_norm = set()
        for warning in set(pe.get_warnings()):
            suffix = next((s for s in self.warning_suffixes if warning.endswith(s)), None)
            if suffix is not None:
                warnings_norm.add("..." + suffix)
                continue
            prefix = next((p for p in self.warning_prefixes if warning.startswith(p)), None)
            if prefix is not None:
                warnings_norm.add(prefix + "...")
        return sorted(warnings_norm)

    def process_raw_features(self, raw_obj):
        if not raw_obj:
            return np.zeros(self.dim, dtype=np.float32)
        ids = [0 for _ in range(self.dim)]
        for warning_norm in raw_obj:
            ids[self.warning_ids[warning_norm]] = 1.0
        ids[self.dim - 1] = len(raw_obj)
        return np.array(ids, dtype=np.float32)


# ------------------------------------------------------------------ the extractor
class FeatureExtractor:
    """EMBER2024's PEFeatureExtractor: 2568 float32 values for any file (PE parts are zeros
    when the file isn't a PE)."""

    def __init__(self):
        self.features = [GeneralFileInfo(), ByteHistogram(), ByteEntropyHistogram(), StringExtractor(),
                         HeaderFileInfo(), SectionInfo(), ImportsInfo(), ExportsInfo(), DataDirectories(),
                         RichHeader(), AuthenticodeSignature(), PEFormatWarnings()]
        self.dim = sum(fe.dim for fe in self.features)
        assert self.dim == DIM

    @staticmethod
    def parse_pe(bytez: bytes):
        if pefile is None or bytez[:2] != b"MZ":
            return None
        try:
            return pefile.PE(data=bytez)
        except Exception:  # noqa: BLE001 - a file pefile cannot read is "not a PE" (thrember: PEFormatError)
            return None

    def vector(self, bytez: bytes, pe=None, parse: bool = True) -> tuple[np.ndarray, list[str]]:
        """(feature vector, names of groups that failed and were zeroed)."""
        if not bytez:
            raise ValueError("empty file")
        if pe is None and parse:
            pe = self.parse_pe(bytez)
        parts, degraded = [], []
        for fe in self.features:
            try:
                part = fe.process_raw_features(fe.raw_features(bytez, pe))
                part = np.asarray(part, dtype=np.float32)
                if part.shape != (fe.dim,):
                    raise ValueError(f"{fe.name}: {part.shape} instead of {fe.dim}")
            except Exception:  # noqa: BLE001 - a malformed part must not stop the scan
                part = np.zeros(fe.dim, dtype=np.float32)
                degraded.append(fe.name)
            parts.append(part)
        return np.hstack(parts).astype(np.float32), degraded

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        return self.vector(bytez)[0]
