"""Build the public changelog from this repository's git history.

    python tools/changelog.py

Writes web_v/static/data/changelog.json and fills the release list in web_v/static/changelog.html
(between <!-- CHANGELOG:START --> and <!-- CHANGELOG:END -->, so the page works without scripts
and search engines see it). Commits are grouped into one release per day; each commit subject
becomes an entry, tagged New / Fixed / Changed from its first word. The release version is the
date (2026.11.21). Merge commits and housekeeping subjects are left out.
"""
from __future__ import annotations

import html
import json
import re
import subprocess
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "web_v" / "static"
SKIP = re.compile(r"^(merge\b|wip\b|input$|baseline\b|bump\b|chore\b)", re.I)
KIND = [("fixed", re.compile(r"^(fix|repair|correct|stop|keep|hide|retry|limit|expect)\b", re.I)),
        ("new", re.compile(r"^(add|introduce|create|support|ask|narrate|give|map|make repair real)\b", re.I))]
LABEL = {"new": ("New", "جديد"), "fixed": ("Fixed", "إصلاح"), "changed": ("Changed", "تغيير")}
CLASS = {"new": "ok", "fixed": "info", "changed": "warn"}


def commits() -> list[dict]:
    out = subprocess.run(["git", "-C", str(ROOT), "log", "--no-merges", "--date=short", "--format=%h%x09%ad%x09%s"],
                         capture_output=True, text=True, check=True, encoding="utf-8").stdout
    rows = []
    for line in out.splitlines():
        sha, date, subject = (line.split("\t", 2) + ["", ""])[:3]
        subject = subject.strip()
        if subject and not SKIP.search(subject):
            kind = next((k for k, rx in KIND if rx.search(subject)), "changed")
            rows.append({"commit": sha, "date": date, "text": subject.rstrip("."), "kind": kind})
    return rows


def releases(rows: list[dict]) -> list[dict]:
    days: OrderedDict[str, list[dict]] = OrderedDict()
    for r in rows:   # newest first, as git prints them
        days.setdefault(r["date"], []).append(r)
    out = []
    for date, items in days.items():
        order = {"new": 0, "changed": 1, "fixed": 2}
        items = sorted(items, key=lambda r: order[r["kind"]])
        out.append({"version": date.replace("-", "."), "date": date, "commit": items[0]["commit"] if items else "",
                    "entries": [{"kind": r["kind"], "text": r["text"], "commit": r["commit"]} for r in items]})
    if out:   # the newest release's commit is the newest commit of that day
        out[0]["commit"] = days[out[0]["date"]][0]["commit"]
    return out


def render(rels: list[dict]) -> str:
    parts = []
    for rel in rels:
        lis = "".join(
            f'<li><span class="tr-pill {CLASS[e["kind"]]}"><span data-l="en">{LABEL[e["kind"]][0]}</span><span data-l="ar">{LABEL[e["kind"]][1]}</span></span>'
            f'<span lang="en" dir="ltr">{html.escape(e["text"])}</span></li>' for e in rel["entries"])
        parts.append(f'\n      <section class="tr-card tr-release" id="v{rel["version"]}"><h2><time datetime="{rel["date"]}">{rel["version"]}</time>'
                     f'<small>{len(rel["entries"])} <span data-l="en">changes</span><span data-l="ar">تغييرات</span></small></h2><ul>{lis}</ul></section>')
    return "".join(parts) + "\n      "


def main() -> None:
    rels = releases(commits())
    data = {"generated_from": "git log", "releases": rels}
    (STATIC / "data").mkdir(parents=True, exist_ok=True)
    (STATIC / "data" / "changelog.json").write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    page = STATIC / "changelog.html"
    text = page.read_text(encoding="utf-8")
    start, end = "<!-- CHANGELOG:START -->", "<!-- CHANGELOG:END -->"
    i, j = text.find(start), text.find(end)
    if i < 0 or j < i:
        raise SystemExit("changelog.html has no CHANGELOG markers")
    page.write_text(text[:i + len(start)] + render(rels) + text[j:], encoding="utf-8", newline="\n")
    print(f"{len(rels)} releases, {sum(len(r['entries']) for r in rels)} entries -> {page}")


if __name__ == "__main__":
    main()
