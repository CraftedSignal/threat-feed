#!/usr/bin/env python3
"""
Reads a list of brief Markdown paths on stdin (one per line) and emits a
JSON payload for the feed-notifier /dispatch endpoint:

    {"briefs": [{slug, title, description, url, type, severity, ...}, ...]}

Files that don't exist (e.g. deletions) and files without YAML frontmatter
are skipped silently. The payload is written to stdout.
"""
from __future__ import annotations

import json
import os
import sys

import yaml


SITE = "https://feed.craftedsignal.io"


def frontmatter(text: str) -> str | None:
    """Return the YAML between the opening "---" line and the first line that
    is exactly "---". The sequence also occurs inside briefs (Atomic Red Team
    anchors such as "#atomic-test-3---esentutl", titles), so ending at the
    first "---" anywhere dropped tags, vendors, products or even the type."""
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 3)
    if end == -1:
        if not text.endswith("\n---"):
            return None
        end = len(text) - 4
    return text[4:end]


def parse(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    raw = frontmatter(text)
    if raw is None:
        return None
    try:
        fm = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        return None

    severities = fm.get("severities") or []
    severity = severities[0] if severities else fm.get("severity", "medium")

    return {
        "slug": fm.get("slug", ""),
        "title": fm.get("title", ""),
        "description": fm.get("description", "") or fm.get("summary", ""),
        "url": f"{SITE}/briefs/{fm.get('slug', '')}/",
        "type": fm.get("type", "coverage"),
        "severity": severity,
        "actors": list(fm.get("actors", []) or []),
        "vendors": list(fm.get("vendors", []) or []),
        "products": list(fm.get("products", []) or []),
        "tags": list(fm.get("tags", []) or []),
        "exploited": bool(fm.get("exploited", False)),
        "has_poc": bool(fm.get("has_poc", False)),
    }


def main() -> int:
    briefs: list[dict] = []
    for line in sys.stdin:
        path = line.strip()
        if not path or not path.endswith(".md"):
            continue
        b = parse(path)
        if b and b.get("slug"):
            briefs.append(b)
    json.dump({"briefs": briefs}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
