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


def parse(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.startswith("---"):
        return None
    end = text.find("---", 4)
    if end == -1:
        return None
    try:
        fm = yaml.safe_load(text[4:end]) or {}
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
