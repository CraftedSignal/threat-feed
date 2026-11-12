#!/usr/bin/env python3
"""Check taxonomy and vendor-subscription links in generated detail pages."""
from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

DETAIL_SECTIONS = ("briefs", "coverage", "advisory", "rumours", "threats")


class Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.hrefs.append(href)


def check(root: Path) -> list[str]:
    errors: list[str] = []
    pages = [p for section in DETAIL_SECTIONS for p in (root / section).rglob("*.html")]
    if not pages:
        return [f"no generated detail pages found under {root}"]
    taxonomy_links = 0
    for page in pages:
        parser = Links()
        parser.feed(page.read_text(encoding="utf-8"))
        for href in parser.hrefs:
            parsed = urlsplit(href)
            path = unquote(parsed.path)
            if not parsed.netloc and path.startswith(("/vendors/", "/products/")):
                taxonomy_links += 1
                target = root / path.lstrip("/") / "index.html"
                if not target.is_file():
                    errors.append(f"{page}: taxonomy link has no generated target: {href}")
            if not parsed.netloc and path == "/subscribe/" and parsed.query:
                target = root / "subscribe" / "index.html"
                if not target.is_file():
                    errors.append(f"{page}: vendor subscription link target is missing")
    if taxonomy_links == 0:
        errors.append("no taxonomy links found in generated detail pages")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "site/public")
    errors = check(root)
    if errors:
        print("taxonomy link contract failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"taxonomy link contract: validated generated detail pages under {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
