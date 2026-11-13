#!/usr/bin/env python3
"""Split Hugo's canonical sitemap into protocol-bounded URL shards."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
from typing import Optional
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

SITEMAP_NS = "http://www.sitemaps.org/schemas/sitemap/0.9"
XHTML_NS = "http://www.w3.org/1999/xhtml"
MAX_URLS = 50_000
MAX_BYTES = 50 * 1024 * 1024
XML_DECLARATION = b'<?xml version="1.0" encoding="UTF-8"?>\n'
URLSET_OPEN = f'<urlset xmlns="{SITEMAP_NS}" xmlns:xhtml="{XHTML_NS}">\n'.encode()
URLSET_CLOSE = b"</urlset>\n"
SITEMAP_INDEX_OPEN = f'<sitemapindex xmlns="{SITEMAP_NS}">\n'.encode()
SITEMAP_INDEX_CLOSE = b"</sitemapindex>\n"
SITEMAP_TAG = f"{{{SITEMAP_NS}}}"
SHARD_NAME = re.compile(r"^sitemap-\d+\.xml$")

ET.register_namespace("", SITEMAP_NS)
ET.register_namespace("xhtml", XHTML_NS)


@dataclass(frozen=True)
class Shard:
    filename: str
    data: bytes
    url_count: int
    latest_lastmod: Optional[str]


def build_shards(source: bytes, max_urls: int = MAX_URLS, max_bytes: int = MAX_BYTES) -> list[Shard]:
    if max_urls < 1 or max_bytes <= len(XML_DECLARATION) + len(URLSET_OPEN) + len(URLSET_CLOSE):
        raise ValueError("sitemap shard limits are too small")

    root = ET.fromstring(source)
    if root.tag != SITEMAP_TAG + "urlset":
        raise ValueError("Hugo sitemap source must be a sitemap urlset")

    urls = root.findall(SITEMAP_TAG + "url")
    chunks: list[tuple[list[bytes], list[str]]] = []
    current_urls: list[bytes] = []
    current_lastmods: list[str] = []
    current_size = len(XML_DECLARATION) + len(URLSET_OPEN) + len(URLSET_CLOSE)

    for url in urls:
        fragment = ET.tostring(url, encoding="utf-8", short_empty_elements=True)
        addition_size = len(fragment) + 1
        if current_urls and (len(current_urls) >= max_urls or current_size + addition_size > max_bytes):
            chunks.append((current_urls, current_lastmods))
            current_urls = []
            current_lastmods = []
            current_size = len(XML_DECLARATION) + len(URLSET_OPEN) + len(URLSET_CLOSE)
        if current_size + addition_size > max_bytes:
            raise ValueError("single sitemap URL exceeds the configured uncompressed byte limit")
        current_urls.append(fragment)
        lastmod = url.findtext(SITEMAP_TAG + "lastmod")
        if lastmod:
            current_lastmods.append(lastmod.strip())
        current_size += addition_size

    if current_urls:
        chunks.append((current_urls, current_lastmods))

    shards = []
    for index, (fragments, lastmods) in enumerate(chunks, start=1):
        data = XML_DECLARATION + URLSET_OPEN + b"\n".join(fragments) + b"\n" + URLSET_CLOSE
        if len(fragments) > max_urls or len(data) > max_bytes:
            raise AssertionError("sitemap shard exceeds configured limits")
        shards.append(Shard(f"sitemap-{index:04d}.xml", data, len(fragments), max(lastmods) if lastmods else None))
    return shards


def site_origin(source: bytes) -> str:
    root = ET.fromstring(source)
    first = root.find(SITEMAP_TAG + "url/" + SITEMAP_TAG + "loc")
    if first is None or not first.text:
        raise ValueError("Hugo sitemap source must contain at least one canonical URL")
    parsed = urlsplit(first.text.strip())
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Hugo sitemap contains an invalid canonical URL")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for loc in root.findall(SITEMAP_TAG + "url/" + SITEMAP_TAG + "loc"):
        candidate = urlsplit((loc.text or "").strip())
        if candidate.scheme != "https" or f"{candidate.scheme}://{candidate.netloc}" != origin or candidate.query or candidate.fragment:
            raise ValueError("Hugo sitemap contains a URL outside its canonical origin")
    return origin


def build_index(shards: list[Shard], origin: str, max_bytes: int = MAX_BYTES) -> bytes:
    root = ET.Element(SITEMAP_TAG + "sitemapindex")
    for shard in shards:
        entry = ET.SubElement(root, SITEMAP_TAG + "sitemap")
        ET.SubElement(entry, SITEMAP_TAG + "loc").text = f"{origin}/{shard.filename}"
        if shard.latest_lastmod:
            ET.SubElement(entry, SITEMAP_TAG + "lastmod").text = shard.latest_lastmod
    data = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if len(shards) > MAX_URLS or len(data) > max_bytes:
        raise ValueError("sitemap index exceeds the protocol limit")
    return data


def shard_sitemap(public_dir: Path, max_urls: int = MAX_URLS, max_bytes: int = MAX_BYTES) -> None:
    public_dir = public_dir.resolve()
    source_path = public_dir / "sitemap.xml"
    source = source_path.read_bytes()
    index_path = public_dir / "sitemap.xml"
    shards = build_shards(source, max_urls=max_urls, max_bytes=max_bytes)
    origin = site_origin(source)
    index = build_index(shards, origin, max_bytes=max_bytes)

    with tempfile.TemporaryDirectory(prefix="sitemap-", dir=public_dir) as temporary:
        staging = Path(temporary)
        for shard in shards:
            (staging / shard.filename).write_bytes(shard.data)
        (staging / "sitemap.xml").write_bytes(index)

        for shard in shards:
            os.replace(staging / shard.filename, public_dir / shard.filename)
        os.replace(staging / "sitemap.xml", index_path)

    for old_shard in public_dir.glob("sitemap-*.xml"):
        if SHARD_NAME.fullmatch(old_shard.name) and old_shard.name not in {s.filename for s in shards}:
            old_shard.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_dir", type=Path, nargs="?", default=Path("public"))
    args = parser.parse_args()
    try:
        shard_sitemap(args.public_dir)
    except (OSError, ET.ParseError, ValueError) as error:
        parser.error(str(error))
    print(f"sitemap sharding: wrote bounded sitemap index and URL shards under {args.public_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
