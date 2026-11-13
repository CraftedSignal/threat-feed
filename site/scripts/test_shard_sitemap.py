import unittest
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

from scripts.shard_sitemap import SITEMAP_NS, build_shards, shard_sitemap


def source_sitemap(count):
    urls = "".join(
        f'<url><loc>https://feed.craftedsignal.io/briefs/{index}/</loc>'
        f'<lastmod>2026-11-{(index % 28) + 1:02d}T00:00:00Z</lastmod>'
        f'<xhtml:link rel="alternate" hreflang="en" href="https://feed.craftedsignal.io/briefs/{index}/" />'
        f'</url>'
        for index in range(count)
    )
    return (
        f'<urlset xmlns="{SITEMAP_NS}" xmlns:xhtml="http://www.w3.org/1999/xhtml">'
        f'{urls}</urlset>'
    ).encode()


class SitemapShardTests(unittest.TestCase):
    def test_chunks_by_url_count_without_dropping_metadata_or_urls(self):
        shards = build_shards(source_sitemap(5), max_urls=2, max_bytes=10_000)

        self.assertEqual([shard.url_count for shard in shards], [2, 2, 1])
        locations = []
        for shard in shards:
            root = ET.fromstring(shard.data)
            urls = root.findall(f'{{{SITEMAP_NS}}}url')
            locations.extend(url.findtext(f'{{{SITEMAP_NS}}}loc') for url in urls)
            self.assertTrue(urls[0].findtext(f'{{{SITEMAP_NS}}}lastmod'))
            self.assertEqual(len(urls[0].findall('{http://www.w3.org/1999/xhtml}link')), 1)
        self.assertEqual(len(locations), 5)
        self.assertEqual(len(set(locations)), 5)

    def test_chunks_by_uncompressed_bytes(self):
        shards = build_shards(source_sitemap(3), max_urls=10, max_bytes=500)

        self.assertGreater(len(shards), 1)
        self.assertTrue(all(len(shard.data) <= 500 for shard in shards))
        self.assertEqual(sum(shard.url_count for shard in shards), 3)

    def test_rejects_a_single_url_that_cannot_fit_without_dropping_it(self):
        with self.assertRaisesRegex(ValueError, 'single sitemap URL exceeds'):
            build_shards(source_sitemap(1), max_urls=10, max_bytes=200)

    def test_replaces_source_with_index_and_removes_stale_shards(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory)
            (public / 'sitemap.xml').write_bytes(source_sitemap(5))
            (public / 'sitemap-9999.xml').write_text('stale', encoding='utf-8')

            shard_sitemap(public, max_urls=2, max_bytes=10_000)

            index = ET.fromstring((public / 'sitemap.xml').read_bytes())
            locations = [node.text for node in index.findall(f'{{{SITEMAP_NS}}}sitemap/{{{SITEMAP_NS}}}loc')]
            self.assertEqual(len(locations), 3)
            self.assertFalse((public / 'sitemap-9999.xml').exists())
            self.assertTrue((public / 'sitemap-0001.xml').exists())


if __name__ == '__main__':
    unittest.main()
