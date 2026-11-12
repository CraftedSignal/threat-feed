import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent

def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module

payload = load("payload", HERE / "build-dispatch-payload.py")
link_contract = load("taxonomy_links", HERE / "check_taxonomy_links.py")


class VendorSubscriptionContracts(unittest.TestCase):
    def test_dispatch_emits_poc_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            brief = Path(directory) / "brief.md"
            brief.write_text('---\nslug: test-brief\ntitle: Test\nhas_poc: true\n---\n', encoding="utf-8")
            self.assertTrue(payload.parse(str(brief))["has_poc"])
            brief.write_text('---\nslug: test-brief\ntitle: Test\n---\n', encoding="utf-8")
            self.assertFalse(payload.parse(str(brief))["has_poc"])

    def test_contract_rejects_dead_taxonomy_but_ignores_external_products_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            page = root / "briefs" / "story" / "index.html"
            page.parent.mkdir(parents=True)
            page.write_text('<a href="/vendors/missing/">Missing</a><a href="https://example.test/products/a">Source</a>', encoding="utf-8")
            self.assertTrue(any("/vendors/missing/" in error for error in link_contract.check(root)))
            target = root / "vendors" / "missing" / "index.html"
            target.parent.mkdir(parents=True)
            target.write_text("ok", encoding="utf-8")
            self.assertFalse(link_contract.check(root))


if __name__ == "__main__":
    unittest.main()
