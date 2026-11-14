import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('feedcheck_install', Path(__file__).with_name('install-feedcheck.py'))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class FeedcheckInstallContracts(unittest.TestCase):
    def manifest(self, payload):
        source = '49d06e1f8c413fc762d755f190e2787081ca351e'
        return {'schema_version': 1, 'source_repository': 'CraftedSignal/ti-bot', 'source_sha': source,
                'platform': 'linux/amd64', 'url': 'https://github.com/CraftedSignal/threat-feed/releases/download/feedcheck-' + source + '/feedcheck-linux-amd64',
                'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)}

    def test_installs_only_exact_pinned_bytes_without_private_checkout(self):
        payload = b'public checker bytes'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'feedcheck'
            installer.install(self.manifest(payload), output, lambda _: io.BytesIO(payload))
            self.assertEqual(output.read_bytes(), payload)
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)

    def test_wrong_digest_or_size_never_replaces_existing_checker(self):
        payload = b'public checker bytes'
        for bad in [b'wrong content', payload + b'x', payload[:-1]]:
            with self.subTest(payload=bad), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'feedcheck'
                output.write_bytes(b'known checker')
                with self.assertRaises(ValueError):
                    installer.install(self.manifest(payload), output, lambda _: io.BytesIO(bad))
                self.assertEqual(output.read_bytes(), b'known checker')
                self.assertEqual([p.name for p in output.parent.iterdir()], ['feedcheck'])

    def test_rejects_mutable_foreign_or_malformed_artifact_pins_before_download(self):
        for field, value in [('source_sha', 'main'), ('platform', 'darwin/arm64'),
                             ('url', 'https://github.com/CraftedSignal/threat-feed/releases/latest/download/feedcheck-linux-amd64'),
                             ('url', 'http://example.test/checker'), ('sha256', 'bad'),
                             ('size_bytes', 100_000_000), ('source_repository', 'other/repo')]:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                manifest = self.manifest(b'checker')
                manifest[field] = value
                def forbidden(_):
                    self.fail('invalid pin attempted network download')
                with self.assertRaises(ValueError):
                    installer.install(manifest, Path(directory) / 'feedcheck', forbidden)

    def test_rejects_plain_http_redirect(self):
        with self.assertRaises(ValueError):
            installer.HTTPSOnlyRedirect().redirect_request(None, None, 302, 'redirect', {}, 'http://example.test/checker')
