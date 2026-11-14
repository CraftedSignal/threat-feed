#!/usr/bin/env python3
"""Install only the public, committed-digest feed validator; no private source/auth."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.parse
import urllib.request


class HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).scheme != 'https':
            raise ValueError('checker download must remain HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url):
    return urllib.request.build_opener(HTTPSOnlyRedirect()).open(url, timeout=60)


def install(manifest, output, opener=download):
    source = manifest.get('source_sha', '')
    digest = manifest.get('sha256', '')
    size = manifest.get('size_bytes', 0)
    url = ('https://github.com/CraftedSignal/threat-feed/releases/download/feedcheck-'
           + source + '/feedcheck-linux-amd64')
    if (manifest.get('schema_version') != 1 or manifest.get('source_repository') != 'CraftedSignal/ti-bot'
            or not re.fullmatch(r'[0-9a-f]{40}', source) or manifest.get('platform') != 'linux/amd64'
            or manifest.get('url') != url or not re.fullmatch(r'[0-9a-f]{64}', digest)
            or type(size) is not int or not 0 < size <= 32 * 1024 * 1024):
        raise ValueError('invalid immutable public checker pin')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        hasher, count = hashlib.sha256(), 0
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix='.feedcheck-', delete=False) as target:
            temporary = Path(target.name)
            with opener(url) as response:
                while True:
                    block = response.read(64 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > size:
                        raise ValueError('checker download exceeds pinned size')
                    hasher.update(block)
                    target.write(block)
        if count != size or hasher.hexdigest() != digest:
            raise ValueError('checker bytes do not match committed digest/size')
        temporary.chmod(0o755)
        os.replace(temporary, output)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', default='.github/tooling/feedcheck.json')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    installed = install(json.loads(Path(args.manifest).read_text()), Path(args.output))
    print('Installed verified public validator:', installed)


if __name__ == '__main__':
    main()
