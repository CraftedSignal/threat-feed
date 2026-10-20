import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const destination = mkdtempSync(join(tmpdir(), 'threat-feed-detail-contract-'));
const build = spawnSync('hugo', [
  '--buildDrafts',
  '--contentDir', 'testdata/content',
  '--destination', destination,
], { cwd: new URL('..', import.meta.url), encoding: 'utf8' });
try {
  if (build.status !== 0) {
    process.stderr.write(build.stdout);
    process.stderr.write(build.stderr);
    process.exitCode = build.status || 1;
  } else {
    for (const slug of ['generic-fixture', 'advisory-fixture', 'threat-fixture', 'rumour-fixture', 'coverage-fixture']) {
      const html = readFileSync(join(destination, 'briefs', slug, 'index.html'), 'utf8');
      assert.match(html, /data-brief-triage/, `${slug}: missing triage block`);
      for (const label of ['Applicability', 'Evidence', 'Severity', 'Action', 'Sources', 'Freshness', 'Detection']) {
        assert.match(html, new RegExp(`>${label}<`), `${slug}: missing ${label}`);
      }
      assert.match(html, /data-revision-history/, `${slug}: missing revision history`);
      assert.match(html, /Revision 2/, `${slug}: missing current revision metadata`);
      assert.match(html, /Confirmed active exploitation\./, `${slug}: missing revision summary`);
    }
    console.log('detail contract: 5/5 single-page kinds passed');
  }
} finally {
  rmSync(destination, { recursive: true, force: true });
}
