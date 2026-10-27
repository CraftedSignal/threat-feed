import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { stageCurrentSTIXReleases } from '../scripts/stage-current-stix-releases.mjs';

const rollingName = `sha256-${'a'.repeat(64)}.json`;
const monthName = `2026-10-sha256-${'b'.repeat(64)}.json`;
const staleName = `sha256-${'c'.repeat(64)}.json`;

async function fixture(t, index) {
  const publicRoot = await mkdtemp(join(tmpdir(), 'stage-stix-'));
  t.after(() => rm(publicRoot, { recursive: true, force: true }));
  const releases = join(publicRoot, 'stix', 'releases');
  await mkdir(releases, { recursive: true });
  await writeFile(join(publicRoot, 'stix', 'index.json'), JSON.stringify(index));
  for (const name of [rollingName, monthName, staleName]) {
    await writeFile(join(releases, name), name);
  }
  return { publicRoot, releases };
}

test('stages only immutable STIX releases referenced by the current index', async (t) => {
  const { publicRoot, releases } = await fixture(t, {
    rolling: { path: `/stix/releases/${rollingName}` },
    months: [{ path: `/stix/releases/${monthName}` }],
  });

  const result = await stageCurrentSTIXReleases(publicRoot);

  assert.deepEqual((await readdir(releases)).sort(), [monthName, rollingName].sort());
  assert.deepEqual(result, { retained: 2, removed: 1 });
});

test('fails before pruning when a referenced release is absent', async (t) => {
  const missingName = `2026-09-sha256-${'d'.repeat(64)}.json`;
  const { publicRoot, releases } = await fixture(t, {
    rolling: { path: `/stix/releases/${rollingName}` },
    months: [{ path: `/stix/releases/${missingName}` }],
  });

  await assert.rejects(
    stageCurrentSTIXReleases(publicRoot),
    /referenced STIX release is absent/,
  );
  assert.deepEqual(
    (await readdir(releases)).sort(),
    [monthName, rollingName, staleName].sort(),
  );
});
