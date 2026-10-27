import { lstat, readFile, readdir, unlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const releaseName = /^(?:\d{4}-(?:0[1-9]|1[0-2])-)?sha256-[0-9a-f]{64}\.json$/;

function manifestReleaseName(path) {
  if (typeof path !== 'string' || !path.startsWith('/stix/releases/')) {
    throw new Error(`invalid STIX release path: ${String(path)}`);
  }
  const name = path.slice('/stix/releases/'.length);
  if (!releaseName.test(name)) {
    throw new Error(`invalid STIX release filename: ${name}`);
  }
  return name;
}

export async function stageCurrentSTIXReleases(publicRoot) {
  const root = resolve(publicRoot);
  const releasesRoot = join(root, 'stix', 'releases');
  const indexPath = join(root, 'stix', 'index.json');
  const index = JSON.parse(await readFile(indexPath, 'utf8'));
  const referenced = new Set([
    manifestReleaseName(index.rolling?.path),
    ...(index.months ?? []).map((entry) => manifestReleaseName(entry?.path)),
  ]);

  for (const name of referenced) {
    let info;
    try {
      info = await lstat(join(releasesRoot, name));
    } catch (error) {
      if (error?.code === 'ENOENT') {
        throw new Error(`referenced STIX release is absent: ${name}`);
      }
      throw error;
    }
    if (!info.isFile()) {
      throw new Error(`referenced STIX release is not a regular file: ${name}`);
    }
  }

  const entries = await readdir(releasesRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !releaseName.test(entry.name)) {
      throw new Error(`unexpected entry in generated STIX releases: ${entry.name}`);
    }
  }

  const stale = entries.filter((entry) => !referenced.has(entry.name));
  await Promise.all(stale.map((entry) => unlink(join(releasesRoot, entry.name))));
  return { retained: referenced.size, removed: stale.length };
}

async function main() {
  const publicRoot = process.argv[2] ?? process.env.SITE_OUTPUT ?? 'public';
  const result = await stageCurrentSTIXReleases(publicRoot);
  console.log(`Staged ${result.retained} current STIX releases; removed ${result.removed} superseded generated copies.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
