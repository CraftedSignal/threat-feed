import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

test('production CSS keeps the site theme, dynamic severity, and typography contracts', async () => {
  const cssDirectory = join(import.meta.dirname, '..', 'public', 'css');
  const compiledFiles = (await readdir(cssDirectory)).filter((name) =>
    /^main\.min\.[a-f0-9]+\.css$/.test(name),
  );

  assert.equal(compiledFiles.length, 1, 'expected one fingerprinted main stylesheet');
  const css = await readFile(join(cssDirectory, compiledFiles[0]), 'utf8');

  for (const requiredOutput of [
    '--color-accent',
    '.bg-base',
    '.text-text',
    '.brief-sidebar-toggle',
    '.bg-sev-critical',
    String.raw`.group-hover\:text-sev-critical`,
    '.type-threat',
    '.prose',
  ]) {
    assert.ok(css.includes(requiredOutput), `compiled CSS is missing ${requiredOutput}`);
  }

  assert.doesNotMatch(css, /@(?:tailwind|apply)\b/, 'Tailwind directives must be compiled');
});
