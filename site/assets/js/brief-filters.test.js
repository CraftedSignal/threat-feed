import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalBriefURL,
  filterBriefs,
  paginateBriefs,
  parseBriefQuery,
  serializeBriefQuery,
} from './brief-filters.js';

const generatedAt = '2026-10-20T12:00:00.000Z';

function brief(overrides = {}) {
  return {
    url: '/briefs/example/',
    title: 'Example',
    activity_at: '2026-10-20T11:00:00.000Z',
    severity: 'high',
    type: 'threat',
    flags: { exploited: false, poc: false, ioc: false },
    ...overrides,
  };
}

test('brief filters parse and serialize canonical query state', () => {
  const state = parseBriefQuery('?page=3&flags=ioc,poc&severity=high,critical&type=rumour,threat&window=24h');
  assert.deepEqual(state, {
    window: '24h',
    severities: ['critical', 'high'],
    types: ['threat', 'rumour'],
    flags: ['poc', 'ioc'],
    page: 3,
  });
  assert.equal(
    serializeBriefQuery(state),
    'window=24h&severity=critical%2Chigh&type=threat%2Crumour&flags=poc%2Cioc&page=3',
  );
});

test('brief filters ignore unknown keys and values', () => {
  assert.deepEqual(parseBriefQuery('?window=today&severity=urgent,high&type=malware&flags=kev&page=-2&wat=no'), {
    window: null,
    severities: ['high'],
    types: [],
    flags: [],
    page: 1,
  });
  assert.equal(serializeBriefQuery(parseBriefQuery('?wat=no')), '');
});

test('brief filters use one inclusive 24 hour cutoff from index build time', () => {
  const items = [
    brief({ url: '/new/', activity_at: '2026-10-20T11:59:59.999Z' }),
    brief({ url: '/boundary/', activity_at: '2026-10-19T12:00:00.000Z' }),
    brief({ url: '/old/', activity_at: '2026-10-19T11:59:59.999Z' }),
  ];
  assert.deepEqual(
    filterBriefs(items, parseBriefQuery('?window=24h'), generatedAt).map((item) => item.url),
    ['/new/', '/boundary/'],
  );
});

test('brief filters combine categories and OR values within a category', () => {
  const items = [
    brief({ url: '/match/', severity: 'critical', type: 'threat', flags: { exploited: true, poc: false, ioc: true } }),
    brief({ url: '/wrong-type/', severity: 'high', type: 'advisory', flags: { exploited: true, poc: false, ioc: false } }),
    brief({ url: '/wrong-flag/', severity: 'high', type: 'rumour', flags: { exploited: false, poc: false, ioc: false } }),
  ];
  const state = parseBriefQuery('?severity=critical,high&type=threat,rumour&flags=exploited');
  assert.deepEqual(filterBriefs(items, state, generatedAt).map((item) => item.url), ['/match/']);
});

test('brief filters sort stably before paginating the full result set', () => {
  const items = Array.from({ length: 65 }, (_, index) => brief({
    url: `/briefs/${String(index).padStart(2, '0')}/`,
    activity_at: `2026-10-20T${String(Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}:00.000Z`,
  }));
  const filtered = filterBriefs(items, parseBriefQuery('?window=24h'), generatedAt);
  const page = paginateBriefs(filtered, 3, 30);
  assert.equal(filtered.length, 65);
  assert.equal(page.totalItems, 65);
  assert.equal(page.totalPages, 3);
  assert.equal(page.page, 3);
  assert.equal(page.items.length, 5);
});

test('brief filters handle empty and out-of-range pages', () => {
  assert.deepEqual(paginateBriefs([], 9, 30), {
    items: [], page: 1, pageSize: 30, totalItems: 0, totalPages: 0, hasPrev: false, hasNext: false,
  });
  const result = paginateBriefs([brief(), brief({ url: '/two/' })], 99, 1);
  assert.equal(result.page, 2);
  assert.equal(result.items[0].url, '/two/');
});

test('brief filters preserve the canonical query in pagination URLs', () => {
  const state = parseBriefQuery('?flags=ioc&window=24h&page=2&unknown=x');
  assert.equal(canonicalBriefURL('/briefs/', state, 3), '/briefs/?window=24h&flags=ioc&page=3');
  assert.equal(canonicalBriefURL('/briefs/', state, 1), '/briefs/?window=24h&flags=ioc');
});
