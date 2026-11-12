import test from 'node:test';
import assert from 'node:assert/strict';
import { vendorsFromInput } from './vendor-filter.js';

test('prefilled query vendor with a comma remains one request filter value', () => {
  const requestedVendor = new URLSearchParams('?vendor=Amazon%20Web%20Services%2C%20Inc.').get('vendor');
  const body = { filter: { vendors: vendorsFromInput(requestedVendor, [requestedVendor]) } };

  assert.deepEqual(body.filter.vendors, ['Amazon Web Services, Inc.']);
});

test('datalist titles with commas stay intact across multiple vendor selections', () => {
  const knownVendors = ['Amazon Web Services, Inc.', 'Anthropic, PBC'];
  const body = {
    filter: {
      vendors: vendorsFromInput('Amazon Web Services, Inc., Anthropic, PBC', knownVendors),
    },
  };

  assert.deepEqual(body.filter.vendors, knownVendors);
});

test('ordinary comma-separated vendor input still supports freeform multiple values', () => {
  assert.deepEqual(vendorsFromInput('Synology, Fortinet', ['Synology', 'Fortinet']), ['Synology', 'Fortinet']);
});
