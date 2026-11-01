/** Unknown v1.1 event types and stages must render as text, not crash. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { styleOf } from '../src/lib/eventStyle.ts';

test('unknown event types get a neutral style', () => {
  assert.equal(styleOf('future_unrecognised_event').tone, 'muted');
  assert.equal(styleOf('bait_served').tone, 'warn');
  assert.equal(styleOf('auth_success').tone, 'danger');
});
