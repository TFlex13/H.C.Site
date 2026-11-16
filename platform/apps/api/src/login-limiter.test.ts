import test from 'node:test';
import assert from 'node:assert/strict';
import { LoginAttemptLimiter } from './login-limiter.js';

test('five failures block the account and return a retry window', () => {
  const limiter = new LoginAttemptLimiter(5, 60_000);
  for (let i = 0; i < 5; i++) {
    assert.equal(limiter.blocked(['account:a'], 1000), false);
    limiter.failed(['account:a'], 1000);
  }
  assert.equal(limiter.blocked(['account:a'], 1000), true);
  assert.equal(limiter.retryAfterSeconds(['account:a'], 1000), 60);
  assert.equal(limiter.blocked(['account:a'], 61_000), false);
});

test('account and IP limits independently stop repeated guesses', () => {
  const limiter = new LoginAttemptLimiter(2, 60_000);
  limiter.failed(['account:a', 'ip:x'], 1000);
  limiter.failed(['account:b', 'ip:x'], 1000);
  assert.equal(limiter.blocked(['account:c', 'ip:x'], 1000), true);
  assert.equal(limiter.blocked(['account:a', 'ip:y'], 1000), false);
});

test('successful login clears account failures without resetting IP failures', () => {
  const limiter = new LoginAttemptLimiter(2, 60_000);
  limiter.failed(['account:a', 'ip:x'], 1000);
  limiter.clear('account:a');
  assert.equal(limiter.blocked(['account:a'], 1000), false);
  assert.equal(limiter.blocked(['ip:x'], 1000), false);
  limiter.failed(['account:b', 'ip:x'], 1000);
  assert.equal(limiter.blocked(['ip:x'], 1000), true);
});

test('window expiration and bounded storage do not permanently block new keys', () => {
  const limiter = new LoginAttemptLimiter(1, 1000, 2);
  limiter.failed(['account:a'], 100);
  limiter.failed(['account:b'], 100);
  limiter.failed(['account:c'], 200);
  assert.equal(limiter.blocked(['account:c'], 200), true);
  assert.equal(limiter.blocked(['account:c'], 1200), false);
});
