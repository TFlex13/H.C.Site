import test from 'node:test';
import assert from 'node:assert/strict';
import type { Pool } from 'pg';
import { createApp } from './app.js';
import { newToken, tokenHash } from './security.js';

test('health and database-unavailable routes work without a listener', async (t) => {
  const app = await createApp(null);
  t.after(() => app.close());
  const dashboard = await app.inject({ method: 'GET', url: '/admin/dashboard' });
  assert.equal(dashboard.statusCode, 200);
  assert.match(dashboard.headers['content-type'] ?? '', /text\/html/);
  assert.match(dashboard.headers['content-security-policy'] ?? '', /frame-ancestors 'none'/);
  assert.equal(dashboard.headers['cache-control'], 'no-store');
  assert.match(dashboard.body, /Financial overview/);
  assert.doesNotMatch(dashboard.body, /localStorage|sessionStorage/);
  const health = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(health.statusCode, 200);
  assert.deepEqual(health.json(), { status: 'ok', service: 'highline-api' });
  assert.equal((await app.inject({ method: 'GET', url: '/health/db' })).statusCode, 503);
  assert.equal((await app.inject({ method: 'POST', url: '/auth/login', payload: { email: 'test@example.com', password: 'example' } })).statusCode, 503);
});

test('missing or malformed bearer tokens cannot access protected routes', async (t) => {
  const app = await createApp(null);
  t.after(() => app.close());
  assert.equal((await app.inject({ method: 'GET', url: '/auth/me' })).statusCode, 401);
  assert.equal((await app.inject({ method: 'POST', url: '/auth/logout', payload: {} })).statusCode, 401);
  assert.equal((await app.inject({ method: 'POST', url: '/admin/invitations', payload: { email: 'valid@example.com' } })).statusCode, 403);
  assert.equal((await app.inject({ method: 'POST', url: '/admin/invitations', headers: { authorization: 'Bearer invalid' }, payload: { email: 'valid@example.com' } })).statusCode, 403);
});

test('representatives are forbidden and administrators reach invitation validation', async (t) => {
  const adminToken = newToken();
  const representativeToken = newToken();
  const identities = new Map([
    [tokenHash(adminToken), { id: 'admin-id', email: 'admin@example.com', display_name: 'Admin', role: 'admin' }],
    [tokenHash(representativeToken), { id: 'rep-id', email: 'rep@example.com', display_name: 'Rep', role: 'representative' }]
  ]);
  const fakePool = {
    query: async (sql: string, params?: unknown[]) => {
      if (!sql.includes('FROM sessions s JOIN users u')) throw new Error('Unexpected database query');
      const actor = identities.get(String(params?.[0]));
      return { rows: actor ? [actor] : [], rowCount: actor ? 1 : 0 };
    }
  } as unknown as Pool;
  const app = await createApp(fakePool);
  t.after(() => app.close());
  const request = (token: string) => app.inject({
    method: 'POST',
    url: '/admin/invitations',
    headers: { authorization: 'Bearer ' + token },
    payload: { email: 'not-an-email' }
  });
  assert.equal((await request(representativeToken)).statusCode, 403);
  assert.equal((await request(adminToken)).statusCode, 400);
  assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: 'Bearer ' + adminToken } })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: 'Bearer ' + newToken() } })).statusCode, 401);
});
