import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { createApp } from './app.js';
import { hashPassword, tokenHash } from './security.js';

// Explicit opt-in: never connect to the development or production database.
const url = process.env.HIGHLINE_TEST_DATABASE_URL;
test('PostgreSQL-backed authentication lifecycle (dedicated test database only)', { skip: !url ? 'Set HIGHLINE_TEST_DATABASE_URL to run PostgreSQL integration tests' : false }, async (t) => {
  const parsed = new URL(url!);
  if (!/^highline[_-].*test$/.test(parsed.pathname.slice(1))) {
    throw new Error('Refusing integration test: database name must start with highline_ or highline- and end with test');
  }
  if (!['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname)) {
    throw new Error('Refusing integration test: only local PostgreSQL is permitted');
  }
  const schema = 'auth_test_' + randomUUID().replace(/-/g, '');
  const admin = new pg.Pool({ connectionString: url, max: 2 });
  let scoped: pg.Pool | undefined;
  try {
    await admin.query('CREATE SCHEMA "' + schema + '"');
    // Minimal tables required by the live auth routes, isolated per test run.
    await admin.query(`
      CREATE TABLE "${schema}".users (
        id uuid PRIMARY KEY, email text NOT NULL UNIQUE, display_name text NOT NULL,
        role text NOT NULL, password_hash text NOT NULL, active boolean NOT NULL DEFAULT true
      );
      CREATE TABLE "${schema}".sessions (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES "${schema}".users(id),
        token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL
      );
      CREATE TABLE "${schema}".auth_audit_events (
        actor_id uuid NOT NULL, action text NOT NULL, subject_email text NOT NULL
      );
    `);
    scoped = new pg.Pool({ connectionString: url, max: 2, options: '-c search_path=' + schema });
    const pool = scoped;
    const password = 'Local-test-only-password-' + randomUUID();
    const adminId = randomUUID();
    const repId = randomUUID();
    await pool.query('INSERT INTO users(id,email,display_name,role,password_hash) VALUES($1,$2,$3,$4,$5),($6,$7,$8,$9,$10)', [
      adminId, 'admin@test.invalid', 'Test Admin', 'admin', await hashPassword(password),
      repId, 'rep@test.invalid', 'Test Rep', 'representative', await hashPassword(password)
    ]);
    const app = await createApp(pool);
    t.after(() => app.close());
    const login = (email: string, secret: string) => app.inject({ method: 'POST', url: '/auth/login', payload: { email, password: secret } });
    const bad = await login('admin@test.invalid', 'wrong-password');
    assert.equal(bad.statusCode, 401);
    const success = await login('admin@test.invalid', password);
    assert.equal(success.statusCode, 200);
    const { token, expiresInSeconds } = success.json() as { token: string; expiresInSeconds: number };
    assert.equal(expiresInSeconds, 43200);
    assert.equal((await pool.query('SELECT 1 FROM sessions WHERE token_hash=$1', [tokenHash(token)])).rowCount, 1);
    const headers = { authorization: 'Bearer ' + token };
    assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers })).statusCode, 200);
    assert.equal((await app.inject({ method: 'POST', url: '/auth/logout', headers })).statusCode, 200);
    assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers })).statusCode, 401);
    const second = await login('admin@test.invalid', password);
    assert.equal(second.statusCode, 200);
    const expiredToken = (second.json() as { token: string }).token;
    await pool.query("UPDATE sessions SET expires_at=now()-interval '1 minute' WHERE token_hash=$1", [tokenHash(expiredToken)]);
    assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: 'Bearer ' + expiredToken } })).statusCode, 401);
    const rep = await login('rep@test.invalid', password);
    assert.equal(rep.statusCode, 200);
    const repToken = (rep.json() as { token: string }).token;
    assert.equal((await app.inject({
      method: 'POST', url: '/admin/invitations',
      headers: { authorization: 'Bearer ' + repToken }, payload: { email: 'new@test.invalid' }
    })).statusCode, 403);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM auth_audit_events WHERE action=$1', ['login'])).rows[0].count, 3);
  } finally {
    await scoped?.end();
    await admin.query('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE').catch(() => {});
    await admin.end();
  }
});
