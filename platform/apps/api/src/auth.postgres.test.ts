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
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL UNIQUE, display_name text NOT NULL,
        role text NOT NULL, password_hash text NOT NULL, active boolean NOT NULL DEFAULT true
      );
      CREATE TABLE "${schema}".sessions (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES "${schema}".users(id),
        token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL
      );
      CREATE TABLE "${schema}".invitations (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text NOT NULL,
        token_hash text NOT NULL UNIQUE, invited_by uuid NOT NULL REFERENCES "${schema}".users(id),
        expires_at timestamptz NOT NULL, accepted_at timestamptz
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
    // Invitation creation and acceptance use the actual database transaction.
    // The second session was expired above, so create a fresh admin session.
    const freshAdmin = await login('admin@test.invalid', password);
    assert.equal(freshAdmin.statusCode, 200);
    const adminHeaders = { authorization: 'Bearer ' + (freshAdmin.json() as { token: string }).token };
    const invite = (email: string) => app.inject({
      method: 'POST', url: '/admin/invitations', headers: adminHeaders, payload: { email }
    });
    const invitation = await invite(' NEW@TEST.INVALID ');
    assert.equal(invitation.statusCode, 201);
    const invitationBody = invitation.json() as { email: string; invitationToken: string; delivery: string };
    assert.equal(invitationBody.email, 'new@test.invalid');
    assert.equal(invitationBody.delivery, 'manual-local-development');
    assert.equal((await pool.query('SELECT 1 FROM invitations WHERE token_hash=$1', [tokenHash(invitationBody.invitationToken)])).rowCount, 1);
    const accept = (token: string, displayName = 'New Representative') => app.inject({
      method: 'POST', url: '/auth/accept-invitation',
      payload: { token, displayName, password: 'New-Representative-Password-2026' }
    });
    assert.equal((await accept(invitationBody.invitationToken)).statusCode, 201);
    assert.equal((await accept(invitationBody.invitationToken)).statusCode, 400, 'accepted token must not be reusable');
    const newUser = await pool.query('SELECT role,display_name FROM users WHERE email=$1', ['new@test.invalid']);
    assert.equal(newUser.rowCount, 1);
    assert.equal(newUser.rows[0].role, 'representative');
    assert.equal(newUser.rows[0].display_name, 'New Representative');
    assert.equal((await invite('new@test.invalid')).statusCode, 409);
    assert.equal((await accept('a'.repeat(43))).statusCode, 400, 'unknown token must be rejected');
    const expired = await invite('expired@test.invalid');
    assert.equal(expired.statusCode, 201);
    const expiredInvitationToken = (expired.json() as { invitationToken: string }).invitationToken;
    await pool.query("UPDATE invitations SET expires_at=now()-interval '1 minute' WHERE token_hash=$1", [tokenHash(expiredToken)]);
    assert.equal((await accept(expiredToken)).statusCode, 400, 'expired token must be rejected');
    assert.equal((await pool.query('SELECT 1 FROM users WHERE email=$1', ['expired@test.invalid'])).rowCount, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM auth_audit_events WHERE action=$1', ['invitation_accepted'])).rows[0].count, 1);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM auth_audit_events WHERE action=$1', ['invitation_created'])).rows[0].count, 2);

  } finally {
    await scoped?.end();
    await admin.query('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE').catch(() => {});
    await admin.end();
  }
});
