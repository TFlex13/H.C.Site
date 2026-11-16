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
      CREATE TABLE "${schema}".representative_profiles (
        user_id uuid PRIMARY KEY REFERENCES "${schema}".users(id) ON DELETE CASCADE,
        phone text, company_name text, notes text,
        created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE "${schema}".territories (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL UNIQUE,
        description text, active boolean NOT NULL DEFAULT true
      );
      CREATE TABLE "${schema}".representative_territories (
        representative_id uuid NOT NULL REFERENCES "${schema}".users(id),
        territory_id uuid NOT NULL REFERENCES "${schema}".territories(id),
        assigned_by uuid REFERENCES "${schema}".users(id),
        assigned_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (representative_id,territory_id)
      );
      CREATE TABLE "${schema}".stores (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name text NOT NULL, address_line1 text NOT NULL,
        address_line2 text, city text NOT NULL, state_region text NOT NULL, postal_code text NOT NULL,
        country_code char(2) NOT NULL DEFAULT 'US', contact_name text, contact_email text,
        contact_phone text, notes text, territory_id uuid REFERENCES "${schema}".territories(id),
        primary_representative_id uuid REFERENCES "${schema}".users(id),
        active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
      );
      CREATE TABLE "${schema}".store_assignment_events (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        store_id uuid NOT NULL REFERENCES "${schema}".stores(id),
        previous_territory_id uuid, new_territory_id uuid,
        previous_representative_id uuid, new_representative_id uuid,
        changed_by uuid, reason text NOT NULL, effective_at timestamptz NOT NULL DEFAULT now(), changed_at timestamptz NOT NULL DEFAULT now()
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
    await pool.query("UPDATE invitations SET expires_at=now()-interval '1 minute' WHERE token_hash=$1", [tokenHash(expiredInvitationToken)]);
    assert.equal((await accept(expiredInvitationToken)).statusCode, 400, 'expired token must be rejected');
    assert.equal((await pool.query('SELECT 1 FROM users WHERE email=$1', ['expired@test.invalid'])).rowCount, 0);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM auth_audit_events WHERE action=$1', ['invitation_accepted'])).rows[0].count, 1);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM auth_audit_events WHERE action=$1', ['invitation_created'])).rows[0].count, 2);

    // Representatives can maintain their own profile, but cannot edit another account.
    const repHeaders = { authorization: 'Bearer ' + repToken };
    assert.equal((await app.inject({ method: 'GET', url: '/representative/profile', headers: adminHeaders })).statusCode, 403);
    const emptyProfile = await app.inject({ method: 'GET', url: '/representative/profile', headers: repHeaders });
    assert.equal(emptyProfile.statusCode, 200);
    assert.equal((emptyProfile.json() as { profile: { phone: string | null } }).profile.phone, null);
    assert.equal((await app.inject({ method: 'PUT', url: '/representative/profile', headers: repHeaders, payload: { phone: ' 555-0100 ', companyName: ' Highline Partner ' } })).statusCode, 200);
    const updatedProfile = await app.inject({ method: 'GET', url: '/representative/profile', headers: repHeaders });
    assert.equal((updatedProfile.json() as { profile: { phone: string; companyName: string } }).profile.phone, '555-0100');
    assert.equal((updatedProfile.json() as { profile: { phone: string; companyName: string } }).profile.companyName, 'Highline Partner');
    // Fastify removes unrecognized fields; the request must still update only the actor's profile.
    const attemptedCrossAccount = await app.inject({ method: 'PUT', url: '/representative/profile', headers: repHeaders, payload: { phone: '555', companyName: null, userId: adminId } });
    assert.equal(attemptedCrossAccount.statusCode, 200);
    assert.equal((attemptedCrossAccount.json() as { profile: { id: string } }).profile.id, repId);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM representative_profiles')).rows[0].count, 1);
    assert.equal((await pool.query('SELECT user_id FROM representative_profiles')).rows[0].user_id, repId);
    assert.equal((await pool.query('SELECT 1 FROM representative_profiles WHERE user_id=$1', [adminId])).rowCount, 0);

    // Shared territory assignments: admin-only writes and representative-scoped reads.
    assert.equal((await app.inject({ method: 'POST', url: '/admin/territories', headers: repHeaders, payload: { name: 'Chino' } })).statusCode, 403);
    assert.equal((await app.inject({ method: 'POST', url: '/admin/territories', headers: adminHeaders, payload: { name: '   ' } })).statusCode, 400);
    const createdTerritory = await app.inject({ method: 'POST', url: '/admin/territories', headers: adminHeaders, payload: { name: ' Chino ', description: ' West Inland Empire ' } });
    assert.equal(createdTerritory.statusCode, 201);
    const territoryId = (createdTerritory.json() as { territory: { id: string } }).territory.id;
    assert.equal((await app.inject({ method: 'POST', url: '/admin/territories', headers: adminHeaders, payload: { name: 'Chino' } })).statusCode, 409);
    const assignUrl = '/admin/territories/' + territoryId + '/representatives/' + repId;
    assert.equal((await app.inject({ method: 'PUT', url: assignUrl, headers: repHeaders })).statusCode, 403);
    assert.equal((await app.inject({ method: 'PUT', url: '/admin/territories/' + territoryId + '/representatives/' + adminId, headers: adminHeaders })).statusCode, 404);
    assert.equal((await app.inject({ method: 'PUT', url: assignUrl, headers: adminHeaders })).statusCode, 201);
    assert.equal((await app.inject({ method: 'PUT', url: assignUrl, headers: adminHeaders })).statusCode, 200);
    const invitedRepId = (await pool.query('SELECT id FROM users WHERE email=$1', ['new@test.invalid'])).rows[0].id as string;
    assert.equal((await app.inject({ method: 'PUT', url: '/admin/territories/' + territoryId + '/representatives/' + invitedRepId, headers: adminHeaders })).statusCode, 201);
    const territoryList = await app.inject({ method: 'GET', url: '/admin/territories', headers: adminHeaders });
    assert.equal(territoryList.statusCode, 200);
    assert.equal((territoryList.json() as { territories: Array<{ representatives: unknown[] }> }).territories[0].representatives.length, 2);
    assert.equal((await app.inject({ method: 'GET', url: '/admin/territories', headers: repHeaders })).statusCode, 403);
    const myTerritories = await app.inject({ method: 'GET', url: '/representative/territories', headers: repHeaders });
    assert.equal(myTerritories.statusCode, 200);
    assert.equal((myTerritories.json() as { territories: Array<{ name: string }> }).territories[0].name, 'Chino');
    assert.equal((await app.inject({ method: 'DELETE', url: assignUrl, headers: adminHeaders })).statusCode, 200);
    assert.equal((await app.inject({ method: 'DELETE', url: assignUrl, headers: adminHeaders })).statusCode, 200);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM representative_territories')).rows[0].count, 1);
    assert.equal((await app.inject({ method: 'GET', url: '/representative/territories', headers: repHeaders })).json().territories.length, 0);

    // Stores start unassigned and can only be assigned to an active representative in the territory.
    const storePayload = { name: 'Corner Market', addressLine1: '100 Main St', city: 'Chino', stateRegion: 'CA', postalCode: '91710' };
    assert.equal((await app.inject({ method: 'POST', url: '/admin/stores', headers: repHeaders, payload: storePayload })).statusCode, 403);
    assert.equal((await app.inject({ method: 'POST', url: '/admin/stores', headers: adminHeaders, payload: { ...storePayload, name: ' ' } })).statusCode, 400);
    const newStore = await app.inject({ method: 'POST', url: '/admin/stores', headers: adminHeaders, payload: storePayload });
    assert.equal(newStore.statusCode, 201);
    const storeId = (newStore.json() as { store: { id: string } }).store.id;
    const storeAssignUrl = '/admin/stores/' + storeId + '/assignment';
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: repHeaders, payload: { territoryId, representativeId: repId, reason: 'Initial store assignment' } })).statusCode, 403);
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: adminHeaders, payload: { territoryId, representativeId: repId, reason: 'Initial store assignment' } })).statusCode, 409, 'unassigned representative cannot own store');
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: adminHeaders, payload: { territoryId, representativeId: invitedRepId, reason: 'Assigned for store servicing' } })).statusCode, 200);
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: adminHeaders, payload: { territoryId, representativeId: invitedRepId, reason: 'Assigned for store servicing' } })).json().changed, false);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM store_assignment_events WHERE store_id=$1', [storeId])).rows[0].count, 1);
    assert.equal((await app.inject({ method: 'GET', url: '/representative/stores', headers: repHeaders })).json().stores.length, 0);
    assert.equal((await app.inject({ method: 'GET', url: '/admin/stores', headers: repHeaders })).statusCode, 403);
    assert.equal((await app.inject({ method: 'GET', url: '/admin/stores', headers: adminHeaders })).json().stores.length, 1);
    const history = await app.inject({ method: 'GET', url: '/admin/stores/' + storeId + '/assignment-history', headers: adminHeaders });
    assert.equal(history.statusCode, 200);
    assert.equal(history.json().events.length, 1);
    assert.equal(history.json().events[0].reason, 'Assigned for store servicing');
    assert.ok(history.json().events[0].effectiveAt);
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: adminHeaders, payload: { territoryId: null, representativeId: null } })).statusCode, 400, 'reason is required');
    assert.equal((await app.inject({ method: 'GET', url: '/admin/stores/' + storeId + '/assignment-history', headers: repHeaders })).statusCode, 403);
    assert.equal((await app.inject({ method: 'PUT', url: storeAssignUrl, headers: adminHeaders, payload: { territoryId: null, representativeId: null, reason: 'Representative departed company' } })).statusCode, 200);
    assert.equal((await pool.query('SELECT count(*)::int AS count FROM store_assignment_events WHERE store_id=$1', [storeId])).rows[0].count, 2);

    // Only administrators may list or suspend representatives.
    assert.equal((await app.inject({ method: 'GET', url: '/admin/representatives', headers: { authorization: 'Bearer ' + repToken } })).statusCode, 403);
    const directory = await app.inject({ method: 'GET', url: '/admin/representatives', headers: adminHeaders });
    assert.equal(directory.statusCode, 200);
    const reps = (directory.json() as { representatives: Array<{ id: string; email: string; active: boolean }> }).representatives;
    assert.equal(reps.length, 2);
    assert.ok(reps.every(item => !('password_hash' in item) && !('passwordHash' in item)));
    assert.equal(reps.find(item => item.id === repId)?.active, true);
    const statusUrl = '/admin/representatives/' + repId + '/status';
    assert.equal((await app.inject({ method: 'PATCH', url: statusUrl, headers: { authorization: 'Bearer ' + repToken }, payload: { active: false } })).statusCode, 403);
    assert.equal((await app.inject({ method: 'PATCH', url: '/admin/representatives/' + adminId + '/status', headers: adminHeaders, payload: { active: false } })).statusCode, 404);
    const suspended = await app.inject({ method: 'PATCH', url: statusUrl, headers: adminHeaders, payload: { active: false } });
    assert.equal(suspended.statusCode, 200);
    assert.equal((suspended.json() as { representative: { active: boolean } }).representative.active, false);
    assert.equal((await app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: 'Bearer ' + repToken } })).statusCode, 401);
    assert.equal((await login('rep@test.invalid', password)).statusCode, 401);
    assert.equal((await pool.query('SELECT 1 FROM sessions WHERE user_id=$1', [repId])).rowCount, 0);
    assert.equal((await app.inject({ method: 'PATCH', url: statusUrl, headers: adminHeaders, payload: { active: false } })).statusCode, 200);
    assert.equal((await pool.query("SELECT count(*)::int AS count FROM auth_audit_events WHERE action='representative_disabled' AND subject_email='rep@test.invalid'")).rows[0].count, 1);
    const restored = await app.inject({ method: 'PATCH', url: statusUrl, headers: adminHeaders, payload: { active: true } });
    assert.equal(restored.statusCode, 200);
    assert.equal((await login('rep@test.invalid', password)).statusCode, 200);
    assert.equal((await pool.query("SELECT count(*)::int AS count FROM auth_audit_events WHERE action='representative_enabled' AND subject_email='rep@test.invalid'")).rows[0].count, 1);


  } finally {
    await scoped?.end();
    await admin.query('DROP SCHEMA IF EXISTS "' + schema + '" CASCADE').catch(() => {});
    await admin.end();
  }
});
