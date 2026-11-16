import Fastify from 'fastify';
import type { Pool } from 'pg';
import { hashPassword, verifyPassword, newToken, tokenHash } from './security.js';
import { LoginAttemptLimiter } from './login-limiter.js';

export async function createApp(pool: Pool | null) {
const app = Fastify({ logger: true, bodyLimit: 16384 });
const email = (value: string) => value.trim().toLowerCase();
const loginLimiter = new LoginAttemptLimiter();
// Verify an actual scrypt hash even when the account does not exist.
const dummyPasswordHash = await hashPassword('highline-dummy-login-password-not-a-user');
const bearer = (value?: string) => /^Bearer ([A-Za-z0-9_-]{43})$/.exec(value ?? '')?.[1];
async function actor(authorization?: string) {
  const token = bearer(authorization);
  if (!token || !pool) return null;
  const result = await pool.query('SELECT u.id,u.email,u.display_name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true', [tokenHash(token)]);
  return result.rows[0] as { id: string; email: string; display_name: string; role: string } | undefined ?? null;
}
const credentials = { body: { type: 'object', additionalProperties: false, required: ['email','password'], properties: { email: { type: 'string', maxLength: 254 }, password: { type: 'string', minLength: 1, maxLength: 1024 } } } } as const;
app.get('/health', async () => ({ status: 'ok', service: 'highline-api' }));
app.get('/health/db', async (_request, reply) => {
  if (!pool) return reply.code(503).send({ status: 'unavailable', reason: 'DATABASE_URL not configured' });
  try { await pool.query('SELECT 1'); return { status: 'ok', database: 'postgresql' }; }
  catch (err) { app.log.error({ err }, 'DB health check failed'); return reply.code(503).send({ status: 'unavailable', database: 'postgresql' }); }
});
app.post('/auth/login', { schema: credentials }, async (request, reply) => {
  if (!pool) return reply.code(503).send({ error: 'Database unavailable' });
  const body = request.body as { email: string; password: string };
  const normalized = email(body.email);
  // Fastify does not trust proxy-supplied IP headers by default.
  const accountKey = 'account:' + tokenHash(normalized);
  const ipKey = 'ip:' + tokenHash(request.ip);
  const keys = [accountKey, ipKey];
  if (loginLimiter.blocked(keys)) {
    reply.header('Retry-After', String(loginLimiter.retryAfterSeconds(keys)));
    return reply.code(429).send({ error: 'Too many login attempts. Try again later.' });
  }
  const found = await pool.query('SELECT id,email,display_name,role,password_hash FROM users WHERE email=$1 AND active=true', [normalized]);
  const user = found.rows[0];
  const passwordValid = await verifyPassword(body.password, user?.password_hash ?? dummyPasswordHash);
  if (!user || !passwordValid) {
    loginLimiter.failed(keys);
    return reply.code(401).send({ error: 'Invalid credentials' });
  }
  loginLimiter.clear(accountKey);
  const token = newToken();
  await pool.query("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '12 hours')", [user.id, tokenHash(token)]);
  await pool.query('INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,$2,$3)', [user.id,'login',normalized]);
  return { token, expiresInSeconds: 43200, user: { id: user.id, email: user.email, displayName: user.display_name, role: user.role } };
});
app.get('/auth/me', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user) return reply.code(401).send({ error: 'Unauthorized' });
  return { user: { id: user.id, email: user.email, displayName: user.display_name, role: user.role } };
});
app.post('/auth/logout', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  const token = bearer(request.headers.authorization);
  if (!user || !token || !pool) return reply.code(401).send({ error: 'Unauthorized' });
  await pool.query('DELETE FROM sessions WHERE token_hash=$1', [tokenHash(token)]);
  return { status: 'ok' };
});
// Administrative representative directory. Never expose password hashes or session tokens.
app.get('/admin/representatives', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query("SELECT id,email,display_name,active FROM users WHERE role='representative' ORDER BY email,id");
  return { representatives: result.rows.map(row => ({ id: row.id, email: row.email, displayName: row.display_name, active: row.active })) };
});
app.patch('/admin/representatives/:id/status', {
  schema: {
    params: { type: 'object', additionalProperties: false, required: ['id'], properties: { id: { type: 'string', minLength: 1, maxLength: 64 } } },
    body: { type: 'object', additionalProperties: false, required: ['active'], properties: { active: { type: 'boolean' } } }
  }
}, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  if (!/^[0-9a-fA-F-]{36}$/.test(id) || id.split('-').map(part => part.length).join(',') !== '8,4,4,4,12') return reply.code(400).send({ error: 'Invalid representative ID' });
  const { active } = request.body as { active: boolean };
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const changed = await client.query("UPDATE users SET active=$1 WHERE id=$2 AND role='representative' AND active IS DISTINCT FROM $1 RETURNING id,email,display_name,active", [active,id]);
    if (!changed.rowCount) {
      const existing = await client.query("SELECT id,email,display_name,active FROM users WHERE id=$1 AND role='representative'", [id]);
      await client.query('ROLLBACK');
      if (!existing.rowCount) return reply.code(404).send({ error: 'Representative not found' });
      return { representative: { id: existing.rows[0].id, email: existing.rows[0].email, displayName: existing.rows[0].display_name, active: existing.rows[0].active } };
    }
    const row = changed.rows[0];
    if (!active) await client.query('DELETE FROM sessions WHERE user_id=$1', [id]);
    await client.query('INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,$2,$3)', [user.id,active ? 'representative_enabled' : 'representative_disabled',row.email]);
    await client.query('COMMIT');
    return { representative: { id: row.id, email: row.email, displayName: row.display_name, active: row.active } };
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});

// Representative profile is self-service; administrators may inspect profiles separately later.
app.get('/representative/profile', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user) return reply.code(401).send({ error: 'Unauthorized' });
  if (user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const found = await pool.query('SELECT phone,company_name FROM representative_profiles WHERE user_id=$1', [user.id]);
  const row = found.rows[0];
  return { profile: { id: user.id, email: user.email, displayName: user.display_name, phone: row?.phone ?? null, companyName: row?.company_name ?? null } };
});
app.put('/representative/profile', {
  schema: { body: { type: 'object', additionalProperties: false, required: ['phone','companyName'],
    properties: { phone: { anyOf: [{ type: 'string', maxLength: 40 }, { type: 'null' }] },
      companyName: { anyOf: [{ type: 'string', maxLength: 160 }, { type: 'null' }] } } } }
}, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user) return reply.code(401).send({ error: 'Unauthorized' });
  if (user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const body = request.body as { phone: string | null; companyName: string | null };
  const phone = body.phone?.trim() || null;
  const companyName = body.companyName?.trim() || null;
  const result = await pool.query(
    'INSERT INTO representative_profiles(user_id,phone,company_name) VALUES($1,$2,$3) ON CONFLICT(user_id) DO UPDATE SET phone=EXCLUDED.phone,company_name=EXCLUDED.company_name,updated_at=now() RETURNING phone,company_name',
    [user.id,phone,companyName]
  );
  return { profile: { id: user.id, email: user.email, displayName: user.display_name, phone: result.rows[0].phone, companyName: result.rows[0].company_name } };
});
// Shared territories: multiple representatives may be assigned to one territory.
const uuid = (value: string) => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value);
const territoryBody = { type: 'object', additionalProperties: false, required: ['name'],
  properties: { name: { type: 'string', minLength: 1, maxLength: 120 },
    description: { anyOf: [{ type: 'string', maxLength: 1000 }, { type: 'null' }] } } } as const;
app.get('/admin/territories', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT t.id,t.name,t.description,t.active,COALESCE(json_agg(json_build_object(\'id\',u.id,\'email\',u.email,\'displayName\',u.display_name) ORDER BY u.email) FILTER (WHERE u.id IS NOT NULL),\'[]\'::json) AS representatives FROM territories t LEFT JOIN representative_territories rt ON rt.territory_id=t.id LEFT JOIN users u ON u.id=rt.representative_id GROUP BY t.id ORDER BY t.name,t.id');
  return { territories: result.rows };
});
app.post('/admin/territories', { schema: { body: territoryBody } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const body = request.body as { name: string; description?: string | null };
  const name = body.name.trim();
  if (!name) return reply.code(400).send({ error: 'Territory name required' });
  const description = body.description?.trim() || null;
  const result = await pool.query('INSERT INTO territories(name,description) VALUES($1,$2) ON CONFLICT(name) DO NOTHING RETURNING id,name,description,active', [name,description]);
  if (!result.rowCount) return reply.code(409).send({ error: 'Territory already exists' });
  return reply.code(201).send({ territory: result.rows[0] });
});
app.put('/admin/territories/:territoryId/representatives/:representativeId', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { territoryId, representativeId } = request.params as { territoryId: string; representativeId: string };
  if (!uuid(territoryId) || !uuid(representativeId)) return reply.code(400).send({ error: 'Invalid ID' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const territory = await client.query('SELECT id FROM territories WHERE id=$1 AND active=true FOR SHARE', [territoryId]);
    if (!territory.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active territory not found' }); }
    const rep = await client.query("SELECT id FROM users WHERE id=$1 AND role='representative' AND active=true FOR SHARE", [representativeId]);
    if (!rep.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active representative not found' }); }
    const added = await client.query('INSERT INTO representative_territories(representative_id,territory_id,assigned_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING representative_id', [representativeId,territoryId,user.id]);
    await client.query('COMMIT');
    return reply.code(added.rowCount ? 201 : 200).send({ territoryId, representativeId, assigned: true, created: Boolean(added.rowCount) });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});
app.delete('/admin/territories/:territoryId/representatives/:representativeId', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { territoryId, representativeId } = request.params as { territoryId: string; representativeId: string };
  if (!uuid(territoryId) || !uuid(representativeId)) return reply.code(400).send({ error: 'Invalid ID' });
  const removed = await pool.query('DELETE FROM representative_territories WHERE territory_id=$1 AND representative_id=$2', [territoryId,representativeId]);
  return { territoryId, representativeId, assigned: false, removed: Boolean(removed.rowCount) };
});
app.get('/representative/territories', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user) return reply.code(401).send({ error: 'Unauthorized' });
  if (user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT t.id,t.name,t.description FROM territories t JOIN representative_territories rt ON rt.territory_id=t.id WHERE rt.representative_id=$1 AND t.active=true ORDER BY t.name,t.id', [user.id]);
  return { territories: result.rows };
});
// Store registry: administrators manage stores, representatives see only their assigned stores.
const storeShape = { type: 'object', additionalProperties: false,
  required: ['name','addressLine1','city','stateRegion','postalCode'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 200 },
    addressLine1: { type: 'string', minLength: 1, maxLength: 250 },
    addressLine2: { anyOf: [{ type: 'string', maxLength: 250 }, { type: 'null' }] },
    city: { type: 'string', minLength: 1, maxLength: 120 },
    stateRegion: { type: 'string', minLength: 1, maxLength: 120 },
    postalCode: { type: 'string', minLength: 1, maxLength: 30 },
    contactName: { anyOf: [{ type: 'string', maxLength: 160 }, { type: 'null' }] },
    contactEmail: { anyOf: [{ type: 'string', maxLength: 254 }, { type: 'null' }] },
    contactPhone: { anyOf: [{ type: 'string', maxLength: 40 }, { type: 'null' }] }
  }
} as const;
const storeColumns = 'id,name,address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state_region AS "stateRegion",postal_code AS "postalCode",country_code AS "countryCode",contact_name AS "contactName",contact_email AS "contactEmail",contact_phone AS "contactPhone",territory_id AS "territoryId",primary_representative_id AS "primaryRepresentativeId",active,created_at AS "createdAt",updated_at AS "updatedAt"';
app.post('/admin/stores', { schema: { body: storeShape } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const v = request.body as Record<string, string | null | undefined>;
  for (const key of ['name','addressLine1','city','stateRegion','postalCode']) {
    if (!v[key]?.trim()) return reply.code(400).send({ error: key + ' required' });
  }
  const result = await pool.query(
    'INSERT INTO stores(name,address_line1,address_line2,city,state_region,postal_code,contact_name,contact_email,contact_phone) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING ' + storeColumns,
    [v.name!.trim(),v.addressLine1!.trim(),v.addressLine2?.trim() || null,v.city!.trim(),v.stateRegion!.trim(),v.postalCode!.trim(),v.contactName?.trim() || null,v.contactEmail?.trim().toLowerCase() || null,v.contactPhone?.trim() || null]
  );
  return reply.code(201).send({ store: result.rows[0] });
});
app.get('/admin/stores', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + storeColumns + ' FROM stores ORDER BY created_at DESC,id');
  return { stores: result.rows };
});
app.get('/representative/stores', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user) return reply.code(401).send({ error: 'Unauthorized' });
  if (user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + storeColumns + ' FROM stores WHERE primary_representative_id=$1 AND active=true ORDER BY name,id', [user.id]);
  return { stores: result.rows };
});
app.put('/admin/stores/:id/assignment', {
  schema: { body: { type: 'object', additionalProperties: false, required: ['territoryId','representativeId','reason'],
    properties: { territoryId: { type: ['string', 'null'] },
      representativeId: { type: ['string', 'null'] }, reason: { type: 'string', minLength: 5, maxLength: 1000 } } } }
}, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { territoryId, representativeId, reason } = request.body as { territoryId: string | null; representativeId: string | null; reason: string };
  if (reason.trim().length < 5) return reply.code(400).send({ error: 'Transfer reason must be at least 5 characters' });
  if (!uuid(id) || (territoryId !== null && !uuid(territoryId)) || (representativeId !== null && !uuid(representativeId)) || (representativeId !== null && territoryId === null)) return reply.code(400).send({ error: 'Invalid assignment' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const current = await client.query('SELECT territory_id,primary_representative_id FROM stores WHERE id=$1 FOR UPDATE', [id]);
    if (!current.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Store not found' }); }
    const old = current.rows[0];
    if (territoryId !== null && !(await client.query('SELECT 1 FROM territories WHERE id=$1 AND active=true FOR SHARE', [territoryId])).rowCount) {
      await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active territory not found' });
    }
    if (representativeId !== null && !(await client.query("SELECT 1 FROM users u JOIN representative_territories rt ON rt.representative_id=u.id WHERE u.id=$1 AND rt.territory_id=$2 AND u.role='representative' AND u.active=true FOR SHARE OF u,rt", [representativeId,territoryId])).rowCount) {
      await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Representative is not active and assigned to territory' });
    }
    const changed = old.territory_id !== territoryId || old.primary_representative_id !== representativeId;
    if (changed) {
      await client.query('UPDATE stores SET territory_id=$1,primary_representative_id=$2,updated_at=now() WHERE id=$3', [territoryId,representativeId,id]);
      await client.query('INSERT INTO store_assignment_events(store_id,previous_territory_id,new_territory_id,previous_representative_id,new_representative_id,changed_by,reason,effective_at) VALUES($1,$2,$3,$4,$5,$6,$7,now())', [id,old.territory_id,territoryId,old.primary_representative_id,representativeId,user.id,reason.trim()]);
    }
    await client.query('COMMIT');
    return { storeId: id, territoryId, representativeId, changed };
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});
app.get('/admin/stores/:id/assignment-history', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  if (!uuid(id)) return reply.code(400).send({ error: 'Invalid store ID' });
  if (!(await pool.query('SELECT 1 FROM stores WHERE id=$1', [id])).rowCount) return reply.code(404).send({ error: 'Store not found' });
  const result = await pool.query('SELECT id,previous_territory_id AS "previousTerritoryId",new_territory_id AS "newTerritoryId",previous_representative_id AS "previousRepresentativeId",new_representative_id AS "newRepresentativeId",changed_by AS "changedBy",reason,effective_at AS "effectiveAt",changed_at AS "changedAt" FROM store_assignment_events WHERE store_id=$1 ORDER BY changed_at DESC,id DESC', [id]);
  return { events: result.rows };
});
app.post('/admin/invitations', { schema: { body: { type: 'object', additionalProperties: false, required: ['email'], properties: { email: { type: 'string', maxLength: 254 } } } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const normalized = email((request.body as { email: string }).email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) return reply.code(400).send({ error: 'Invalid email' });
  if ((await pool.query('SELECT 1 FROM users WHERE email=$1', [normalized])).rowCount) return reply.code(409).send({ error: 'Account already exists' });
  const token = newToken();
  await pool.query("INSERT INTO invitations(email,token_hash,invited_by,expires_at) VALUES($1,$2,$3,now()+interval '48 hours')", [normalized, tokenHash(token), user.id]);
  await pool.query('INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,$2,$3)', [user.id,'invitation_created',normalized]);
  // Local-development handoff only. Replace with out-of-band email delivery before deployment.
  return reply.code(201).send({ email: normalized, invitationToken: token, expiresInHours: 48, delivery: 'manual-local-development' });
});
app.post('/auth/accept-invitation', { schema: { body: { type: 'object', additionalProperties: false, required: ['token','displayName','password'], properties: { token: { type: 'string', minLength: 43, maxLength: 43 }, displayName: { type: 'string', minLength: 1, maxLength: 120 }, password: { type: 'string', minLength: 12, maxLength: 1024 } } } } }, async (request, reply) => {
  if (!pool) return reply.code(503).send({ error: 'Database unavailable' });
  const body = request.body as { token: string; displayName: string; password: string };
  if (!body.displayName.trim()) return reply.code(400).send({ error: 'Display name required' });
  const passwordHash = await hashPassword(body.password);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query('SELECT id,email FROM invitations WHERE token_hash=$1 AND accepted_at IS NULL AND expires_at>now() FOR UPDATE', [tokenHash(body.token)]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return reply.code(400).send({ error: 'Invalid or expired invitation' }); }
    const invitation = found.rows[0];
    const created = await client.query("INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,'representative') ON CONFLICT (email) DO NOTHING RETURNING id", [invitation.email,body.displayName.trim(),passwordHash]);
    if (!created.rowCount) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Account already exists' }); }
    await client.query('UPDATE invitations SET accepted_at=now() WHERE id=$1', [invitation.id]);
    await client.query('INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,$2,$3)', [created.rows[0].id,'invitation_accepted',invitation.email]);
    await client.query('COMMIT');
    return reply.code(201).send({ status: 'created' });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});
return app;
}
