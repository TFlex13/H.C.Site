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

const percentPattern = /^(?:0|[1-9]\d{0,2})(?:\.\d{1,4})?$/;
const percentUnits = (value: string) => percentPattern.test(value) && Number(value) <= 100
  ? Math.round(Number(value) * 10000) : null;
const agreementColumns = 'id,vendor_id AS "vendorId",service_fee_percent::text AS "serviceFeePercent",highline_percent::text AS "highlinePercent",representative_percent::text AS "representativePercent",effective_from AS "effectiveFrom",effective_until AS "effectiveUntil",created_by AS "createdBy",created_at AS "createdAt"';
app.post('/admin/vendors', { schema: { body: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: { type: 'string', minLength: 1, maxLength: 200 } } } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const name = (request.body as { name: string }).name.trim();
  if (!name) return reply.code(400).send({ error: 'Vendor name required' });
  try {
    const result = await pool.query('INSERT INTO vendors(name) VALUES($1) RETURNING id,name,active,created_at AS "createdAt"', [name]);
    return reply.code(201).send({ vendor: result.rows[0] });
  } catch (err) {
    if ((err as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Vendor already exists' });
    throw err;
  }
});
app.get('/admin/vendors', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT id,name,active,created_at AS "createdAt" FROM vendors ORDER BY name,id');
  return { vendors: result.rows };
});
app.get('/admin/vendors/:id/agreements', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  if (!uuid(id)) return reply.code(400).send({ error: 'Invalid vendor ID' });
  if (!(await pool.query('SELECT 1 FROM vendors WHERE id=$1', [id])).rowCount) return reply.code(404).send({ error: 'Vendor not found' });
  const result = await pool.query('SELECT ' + agreementColumns + ' FROM vendor_commission_agreements WHERE vendor_id=$1 ORDER BY effective_from DESC,id DESC', [id]);
  return { agreements: result.rows };
});
app.post('/admin/vendors/:id/agreements', { schema: { body: { type: 'object', additionalProperties: false, required: ['serviceFeePercent','highlinePercent','representativePercent'], properties: {
  serviceFeePercent: { type: 'string', minLength: 1, maxLength: 8 },
  highlinePercent: { type: 'string', minLength: 1, maxLength: 8 },
  representativePercent: { type: 'string', minLength: 1, maxLength: 8 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  if (!uuid(id)) return reply.code(400).send({ error: 'Invalid vendor ID' });
  const body = request.body as { serviceFeePercent: string; highlinePercent: string; representativePercent: string };
  const total = percentUnits(body.serviceFeePercent), hc = percentUnits(body.highlinePercent), rep = percentUnits(body.representativePercent);
  if (total === null || hc === null || rep === null || hc + rep !== total) return reply.code(400).send({ error: 'Percentages must be between 0 and 100, with Highline plus representative equal to vendor service fee' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize changes for this vendor, including concurrent agreement requests.
    const vendor = await client.query('SELECT id FROM vendors WHERE id=$1 AND active=true FOR UPDATE', [id]);
    if (!vendor.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active vendor not found' }); }
    const now = await client.query('SELECT clock_timestamp() AS ts');
    const effective = now.rows[0].ts as Date;
    const previous = await client.query('SELECT id,effective_from FROM vendor_commission_agreements WHERE vendor_id=$1 AND effective_until IS NULL FOR UPDATE', [id]);
    if (previous.rowCount) {
      // No retroactive edits: close the old agreement at the instant the new one starts.
      if (effective <= previous.rows[0].effective_from) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Agreement timestamp conflict; retry' }); }
      await client.query('UPDATE vendor_commission_agreements SET effective_until=$1 WHERE id=$2', [effective,previous.rows[0].id]);
    }
    const result = await client.query('INSERT INTO vendor_commission_agreements(vendor_id,service_fee_percent,highline_percent,representative_percent,effective_from,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING ' + agreementColumns, [id,body.serviceFeePercent,body.highlinePercent,body.representativePercent,effective,user.id]);
    await client.query('COMMIT');
    return reply.code(201).send({ agreement: result.rows[0] });
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});


const pricePattern = /^(?:0|[1-9]\d{0,9})(?:\.\d{1,4})?$/;
const priceUnits = (value: string) => pricePattern.test(value)
  ? BigInt(value.split('.')[0]) * 10000n + BigInt((value.split('.')[1] ?? '').padEnd(4,'0')) : null;
const money = (value: bigint) => (value / 10000n).toString() + '.' + (value % 10000n).toString().padStart(4,'0');
const percentAmount = (profitUnits: bigint, percent: string) => {
  const units = percentUnits(percent);
  if (units === null) throw new Error('Invalid stored commission percentage');
  return (profitUnits * BigInt(units) + 500000n) / 1000000n;
};
const orderColumns = 'id,external_order_reference AS "externalOrderReference",vendor_id AS "vendorId",store_id AS "storeId",representative_id AS "representativeId",agreement_id AS "agreementId",currency_code AS "currencyCode",quantity,unit_wholesale_price::text AS "unitWholesalePrice",unit_vendor_cost::text AS "unitVendorCost",gross_profit::text AS "grossProfit",service_fee_percent::text AS "serviceFeePercent",highline_percent::text AS "highlinePercent",representative_percent::text AS "representativePercent",service_fee_amount::text AS "serviceFeeAmount",highline_amount::text AS "highlineAmount",representative_amount::text AS "representativeAmount",status,recorded_by AS "recordedBy",recorded_at AS "recordedAt"';
app.post('/admin/orders', { schema: { body: { type: 'object', additionalProperties: false, required: ['externalOrderReference','vendorId','storeId','quantity','unitWholesalePrice','unitVendorCost'], properties: {
  externalOrderReference: { type: 'string', minLength: 1, maxLength: 200 },
  vendorId: { type: 'string', minLength: 36, maxLength: 36 },
  storeId: { type: 'string', minLength: 36, maxLength: 36 },
  quantity: { type: 'integer', minimum: 1, maximum: 1000000 },
  unitWholesalePrice: { type: 'string', minLength: 1, maxLength: 16 },
  unitVendorCost: { type: 'string', minLength: 1, maxLength: 16 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const body = request.body as { externalOrderReference: string; vendorId: string; storeId: string; quantity: number; unitWholesalePrice: string; unitVendorCost: string };
  const reference = body.externalOrderReference.trim();
  const wholesale = priceUnits(body.unitWholesalePrice), cost = priceUnits(body.unitVendorCost);
  if (!reference || !uuid(body.vendorId) || !uuid(body.storeId) || wholesale === null || cost === null || wholesale < cost)
    return reply.code(400).send({ error: 'Invalid order reference, IDs or unit prices' });
  const profit = (wholesale - cost) * BigInt(body.quantity);
  // Keep amounts within numeric(16,4); the database remains the final authority.
  if (profit > 9999999999999999n) return reply.code(400).send({ error: 'Order amount exceeds supported limit' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Lock the store to serialize order attribution against administrative transfers.
    const store = await client.query('SELECT s.primary_representative_id FROM stores s WHERE s.id=$1 AND s.active=true FOR UPDATE OF s', [body.storeId]);
    if (!store.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active store not found' }); }
    const repId = store.rows[0].primary_representative_id as string | null;
    if (!repId) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Store has no assigned representative' }); }
    const rep = await client.query("SELECT 1 FROM users WHERE id=$1 AND role='representative' AND active=true FOR SHARE", [repId]);
    if (!rep.rowCount) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Store representative is inactive' }); }
    const vendor = await client.query('SELECT 1 FROM vendors WHERE id=$1 AND active=true FOR SHARE', [body.vendorId]);
    if (!vendor.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Active vendor not found' }); }
    const agreement = await client.query('SELECT id,service_fee_percent::text,highline_percent::text,representative_percent::text FROM vendor_commission_agreements WHERE vendor_id=$1 AND effective_from<=clock_timestamp() AND (effective_until IS NULL OR effective_until>clock_timestamp()) ORDER BY effective_from DESC LIMIT 1', [body.vendorId]);
    if (!agreement.rowCount) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'No effective vendor commission agreement' }); }
    const rate = agreement.rows[0];
    const total = percentAmount(profit,rate.service_fee_percent);
    const representative = percentAmount(profit,rate.representative_percent);
    const highline = total - representative;
    const result = await client.query('INSERT INTO commission_orders(external_order_reference,vendor_id,store_id,representative_id,agreement_id,quantity,unit_wholesale_price,unit_vendor_cost,gross_profit,service_fee_percent,highline_percent,representative_percent,service_fee_amount,highline_amount,representative_amount,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING ' + orderColumns,
      [reference,body.vendorId,body.storeId,repId,rate.id,body.quantity,money(wholesale),money(cost),money(profit),rate.service_fee_percent,rate.highline_percent,rate.representative_percent,money(total),money(highline),money(representative),user.id]);
    await client.query('COMMIT');
    return reply.code(201).send({ order: result.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    if ((err as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Order reference already recorded for vendor' });
    throw err;
  } finally { client.release(); }
});
app.get('/admin/orders', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + orderColumns + ' FROM commission_orders ORDER BY recorded_at DESC,id DESC LIMIT 100');
  return { orders: result.rows };
});
app.post('/admin/orders/:id/decision', { schema: { body: { type: 'object', additionalProperties: false, required: ['decision','reason'], properties: {
  decision: { type: 'string', enum: ['approved','voided'] },
  reason: { type: 'string', minLength: 5, maxLength: 1000 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { decision, reason } = request.body as { decision: 'approved' | 'voided'; reason: string };
  if (!uuid(id) || reason.trim().length < 5) return reply.code(400).send({ error: 'Invalid order ID or reason' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT status FROM commission_orders WHERE id=$1 FOR UPDATE', [id]);
    if (!existing.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Order not found' }); }
    if (existing.rows[0].status !== 'pending') { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Order already decided' }); }
    await client.query("SELECT set_config('highline.decision_actor',$1,true),set_config('highline.decision_reason',$2,true)", [user.id,reason.trim()]);
    const result = await client.query('UPDATE commission_orders SET status=$1 WHERE id=$2 RETURNING ' + orderColumns, [decision,id]);
    const audit = await client.query('SELECT id,order_id AS "orderId",previous_status AS "previousStatus",new_status AS "newStatus",decided_by AS "decidedBy",reason,decided_at AS "decidedAt" FROM commission_order_decisions WHERE order_id=$1', [id]);
    await client.query('COMMIT');
    return { order: result.rows[0], decision: audit.rows[0] };
  } catch (err) { await client.query('ROLLBACK'); throw err; }
  finally { client.release(); }
});
app.get('/admin/orders/:id/decisions', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  if (!uuid(id)) return reply.code(400).send({ error: 'Invalid order ID' });
  if (!(await pool.query('SELECT 1 FROM commission_orders WHERE id=$1', [id])).rowCount) return reply.code(404).send({ error: 'Order not found' });
  const result = await pool.query('SELECT id,order_id AS "orderId",previous_status AS "previousStatus",new_status AS "newStatus",decided_by AS "decidedBy",reason,decided_at AS "decidedAt" FROM commission_order_decisions WHERE order_id=$1 ORDER BY decided_at,id', [id]);
  return { decisions: result.rows };
});
// Receipt is a full settlement of the vendor service fee for one approved order.
// It does not imply the representative has been paid.
const receiptColumns = 'r.id,r.order_id AS "orderId",r.vendor_id AS "vendorId",r.payment_reference AS "paymentReference",r.amount::text,r.currency_code AS "currencyCode",r.received_on::text AS "receivedOn",r.recorded_by AS "recordedBy",r.recorded_at AS "recordedAt"';
app.post('/admin/orders/:id/vendor-receipt', { schema: { body: { type: 'object', additionalProperties: false, required: ['paymentReference','receivedOn'], properties: {
  paymentReference: { type: 'string', minLength: 1, maxLength: 200 },
  receivedOn: { type: 'string', pattern: '^\\d{4}-\\d{2}-\\d{2}, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + orderColumns + ' FROM commission_orders WHERE representative_id=$1 ORDER BY recorded_at DESC,id DESC LIMIT 100', [user.id]);
  return { orders: result.rows };
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
 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { paymentReference, receivedOn } = request.body as { paymentReference: string; receivedOn: string };
  const date = new Date(receivedOn + 'T00:00:00.000Z');
  if (!uuid(id) || !paymentReference.trim() || Number.isNaN(date.getTime()) || date.toISOString().slice(0,10) !== receivedOn)
    return reply.code(400).send({ error: 'Invalid order, payment reference or calendar date' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const order = await client.query('SELECT id,vendor_id,service_fee_amount::text AS amount,status FROM commission_orders WHERE id=$1 FOR UPDATE', [id]);
    if (!order.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Order not found' }); }
    if (order.rows[0].status !== 'approved') { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Only approved orders can be reconciled' }); }
    const receipt = await client.query('INSERT INTO commission_vendor_receipts(order_id,vendor_id,payment_reference,amount,received_on,recorded_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
      [id,order.rows[0].vendor_id,paymentReference.trim(),order.rows[0].amount,receivedOn,user.id]);
    const result = await client.query('SELECT ' + receiptColumns + ' FROM commission_vendor_receipts r WHERE r.id=$1', [receipt.rows[0].id]);
    await client.query('COMMIT');
    return reply.code(201).send({ receipt: result.rows[0], representativePaid: false });
  } catch (err) {
    await client.query('ROLLBACK');
    if ((err as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Vendor receipt already recorded for order' });
    throw err;
  } finally { client.release(); }
});
app.get('/admin/vendor-receipts', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + receiptColumns + ' FROM commission_vendor_receipts r ORDER BY r.recorded_at DESC,r.id DESC LIMIT 100');
  return { receipts: result.rows };
});
app.get('/admin/commissions/reconciliation', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query(`
    SELECT o.vendor_id AS "vendorId",
      count(*)::int AS "approvedOrders",
      count(r.id)::int AS "receivedOrders",
      coalesce(sum(o.service_fee_amount),0)::text AS "approvedFees",
      coalesce(sum(o.service_fee_amount) FILTER (WHERE r.id IS NULL),0)::text AS "outstandingFees",
      coalesce(sum(r.amount),0)::text AS "receivedFees",
      coalesce(sum(o.representative_amount) FILTER (WHERE r.id IS NOT NULL),0)::text AS "representativeLiabilityOnReceivedOrders"
    FROM commission_orders o
    LEFT JOIN commission_vendor_receipts r ON r.order_id=o.id
    WHERE o.status='approved'
    GROUP BY o.vendor_id ORDER BY o.vendor_id
  `);
  return { vendors: result.rows, representativePayoutsImplemented: false };
});
app.get('/representative/orders', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + orderColumns + ' FROM commission_orders WHERE representative_id=$1 ORDER BY recorded_at DESC,id DESC LIMIT 100', [user.id]);
  return { orders: result.rows };
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
