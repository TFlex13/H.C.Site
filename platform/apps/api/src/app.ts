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
