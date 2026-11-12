import './config.js';
import Fastify from 'fastify';
import pg from 'pg';
import { databaseUrl } from './config.js';
import { hashPassword, verifyPassword, newToken, tokenHash } from './security.js';

const app = Fastify({ logger: true, bodyLimit: 16384 });
const pool = databaseUrl ? new pg.Pool({ connectionString: databaseUrl, max: 10, connectionTimeoutMillis: 3000 }) : null;
const email = (value: string) => value.trim().toLowerCase();
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
  const found = await pool.query('SELECT id,email,display_name,role,password_hash FROM users WHERE email=$1 AND active=true', [normalized]);
  const user = found.rows[0];
  if (!user || !(await verifyPassword(body.password, user.password_hash))) return reply.code(401).send({ error: 'Invalid credentials' });
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
const shutdown = async () => { await app.close(); await pool?.end(); };
process.on('SIGINT', () => { void shutdown().then(() => process.exit(0)); });
process.on('SIGTERM', () => { void shutdown().then(() => process.exit(0)); });
try { await app.listen({ port: Number(process.env.API_PORT ?? 3002), host: process.env.API_HOST ?? '127.0.0.1' }); }
catch (err) { app.log.error(err); process.exit(1); }
