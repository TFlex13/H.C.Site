import Fastify from 'fastify';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdir, writeFile, unlink, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { financeDashboardHtml } from './finance-dashboard.js';
import { invitationPageHtml } from './invitation-page.js';
import { onboardingPageHtml } from './onboarding-page.js';
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
app.get('/representative/onboarding/profile', async (_request, reply) => {
  reply.header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  reply.header('Cache-Control', 'no-store');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.type('text/html; charset=utf-8').send(onboardingPageHtml);
});
app.get('/auth/invitation', async (_request, reply) => {
  reply.header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  reply.header('Cache-Control', 'no-store');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.type('text/html; charset=utf-8').send(invitationPageHtml);
});
app.get('/admin/dashboard', async (_request, reply) => {
  reply.header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src blob:; frame-src blob:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
  reply.header('Cache-Control', 'no-store');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Referrer-Policy', 'no-referrer');
  return reply.type('text/html; charset=utf-8').send(financeDashboardHtml);
});
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
// Sensitive uploads are encrypted before disk write. The encryption key must be
// provisioned separately and backed up securely; never commit it to source control.
const documentKeyHex = process.env.HIGHLINE_DOCUMENT_ENCRYPTION_KEY ?? '';
const documentKey = /^[a-fA-F0-9]{64}$/.test(documentKeyHex) ? Buffer.from(documentKeyHex,'hex') : null;
const documentRoot = process.env.HIGHLINE_PRIVATE_DOCUMENT_DIR;
const documentUploadsEnabled = Boolean(documentKey && documentRoot);
app.addContentTypeParser('application/octet-stream', { parseAs: 'buffer', bodyLimit: 10 * 1024 * 1024 }, (_req, body, done) => done(null,body));
const documentTypes = ['id_front','id_back','w9'] as const;
app.get('/representative/documents', async (request, reply) => {
 const user = await actor(request.headers.authorization);
 if (!user || user.role!=='representative' || !pool) return reply.code(403).send({error:'Forbidden'});
 const found=await pool.query('SELECT document_type AS "documentType",original_filename AS "filename",review_status AS "status",submitted_at AS "submittedAt" FROM representative_documents WHERE representative_id=$1 ORDER BY document_type',[user.id]);
 return { uploadsEnabled:documentUploadsEnabled, documents:found.rows };
});
app.post('/representative/documents/:type', { bodyLimit: 10*1024*1024 }, async (request, reply) => {
 const user=await actor(request.headers.authorization);
 if (!user || user.role!=='representative' || !pool) return reply.code(403).send({error:'Forbidden'});
 if (!documentUploadsEnabled || !documentKey || !documentRoot) return reply.code(503).send({error:'Secure document storage is not configured'});
 const eligibility=await pool.query("SELECT approval_status,submitted_at FROM representative_onboarding WHERE representative_id=$1",[user.id]);
 if (!eligibility.rowCount || (!['pending','rejected'].includes(eligibility.rows[0].approval_status) || eligibility.rows[0].submitted_at)) return reply.code(409).send({error:'Document submissions are locked; contact an administrator'});
 const type=(request.params as {type:string}).type;
 if (!documentTypes.some(x=>x===type)) return reply.code(400).send({error:'Invalid document type'});
 const mime=request.headers['x-document-mime'];
 const filename=request.headers['x-document-name'];
 const data=request.body;
 if (!Buffer.isBuffer(data) || data.length<1 || data.length>10*1024*1024 || typeof filename!=='string' || filename.length>180 || !/^[a-zA-Z0-9_. ()-]+$/.test(filename))
   return reply.code(400).send({error:'Invalid document'});
 const pdf=data.subarray(0,5).toString()==='%PDF-';
 const jpeg=data[0]===0xff && data[1]===0xd8 && data[2]===0xff;
 const png=data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
 if (!((mime==='application/pdf'&&pdf)||(mime==='image/jpeg'&&jpeg)||(mime==='image/png'&&png)) || (type==='w9'&&!pdf))
   return reply.code(415).send({error:'Use PDF for W-9 or PDF/JPEG/PNG for ID'});
 const storageKey=randomBytes(24).toString('hex');
 const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',documentKey,iv);
 const encrypted=Buffer.concat([iv,cipher.update(data),cipher.final(),cipher.getAuthTag()]);
 await mkdir(documentRoot,{recursive:true,mode:0o700});
 const file=join(documentRoot,storageKey);
 await writeFile(file,encrypted,{flag:'wx',mode:0o600});
 try {
   await pool.query(`INSERT INTO representative_documents(representative_id,document_type,original_filename,mime_type,byte_size,storage_key)
     VALUES($1,$2,$3,$4,$5,$6)
     ON CONFLICT(representative_id,document_type) DO UPDATE SET original_filename=EXCLUDED.original_filename,mime_type=EXCLUDED.mime_type,byte_size=EXCLUDED.byte_size,storage_key=EXCLUDED.storage_key,submitted_at=now(),review_status='pending_review',reviewed_at=NULL,reviewed_by=NULL`,[user.id,type,filename,mime,data.length,storageKey]);
 } catch(err){await unlink(file).catch(()=>{});throw err;}
 const docs=await pool.query("SELECT document_type FROM representative_documents WHERE representative_id=$1",[user.id]);
 const types=new Set(docs.rows.map((x:{document_type:string})=>x.document_type));
 await pool.query("UPDATE representative_onboarding SET identity_document_status=CASE WHEN $2 THEN 'pending_review' ELSE 'not_submitted' END,tax_document_status=CASE WHEN $3 THEN 'pending_review' ELSE 'not_submitted' END,updated_at=now() WHERE representative_id=$1",[user.id,types.has('id_front')&&types.has('id_back'),types.has('w9')]);
 return reply.code(201).send({documentType:type,status:'pending_review'});
});
// Self-service onboarding stores contact details only. Sensitive document uploads
// require a separate vetted private-storage integration.
const onboardingFields = 'representative_id AS "representativeId",legal_first_name AS "legalFirstName",legal_last_name AS "legalLastName",mobile_phone AS "mobilePhone",alternate_phone AS "alternatePhone",address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state_region AS "stateRegion",postal_code AS "postalCode",country_code AS "countryCode",preferred_contact_method AS "preferredContactMethod",tax_document_status AS "taxDocumentStatus",identity_document_status AS "identityDocumentStatus",contractor_agreement_status AS "contractorAgreementStatus",approval_status AS "approvalStatus",reviewed_at AS "reviewedAt",submitted_at AS "submittedAt"';
const onboardingBody = { body: { type: 'object', additionalProperties: false, required: ['legalFirstName','legalLastName','mobilePhone','addressLine1','city','stateRegion','postalCode','preferredContactMethod'], properties: {
  legalFirstName: { type: 'string', minLength: 1, maxLength: 120 },
  legalLastName: { type: 'string', minLength: 1, maxLength: 120 },
  mobilePhone: { type: 'string', minLength: 7, maxLength: 30 },
  alternatePhone: { type: ['string','null'], maxLength: 30 },
  addressLine1: { type: 'string', minLength: 1, maxLength: 200 },
  addressLine2: { type: ['string','null'], maxLength: 200 },
  city: { type: 'string', minLength: 1, maxLength: 120 },
  stateRegion: { type: 'string', minLength: 1, maxLength: 120 },
  postalCode: { type: 'string', minLength: 1, maxLength: 20 },
  preferredContactMethod: { type: 'string', enum: ['email','mobile','phone'] }
} } } as const;
app.get('/representative/onboarding', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const found = await pool.query('SELECT '+onboardingFields+' FROM representative_onboarding WHERE representative_id=$1', [user.id]);
  if (!found.rowCount) return reply.code(404).send({ error: 'Onboarding record missing' });
  return { profile: found.rows[0], email: user.email };
});
app.put('/representative/onboarding', { schema: onboardingBody }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'representative' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const v = request.body as Record<string,string|null|undefined>;
  for (const key of ['legalFirstName','legalLastName','mobilePhone','addressLine1','city','stateRegion','postalCode'])
    if (!v[key]?.trim()) return reply.code(400).send({ error: key+' required' });
  const values = ['legalFirstName','legalLastName','mobilePhone','alternatePhone','addressLine1','addressLine2','city','stateRegion','postalCode'].map(key => v[key]?.trim() || null);
  const updated = await pool.query(
    "UPDATE representative_onboarding SET legal_first_name=$2,legal_last_name=$3,mobile_phone=$4,alternate_phone=$5,address_line1=$6,address_line2=$7,city=$8,state_region=$9,postal_code=$10,preferred_contact_method=$11,approval_status='pending',reviewed_by=NULL,reviewed_at=NULL,updated_at=now() WHERE representative_id=$1 AND submitted_at IS NULL AND approval_status IN ('pending','rejected') RETURNING "+onboardingFields,
    [user.id,...values,v.preferredContactMethod]);
  if (!updated.rowCount) return reply.code(409).send({ error: 'Profile is locked during approval or suspension; contact administrator' });
  return { profile: updated.rows[0] };
});
// Submission requests review; it never verifies documents or grants assignments.
app.post('/representative/onboarding/submit', async (request, reply) => {
 const user=await actor(request.headers.authorization);
 if (!user || user.role!=='representative' || !pool) return reply.code(403).send({error:'Forbidden'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const found=await client.query('SELECT * FROM representative_onboarding WHERE representative_id=$1 FOR UPDATE',[user.id]);
  const p=found.rows[0];
  if (!p) { await client.query('ROLLBACK'); return reply.code(404).send({error:'Onboarding record missing'}); }
  if (!['pending','rejected'].includes(p.approval_status) || p.submitted_at) { await client.query('ROLLBACK'); return reply.code(409).send({error:'Onboarding already submitted or locked'}); }
  if (!['legal_first_name','legal_last_name','mobile_phone','address_line1','city','state_region','postal_code','preferred_contact_method'].every(k=>typeof p[k]==='string' && p[k].trim())) { await client.query('ROLLBACK'); return reply.code(409).send({error:'Complete your personal information before submitting'}); }
  const docs=await client.query('SELECT document_type FROM representative_documents WHERE representative_id=$1',[user.id]);
  const types=new Set(docs.rows.map((x:{document_type:string})=>x.document_type));
  if (!['id_front','id_back','w9'].every(t=>types.has(t))) { await client.query('ROLLBACK'); return reply.code(409).send({error:'Upload both ID sides and W-9 before submitting'}); }
  await client.query("UPDATE representative_onboarding SET submitted_at=now(),approval_status='pending',reviewed_by=NULL,reviewed_at=NULL,updated_at=now() WHERE representative_id=$1",[user.id]);
  await client.query('INSERT INTO representative_onboarding_submissions(representative_id,identity_status,tax_status,agreement_status) VALUES($1,$2,$3,$4)',[user.id,p.identity_document_status,p.tax_document_status,p.contractor_agreement_status]);
  await client.query('COMMIT');
  return {status:'submitted',message:'Submitted for preliminary review. Contractor agreement signing is still required before final approval.'};
 } catch(err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
});
app.get('/admin/representative-onboarding', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const found = await pool.query("SELECT "+onboardingFields+",u.display_name AS \"displayName\",u.email FROM representative_onboarding o JOIN users u ON u.id=o.representative_id ORDER BY u.display_name LIMIT 200");
  return { representatives: found.rows };
});
// Admin-only metadata review queue. No sensitive document bytes or storage paths are exposed.
app.get('/admin/representative-onboarding/:id/documents', async (request, reply) => {
 const user=await actor(request.headers.authorization);
 if (!user || user.role!=='admin' || !pool) return reply.code(403).send({error:'Forbidden'});
 const {id}=request.params as {id:string};
 if (!uuid(id)) return reply.code(400).send({error:'Invalid representative'});
 const rep=await pool.query('SELECT submitted_at,approval_status FROM representative_onboarding WHERE representative_id=$1',[id]);
 if (!rep.rowCount) return reply.code(404).send({error:'Representative not found'});
 const docs=await pool.query('SELECT document_type AS "documentType",original_filename AS "filename",mime_type AS "mimeType",byte_size AS "byteSize",review_status AS "status",submitted_at AS "submittedAt",reviewed_at AS "reviewedAt" FROM representative_documents WHERE representative_id=$1 ORDER BY document_type',[id]);
 return {submittedAt:rep.rows[0].submitted_at,approvalStatus:rep.rows[0].approval_status,documents:docs.rows};
});
// Sensitive bytes are available only to authenticated administrators, never by public URL.
app.get('/admin/representative-onboarding/:id/documents/:type/content', async (request, reply) => {
 const user=await actor(request.headers.authorization);
 if (!user || user.role!=='admin' || !pool) return reply.code(403).send({error:'Forbidden'});
 const {id,type}=request.params as {id:string;type:string};
 if (!uuid(id) || !documentTypes.some(t=>t===type)) return reply.code(400).send({error:'Invalid document'});
 if (!documentKey || !documentRoot) return reply.code(503).send({error:'Encrypted storage not configured for this server'});
 const result=await pool.query('SELECT id,storage_key,mime_type,byte_size FROM representative_documents WHERE representative_id=$1 AND document_type=$2',[id,type]);
 if (!result.rowCount) return reply.code(404).send({error:'Document not found'});
 const d=result.rows[0];
 if (!/^[0-9a-f]{48}$/.test(d.storage_key)) return reply.code(500).send({error:'Invalid storage record'});
 let encrypted:Buffer;
 try { encrypted=await readFile(join(documentRoot,d.storage_key)); }
 catch { return reply.code(503).send({error:'Encrypted file unavailable; verify the original storage directory and encryption key'}); }
 if (encrypted.length<29 || encrypted.length>10*1024*1024+28) return reply.code(422).send({error:'Encrypted document invalid'});
 let clear:Buffer;
 try {
  const decipher=createDecipheriv('aes-256-gcm',documentKey,encrypted.subarray(0,12));
  decipher.setAuthTag(encrypted.subarray(encrypted.length-16));
  clear=Buffer.concat([decipher.update(encrypted.subarray(12,encrypted.length-16)),decipher.final()]);
 } catch { return reply.code(422).send({error:'Document decryption failed; verify original encryption key'}); }
 if (clear.length!==d.byte_size) return reply.code(422).send({error:'Document integrity mismatch'});
 await pool.query("INSERT INTO representative_document_access_audit(representative_id,document_type,document_id,administrator_id,action) VALUES($1,$2,$3,$4,'view')",[id,type,d.id,user.id]);
 reply.header('Cache-Control','no-store, no-cache, must-revalidate, private');
 reply.header('Pragma','no-cache');
 reply.header('X-Content-Type-Options','nosniff');
 reply.header('Content-Security-Policy',"default-src 'none'; sandbox");
 reply.header('Content-Disposition','inline');
 return reply.type(d.mime_type).send(clear);
});
app.patch('/admin/representative-onboarding/:id/documents/:type/review', {schema:{body:{type:'object',additionalProperties:false,required:['status','reason'],properties:{status:{type:'string',enum:['verified','rejected']},reason:{type:'string',minLength:5,maxLength:1000}}}}}, async (request,reply)=>{
 const user=await actor(request.headers.authorization);
 if (!user || user.role!=='admin' || !pool) return reply.code(403).send({error:'Forbidden'});
 const {id,type}=request.params as {id:string;type:string};
 const {status,reason}=request.body as {status:'verified'|'rejected';reason:string};
 if(!uuid(id)||!documentTypes.some(t=>t===type)||reason.trim().length<5)return reply.code(400).send({error:'Invalid review'});
 const client=await pool.connect();
 try {
  await client.query('BEGIN');
  const onboarding=await client.query('SELECT approval_status,submitted_at FROM representative_onboarding WHERE representative_id=$1 FOR UPDATE',[id]);
  if(!onboarding.rowCount){await client.query('ROLLBACK');return reply.code(404).send({error:'Representative not found'})}
  if(!onboarding.rows[0].submitted_at||onboarding.rows[0].approval_status!=='pending'){await client.query('ROLLBACK');return reply.code(409).send({error:'Only submitted, pending onboarding can be reviewed'})}
  const doc=await client.query('SELECT id,review_status FROM representative_documents WHERE representative_id=$1 AND document_type=$2 FOR UPDATE',[id,type]);
  if(!doc.rowCount){await client.query('ROLLBACK');return reply.code(404).send({error:'Document not found'})}
  if(doc.rows[0].review_status!=='pending_review'){await client.query('ROLLBACK');return reply.code(409).send({error:'Document already reviewed'})}
  const seen=await client.query("SELECT 1 FROM representative_document_access_audit WHERE document_id=$1 AND administrator_id=$2 AND action='view' AND occurred_at>now()-interval '15 minutes' LIMIT 1",[doc.rows[0].id,user.id]);
  if(!seen.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'Open and inspect this document before reviewing it'})}
  await client.query('UPDATE representative_documents SET review_status=$3,reviewed_at=now(),reviewed_by=$4 WHERE representative_id=$1 AND document_type=$2',[id,type,status,user.id]);
  await client.query('INSERT INTO representative_document_access_audit(representative_id,document_type,document_id,administrator_id,action,reason) VALUES($1,$2,$3,$4,$5,$6)',[id,type,doc.rows[0].id,user.id,status,reason.trim()]);
  const rows=await client.query('SELECT document_type,review_status FROM representative_documents WHERE representative_id=$1',[id]);
  const state=new Map(rows.rows.map((d:{document_type:string;review_status:string})=>[d.document_type,d.review_status]));
  const identity=state.get('id_front')==='verified'&&state.get('id_back')==='verified'?'verified':state.get('id_front')==='rejected'||state.get('id_back')==='rejected'?'rejected':'pending_review';
  const tax=state.get('w9')==='verified'?'verified':state.get('w9')==='rejected'?'rejected':'pending_review';
  await client.query('UPDATE representative_onboarding SET identity_document_status=$2,tax_document_status=$3,updated_at=now() WHERE representative_id=$1',[id,identity,tax]);
  await client.query('COMMIT');
  return {documentType:type,status,identityStatus:identity,taxStatus:tax};
 }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
});
app.patch('/admin/representative-onboarding/:id/review', { schema: { body: { type: 'object', additionalProperties: false, required: ['status','reason'], properties: { status: { type: 'string', enum: ['approved','rejected','suspended','pending'] }, reason: { type: 'string', minLength: 5, maxLength: 1000 } } } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { status, reason } = request.body as { status: string; reason: string };
  if (!uuid(id) || reason.trim().length < 5) return reply.code(400).send({ error: 'Invalid review' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT approval_status FROM representative_onboarding WHERE representative_id=$1 FOR UPDATE', [id]);
    if (!existing.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Representative not found' }); }
    if (status==='approved') {
      const eligible = await client.query("SELECT 1 FROM representative_onboarding WHERE representative_id=$1 AND tax_document_status='verified' AND identity_document_status='verified' AND contractor_agreement_status='verified' AND legal_first_name IS NOT NULL AND legal_last_name IS NOT NULL AND mobile_phone IS NOT NULL AND address_line1 IS NOT NULL AND city IS NOT NULL AND state_region IS NOT NULL AND postal_code IS NOT NULL", [id]);
      if (!eligible.rowCount) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Required profile and verified documents must be complete before approval' }); }
    }
    await client.query("UPDATE representative_onboarding SET approval_status=$2,reviewed_by=$3,reviewed_at=now(),review_notes=$4,submitted_at=CASE WHEN $2='rejected' THEN NULL ELSE submitted_at END,updated_at=now() WHERE representative_id=$1", [id,status,user.id,reason.trim()]);
    await client.query('INSERT INTO representative_onboarding_reviews(representative_id,reviewed_by,old_status,new_status,reason) VALUES($1,$2,$3,$4,$5)', [id,user.id,existing.rows[0].approval_status,status,reason.trim()]);
    await client.query('COMMIT');
    return { representativeId:id, status };
  } catch (err) { await client.query('ROLLBACK'); throw err; } finally { client.release(); }
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
  receivedOn: { type: 'string', minLength: 10, maxLength: 10 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { paymentReference, receivedOn } = request.body as { paymentReference: string; receivedOn: string };
  const date = new Date(receivedOn + 'T00:00:00.000Z');
  if (!uuid(id) || !paymentReference.trim() || !/^\d{4}-\d{2}-\d{2}$/.test(receivedOn) || Number.isNaN(date.getTime()) || date.toISOString().slice(0,10) !== receivedOn)
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
// A payout records an actual external payment, never initiates one.
const payoutColumns = 'p.id,p.order_id AS "orderId",p.vendor_receipt_id AS "vendorReceiptId",p.representative_id AS "representativeId",p.payment_reference AS "paymentReference",p.amount::text,p.currency_code AS "currencyCode",p.paid_on::text AS "paidOn",p.recorded_by AS "recordedBy",p.recorded_at AS "recordedAt"';
app.post('/admin/orders/:id/representative-payout', { schema: { body: { type: 'object', additionalProperties: false, required: ['paymentReference','paidOn'], properties: {
  paymentReference: { type: 'string', minLength: 1, maxLength: 200 },
  paidOn: { type: 'string', minLength: 10, maxLength: 10 }
} } } }, async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const { id } = request.params as { id: string };
  const { paymentReference, paidOn } = request.body as { paymentReference: string; paidOn: string };
  const date = new Date(paidOn + 'T00:00:00.000Z');
  if (!uuid(id) || !paymentReference.trim() || !/^\d{4}-\d{2}-\d{2}$/.test(paidOn) || Number.isNaN(date.getTime()) || date.toISOString().slice(0,10) !== paidOn)
    return reply.code(400).send({ error: 'Invalid order, payment reference or calendar date' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const order = await client.query('SELECT id,representative_id,representative_amount::text AS amount,status FROM commission_orders WHERE id=$1 FOR UPDATE', [id]);
    if (!order.rowCount) { await client.query('ROLLBACK'); return reply.code(404).send({ error: 'Order not found' }); }
    if (order.rows[0].status !== 'approved' || Number(order.rows[0].amount) <= 0) {
      await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Order has no approved representative earnings' });
    }
    const receipt = await client.query('SELECT id FROM commission_vendor_receipts WHERE order_id=$1', [id]);
    if (!receipt.rowCount) { await client.query('ROLLBACK'); return reply.code(409).send({ error: 'Vendor payment must be recorded before payout' }); }
    const inserted = await client.query('INSERT INTO commission_representative_payouts(order_id,vendor_receipt_id,representative_id,payment_reference,amount,paid_on,recorded_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id',
      [id,receipt.rows[0].id,order.rows[0].representative_id,paymentReference.trim(),order.rows[0].amount,paidOn,user.id]);
    const result = await client.query('SELECT ' + payoutColumns + ' FROM commission_representative_payouts p WHERE p.id=$1', [inserted.rows[0].id]);
    await client.query('COMMIT');
    return reply.code(201).send({ payout: result.rows[0], transferInitiated: false });
  } catch (err) {
    await client.query('ROLLBACK');
    if ((err as { code?: string }).code === '23505') return reply.code(409).send({ error: 'Representative payout already recorded for order' });
    throw err;
  } finally { client.release(); }
});
app.get('/admin/representative-payouts', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query('SELECT ' + payoutColumns + ' FROM commission_representative_payouts p ORDER BY p.recorded_at DESC,p.id DESC LIMIT 100');
  return { payouts: result.rows };
});
app.get('/admin/commissions/representative-balances', async (request, reply) => {
  const user = await actor(request.headers.authorization);
  if (!user || user.role !== 'admin' || !pool) return reply.code(403).send({ error: 'Forbidden' });
  const result = await pool.query(`
    SELECT o.representative_id AS "representativeId",
      count(*)::int AS "approvedOrders",
      count(r.id)::int AS "fundedOrders",
      count(p.id)::int AS "paidOrders",
      coalesce(sum(o.representative_amount),0)::text AS "approvedEarnings",
      coalesce(sum(o.representative_amount) FILTER (WHERE r.id IS NOT NULL),0)::text AS "fundedEarnings",
      coalesce(sum(p.amount),0)::text AS "paidEarnings",
      coalesce(sum(o.representative_amount) FILTER (WHERE r.id IS NOT NULL AND p.id IS NULL),0)::text AS "fundedUnpaidBalance",
      coalesce(sum(o.representative_amount) FILTER (WHERE r.id IS NULL),0)::text AS "awaitingVendorPayment"
    FROM commission_orders o
    LEFT JOIN commission_vendor_receipts r ON r.order_id=o.id
    LEFT JOIN commission_representative_payouts p ON p.order_id=o.id
    WHERE o.status='approved'
    GROUP BY o.representative_id ORDER BY o.representative_id
  `);
  return { representatives: result.rows };
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
