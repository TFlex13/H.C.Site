import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdir,writeFile,unlink,readFile } from 'node:fs/promises';
import { join } from 'node:path';

type Actor = { id:string;role:string } | null | undefined;
const sha = (value:string)=>createHash('sha256').update(value).digest('hex');
const uuid = (value:string)=>/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
const emailRegex=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const tokenRegex=/^[a-f0-9]{64}$/;
const docTypes=['ein_letter','business_license','tobacco_license','other_license'];
const clean=(value:unknown,max=200)=>typeof value==='string'?value.trim().slice(0,max):'';
export function registerStoreOnboarding(app:FastifyInstance,pool:Pool|null,actor:(auth?:string)=>Promise<Actor>,storageRoot:string|undefined,key:Buffer|null) {
 const access=async (request:{headers:{authorization?:string}})=>actor(request.headers.authorization);
 const validInvite=async (token:unknown)=>{
  if(!pool||typeof token!=='string'||!tokenRegex.test(token))return null;
  const found=await pool.query(`SELECT i.id,i.representative_id,i.store_email,a.id AS application_id,a.status
    FROM store_onboarding_invites i LEFT JOIN store_onboarding_applications a ON a.invite_id=i.id
    WHERE i.token_hash=$1 AND i.revoked_at IS NULL AND i.expires_at>now()`,[sha(token)]);
  return found.rows[0] as {id:string;representative_id:string;store_email:string;application_id:string|null;status:string|null}|undefined??null;
 };
 app.post('/representative/store-invitations', {schema:{body:{type:'object',additionalProperties:false,required:['email'],properties:{email:{type:'string',maxLength:254}}}}},async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='representative'||!pool)return reply.code(403).send({error:'Forbidden'});
  const address=clean((request.body as {email:string}).email,254).toLowerCase();
  if(!emailRegex.test(address))return reply.code(400).send({error:'Enter a valid store email'});
  const approved=await pool.query("SELECT 1 FROM representative_onboarding WHERE representative_id=$1 AND approval_status='approved'",[user.id]);
  if(!approved.rowCount)return reply.code(403).send({error:'Representative approval required'});
  const token=randomBytes(32).toString('hex');
  await pool.query("INSERT INTO store_onboarding_invites(representative_id,store_email,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '7 days')",[user.id,address,sha(token)]);
  reply.header('Cache-Control','no-store');return {path:'/store/onboarding#token='+token,email:address,expiresInDays:7,sent:false};
 });
 app.get('/representative/store-invitations',async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='representative'||!pool)return reply.code(403).send({error:'Forbidden'});
  const found=await pool.query(`SELECT i.id,i.store_email AS "storeEmail",i.created_at AS "createdAt",i.expires_at AS "expiresAt",a.status
   FROM store_onboarding_invites i LEFT JOIN store_onboarding_applications a ON a.invite_id=i.id
   WHERE i.representative_id=$1 ORDER BY i.created_at DESC LIMIT 50`,[user.id]);
  return {invitations:found.rows};
 });
 app.post('/store/onboarding/details', {schema:{body:{type:'object',additionalProperties:false,required:['token'],properties:{token:{type:'string',maxLength:64}}}}},async(request,reply)=>{
  const invite=await validInvite((request.body as {token:string}).token);
  if(!invite||!pool)return reply.code(404).send({error:'Invitation invalid or expired'});
  const application=invite.application_id?(await pool.query(`SELECT legal_business_name AS "legalBusinessName",doing_business_as AS "doingBusinessAs",contact_name AS "contactName",contact_phone AS "contactPhone",address_line1 AS "addressLine1",address_line2 AS "addressLine2",city,state_region AS "stateRegion",postal_code AS "postalCode",ein_last4 AS "einLast4",status,review_reason AS "reviewReason" FROM store_onboarding_applications WHERE id=$1`,[invite.application_id])).rows[0]:null;
  const docs=invite.application_id?(await pool.query(`SELECT id,document_type AS "documentType",label,expiration_date::text AS "expirationDate",filename,review_status AS "status",rejection_reason AS "rejectionReason" FROM store_onboarding_documents WHERE application_id=$1 AND review_status<>'superseded' ORDER BY submitted_at DESC`,[invite.application_id])).rows:[];
  reply.header('Cache-Control','no-store');return {email:invite.store_email,application,documents:docs,uploadsEnabled:Boolean(key&&storageRoot)};
 });
 app.post('/store/onboarding/application',async(request,reply)=>{
  const body=request.body as Record<string,unknown>;
  const invite=await validInvite(body?.token);
  if(!invite||!pool)return reply.code(404).send({error:'Invitation invalid or expired'});
  const keys=['legalBusinessName','contactName','contactPhone','addressLine1','city','stateRegion','postalCode'];
  if(!keys.every(k=>clean(body[k],250)))return reply.code(400).send({error:'Complete all required business and contact fields'});
  const ein=clean(body.ein,20).replace(/-/g,'');
  if(ein&&!/^\d{9}$/.test(ein))return reply.code(400).send({error:'EIN must contain nine digits'});
  if(ein&&!key)return reply.code(503).send({error:'EIN encryption unavailable; configure private storage key'});
  let encrypted:Buffer|null=null;
  if(ein&&key){const iv=randomBytes(12);const cipher=createCipheriv('aes-256-gcm',key,iv);encrypted=Buffer.concat([iv,cipher.update(ein,'utf8'),cipher.final(),cipher.getAuthTag()]);}
  const values=[clean(body.legalBusinessName),clean(body.doingBusinessAs)||null,clean(body.contactName),clean(body.contactPhone,40),clean(body.addressLine1,250),clean(body.addressLine2,250)||null,clean(body.city,120),clean(body.stateRegion,120),clean(body.postalCode,30)];
  const client=await pool.connect();try{
   await client.query('BEGIN');
   const existing=await client.query('SELECT id,status,ein_ciphertext,ein_last4 FROM store_onboarding_applications WHERE invite_id=$1 FOR UPDATE',[invite.id]);
   if(existing.rowCount&&['submitted','approved','rejected'].includes(existing.rows[0].status)){await client.query('ROLLBACK');return reply.code(409).send({error:'Application is locked for review'});}
   const row=existing.rowCount?await client.query(`UPDATE store_onboarding_applications SET legal_business_name=$2,doing_business_as=$3,contact_name=$4,contact_phone=$5,address_line1=$6,address_line2=$7,city=$8,state_region=$9,postal_code=$10,ein_ciphertext=$11,ein_last4=$12,status='draft',updated_at=now() WHERE id=$1 RETURNING id`,[existing.rows[0].id,...values,encrypted??existing.rows[0].ein_ciphertext,ein?ein.slice(-4):existing.rows[0].ein_last4]):await client.query(`INSERT INTO store_onboarding_applications(invite_id,legal_business_name,doing_business_as,contact_name,contact_phone,address_line1,address_line2,city,state_region,postal_code,ein_ciphertext,ein_last4) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,[invite.id,...values,encrypted,ein?ein.slice(-4):null]);
   await client.query('COMMIT');return {applicationId:row.rows[0].id,status:'draft'};
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
 });
 app.post('/store/onboarding/documents/:type',{bodyLimit:10*1024*1024},async(request,reply)=>{
  if(!pool||!key||!storageRoot)return reply.code(503).send({error:'Encrypted document storage unavailable'});
  const type=(request.params as {type:string}).type;
  if(!docTypes.includes(type))return reply.code(400).send({error:'Invalid document type'});
  const token=request.headers['x-store-invite'];
  const invite=await validInvite(token);
  if(!invite?.application_id)return reply.code(403).send({error:'Save the application before uploading documents'});
  const state=await pool.query('SELECT status FROM store_onboarding_applications WHERE id=$1',[invite.application_id]);
  if(!['draft','changes_requested'].includes(state.rows[0]?.status))return reply.code(409).send({error:'Application documents are locked'});
  const filename=clean(request.headers['x-document-name'],180);
  const mime=clean(request.headers['x-document-mime'],80);
  const label=clean(request.headers['x-license-label'],120)||type.replaceAll('_',' ');
  const expiration=clean(request.headers['x-license-expires'],10);
  if(type!=='ein_letter'&&(!/^\d{4}-\d{2}-\d{2}$/.test(expiration)||Number.isNaN(Date.parse(expiration))||new Date(expiration).toISOString().slice(0,10)!==expiration))return reply.code(400).send({error:'Enter a valid license expiration date'});
  const data=request.body;
  if(!Buffer.isBuffer(data)||!data.length||data.length>10485760||!/^[a-zA-Z0-9_. ()-]{1,180}$/.test(filename))return reply.code(400).send({error:'Invalid file'});
  const pdf=data.subarray(0,5).toString()==='%PDF-',jpeg=data[0]===255&&data[1]===216&&data[2]===255,png=data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
  if(!((mime==='application/pdf'&&pdf)||(mime==='image/jpeg'&&jpeg)||(mime==='image/png'&&png)))return reply.code(415).send({error:'Use PDF, JPG or PNG'});
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
  const encrypted=Buffer.concat([iv,cipher.update(data),cipher.final(),cipher.getAuthTag()]);
  const storageKey=randomBytes(24).toString('hex');
  await mkdir(storageRoot,{recursive:true,mode:0o700});
  await writeFile(join(storageRoot,storageKey),encrypted,{flag:'wx',mode:0o600});
  const client=await pool.connect();
  try{
   await client.query('BEGIN');
   // Supersede only rejected evidence of the same type and label. Other licenses remain independent.
   await client.query("UPDATE store_onboarding_documents SET review_status='superseded' WHERE application_id=$1 AND document_type=$2 AND (label=$3 OR $2<>'other_license') AND review_status='rejected'",[invite.application_id,type,label]);
   const created=await client.query(`INSERT INTO store_onboarding_documents(application_id,document_type,label,expiration_date,filename,mime_type,byte_size,storage_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,[invite.application_id,type,label,type==='ein_letter'?null:expiration,filename,mime,data.length,storageKey]);
   await client.query('COMMIT');
   return reply.code(201).send({documentId:created.rows[0].id,status:'pending_review'});
  }catch(e){await client.query('ROLLBACK');await unlink(join(storageRoot,storageKey)).catch(()=>{});throw e}finally{client.release()}
 });
 app.post('/store/onboarding/submit',async(request,reply)=>{
  const invite=await validInvite((request.body as {token?:string})?.token);
  if(!invite?.application_id||!pool)return reply.code(404).send({error:'Application not found'});
  const changed=await pool.query("UPDATE store_onboarding_applications SET status='submitted',submitted_at=now(),review_reason=NULL,updated_at=now() WHERE id=$1 AND status IN ('draft','changes_requested') RETURNING id",[invite.application_id]);
  if(!changed.rowCount)return reply.code(409).send({error:'Application already submitted or locked'});
  return {status:'submitted',message:'Application received for administrator review. Licensing may require additional evidence.'};
 });
 app.get('/admin/store-onboarding',async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const found=await pool.query(`SELECT a.id,a.legal_business_name AS "businessName",a.city,a.state_region AS "stateRegion",a.status,a.submitted_at AS "submittedAt",a.review_reason AS "reviewReason",i.store_email AS "email",u.display_name AS "representativeName",i.representative_id AS "representativeId"
   FROM store_onboarding_applications a JOIN store_onboarding_invites i ON i.id=a.invite_id JOIN users u ON u.id=i.representative_id ORDER BY a.updated_at DESC LIMIT 200`);
  return {applications:found.rows};
 });
 app.get('/admin/store-onboarding/:id',async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const id=(request.params as {id:string}).id;if(!uuid(id))return reply.code(400).send({error:'Invalid ID'});
  const a=await pool.query(`SELECT a.id,a.legal_business_name AS "businessName",a.doing_business_as AS "dba",a.contact_name AS "contactName",a.contact_phone AS "contactPhone",a.address_line1 AS "addressLine1",a.address_line2 AS "addressLine2",a.city,a.state_region AS "stateRegion",a.postal_code AS "postalCode",a.ein_last4 AS "einLast4",a.status,a.review_reason AS "reviewReason",i.store_email AS "email",i.representative_id AS "representativeId" FROM store_onboarding_applications a JOIN store_onboarding_invites i ON i.id=a.invite_id WHERE a.id=$1`,[id]);
  if(!a.rowCount)return reply.code(404).send({error:'Not found'});
  const [docs,territories]=await Promise.all([
   pool.query(`SELECT id,document_type AS "documentType",label,expiration_date::text AS "expirationDate",filename,review_status AS "status",rejection_reason AS "rejectionReason" FROM store_onboarding_documents WHERE application_id=$1 AND review_status<>'superseded' ORDER BY submitted_at DESC`,[id]),
   pool.query(`SELECT t.id,t.name FROM representative_territories rt JOIN territories t ON t.id=rt.territory_id WHERE rt.representative_id=$1 AND t.active=true ORDER BY t.name`,[a.rows[0].representativeId])
  ]);
  return {application:a.rows[0],documents:docs.rows,eligibleTerritories:territories.rows};
 });
 app.get('/admin/store-onboarding/:id/documents/:docId/content',async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  if(!key||!storageRoot)return reply.code(503).send({error:'Private storage unavailable'});
  const {id,docId}=request.params as {id:string;docId:string};if(!uuid(id)||!uuid(docId))return reply.code(400).send({error:'Invalid ID'});
  const result=await pool.query('SELECT storage_key,mime_type,byte_size FROM store_onboarding_documents WHERE application_id=$1 AND id=$2',[id,docId]);
  if(!result.rowCount)return reply.code(404).send({error:'Document not found'});
  const d=result.rows[0];
  let encrypted:Buffer;try{encrypted=await readFile(join(storageRoot,d.storage_key));}catch{return reply.code(503).send({error:'Encrypted document unavailable'});}
  if(encrypted.length<29||encrypted.length>10485788)return reply.code(422).send({error:'Encrypted file invalid'});
  let clear:Buffer;try{const decipher=createDecipheriv('aes-256-gcm',key,encrypted.subarray(0,12));decipher.setAuthTag(encrypted.subarray(encrypted.length-16));clear=Buffer.concat([decipher.update(encrypted.subarray(12,encrypted.length-16)),decipher.final()]);}catch{return reply.code(422).send({error:'Decryption failed'});}
  if(clear.length!==d.byte_size)return reply.code(422).send({error:'File integrity mismatch'});
  await pool.query("INSERT INTO store_onboarding_audit(application_id,document_id,actor_id,action) VALUES($1,$2,$3,'view')",[id,docId,user.id]);
  reply.header('Cache-Control','no-store, private');reply.header('Content-Security-Policy',"default-src 'none'; sandbox");reply.header('X-Content-Type-Options','nosniff');reply.header('Content-Disposition','inline');return reply.type(d.mime_type).send(clear);
 });
 app.patch('/admin/store-onboarding/:id/documents/:docId/review',{schema:{body:{type:'object',required:['status'],additionalProperties:false,properties:{status:{type:'string',enum:['verified','rejected']},reason:{type:'string',maxLength:1000}}}}},async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const {id,docId}=request.params as {id:string;docId:string};if(!uuid(id)||!uuid(docId))return reply.code(400).send({error:'Invalid ID'});
  const {status,reason}=request.body as {status:'verified'|'rejected';reason?:string};
  if(status==='rejected'&&(!reason||reason.trim().length<5))return reply.code(400).send({error:'Explain the rejection in at least five characters'});
  const found=await pool.query(`SELECT d.id,d.submitted_at,d.expiration_date FROM store_onboarding_documents d JOIN store_onboarding_applications a ON a.id=d.application_id WHERE a.id=$1 AND d.id=$2 AND d.review_status='pending_review' AND a.status='submitted'`,[id,docId]);
  if(!found.rowCount)return reply.code(409).send({error:'Document is not awaiting review'});
  if(status==='verified' && found.rows[0].expiration_date && new Date(found.rows[0].expiration_date).getTime()<new Date(new Date().toISOString().slice(0,10)).getTime())return reply.code(409).send({error:'Expired licenses cannot be verified; request a current license'});
  const viewed=await pool.query("SELECT 1 FROM store_onboarding_audit WHERE application_id=$1 AND document_id=$2 AND actor_id=$3 AND action='view' AND occurred_at >= $4 AND occurred_at>now()-interval '15 minutes' LIMIT 1",[id,docId,user.id,found.rows[0].submitted_at]);
  if(!viewed.rowCount)return reply.code(409).send({error:'Open the document before reviewing'});
  await pool.query('UPDATE store_onboarding_documents SET review_status=$3,rejection_reason=$4,reviewed_by=$5,reviewed_at=now() WHERE application_id=$1 AND id=$2',[id,docId,status,status==='rejected'?reason!.trim():null,user.id]);
  await pool.query('INSERT INTO store_onboarding_audit(application_id,document_id,actor_id,action,reason) VALUES($1,$2,$3,$4,$5)',[id,docId,user.id,status,status==='rejected'?reason!.trim():null]);
  return {status};
 });
 app.patch('/admin/store-onboarding/:id/decision',{schema:{body:{type:'object',required:['status'],additionalProperties:false,properties:{status:{type:'string',enum:['approved','changes_requested','rejected']},reason:{type:'string',maxLength:1000}}}}},async(request,reply)=>{
  const user=await access(request);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const id=(request.params as {id:string}).id;if(!uuid(id))return reply.code(400).send({error:'Invalid ID'});
  const {status,reason}=request.body as {status:'approved'|'changes_requested'|'rejected';reason?:string};
  if(status!=='approved'&&(!reason||reason.trim().length<5))return reply.code(400).send({error:'Review reason required'});
  const client=await pool.connect();
  try{
   await client.query('BEGIN');
   const result=await client.query(`SELECT a.*,i.representative_id,i.store_email FROM store_onboarding_applications a JOIN store_onboarding_invites i ON i.id=a.invite_id WHERE a.id=$1 FOR UPDATE OF a`,[id]);
   const a=result.rows[0];if(!a||a.status!=='submitted'){await client.query('ROLLBACK');return reply.code(409).send({error:'Only submitted applications can be reviewed'});}
   let storeId:string|null=null;
   if(status==='approved'){
    const review=await client.query("SELECT count(*) FILTER (WHERE review_status NOT IN ('verified','superseded'))::int AS outstanding, count(*) FILTER (WHERE review_status='verified' AND expiration_date<current_date)::int AS expired FROM store_onboarding_documents WHERE application_id=$1",[id]);
    if(review.rows[0].outstanding>0||review.rows[0].expired>0){await client.query('ROLLBACK');return reply.code(409).send({error:'All active submitted documents must be verified and unexpired before approval'});}
    // Serialize all first-store approvals for the same representative.
    // The inviting representative is fixed by the invitation; administrators do not reassign here.
    const rep=await client.query(`SELECT u.id,u.display_name FROM users u JOIN representative_onboarding o ON o.representative_id=u.id
      WHERE u.id=$1 AND u.role='representative' AND u.active=true AND o.approval_status='approved' FOR UPDATE OF u`,[a.representative_id]);
    if(!rep.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'Inviting representative must have an active approved account'});}
    let portfolio=await client.query('SELECT territory_id FROM representative_store_portfolios WHERE representative_id=$1',[a.representative_id]);
    let territoryId:string;
    if(portfolio.rowCount){
      territoryId=portfolio.rows[0].territory_id;
      const active=await client.query('SELECT 1 FROM territories WHERE id=$1 AND active=true',[territoryId]);
      if(!active.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'Representative store portfolio is inactive; contact an administrator'});}
    }else{
      const label=(rep.rows[0].display_name||'Representative').slice(0,65);
      const name=label+' store portfolio ('+a.representative_id.slice(0,8)+')';
      const created=await client.query('INSERT INTO territories(name,description) VALUES($1,$2) RETURNING id',[name,'Store portfolio created from representative-originated approved registrations; not an exclusive geographic boundary']);
      territoryId=created.rows[0].id;
      await client.query('INSERT INTO representative_territories(representative_id,territory_id,assigned_by) VALUES($1,$2,$3)',[a.representative_id,territoryId,user.id]);
      await client.query('INSERT INTO representative_store_portfolios(representative_id,territory_id) VALUES($1,$2)',[a.representative_id,territoryId]);
    }
    const store=await client.query(`INSERT INTO stores(name,address_line1,address_line2,city,state_region,postal_code,contact_name,contact_email,contact_phone,territory_id,primary_representative_id,active) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true) RETURNING id`,[a.doing_business_as||a.legal_business_name,a.address_line1,a.address_line2,a.city,a.state_region,a.postal_code,a.contact_name,a.store_email,a.contact_phone,territoryId,a.representative_id]);
    storeId=store.rows[0].id;
    await client.query('INSERT INTO store_assignment_events(store_id,new_territory_id,new_representative_id,changed_by) VALUES($1,$2,$3,$4)',[storeId,territoryId,a.representative_id,user.id]);
   }
   await client.query('UPDATE store_onboarding_applications SET status=$2,reviewed_by=$3,reviewed_at=now(),review_reason=$4,approved_store_id=$5,updated_at=now() WHERE id=$1',[id,status,user.id,reason?.trim()||null,storeId]);
   await client.query('INSERT INTO store_onboarding_audit(application_id,actor_id,action,reason) VALUES($1,$2,$3,$4)',[id,user.id,status,reason?.trim()||null]);
   await client.query('COMMIT');return {status,storeId};
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
 });
}
