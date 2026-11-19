import type {FastifyInstance} from 'fastify';
import type {Pool} from 'pg';
import {hashPassword,newToken,tokenHash} from './security.js';
type Actor={id:string;role:string;email?:string;display_name?:string}|null|undefined;
const uuid=(s:string)=>/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(s);
const emailFormat=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const catalogQuery=`SELECT p.id,p.sku,p.name,p.description,p.category,p.unit_label AS "unitLabel",v.name AS "vendorName",
 o.id AS "offerId",o.wholesale_price::text AS "wholesalePrice"
 FROM vendor_products p JOIN vendors v ON v.id=p.vendor_id AND v.active=true
 JOIN LATERAL(SELECT id,wholesale_price FROM vendor_product_offers
 WHERE product_id=p.id AND status='approved' ORDER BY reviewed_at DESC,id DESC LIMIT 1)o ON true
 WHERE p.active=true ORDER BY v.name,p.name LIMIT 500`;
export function registerCatalogOrders(app:FastifyInstance,pool:Pool|null,actor:(auth?:string)=>Promise<Actor>){
 const storeFor=async(user:Actor)=>{
  if(!user||!pool||user.role!=='store')return null;
  const found=await pool.query(`SELECT s.id,s.name,s.active,s.primary_representative_id AS "representativeId"
    FROM store_memberships m JOIN stores s ON s.id=m.store_id WHERE m.user_id=$1`,[user.id]);
  return found.rows[0]||null;
 };
 const repCheck=async(id:string)=>pool!.query("SELECT 1 FROM users u JOIN representative_onboarding o ON o.representative_id=u.id WHERE u.id=$1 AND u.role='representative' AND u.active=true AND o.approval_status='approved'",[id]);
 app.post('/admin/stores/:id/account-invitations',{schema:{body:{type:'object',additionalProperties:false,required:['email'],properties:{email:{type:'string',maxLength:254}}}}},async(request,reply)=>{
  const user=await actor(request.headers.authorization);if(!user||user.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const id=(request.params as {id:string}).id,mail=String((request.body as {email:string}).email||'').trim().toLowerCase();
  if(!uuid(id)||!emailFormat.test(mail))return reply.code(400).send({error:'Invalid store or email'});
  const store=await pool.query('SELECT id,contact_email FROM stores WHERE id=$1 AND active=true',[id]);
  if(!store.rowCount)return reply.code(404).send({error:'Active store not found'});
  if(mail!==String(store.rows[0].contact_email||'').toLowerCase())return reply.code(409).send({error:'Invitation email must match the approved store contact email'});
  if((await pool.query('SELECT 1 FROM users WHERE email=$1',[mail])).rowCount)return reply.code(409).send({error:'This email already has an account'});
  const secret=newToken();
  await pool.query("INSERT INTO store_account_invitations(store_id,email,token_hash,invited_by,expires_at) VALUES($1,$2,$3,$4,now()+interval '48 hours')",[id,mail,tokenHash(secret),user.id]);
  reply.header('Cache-Control','no-store, private');return {path:'/store/account#token='+secret,expiresInHours:48,sent:false};
 });
 app.post('/store/account/accept',{schema:{body:{type:'object',additionalProperties:false,required:['token','displayName','password'],properties:{
  token:{type:'string',minLength:43,maxLength:43},displayName:{type:'string',minLength:1,maxLength:160},password:{type:'string',minLength:12,maxLength:1024}
 }}}},async(request,reply)=>{
  if(!pool)return reply.code(503).send({error:'Database unavailable'});
  const b=request.body as {token:string;displayName:string;password:string};
  const name=b.displayName.trim();if(!name)return reply.code(400).send({error:'Display name is required'});
  const hash=await hashPassword(b.password);const client=await pool.connect();
  try{await client.query('BEGIN');
   const result=await client.query(`SELECT i.id,i.store_id,i.email FROM store_account_invitations i JOIN stores s ON s.id=i.store_id
    WHERE i.token_hash=$1 AND i.accepted_at IS NULL AND i.expires_at>now() AND s.active=true FOR UPDATE OF i`,[tokenHash(b.token)]);
   if(!result.rowCount){await client.query('ROLLBACK');return reply.code(410).send({error:'Invitation expired or already used'})}
   const invite=result.rows[0];
   const created=await client.query("INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,'store') ON CONFLICT(email) DO NOTHING RETURNING id",[invite.email,name,hash]);
   if(!created.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'Email already registered'})}
   await client.query('INSERT INTO store_memberships(user_id,store_id) VALUES($1,$2)',[created.rows[0].id,invite.store_id]);
   await client.query('UPDATE store_account_invitations SET accepted_at=now() WHERE id=$1',[invite.id]);
   await client.query("INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,'store_invitation_accepted',$2)",[created.rows[0].id,invite.email]);
   await client.query('COMMIT');return reply.code(201).send({status:'created'})
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 });
 app.get('/store/account/overview',async(request,reply)=>{
  const user=await actor(request.headers.authorization);const store=await storeFor(user);
  if(!store||!store.active)return reply.code(403).send({error:'Active store login required'});
  reply.header('Cache-Control','no-store, private');
  return {store:{id:store.id,name:store.name},account:{email:user!.email,displayName:user!.display_name}};
 });
 app.get('/store/catalog',async(request,reply)=>{
  const user=await actor(request.headers.authorization),store=await storeFor(user);
  if(!store||!store.active||!pool)return reply.code(403).send({error:'Active store login required'});
  const rows=await pool.query(catalogQuery);
  reply.header('Cache-Control','no-store, private');return {products:rows.rows,currencyCode:'USD'};
 });
 app.get('/representative/catalog/orderable',async(request,reply)=>{
  const user=await actor(request.headers.authorization);
  if(!user||user.role!=='representative'||!pool||!(await repCheck(user.id)).rowCount)return reply.code(403).send({error:'Approved representative required'});
  const [stores,products]=await Promise.all([pool.query('SELECT id,name FROM stores WHERE primary_representative_id=$1 AND active=true ORDER BY name',[user.id]),pool.query(catalogQuery)]);
  reply.header('Cache-Control','no-store, private');return {stores:stores.rows,products:products.rows,currencyCode:'USD'};
 });
 app.post('/catalog/order-requests',{schema:{body:{type:'object',additionalProperties:false,required:['storeId','items'],properties:{
  storeId:{type:'string',minLength:36,maxLength:36},items:{type:'array',minItems:1,maxItems:50,items:{type:'object',additionalProperties:false,required:['productId','quantity'],properties:{
   productId:{type:'string',minLength:36,maxLength:36},quantity:{type:'integer',minimum:1,maximum:10000}
  }}}
 }}}},async(request,reply)=>{
  const user=await actor(request.headers.authorization);if(!user||!['store','representative'].includes(user.role)||!pool)return reply.code(403).send({error:'Unauthorized'});
  const b=request.body as {storeId:string;items:Array<{productId:string;quantity:number}>};
  if(!uuid(b.storeId)||b.items.some(x=>!uuid(x.productId))||new Set(b.items.map(x=>x.productId)).size!==b.items.length)return reply.code(400).send({error:'Invalid store, product or duplicate items'});
  const client=await pool.connect();try{await client.query('BEGIN');
   const store=await client.query('SELECT id,active,primary_representative_id FROM stores WHERE id=$1 FOR SHARE',[b.storeId]);
   if(!store.rowCount||!store.rows[0].active){await client.query('ROLLBACK');return reply.code(404).send({error:'Active store not found'})}
   const repId=store.rows[0].primary_representative_id as string|null;
   if(!repId||(await client.query("SELECT 1 FROM users u JOIN representative_onboarding o ON o.representative_id=u.id WHERE u.id=$1 AND u.active=true AND o.approval_status='approved'",[repId])).rowCount===0){await client.query('ROLLBACK');return reply.code(409).send({error:'Store representative not eligible'})}
   if(user.role==='representative'&&repId!==user.id){await client.query('ROLLBACK');return reply.code(403).send({error:'Store is not assigned to you'})}
   if(user.role==='store'&&!(await client.query('SELECT 1 FROM store_memberships WHERE store_id=$1 AND user_id=$2',[b.storeId,user.id])).rowCount){await client.query('ROLLBACK');return reply.code(403).send({error:'Store account does not belong to this store'})}
   const approved=await client.query(`SELECT p.id,p.name,p.sku,p.vendor_id,o.id AS offer_id,o.wholesale_price::text AS price
     FROM vendor_products p JOIN vendors v ON v.id=p.vendor_id AND v.active=true
     JOIN LATERAL (SELECT id,wholesale_price FROM vendor_product_offers WHERE product_id=p.id AND status='approved' ORDER BY reviewed_at DESC,id DESC LIMIT 1)o ON true
     WHERE p.active=true AND p.id=ANY($1::uuid[]) FOR SHARE OF p`,[b.items.map(x=>x.productId)]);
   if(approved.rowCount!==b.items.length){await client.query('ROLLBACK');return reply.code(409).send({error:'One or more products are unavailable'})}
   const map=new Map(approved.rows.map(p=>[p.id,p]));
   let total=0n;const snapshots=[] as Array<{p:any;q:number;unit:bigint;extended:bigint}>;
   for(const item of b.items){const p=map.get(item.productId);const [whole,fraction='']=String(p.price).split('.');const unit=BigInt(whole)*10000n+BigInt(fraction.padEnd(4,'0'));const extended=unit*BigInt(item.quantity);total+=extended;snapshots.push({p,q:item.quantity,unit,extended})}
   if(total>9999999999999999n){await client.query('ROLLBACK');return reply.code(400).send({error:'Order request exceeds permitted total'})}
   const format=(n:bigint)=>(n/10000n).toString()+'.'+(n%10000n).toString().padStart(4,'0');
   const result=await client.query("INSERT INTO catalog_order_requests(store_id,representative_id,requested_by,requested_by_role,total_wholesale) VALUES($1,$2,$3,$4,$5) RETURNING id,status,requested_at AS \"requestedAt\"",[b.storeId,repId,user.id,user.role,format(total)]);
   for(const {p,q,unit,extended} of snapshots)await client.query('INSERT INTO catalog_order_request_items(request_id,product_id,offer_id,vendor_id,sku,product_name,quantity,unit_wholesale_price,extended_wholesale) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',[result.rows[0].id,p.id,p.offer_id,p.vendor_id,p.sku,p.name,q,format(unit),format(extended)]);
   await client.query('COMMIT');return reply.code(201).send({orderRequest:{...result.rows[0],totalWholesale:format(total)},message:'Request submitted for administrative review; no payment or fulfillment initiated'});
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 });
 app.get('/catalog/order-requests',async(request,reply)=>{
  const user=await actor(request.headers.authorization);if(!user||!pool||!['representative','store','admin'].includes(user.role))return reply.code(403).send({error:'Forbidden'});
  let rows;if(user.role==='store'){const store=await storeFor(user);if(!store)return reply.code(403).send({error:'Forbidden'});rows=await pool.query('SELECT id,store_id AS "storeId",status,requested_by_role AS "requestedByRole",total_wholesale::text AS "totalWholesale",requested_at AS "requestedAt" FROM catalog_order_requests WHERE store_id=$1 ORDER BY requested_at DESC LIMIT 50',[store.id])}
  else if(user.role==='representative')rows=await pool.query('SELECT id,store_id AS "storeId",status,requested_by_role AS "requestedByRole",total_wholesale::text AS "totalWholesale",requested_at AS "requestedAt" FROM catalog_order_requests WHERE representative_id=$1 ORDER BY requested_at DESC LIMIT 50',[user.id]);
  else rows=await pool.query('SELECT r.id,r.store_id AS "storeId",s.name AS "storeName",r.status,r.requested_by_role AS "requestedByRole",r.total_wholesale::text AS "totalWholesale",r.requested_at AS "requestedAt" FROM catalog_order_requests r JOIN stores s ON s.id=r.store_id ORDER BY r.requested_at DESC LIMIT 100');
  reply.header('Cache-Control','no-store, private');return {requests:rows.rows}
 });
}