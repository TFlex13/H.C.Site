import type {FastifyInstance} from 'fastify';
import type {Pool} from 'pg';
import {newToken,tokenHash,hashPassword} from './security.js';
type Actor={id:string;role:string;email?:string;display_name?:string}|null|undefined;
const uuid=(s:string)=>/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
const amountPattern=/^(?:0|[1-9]\d{0,9})(?:\.\d{1,4})?$/;
const percentPattern=/^(?:0|[1-9]\d{0,2})(?:\.\d{1,4})?$/;
const amount=(s:string)=>amountPattern.test(s)&&Number(s)<=9999999999?Number(s):null;
const percent=(s:string)=>percentPattern.test(s)&&Number(s)<=100?Math.round(Number(s)*10000):null;
const text=(v:unknown,max=200)=>typeof v==='string'?v.trim().slice(0,max):'';
const offerFields=`o.id,o.product_id AS "productId",p.sku,p.name,p.description,p.category,p.unit_label AS "unitLabel",p.active,
 o.wholesale_price::text AS "wholesalePrice",o.vendor_unit_cost::text AS "vendorUnitCost",
 o.proposed_service_fee_percent::text AS "serviceFeePercent",o.approved_highline_percent::text AS "highlinePercent",
 o.approved_representative_percent::text AS "representativePercent",
 o.status,o.submitted_at AS "submittedAt",o.reviewed_at AS "reviewedAt",o.review_reason AS "reviewReason"`;
const offerBody={type:'object',additionalProperties:false,required:['wholesalePrice','vendorUnitCost','serviceFeePercent'],properties:{
 wholesalePrice:{type:'string',maxLength:20},vendorUnitCost:{type:'string',maxLength:20},serviceFeePercent:{type:'string',maxLength:12}
}} as const;
export function registerVendorPortal(app:FastifyInstance,pool:Pool|null,actor:(auth?:string)=>Promise<Actor>){
 const current=async(authorization?:string)=>{
  const user=await actor(authorization);
  if(!user||user.role!=='vendor'||!pool)return null;
  const result=await pool.query('SELECT v.id,v.name,v.active FROM vendor_memberships m JOIN vendors v ON v.id=m.vendor_id WHERE m.user_id=$1',[user.id]);
  return result.rowCount&&result.rows[0].active?{...user,vendor:result.rows[0]}:null;
 };
 app.post('/admin/vendors/:id/invitations',{schema:{body:{type:'object',additionalProperties:false,required:['email'],properties:{email:{type:'string',maxLength:254}}}}},async(request,reply)=>{
  const admin=await actor(request.headers.authorization);if(!admin||admin.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const id=(request.params as {id:string}).id,mail=text((request.body as {email:string}).email,254).toLowerCase();
  if(!uuid(id)||! /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail))return reply.code(400).send({error:'Invalid vendor or email'});
  const exists=await pool.query('SELECT id FROM vendors WHERE id=$1 AND active=true',[id]);
  if(!exists.rowCount)return reply.code(404).send({error:'Active vendor not found'});
  const account=await pool.query('SELECT id FROM users WHERE email=$1',[mail]);
  if(account.rowCount)return reply.code(409).send({error:'This email already has a platform login; contact an administrator'});
  const raw=newToken();
  await pool.query("INSERT INTO vendor_invitations(vendor_id,email,token_hash,invited_by,expires_at) VALUES($1,$2,$3,$4,now()+interval '48 hours')",[id,mail,tokenHash(raw),admin.id]);
  reply.header('Cache-Control','no-store');return {path:'/vendor/signup#token='+raw,expiresInHours:48,sent:false};
 });
 app.post('/vendor/invitations/accept',{schema:{body:{type:'object',additionalProperties:false,required:['token','displayName','password'],properties:{
 token:{type:'string',minLength:43,maxLength:43},displayName:{type:'string',minLength:1,maxLength:160},password:{type:'string',minLength:12,maxLength:1024}
 }}}},async(request,reply)=>{
  if(!pool)return reply.code(503).send({error:'Database unavailable'});
  const b=request.body as {token:string;displayName:string;password:string};
  const display=text(b.displayName,160);if(!display)return reply.code(400).send({error:'Enter a display name'});
  const pass=await hashPassword(b.password);
  const client=await pool.connect();try{
   await client.query('BEGIN');
   const found=await client.query(`SELECT i.id,i.email,i.vendor_id FROM vendor_invitations i JOIN vendors v ON v.id=i.vendor_id
   WHERE i.token_hash=$1 AND i.accepted_at IS NULL AND i.expires_at>now() AND v.active=true FOR UPDATE OF i`,[tokenHash(b.token)]);
   if(!found.rowCount){await client.query('ROLLBACK');return reply.code(410).send({error:'Invitation invalid, used or expired'})}
   const invitation=found.rows[0];
   const created=await client.query("INSERT INTO users(email,display_name,password_hash,role) VALUES($1,$2,$3,'vendor') ON CONFLICT(email) DO NOTHING RETURNING id",[invitation.email,display,pass]);
   if(!created.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'Email already registered'})}
   await client.query('INSERT INTO vendor_memberships(user_id,vendor_id) VALUES($1,$2)',[created.rows[0].id,invitation.vendor_id]);
   await client.query('UPDATE vendor_invitations SET accepted_at=now() WHERE id=$1',[invitation.id]);
   await client.query("INSERT INTO auth_audit_events(actor_id,action,subject_email) VALUES($1,'vendor_invitation_accepted',$2)",[created.rows[0].id,invitation.email]);
   await client.query('COMMIT');return reply.code(201).send({status:'created'});
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 });
 app.get('/vendor/overview',async(request,reply)=>{
  const member=await current(request.headers.authorization);if(!member||!pool)return reply.code(403).send({error:'Vendor access required'});
  const products=await pool.query(`SELECT p.id,p.sku,p.name,p.description,p.category,p.unit_label AS "unitLabel",p.active,
   o.id AS "offerId",o.wholesale_price::text AS "wholesalePrice",o.vendor_unit_cost::text AS "vendorUnitCost",
   o.proposed_service_fee_percent::text AS "serviceFeePercent",
   o.approved_highline_percent::text AS "highlinePercent",o.approved_representative_percent::text AS "representativePercent",
   o.status AS "offerStatus",o.review_reason AS "reviewReason"
   FROM vendor_products p LEFT JOIN LATERAL (
     SELECT * FROM vendor_product_offers o WHERE o.product_id=p.id ORDER BY o.submitted_at DESC,o.id DESC LIMIT 1
   ) o ON true WHERE p.vendor_id=$1 ORDER BY p.name,p.id`,[member.vendor.id]);
  reply.header('Cache-Control','no-store, private');
  return {vendor:member.vendor,account:{displayName:member.display_name,email:member.email},products:products.rows,currency:'USD'};
 });
 app.post('/vendor/products',{schema:{body:{type:'object',additionalProperties:false,required:['sku','name','unitLabel','wholesalePrice','vendorUnitCost','serviceFeePercent'],properties:{
 sku:{type:'string',minLength:1,maxLength:80},name:{type:'string',minLength:1,maxLength:200},
 description:{type:'string',maxLength:2000},category:{type:'string',maxLength:100},
 unitLabel:{type:'string',minLength:1,maxLength:80},
 ...offerBody.properties
 }}}},async(request,reply)=>{
  const member=await current(request.headers.authorization);if(!member||!pool)return reply.code(403).send({error:'Vendor access required'});
  const b=request.body as {sku:string;name:string;description?:string;category?:string;unitLabel:string;wholesalePrice:string;vendorUnitCost:string;serviceFeePercent:string};
  const sku=text(b.sku,80),name=text(b.name),unit=text(b.unitLabel,80),sale=amount(b.wholesalePrice),cost=amount(b.vendorUnitCost),fee=percent(b.serviceFeePercent);
  if(!sku||!name||!unit||sale===null||cost===null||cost>sale||fee===null)return reply.code(400).send({error:'Enter valid product details, pricing, cost and commission percent'});
  const client=await pool.connect();try{
   await client.query('BEGIN');
   const product=await client.query('INSERT INTO vendor_products(vendor_id,sku,name,description,category,unit_label) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',[member.vendor.id,sku,name,text(b.description,2000)||null,text(b.category,100)||null,unit]);
   const offer=await client.query("INSERT INTO vendor_product_offers(product_id,vendor_id,wholesale_price,vendor_unit_cost,proposed_service_fee_percent,submitted_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",[product.rows[0].id,member.vendor.id,b.wholesalePrice,b.vendorUnitCost,b.serviceFeePercent,member.id]);
   await client.query("INSERT INTO vendor_catalog_audit(vendor_id,product_id,offer_id,actor_id,action) VALUES($1,$2,$3,$4,'offer_submitted')",[member.vendor.id,product.rows[0].id,offer.rows[0].id,member.id]);
   await client.query('COMMIT');return reply.code(201).send({productId:product.rows[0].id,offerId:offer.rows[0].id,status:'pending_review'});
  }catch(err){await client.query('ROLLBACK');if((err as {code?:string}).code==='23505')return reply.code(409).send({error:'SKU already exists for this vendor'});throw err}finally{client.release()}
 });
 app.post('/vendor/products/:id/offers',{schema:{body:offerBody},async(request,reply)=>{
  const member=await current(request.headers.authorization);if(!member||!pool)return reply.code(403).send({error:'Vendor access required'});
  const id=(request.params as {id:string}).id,b=request.body as {wholesalePrice:string;vendorUnitCost:string;serviceFeePercent:string};
  if(!uuid(id))return reply.code(400).send({error:'Invalid product ID'});
  const sale=amount(b.wholesalePrice),cost=amount(b.vendorUnitCost),fee=percent(b.serviceFeePercent);
  if(sale===null||cost===null||cost>sale||fee===null)return reply.code(400).send({error:'Invalid price, cost or commission'});
  const client=await pool.connect();try{
   await client.query('BEGIN');
   const product=await client.query('SELECT id FROM vendor_products WHERE id=$1 AND vendor_id=$2 FOR UPDATE',[id,member.vendor.id]);
   if(!product.rowCount){await client.query('ROLLBACK');return reply.code(404).send({error:'Product not found'})}
   const pending=await client.query("SELECT 1 FROM vendor_product_offers WHERE product_id=$1 AND status='pending_review'",[id]);
   if(pending.rowCount){await client.query('ROLLBACK');return reply.code(409).send({error:'An offer is already awaiting review'})}
   const offer=await client.query("INSERT INTO vendor_product_offers(product_id,vendor_id,wholesale_price,vendor_unit_cost,proposed_service_fee_percent,submitted_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",[id,member.vendor.id,b.wholesalePrice,b.vendorUnitCost,b.serviceFeePercent,member.id]);
   await client.query("INSERT INTO vendor_catalog_audit(vendor_id,product_id,offer_id,actor_id,action) VALUES($1,$2,$3,$4,'offer_submitted')",[member.vendor.id,id,offer.rows[0].id,member.id]);
   await client.query('COMMIT');return reply.code(201).send({offerId:offer.rows[0].id,status:'pending_review'});
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 });
 app.get('/admin/vendor-catalog/offers',async(request,reply)=>{
  const admin=await actor(request.headers.authorization);if(!admin||admin.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const rows=await pool.query(`SELECT ${offerFields},v.name AS "vendorName",v.id AS "vendorId"
  FROM vendor_product_offers o JOIN vendor_products p ON p.id=o.product_id JOIN vendors v ON v.id=o.vendor_id
  WHERE o.status='pending_review' ORDER BY o.submitted_at ASC LIMIT 200`);
  return {offers:rows.rows};
 });
 app.get('/admin/vendor-catalog/products',async(request,reply)=>{
  const admin=await actor(request.headers.authorization);if(!admin||admin.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const rows=await pool.query(`SELECT p.id,p.sku,p.name,p.category,p.active,v.name AS "vendorName",
    o.wholesale_price::text AS "wholesalePrice",o.proposed_service_fee_percent::text AS "serviceFeePercent",
    o.approved_representative_percent::text AS "representativePercent"
    FROM vendor_products p JOIN vendors v ON v.id=p.vendor_id
    LEFT JOIN LATERAL(SELECT * FROM vendor_product_offers o WHERE o.product_id=p.id AND o.status='approved' ORDER BY o.reviewed_at DESC LIMIT 1)o ON true
    ORDER BY v.name,p.name LIMIT 500`);
  return {products:rows.rows};
 });
 app.patch('/admin/vendor-catalog/offers/:id/review',{schema:{body:{type:'object',additionalProperties:false,required:['status'],properties:{
  status:{type:'string',enum:['approved','rejected']},reason:{type:'string',maxLength:1000},
  highlinePercent:{type:'string',maxLength:12},representativePercent:{type:'string',maxLength:12}
 }}}},async(request,reply)=>{
  const admin=await actor(request.headers.authorization);if(!admin||admin.role!=='admin'||!pool)return reply.code(403).send({error:'Forbidden'});
  const id=(request.params as {id:string}).id,b=request.body as {status:'approved'|'rejected';reason?:string;highlinePercent?:string;representativePercent?:string};
  if(!uuid(id))return reply.code(400).send({error:'Invalid offer ID'});
  if(b.status==='rejected'&&text(b.reason,1000).length<5)return reply.code(400).send({error:'Explain rejection in at least five characters'});
  const client=await pool.connect();try{
   await client.query('BEGIN');
   const found=await client.query("SELECT o.*,p.vendor_id AS product_vendor_id FROM vendor_product_offers o JOIN vendor_products p ON p.id=o.product_id WHERE o.id=$1 FOR UPDATE OF o",[id]);
   const o=found.rows[0];
   if(!o||o.status!=='pending_review'){await client.query('ROLLBACK');return reply.code(409).send({error:'Offer no longer pending'})}
   if(b.status==='approved'){
    const high=percent(b.highlinePercent||''),rep=percent(b.representativePercent||''),fee=percent(String(o.proposed_service_fee_percent));
    if(high===null||rep===null||fee===null||high+rep!==fee){await client.query('ROLLBACK');return reply.code(400).send({error:'Highline plus representative percentages must equal the vendor service fee'})}
    await client.query("UPDATE vendor_product_offers SET status='superseded' WHERE product_id=$1 AND status='approved'",[o.product_id]);
    await client.query("UPDATE vendor_product_offers SET status='approved',approved_highline_percent=$2,approved_representative_percent=$3,reviewed_by=$4,reviewed_at=now(),review_reason=NULL WHERE id=$1",[id,b.highlinePercent,b.representativePercent,admin.id]);
    await client.query('UPDATE vendor_products SET active=true,updated_at=now() WHERE id=$1',[o.product_id]);
   }else{
    await client.query("UPDATE vendor_product_offers SET status='rejected',reviewed_by=$2,reviewed_at=now(),review_reason=$3 WHERE id=$1",[id,admin.id,text(b.reason,1000)]);
   }
   await client.query('INSERT INTO vendor_catalog_audit(vendor_id,product_id,offer_id,actor_id,action,detail) VALUES($1,$2,$3,$4,$5,$6)',[o.vendor_id,o.product_id,id,admin.id,b.status,text(b.reason,1000)||null]);
   await client.query('COMMIT');return {status:b.status};
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 });
}
