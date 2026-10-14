import { makeDeviceVerifier, requireDevice } from './device-proof.mjs';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let runtime;
function getRuntime(){
 if(!runtime){const key=process.env.SUPABASE_SECRET_KEY;
 runtime={db:createClient(new URL(config.identityProvider.issuer).origin,key,{auth:{persistSession:false,autoRefreshToken:false}}),verify:createLoginVerifier({config,supabaseSecretKey:key})};
 runtime.verifyDevice=makeDeviceVerifier({db:runtime.db,origin:new URL(config.publicAppUrl).origin});}
 return runtime;
}
export function makeRestoreHandler(get=getRuntime){return async(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 if(!req.headers?.authorization)return res.status(401).json({error:'login_required'});
 try{
 const {db,verify,verifyDevice}=get();const identity=await verify(req.headers.authorization);
 if(!identity)return res.status(401).json({error:'invalid_login'});
 if (!await requireDevice(req,res,identity,verifyDevice)) return;
      if(identity.kind==='judge' && identity.identity!=='b')return res.status(403).json({error:'test_b_only'});
 if(req.url!=='/api/restore' || Object.keys(req.query??{}).length)return res.status(400).json({error:'invalid_restore_path'});
 if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'method_not_allowed'});}
 let body=req.body;if(typeof body==='string'){try{body=JSON.parse(body);}catch{return res.status(400).json({error:'invalid_json'});}}
 if(!body || Array.isArray(body) || Object.keys(body).length!==1 || !UUID.test(body.id??''))return res.status(400).json({error:'id_required'});
 const {data,error}=await db.rpc('vault_restore_note',{p_id:body.id,p_owner:identity.userId});
 if(error)return res.status(error.code==='P0002'?404:409).json({error:'restore_rejected'});
 if(!data?.verified || data.id!==body.id || data.ownerId!==identity.userId || !/^[0-9a-f]{64}$/.test(data.contentHash??''))throw new Error('invalid_restore_result');
 return res.status(200).json(data);
 }catch{return res.status(500).json({error:'restore_failed'});}
};}
export default makeRestoreHandler();
