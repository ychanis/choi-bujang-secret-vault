import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import {createClient} from '@supabase/supabase-js';
import {createLoginVerifier} from './verify-login.mjs';
import {makeDeviceVerifier,requireDevice} from './device-proof.mjs';
import {RULE_IDS} from './decider.mjs';

const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
let runtime;
function getRuntime(){
  if(!runtime){
    const key=process.env.SUPABASE_SECRET_KEY;
    const db=createClient(new URL(config.identityProvider.issuer).origin,key,
      {auth:{persistSession:false,autoRefreshToken:false}});
    runtime={
      db,
      verify:createLoginVerifier({config,supabaseSecretKey:key}),
      verifyDevice:makeDeviceVerifier({db,origin:new URL(config.publicAppUrl).origin})
    };
  }
  return runtime;
}

export function makeOperationsHandler(get=getRuntime){
  return async(req,res)=>{
    const requestId=randomUUID();
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Request-Id',requestId);
    if(!req.headers?.authorization)
      return res.status(401).json({error:'login_required',requestId});
    try{
      const {db,verify,verifyDevice}=get();
      const identity=await verify(req.headers.authorization);
      if(!identity)return res.status(401).json({error:'invalid_login',requestId});
      if(!await requireDevice(req,res,identity,verifyDevice))return;
      if(req.url!=='/api/operations'||Object.keys(req.query??{}).length)
        return res.status(400).json({error:'invalid_operations_path',requestId});
      if(req.method!=='GET'){
        res.setHeader('Allow','GET');
        return res.status(405).json({error:'method_not_allowed',requestId});
      }

      const {data,error}=await db.from('vault_devices')
        .select('status,expires_at')
        .eq('id',req.headers['x-vault-device'])
        .eq('owner_id',identity.userId).maybeSingle();
      if(error||!data)
        return res.status(503).json({error:'operations_unavailable',requestId});

      const checkedAt=new Date().toISOString();
      const status=Date.parse(data.expires_at)<=Date.now()?'expired':data.status;
      // Recheck after signature verification; never report a revoked device as approved.
      if(status!=='approved')
        return res.status(403).json({error:'device_not_approved',requestId});

      let backup={state:'unavailable',version:null};
      try{
        const manifest=JSON.parse(readFileSync(
          new URL('../backups/policy-stage9/manifest.json',import.meta.url),'utf8'));
        if(manifest.schema==='vault.policy-backup.v1'
          && /^stage9-[a-f0-9]{12}$/.test(manifest.version))
          backup={state:'stored_manifest',version:manifest.version};
      }catch{}

      const report={
        schema:'vault.operations.v1',requestId,checkedAt,
        rules:{state:'configured',ids:[...RULE_IDS]},
        detection:{state:'not_connected',eventCount:null},
        revocation:{
          state:'current_device_only',currentDeviceStatus:status,
          expiresAt:data.expires_at,totalRevoked:null
        },
        recovery:{
          state:'not_connected',verifiedRestoreCount:null,
          backup,activeRestoredVersion:null
        },
        trials:{state:'not_run',total:41,executed:0,passed:0}
      };

      // Masked metadata only: no identity, fingerprint, note, token, or private key.
      console.info(JSON.stringify({
        event:'operations_summary',...report
      }));
      return res.status(200).json(report);
    }catch{
      return res.status(503).json({error:'operations_unavailable',requestId});
    }
  };
}
export default makeOperationsHandler();
