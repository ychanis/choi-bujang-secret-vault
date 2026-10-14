import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { publicDeviceKey } from './device-proof.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
let runtime;
function getRuntime() {
  if (!runtime) {
    const key = process.env.SUPABASE_SECRET_KEY;
    runtime = {db:createClient(new URL(config.identityProvider.issuer).origin,key,
      {auth:{persistSession:false,autoRefreshToken:false}}),verify:createLoginVerifier({config,supabaseSecretKey:key})};
  }
  return runtime;
}
export function makeDeviceHandler(get=getRuntime) {
  return async (req,res) => {
    res.setHeader('Cache-Control','no-store');
    if (!req.headers?.authorization) return res.status(401).json({error:'login_required'});
    try {
      const {db,verify} = get();
      const identity = await verify(req.headers.authorization);
      if (!identity) return res.status(401).json({error:'invalid_login'});
      const url = new URL(req.url,config.publicAppUrl);
      if (url.pathname !== '/api/device' || /[#%\\]/.test(req.url)) return res.status(400).json({error:'invalid_device_path'});
      let id;
      if (req.method === 'POST') {
        if (url.search || Object.keys(req.query ?? {}).length) return res.status(400).json({error:'invalid_device_path'});
        let body = req.body;
        if (typeof body === 'string') {try {body=JSON.parse(body);} catch {return res.status(400).json({error:'invalid_json'});}}
        if (!body || Array.isArray(body) || Object.keys(body).join(',') !== 'publicKey') return res.status(400).json({error:'public_key_required'});
        let parsed;
        try {parsed=publicDeviceKey(body.publicKey);} catch {return res.status(400).json({error:'invalid_device_key'});}
        id=parsed.id;
        // Duplicate enrollment cannot reset an existing approval or revocation.
        const {error} = await db.from('vault_devices').upsert({id, owner_id:identity.userId, public_key:parsed.jwk},
          {onConflict:'id',ignoreDuplicates:true});
        if (error) return res.status(503).json({error:'device_service_unavailable'});
      } else if (req.method === 'GET') {
        id=url.searchParams.get('id');
        if (!/^[0-9a-f]{64}$/.test(id ?? '') || url.searchParams.getAll('id').length !== 1
            || [...url.searchParams.keys()].some(k => k !== 'id')
            || Object.keys(req.query ?? {}).some(k => k !== 'id')
            || (req.query?.id !== undefined && req.query.id !== id)) return res.status(400).json({error:'invalid_device_id'});
      } else {res.setHeader('Allow','GET, POST');return res.status(405).json({error:'method_not_allowed'});}
      const {data,error} = await db.from('vault_devices').select('id,status,expires_at')
        .eq('id',id).eq('owner_id',identity.userId).maybeSingle();
      if (error) return res.status(503).json({error:'device_service_unavailable'});
      if (!data) return res.status(404).json({error:'device_not_found'});
      const expired = Date.parse(data.expires_at) <= Date.now();
      return res.status(200).json({id:data.id,status:expired?'expired':data.status,expiresAt:data.expires_at});
    } catch {return res.status(503).json({error:'device_service_unavailable'});}
  };
}
export default makeDeviceHandler();
