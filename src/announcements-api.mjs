import { makeDeviceVerifier, requireDevice } from './device-proof.mjs';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
import { resourceId } from './resource-id.mjs';
import { parseResourcePath, rejectResource } from './api-resource-path.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
let runtime;
function getRuntime() {
  if (!runtime) {
    const key = process.env.SUPABASE_SECRET_KEY;
    runtime = {
      db: createClient(new URL(config.identityProvider.issuer).origin, key, {auth:{persistSession:false,autoRefreshToken:false}}),
      verify: createLoginVerifier({config,supabaseSecretKey:key})
    };
    runtime.verifyDevice=makeDeviceVerifier({db:runtime.db,origin:new URL(config.publicAppUrl).origin});
  }
  return runtime;
}
const announcement = row => ({id:row.api_id,resourceId:resourceId('announcements',row.api_id),title:row.title,body:row.content});
export function makeAnnouncementsHandler(get = getRuntime) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control','no-store');
    if (!req.headers?.authorization) return rejectResource(res,401,'login_required','로그인이 필요합니다.');
    try {
      const {db,verify,verifyDevice}=get();
      const identity=await verify(req.headers.authorization);
      if (!identity) return rejectResource(res,401,'invalid_login','로그인 인증에 실패했습니다.');
      if (!await requireDevice(req,res,identity,verifyDevice)) return;
      const target=parseResourcePath(req,'announcements');
      if (!target) return rejectResource(res,400,'invalid_resource_path','허용된 자료 경로가 아닙니다.');
      const {id}=target;
      const allowed=id?['GET','PUT']:['GET'];
      if (!allowed.includes(req.method)) {
        res.setHeader('Allow',allowed.join(', '));
        return rejectResource(res,405,'method_not_allowed','허용되지 않은 요청입니다.');
      }
      if (req.method==='GET') {
        let q=db.from('announcements').select('api_id,title,content');
        q=id?q.eq('api_id',id).maybeSingle():q.order('created_at');
        const {data,error}=await q;
        if (error) throw new Error('database');
        if (id&&!data) return rejectResource(res,404,'announcement_not_found','공지를 찾을 수 없습니다.');
        return res.status(200).json(id?announcement(data):data.map(announcement));
      }
      // Roles come exclusively from a protected database table, not from JWT user metadata or a body.
      const {data:member,error:roleError}=await db.from('vault_roles').select('role').eq('user_id',identity.userId).maybeSingle();
      if (roleError) throw new Error('database');
      // The current judge token contract grants test A/B identities, not an instructor role.
      if (identity.kind==='judge'||member?.role!=='instructor')
        return rejectResource(res,403,'instructor_required','강사 권한이 필요합니다.');
      let body=req.body;
      if (typeof body==='string') {try{body=JSON.parse(body);}catch{return rejectResource(res,400,'invalid_json','JSON 형식이 필요합니다.');}}
      if (!body||typeof body!=='object'||Array.isArray(body)
        ||Object.keys(body).some(k=>!['title','body'].includes(k))
        ||typeof body.title!=='string'||!body.title.trim()||body.title.length>200
        ||typeof body.body!=='string'||body.body.length>10000)
        return rejectResource(res,400,'invalid_body','제목과 본문을 확인해 주세요.');
      const {data,error}=await db.from('announcements').update({title:body.title,content:body.body}).eq('api_id',id).select('api_id,title,content').maybeSingle();
      if (error) throw new Error('database');
      if (!data) return rejectResource(res,404,'announcement_not_found','공지를 찾을 수 없습니다.');
      return res.status(200).json(announcement(data));
    } catch {return rejectResource(res,500,'resource_processing_failed','서버 설정 또는 자료 처리에 실패했습니다.');}
  };
}
export default makeAnnouncementsHandler();
