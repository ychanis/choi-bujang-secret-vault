import { makeDeviceVerifier, requireDevice } from './device-proof.mjs';
import { parseResourcePath, rejectResource } from './api-resource-path.mjs';
import { resourceId } from './resource-id.mjs';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from './verify-login.mjs';
const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let runtime;
function getRuntime() {
  if (!runtime) {
    const key = process.env.SUPABASE_SECRET_KEY;
    const db = createClient(new URL(config.identityProvider.issuer).origin, key,
      { auth: { persistSession: false, autoRefreshToken: false } });
    runtime = { db, verify: createLoginVerifier({ config, supabaseSecretKey: key }), verifyDevice:makeDeviceVerifier({db,origin:new URL(config.publicAppUrl).origin}) };
  }
  return runtime;
}
const note = row => ({ id: row.api_id, resourceId: resourceId('notes', row.api_id), title: row.title, body: row.content });
export function makeNotesHandler(get = getRuntime) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    const auth = req.headers?.authorization;
    if (!auth) return res.status(401).json({ error: '로그인이 필요합니다.' });
    try {
      const { db, verify, verifyDevice } = get();
      const identity = await verify(auth);
      if (!identity) return res.status(401).json({ error: '로그인 인증에 실패했습니다.' });
      if (!await requireDevice(req,res,identity,verifyDevice)) return;
      const target = parseResourcePath(req, 'notes');
      if (!target) return rejectResource(res, 400, 'invalid_resource_path', '허용된 자료 경로가 아닙니다.');
      const { id } = target;
      const method = req.method;
      const allowed = id ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
      if (!allowed.includes(method)) { res.setHeader('Allow', allowed.join(', ')); return res.status(405).json({ error: '허용되지 않은 요청입니다.' }); }
      if (method === 'GET') {
        let query = db.from('notes').select('api_id,title,content');
        query = id ? query.eq('api_id', id).eq('owner_id', identity.userId).maybeSingle() : query.eq('owner_id', identity.userId).order('created_at');
        const { data, error } = await query;
        if (error) throw new Error('database');
        if (id && !data) return rejectResource(res, 404, 'note_not_found_or_forbidden', '메모를 찾을 수 없습니다.');
        return res.status(200).json(id ? note(data) : data.map(note));
      }
      if (method === 'DELETE') {
        const { data, error } = await db.from('notes').delete().eq('api_id', id).eq('owner_id', identity.userId).select('api_id');
        if (error) throw new Error('database');
        if (!data.length) return rejectResource(res, 404, 'note_not_found_or_forbidden', '메모를 찾을 수 없습니다.');
        return res.status(200).json({ id });
      }
      let body = req.body;
      if (typeof body === 'string') { try { body = JSON.parse(body); } catch { return res.status(400).json({ error: 'JSON 형식이 필요합니다.' }); } }
      if (!body || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200 || typeof body.body !== 'string' || body.body.length > 10000)
        return res.status(400).json({ error: '제목과 본문을 확인해 주세요.' });
      if (['owner_id', 'userId', 'role', 'resourceId'].some(key => Object.hasOwn(body, key))) return res.status(400).json({ error: '소유자는 직접 지정하거나 변경할 수 없습니다.' });
      if (method === 'POST') {
        const newId = body.id ?? randomUUID();
        if (typeof newId !== 'string' || !UUID.test(newId)) return res.status(400).json({ error: '올바른 UUID가 필요합니다.' });
        const { error } = await db.from('notes').insert({ api_id: newId, owner_id: identity.userId, title: body.title, content: body.body });
        if (error?.code === '23505') return res.status(409).json({ error: '이미 존재하는 메모 ID입니다.' });
        if (error) throw new Error('database');
        return res.status(201).json({ id: newId });
      }
      // 기존 행의 소유자를 확인하고 제목과 본문만 변경합니다.
      const { data, error } = await db.from('notes').update({ title: body.title, content: body.body }).eq('api_id', id).eq('owner_id', identity.userId).select('api_id,title,content').maybeSingle();
      if (error) throw new Error('database');
      if (!data) return rejectResource(res, 404, 'note_not_found_or_forbidden', '메모를 찾을 수 없습니다.');
      return res.status(200).json(note(data));
    } catch { return res.status(500).json({ error: '서버 설정 또는 자료 처리에 실패했습니다.' }); }
  };
}
export default makeNotesHandler();
