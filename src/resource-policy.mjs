// The engine verifies identity and device; the final notes API verifies saved ownership.
// No client role or invented subject-to-Supabase mapping is used here.
const RESERVED = new Set(['all','list','export','import','search','bulk','admin']);
const EMPTY_QUERY_SHA256='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
export function checkResourceAccess(request) {
  const denied = {allowed:false,ruleIds:['resource_scope']};
  if (!request || typeof request.subjectId!=='string' || !request.subjectId.trim()
    || typeof request.classId!=='string' || !request.classId.trim()
    || typeof request.projectId!=='string' || !request.projectId.trim()
    || !/^[0-9a-f]{16}$/.test(request.deviceId??'')
    || !Number.isSafeInteger(request.policyRevision) || request.policyRevision<1
    || request.queryLength!==0 || request.querySha256!==EMPTY_QUERY_SHA256) return denied;
  if (typeof request.path!=='string') return denied;
  const match=/^(\/api)?\/(notes|announcements)(?:\/([A-Za-z0-9_-]{1,128}))?$/.exec(request.path);
  if (!match || (match[3] && RESERVED.has(match[3].toLowerCase()))) return denied;
  const [,prefix='',type,id]=match;
  if (request.service!==type) return denied;
  const expectedRoute=`${request.method} ${prefix}/${type}${id?'/:id':''}`;
  if (request.route!==expectedRoute) return denied;
  if (type==='announcements') {
    // Contract v1 has no instructor role: reject every announcement write at this gate.
    return request.method==='GET'
      ? {allowed:true,ruleIds:['resource_scope','announcement_read_only']}:denied;
  }
  if (!id) {
    // /notes is a broad engine collection, so it stays closed.
    // /api/notes is the existing API, which filters the list by the verified DB owner.
    if (prefix!=='/api' || !['GET','POST'].includes(request.method)) return denied;
  } else if (!['GET','PUT','DELETE'].includes(request.method)) return denied;
  return {allowed:true,ruleIds:['resource_scope','note_api_owner_required']};
}
