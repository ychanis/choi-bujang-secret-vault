import {createClient} from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm';
export async function runRecoveryCheck(){
 if(!confirm('시험 계정 B로 로그인했나요? 새 가상 메모 한 건을 만들고 변조·삭제·복구 시험을 합니다.'))return;
 const auth=createClient('https://mzxveixvhwsvkdzzjdoc.supabase.co','sb_publishable_Hdzt8NX91jem3oNeeQCprg_w0SWJIZ9');
 const {data,error}=await auth.auth.getSession();if(error||!data.session)throw new Error('B 로그인이 필요합니다.');
 const request=async(path,method='GET',body)=>{
 const r=await fetch(path,{method,cache:'no-store',headers:{Authorization:`Bearer ${data.session.access_token}`,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const result=await r.json();if(!r.ok)throw new Error(`HTTP ${r.status}: ${result.error??'failed'}`);return result;};
 const ensure=(ok,label)=>{if(!ok)throw new Error(label+' 실패');console.log('통과 · '+label);};
 const id=crypto.randomUUID(),original={id,title:'10단계 B 복원 시험',body:'복구 확인용 가상 자료'};
 const before=await request('/api/notes');
 await request('/api/notes','POST',original);
 const baseline=await request('/api/restore','POST',{id});
 ensure(baseline.id===id&&baseline.ownerId===data.session.user.id&&baseline.verified,'사전 사본 검증');
 await request('/api/notes/'+id,'PUT',{title:'변조 시험',body:'변조된 가상 자료'});
 const first=await request('/api/restore','POST',{id});
 let restored=await request('/api/notes/'+id);
 ensure(first.contentHash===baseline.contentHash&&first.ownerId===baseline.ownerId&&restored.id===id&&restored.title===original.title&&restored.body===original.body,'변조 복구와 ID·소유자·해시');
 await request('/api/notes/'+id,'DELETE');
 const second=await request('/api/restore','POST',{id});restored=await request('/api/notes/'+id);
 ensure(second.contentHash===baseline.contentHash&&second.ownerId===baseline.ownerId&&restored.id===id&&restored.title===original.title&&restored.body===original.body,'삭제 복구와 ID·소유자·해시');
 const after=await request('/api/notes');
 ensure(before.every(n=>after.some(a=>a.id===n.id&&a.title===n.title&&a.body===n.body)),'기존 B 메모 보존');
 console.log('B 자료 복구 시험 완료. 새로고침해서 시험 메모를 확인하세요. 정책·감사 보존과 A/B 권한 재시험은 별도 확인이 필요합니다.');
}
