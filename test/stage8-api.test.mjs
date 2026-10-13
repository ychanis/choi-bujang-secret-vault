import test from 'node:test';
import assert from 'node:assert/strict';
import { makeAnnouncementsHandler } from '../src/announcements-api.mjs';
import { makeNotesHandler } from '../src/notes-api.mjs';
import { parseResourcePath } from '../src/api-resource-path.mjs';
const id='88888888-8888-4888-8888-888888888888';
function dbMock(role='student',fail=false) {
  const row={api_id:id,title:'notice',content:'original'};
  const writes=[];
  return {row,writes,db:{from(table){
    let single=false,values,filters=[];
    const q={select(){return q;},eq(k,v){filters.push([k,v]);return q;},order(){return q;},maybeSingle(){single=true;return q;},update(v){values=v;return q;},then(resolve){
      if(fail)return Promise.resolve(resolve({data:null,error:{code:'test_error'}}));
      if(table==='vault_roles')return Promise.resolve(resolve({data:role?{role}:null,error:null}));
      let data=filters.every(([k,v])=>row[k]===v)?row:null;
      if(values&&data){writes.push(values);Object.assign(row,values);}
      return Promise.resolve(resolve({data:single?data:(data?[data]:[]),error:null}));
    }};return q;
  }}};
}
async function call(handler,{method='GET',url='/api/announcements/'+id,body,auth='valid',query={id}}={}) {
  const res={code:0,setHeader(){},status(c){this.code=c;return this;},json(data){this.data=data;return this;}};
  await handler({method,url,headers:auth?{authorization:auth}:{},body,query},res);return res;
}
const verifier=async a=>a==='valid'?{kind:'student',userId:'fixture-user'}:null;
test('anonymous and invalid tokens cannot read announcements',async()=>{
 const m=dbMock();const h=makeAnnouncementsHandler(()=>({db:m.db,verify:verifier}));
 for(const auth of [null,'invalid'])assert.equal((await call(h,{auth})).code,401);
});
test('student forged body role cannot modify announcement; stored content remains',async()=>{
 for(const role of ['student',null]){
  const m=dbMock(role),h=makeAnnouncementsHandler(()=>({db:m.db,verify:verifier}));
  const r=await call(h,{method:'PUT',body:{title:'forged',body:'changed',role:'instructor'}});
  assert.equal(r.code,403);assert.equal(m.row.content,'original');assert.equal(m.writes.length,0);
 }
});
test('database instructor can modify; body cannot assign ownership or role',async()=>{
 const m=dbMock('instructor'),h=makeAnnouncementsHandler(()=>({db:m.db,verify:verifier}));
 assert.equal((await call(h,{method:'PUT',body:{title:'new',body:'updated',role:'instructor'}})).code,400);
 const r=await call(h,{method:'PUT',body:{title:'new',body:'updated'}});
 assert.equal(r.code,200);assert.equal(r.data.resourceId,'announcements/'+id);assert.equal(m.row.content,'updated');
});
test('judge A/B test identity is not an instructor',async()=>{
 const m=dbMock('instructor'),h=makeAnnouncementsHandler(()=>({db:m.db,verify:async()=>({kind:'judge',userId:'fixture-user',identity:'a'})}));
 assert.equal((await call(h,{method:'PUT',body:{title:'new',body:'bad'}})).code,403);assert.equal(m.writes.length,0);
});
test('DB role lookup failures never allow a write',async()=>{
 const m=dbMock('instructor',true),h=makeAnnouncementsHandler(()=>({db:m.db,verify:verifier}));
 assert.equal((await call(h,{method:'PUT',body:{title:'new',body:'bad'}})).code,500);assert.equal(m.writes.length,0);
});
test('exact path only: query actions, query id override, export and traversal denied',()=>{
 for(const url of ['/api/notes?id='+id,'/api/notes/export','/api/notes/'+id+'/export','/api/notes/%2e%2e','/api/notes/'+id+'?action=export'])
  assert.equal(parseResourcePath({url,query:{}},'notes'),null);
 assert.equal(parseResourcePath({url:'/api/notes/'+id,query:{id:'forged'}},'notes'),null);
 assert.equal(parseResourcePath({url:'/api/notes/'+id,query:{id,role:'instructor'}},'notes'),null);
 assert.deepEqual(parseResourcePath({url:'/api/notes/'+id,query:{id}},'notes'),{id});
});
test('direct notes API rejects query-selected resource before DB read',async()=>{
 let reads=0;
 const h=makeNotesHandler(()=>({db:{from(){reads++;throw new Error('must not read');}},verify:verifier}));
 const r=await call(h,{url:'/api/notes?id='+id,query:{id}});
 assert.equal(r.code,400);assert.equal(reads,0);
});

test('Vercel matching id query allowed; mismatched id and actions denied',()=>{
  const url='/api/notes/'+id;
  assert.deepEqual(parseResourcePath({url:url+'?id='+id,query:{id}},'notes'),{id});
  assert.equal(parseResourcePath({url:url+'?id=forged',query:{id}},'notes'),null);
  assert.equal(parseResourcePath({url:url+'?action=export',query:{id}},'notes'),null);
  assert.equal(parseResourcePath({url:url+'?id='+id+'&id='+id,query:{id}},'notes'),null);
});
