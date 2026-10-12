import test from 'node:test';
import assert from 'node:assert/strict';
import { makeNotesHandler } from '../src/notes-api.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { readFileSync } from 'node:fs';
const owner = '11111111-1111-4111-8111-111111111111';
const id = '22222222-2222-4222-8222-222222222222';
function mock() {
  const rows = new Map();
  const db = { from() {
    let op = 'get', value, filters = [], single = false;
    const q = { select() { return q; }, eq(k, v) { filters.push([k,v]); return q; }, order() { return q; }, maybeSingle() { single = true; return q; }, insert(v) { op = 'insert'; value = v; return q; }, update(v) { op = 'update'; value = v; return q; }, delete() { op = 'delete'; return q; }, then(resolve) {
      if (op === 'insert') { rows.set(value.api_id, { ...value }); return Promise.resolve(resolve({ data: null, error: null })); }
      let data = [...rows.values()].filter(r => filters.every(([k,v]) => r[k] === v));
      if (op === 'update') data.forEach(r => Object.assign(r,value));
      if (op === 'delete') data.forEach(r => rows.delete(r.api_id));
      return Promise.resolve(resolve({ data: single ? data[0] ?? null : data, error: null }));
    } }; return q;
  } };
  return { rows, handler: makeNotesHandler(() => ({ db, verify: async a => a === 'test-valid' ? {userId:owner} : a === 'test-b' ? {userId:'33333333-3333-4333-8333-333333333333'} : null })) };
}
async function call(handler, method, auth, body, noteId) {
  const res = { code: 0, headers: {}, setHeader(k,v) {this.headers[k]=v;}, status(c) {this.code=c;return this;}, json(data) {this.data=data;return this;} };
  await handler({method,headers:auth ? {authorization:auth}: {},body,query:noteId ? {id:noteId}:{}},res);return res;
}
test('all anonymous methods and invalid authorization reject with JSON',async()=>{
 const {handler}=mock(); for(const method of ['GET','POST','PUT','DELETE']) {const r=await call(handler,method,null,{},['PUT','DELETE'].includes(method)?id:undefined); assert.equal(r.code,401);assert.ok(r.data.error);}
 assert.equal((await call(handler,'GET','invalid')).code,401);
});
test('CRUD stores verified owner, isolates list and blocks other owners',async()=>{
 const {handler,rows}=mock();let r=await call(handler,'POST','test-valid',{id,title:'test',body:'value'});assert.equal(r.code,201);assert.equal(rows.get(id).owner_id,owner);
 assert.deepEqual((await call(handler,'GET','test-valid')).data,[{id,title:'test',body:'value'}]);
 assert.deepEqual((await call(handler,'GET','test-b')).data,[]);
 for (const method of ['GET','PUT','DELETE']) {
    assert.equal((await call(handler,method,'test-b',{title:'changed',body:'updated'},id)).code,404);
  }
  assert.equal((await call(handler,'PUT','test-valid',{title:'changed',body:'updated',owner_id:'forged'},id)).code,400);
  assert.equal((await call(handler,'POST','test-valid',{title:'bad',body:'',owner_id:'forged'})).code,400);
  assert.equal((await call(handler,'PUT','test-valid',{title:'changed',body:'updated'},id)).code,200);
 assert.deepEqual((await call(handler,'GET','test-valid',null,id)).data,{id,title:'changed',body:'updated'});
 assert.equal((await call(handler,'DELETE','test-valid',null,id)).code,200);
 assert.equal((await call(handler,'GET','test-valid',null,id)).code,404);
 r=await call(handler,'POST','test-valid',{title:'auto',body:''});assert.match(r.data.id,/^[0-9a-f-]{36}$/);
 assert.equal((await call(handler,'POST','test-valid',{id:'invalid',title:'a',body:''})).code,400);
});
test('deployment identity reports stage 4',()=>{
 const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url)));
 const identity=deploymentIdentity({VERCEL_GIT_PROVIDER:'github',VERCEL_GIT_REPO_OWNER:'ychanis',VERCEL_GIT_REPO_SLUG:'choi-bujang-secret-vault',VERCEL_GIT_COMMIT_SHA:'a'.repeat(40),VERCEL_URL:'choi-bujang-secret-vault-self.vercel.app'},config);assert.equal(identity.step,4);
});
