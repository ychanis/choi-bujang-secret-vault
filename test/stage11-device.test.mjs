import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,webcrypto} from 'node:crypto';
import {makeDeviceVerifier,publicDeviceKey,proofMessage,sha256,canonicalJson} from '../src/device-proof.mjs';
import {makeDeviceHandler} from '../src/device-api.mjs';
import {makeNotesHandler} from '../src/notes-api.mjs';
import {makeAnnouncementsHandler} from '../src/announcements-api.mjs';
import {makeRestoreHandler} from '../src/restore-api.mjs';
const origin='https://choi-bujang-secret-vault-self.vercel.app';
const owner='11111111-1111-4111-8111-111111111111',other='33333333-3333-4333-8333-333333333333';
const noteId='22222222-2222-4222-8222-222222222222';
const now=1800000000000;
function fixture() {
  const pair=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  const raw=pair.publicKey.export({format:'jwk'}),jwk={crv:raw.crv,kty:raw.kty,x:raw.x,y:raw.y};
  const device=publicDeviceKey(jwk),devices=new Map(),rows=new Map(),nonces=new Set();
  devices.set(device.id,{id:device.id,owner_id:owner,public_key:jwk,status:'approved',expires_at:new Date(now+3600000).toISOString()});
  let nonceNumber=0,deviceDBError=false,nonceDBError=false,resourceReads=0;
  const db={from(table){
    if(table!=='vault_devices')resourceReads++;
    let filters=[],single=false,op='select',values;
    const q={select(){return q;},eq(k,v){filters.push([k,v]);return q;},maybeSingle(){single=true;return q;},order(){return q;},
      upsert(v){op='upsert';values=v;return q;},insert(v){op='insert';values=v;return q;},update(v){op='update';values=v;return q;},delete(){op='delete';return q;},
      then(resolve){
        if(table==='vault_devices' && deviceDBError)return Promise.resolve(resolve({data:null,error:{code:'unavailable'}}));
        const store=table==='vault_devices'?devices:rows;
        if(op==='upsert') {if(!store.has(values.id))store.set(values.id,{...values,status:'pending',expires_at:new Date(now+3600000).toISOString()});}
        if(op==='insert')store.set(values.api_id,{...values});
        const found=[...store.values()].filter(r=>filters.every(([k,v])=>r[k]===v));
        if(op==='update')found.forEach(r=>Object.assign(r,values));
        if(op==='delete')found.forEach(r=>store.delete(r.api_id));
        return Promise.resolve(resolve({data:single?found[0]??null:found,error:null}));
      }};return q;
    },async rpc(name,args){
      if(nonceDBError)return {data:null,error:{code:'unavailable'}};
      assert.equal(name,'vault_consume_device_nonce');
      const d=devices.get(args.p_device),key=args.p_device+args.p_nonce;
      if(!d || d.owner_id!==args.p_owner || d.status!=='approved' || nonces.has(key))return {data:false,error:null};
      nonces.add(key);return {data:true,error:null};
    }};
  const verifyDevice=makeDeviceVerifier({db,origin,clock:()=>now});
  const verify=async authorization=>authorization==='Bearer fixture-a'?{kind:'student',userId:owner}:
    authorization==='Bearer fixture-b'?{kind:'student',userId:other}:null;
  const runtime=()=>({db,verify,verifyDevice});
  function request({method='GET',url='/api/notes',body,token='fixture-a',at=String(now/1000),nonce}={}) {
    nonce??='00000000-0000-4000-8000-'+String(++nonceNumber).padStart(12,'0');
    const text=body===undefined || body===null?'':canonicalJson(body);
    const proof=proofMessage({origin,token,deviceId:device.id,method,path:url,bodyHash:sha256(text),at,nonce});
    const signature=sign('sha256',Buffer.from(proof),{key:pair.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
    return {method,url,body,query:url.startsWith('/api/notes/')?{id:url.split('/').pop()}:{},headers:{authorization:'Bearer '+token,
      'x-vault-device':device.id,'x-vault-time':at,'x-vault-nonce':nonce,'x-vault-signature':signature}};
  }
  return {pair,device,devices,rows,db,runtime,verifyDevice,request,get resourceReads(){return resourceReads;},
    failDeviceDB(){deviceDBError=true;},failNonceDB(){nonceDBError=true;}};
}
async function call(handler,req) {
  const res={code:0,headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(data){this.data=data;return this;}};
  await handler(req,res);return res;
}
test('서명 없는 보호 요청은 메모·공지·복원 모두 DB 처리 전에 거부',async()=>{
  const f=fixture();
  for(const [factory,url,method] of [[makeNotesHandler,'/api/notes','GET'],[makeAnnouncementsHandler,'/api/announcements','GET'],[makeRestoreHandler,'/api/restore','POST']]) {
    const res=await call(factory(f.runtime),{url,method,headers:{authorization:'Bearer fixture-a'},body:{id:noteId},query:{}});
    assert.equal(res.code,403);assert.equal(res.data.reasonCode,'device_signature_required');
  }
  assert.equal(f.resourceReads,0);
});
test('서명 뒤 경로·쿼리·메서드 변경을 거부하고 자료를 읽지 않음',async()=>{
  const f=fixture(),handler=makeNotesHandler(f.runtime);
  for(const change of [r=>r.url='/api/notes/'+noteId,r=>r.url+='?action=export',r=>r.method='DELETE']){
    const r=f.request();change(r);const res=await call(handler,r);assert.equal(res.code,403);assert.equal(res.data.reasonCode,'invalid_device_signature');
  }
  assert.equal(f.resourceReads,0);
});
test('서명 뒤 수정 본문 변경을 거부하고 기존 본문 보존',async()=>{
  const f=fixture();f.rows.set(noteId,{api_id:noteId,owner_id:owner,title:'original',content:'before'});
  const r=f.request({url:'/api/notes/'+noteId,method:'PUT',body:{title:'allowed',body:'signed'}});r.body.body='tampered';
  const res=await call(makeNotesHandler(f.runtime),r);assert.equal(res.code,403);assert.equal(f.rows.get(noteId).content,'before');assert.equal(f.resourceReads,0);
});
test('승인된 서명 요청으로 기존 CRUD 정상; 다른 소유자 접근 거부',async()=>{
  const f=fixture(),handler=makeNotesHandler(f.runtime);
  assert.equal((await call(handler,f.request({method:'POST',body:{id:noteId,title:'test',body:'original'}}))).code,201);
  assert.equal((await call(handler,f.request())).data.length,1);
  assert.equal((await call(handler,f.request({method:'PUT',url:'/api/notes/'+noteId,body:{title:'new',body:'updated'}}))).code,200);
  assert.equal(f.rows.get(noteId).content,'updated');
  // Same device keys cannot be used by a different verified account.
  assert.equal((await call(handler,f.request({token:'fixture-b'}))).code,403);
  // Approve a separate key for B, then the existing owner filter still blocks A's note.
  const b=fixture();b.devices.get(b.device.id).owner_id=other;
  b.rows.set(noteId,{api_id:noteId,owner_id:owner,title:'A',content:'private'});
  assert.equal((await call(makeNotesHandler(b.runtime),b.request({token:'fixture-b',url:'/api/notes/'+noteId}))).code,404);
  assert.deepEqual((await call(makeNotesHandler(b.runtime),b.request({token:'fixture-b'}))).data,[]);
  assert.equal((await call(handler,f.request({method:'DELETE',url:'/api/notes/'+noteId}))).code,200);
});
test('미승인·회수·만료·알 수 없는 기기는 거부',async()=>{
  for(const status of ['pending','revoked','expired','missing']) {
    const f=fixture(),d=f.devices.get(f.device.id);
    if(status==='expired')d.expires_at=new Date(now-1000).toISOString();
    else if(status==='missing')f.devices.clear();else d.status=status;
    const res=await call(makeNotesHandler(f.runtime),f.request());assert.equal(res.code,403);assert.equal(f.resourceReads,0);
  }
});
test('같은 서명 재사용·시간 만료·토큰 바꿔치기 거부',async()=>{
  const f=fixture(),handler=makeNotesHandler(f.runtime),r=f.request();
  assert.equal((await call(handler,r)).code,200);assert.equal((await call(handler,r)).code,403);
  assert.equal((await call(handler,f.request({at:String(now/1000-120)}))).code,403);
  const swapped=f.request();swapped.headers.authorization='Bearer fixture-b';
  assert.equal((await call(handler,swapped)).code,403);
});
test('기기 DB·nonce 기록 장애는 허용하지 않음',async()=>{
  for(const method of ['failDeviceDB','failNonceDB']) {
    const f=fixture();f[method]();assert.equal((await call(makeNotesHandler(f.runtime),f.request())).code,503);assert.equal(f.resourceReads,0);
  }
});
test('승인 버튼의 등록 요청은 pending만 생성; 승인 위조 본문 거부',async()=>{
  const f=fixture();f.devices.clear();const handler=makeDeviceHandler(f.runtime);
  const base={url:'/api/device',method:'POST',query:{},headers:{authorization:'Bearer fixture-a'}};
  const res=await call(handler,{...base,body:{publicKey:f.device.jwk}});
  assert.equal(res.code,200);assert.equal(res.data.status,'pending');
  assert.equal((await call(makeNotesHandler(f.runtime),f.request())).code,403);
  assert.equal((await call(handler,{...base,body:{publicKey:f.device.jwk,status:'approved'}})).code,400);
  assert.equal((await call(handler,{...base,body:{publicKey:{...f.device.jwk,d:'forged'}}})).code,400);
});
test('브라우저 WebCrypto 비추출 개인키로 만든 서명을 서버가 검증',async()=>{
  const f=fixture(),pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  assert.equal(pair.privateKey.extractable,false);
  await assert.rejects(webcrypto.subtle.exportKey('jwk',pair.privateKey));
  const raw=await webcrypto.subtle.exportKey('jwk',pair.publicKey),d=publicDeviceKey({crv:raw.crv,kty:raw.kty,x:raw.x,y:raw.y});
  f.devices.set(d.id,{id:d.id,owner_id:owner,public_key:d.jwk,status:'approved',expires_at:new Date(now+3600000).toISOString()});
  const r=f.request();r.headers['x-vault-device']=d.id;
  const signed=proofMessage({origin,token:'fixture-a',deviceId:d.id,method:r.method,path:r.url,bodyHash:sha256(''),at:r.headers['x-vault-time'],nonce:r.headers['x-vault-nonce']});
  r.headers['x-vault-signature']=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,new TextEncoder().encode(signed))).toString('base64url');
  assert.equal((await call(makeNotesHandler(f.runtime),r)).code,200);
});
test('기기 검증기를 빠뜨린 서버 구성은 기본 거부',async()=>{
  const f=fixture(),r=await call(makeNotesHandler(()=>({db:f.db,verify:async()=>({userId:owner})})),f.request());
  assert.equal(r.code,403);assert.equal(f.resourceReads,0);
});
