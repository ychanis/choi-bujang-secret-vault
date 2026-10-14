import test from 'node:test';
import assert from 'node:assert/strict';
import {makeRestoreHandler} from '../src/restore-api.mjs';
const id='22222222-2222-4222-8222-222222222222',owner='33333333-3333-4333-8333-333333333333';
async function call({auth='b',method='POST',body={id},url='/api/restore',error=null}={}){
 let args;const handler=makeRestoreHandler(()=>({verify:async a=>a==='bad'?null:{kind:'judge',identity:a,userId:owner},db:{rpc:async(name,p)=>{args={name,...p};return {data:{id,ownerId:owner,contentHash:'a'.repeat(64),verified:true},error};}}}));
 const res={code:0,setHeader(){},status(n){this.code=n;return this;},json(v){this.data=v;return this;}};
 await handler({headers:auth?{authorization:auth}:{},method,body,url,query:{}},res);return {res,args};
}
test('복원 API는 검증된 B 소유자만 전달',async()=>{
 const {res,args}=await call();assert.equal(res.code,200);assert.deepEqual(args,{name:'vault_restore_note',p_id:id,p_owner:owner});assert.equal(Object.hasOwn(res.data,'body'),false);
});
test('미인증·심판 A·소유자 위조·잘못된 경로·없는 사본 거부',async()=>{
 for(const [input,code] of [[{auth:null},401],[{auth:'bad'},401],[{auth:'a'},403],[{body:{id,owner_id:owner}},400],[{body:{id:'bad'}},400],[{url:'/api/restore?x=1'},400],[{method:'GET'},405],[{error:{code:'P0002'}},404]])assert.equal((await call(input)).res.code,code);
});
