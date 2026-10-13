import test from 'node:test';
import assert from 'node:assert/strict';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from '../src/decider.mjs';
const normal=()=>fixtureRequests().normal;
test('normal note requests remain allowed without a fixture permission table',async()=>{
 assert.equal((await decide(normal())).decision,'allow');
 for(const method of ['GET','PUT','DELETE']) {
   const r={...normal(),method,route:`${method} /notes/:id`};
   assert.equal((await decide(r)).decision,'allow');
 }
});
test('notice writes denied for every verified subject: contract has no role',async()=>{
 for(const subjectId of ['learner_fixture','another_fixture'])for(const method of ['POST','PUT','PATCH','DELETE']) {
  const r={...normal(),subjectId,service:'announcements',method,path:'/announcements/demo',route:`${method} /announcements/:id`};
  assert.equal((await decide(r)).decision,'deny');
 }
});
test('global notes lists, function paths and unknown paths denied',async()=>{
 for(const path of ['/notes','/notes/all','/notes/list','/notes/export','/notes/demo/extra','/notes/%64emo','/unknown/demo'])
  assert.equal((await decide({...normal(),path})).decision,'deny');
});
test('existing owner-filtered API collection and note creation remain allowed',async()=>{
 for(const method of ['GET','POST']) {
  const r={...normal(),method,path:'/api/notes',route:`${method} /api/notes`};
  assert.equal((await decide(r)).decision,'allow');
 }
});
test('wrong route, query actions, missing subject or malformed device denied',async()=>{
 for(const change of [{route:'GET /notes'},{queryLength:10},{subjectId:''},{deviceId:'unverified'},{service:'other'}])
  assert.equal((await decide({...normal(),...change})).decision,'deny');
});
test('registered-device and step-up rules preserved; step-up cannot bypass zone denial',async()=>{
 const {normal:n,suspicious:s}=fixtureRequests();
 assert.equal((await decide({...n,deviceRegistered:false})).reasonCode,'device_not_registered');
 assert.equal((await decide(s)).decision,'step_up');
 assert.equal((await decide({...s,stepUp:{verified:true,authAgeSeconds:60}})).decision,'allow');
 assert.equal((await decide({...s,path:'/notes/export',stepUp:{verified:true,authAgeSeconds:60}})).decision,'deny');
});
