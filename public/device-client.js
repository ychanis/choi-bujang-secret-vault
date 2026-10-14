import {auth} from './session.js';
let device=null, keyOwner=null, epoch=0;
const encoder=new TextEncoder();
const hex=buffer=>[...new Uint8Array(buffer)].map(v=>v.toString(16).padStart(2,'0')).join('');
const hash=async text=>hex(await crypto.subtle.digest('SHA-256',encoder.encode(text)));
const base64url=buffer=>btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function canonical(value,depth=0) {
  if(depth>20)throw new Error('자료 형식을 확인해 주세요.');
  if(value===null || typeof value==='string' || typeof value==='boolean')return JSON.stringify(value);
  if(typeof value==='number' && Number.isFinite(value))return JSON.stringify(value);
  if(Array.isArray(value))return '['+value.map(v=>canonical(v,depth+1)).join(',')+']';
  if(value && typeof value==='object' && Object.getPrototypeOf(value)===Object.prototype)
    return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k],depth+1)).join(',')+'}';
  throw new Error('자료 형식을 확인해 주세요.');
}
async function session() {
  const {data,error}=await auth.auth.getSession();
  if(error || !data.session)throw new Error('로그인이 필요합니다.');
  return data.session;
}
async function result(response) {
  let data;try{data=await response.json();}catch{throw new Error('서버 응답을 확인할 수 없습니다.');}
  if(!response.ok) {
    const error=new Error(response.status===403?'기기 승인 또는 요청 서명을 확인해 주세요.':data.error || '요청에 실패했습니다.');
    error.status=response.status;error.reasonCode=data.reasonCode;throw error;
  }
  return data;
}
export function clearDevice(){epoch++;device=null;keyOwner=null;}
export function deviceFingerprint(){return device?.id ?? '';}
export async function requestDevice() {
  const s=await session();
  if(keyOwner!==s.user.id) {clearDevice();keyOwner=s.user.id;}
  const currentEpoch=epoch;
  if(!device) {
    if(!crypto.subtle)throw new Error('HTTPS 접속이 필요합니다.');
    const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
    const raw=await crypto.subtle.exportKey('jwk',pair.publicKey);
    const publicKey={crv:raw.crv,kty:raw.kty,x:raw.x,y:raw.y};
    const id=await hash(JSON.stringify(publicKey));
    if(currentEpoch!==epoch)throw new Error('다시 로그인해 주세요.');
    device={id,publicKey,privateKey:pair.privateKey};
  }
  const current=device;
  const response=await fetch('/api/device',{method:'POST',cache:'no-store',credentials:'omit',
    headers:{Authorization:'Bearer '+s.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({publicKey:current.publicKey})});
  const data=await result(response);
  if(current!==device || keyOwner!==s.user.id)throw new Error('다시 로그인해 주세요.');
  return data;
}
export async function deviceStatus() {
  const s=await session(),current=device;
  if(!current || keyOwner!==s.user.id)throw new Error('먼저 기기 승인을 요청해 주세요.');
  const data=await result(await fetch('/api/device?id='+current.id,{cache:'no-store',credentials:'omit',headers:{Authorization:'Bearer '+s.access_token}}));
  if(current!==device)throw new Error('다시 로그인해 주세요.');
  return data;
}
export async function secureApi(path,method='GET',body) {
  const s=await session(),current=device;
  if(!current || keyOwner!==s.user.id)throw new Error('기기 승인이 필요합니다.');
  if(!path.startsWith('/api/') || path.startsWith('//') || /[\r\n#\\]/.test(path))throw new Error('허용된 경로가 아닙니다.');
  const encoded=body===undefined || body===null?'':canonical(body);
  const at=String(Math.floor(Date.now()/1000)),nonce=crypto.randomUUID();
  const signed=['vault.device.v1',location.origin,await hash(s.access_token),current.id,method,path,await hash(encoded),at,nonce].join('\n');
  const signature=base64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},current.privateKey,encoder.encode(signed)));
  if(current!==device || keyOwner!==s.user.id)throw new Error('다시 로그인해 주세요.');
  return result(await fetch(path,{method,cache:'no-store',credentials:'omit',headers:{
    Authorization:'Bearer '+s.access_token,'x-vault-device':current.id,'x-vault-time':at,
    'x-vault-nonce':nonce,'x-vault-signature':signature,...(encoded?{'Content-Type':'application/json'}:{})
  },...(encoded?{body:encoded}:{})}));
}
