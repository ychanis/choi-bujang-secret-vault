import {auth} from './session.js';
import {secureApi} from './device-client.js';

const panel=document.querySelector('#operations');
const output=document.querySelector('#operations-output');
const button=document.querySelector('#operations-refresh');
let generation=0;

function clear(){
  generation++;
  output.replaceChildren();
}
function row(label,value){
  const p=document.createElement('p');
  const strong=document.createElement('strong');
  strong.textContent=label+'：';
  p.append(strong,document.createTextNode(value));
  output.append(p);
}

button.onclick=async()=>{
  clear();
  const current=generation;
  button.disabled=true;
  try{
    const data=await secureApi('/api/operations');
    if(current!==generation||!navigator.onLine)return;
    if(data.schema!=='vault.operations.v1'||!Array.isArray(data.rules?.ids))
      throw new Error('작전실 응답 형식을 확인할 수 없습니다.');
    row('요청 ID',data.requestId);
    row('서버 확인 시각',data.checkedAt);
    row('판정기 설정',`${data.rules.ids.length}개 — ${data.rules.ids.join(', ')}`);
    row('판정 실행 결과','미연결 — 규칙 개수는 공격 방어 성공 횟수가 아닙니다.');
    row('탐지 사건','미연결 — 사건 수를 조회하지 않았습니다.');
    row('기기 상태',`현재 요청 기기: ${data.revocation.currentDeviceStatus}`);
    row('기기 만료 시각',data.revocation.expiresAt);
    row('전체 회수 상태','미연결 — 전체 회수 수와 회수 뒤 차단 결과는 미확인입니다.');
    row('정책 사본 보관 버전',data.recovery.backup.version??'조회 불가');
    row('실제 복구 결과','미연결 — 사본 보관 버전은 복구 적용 증거가 아닙니다.');
    row('41종 총공세','미실행 — 이 화면은 시험을 실행하거나 통과로 판정하지 않습니다.');
  }catch{
    if(current===generation){
      clear();
      row('조회 실패','로그인·기기 승인·온라인 상태를 확인하세요. 이전 결과는 지웠습니다.');
    }
  }finally{
    button.disabled=false;
  }
};
auth.auth.onAuthStateChange(()=>clear());
window.addEventListener('offline',clear);
window.addEventListener('pagehide',clear);
window.addEventListener('pageshow',event=>{if(event.persisted)clear();});
panel.hidden=false;
