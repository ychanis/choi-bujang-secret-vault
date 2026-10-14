import {auth} from './session.js';
import {requestDevice,deviceStatus,secureApi,clearDevice,deviceFingerprint} from './device-client.js';
const $ = selector => document.querySelector(selector);
let currentSession = null, editingId = null, generation = 0, approved = false;
const message = text => { $('#message').textContent = text; };
function resetEditor() { editingId = null; $('#editor').reset(); $('#editor-heading').textContent = '메모 추가'; }
function lockWorkspace() {
  approved=false;generation++;$('#workspace').hidden=true;
  $('#notes').replaceChildren();resetEditor();
}
async function api(path = '', method = 'GET', body) {
  try{return await secureApi('/api/notes'+path,method,body);}
  catch(error){
    if(error.status===401 || error.status===403){lockWorkspace();$('#device-status').textContent='기기 승인 또는 서명 확인이 필요합니다.';}
    throw error;
  }
}
async function loadNotes() {
  const version = generation;
  try {
    const notes = await api();
    if (version !== generation || !currentSession || !navigator.onLine) return false;
    if (!Array.isArray(notes)) throw new Error('자료 형식이 맞지 않습니다.');
    $('#notes').replaceChildren();
    if (!notes.length) { const li = document.createElement('li'); li.textContent = '아직 내 메모가 없어요. 위에서 새 메모를 추가해 주세요.'; $('#notes').append(li); }
    for (const note of notes) {
      const li = document.createElement('li'), title = document.createElement('h3'), body = document.createElement('p'); title.textContent = note.title; body.textContent = note.body;
      const edit = document.createElement('button'); edit.textContent = '수정'; edit.onclick = () => { editingId = note.id; $('#title').value = note.title; $('#body').value = note.body; $('#editor-heading').textContent = '메모 수정'; $('#title').focus(); };
      const remove = document.createElement('button'); remove.textContent = '삭제'; remove.onclick = async () => { if (!confirm('이 메모를 삭제할까요?')) return; try { await api('/' + note.id, 'DELETE'); if (editingId === note.id) resetEditor(); await loadNotes(); message('삭제했어요.'); } catch (e) { message(e.message); } };
      li.append(title, body, edit, remove); $('#notes').append(li);
    }
    return true;
  } catch (e) { if (version === generation) message(e.message);return false; }
}
function render(session) {
  const changed = currentSession?.user.id !== session?.user.id;
  if(changed || !session) {lockWorkspace();clearDevice();$('#device-fingerprint').textContent='';}
  currentSession=session;
  $('#login').hidden=!!session;$('#device-panel').hidden=!session;
  $('#workspace').hidden=!session || !approved;
  $('#status').textContent=session?'로그인되어 있어요. 기기 승인 후 메모를 열 수 있어요.':'메모를 보려면 로그인해 주세요.';
  if(!approved)$('#device-status').textContent='기기 승인 상태: 미확인';
}
auth.auth.onAuthStateChange((_event,session)=>{setTimeout(()=>render(session),0);});
$('#login-form').onsubmit = async event => {
  event.preventDefault(); message(''); const button = event.submitter; button.disabled = true;
  try { const {data,error} = await auth.auth.signInWithPassword({ email: $('#email').value.trim(), password: $('#password').value }); $('#password').value = ''; if (error) throw error; render(data.session);message('로그인했어요. 기기 승인을 요청해 주세요.'); }
  catch (e) { message(e.message === 'Invalid login credentials' ? '이메일 또는 비밀번호가 맞지 않습니다.' : e.message); }
  finally { button.disabled = false; }
};
$('#logout').onclick = $('#device-logout').onclick = async () => {
  lockWorkspace();clearDevice();
  const { error } = await auth.auth.signOut();
  if (error) message(error.message);else { render(null); message('로그아웃했어요.'); }
};
const stateText={pending:'승인 대기',approved:'서버 승인 확인',revoked:'승인 회수됨',expired:'승인 만료'};
function showDevice(data) {
  $('#device-status').textContent='기기 승인 상태: '+(stateText[data.status] || '미확인');
  $('#device-fingerprint').textContent=deviceFingerprint();
}
$('#request-device').onclick=async event=>{
  event.currentTarget.disabled=true;lockWorkspace();
  try{const data=await requestDevice();showDevice(data);message('승인 요청을 보냈어요. 관리자가 기기 지문을 대조하고 승인한 뒤 결과를 확인해 주세요.');}
  catch(e){message(e.message);}finally{$('#request-device').disabled=false;}
};
$('#check-device').onclick=async event=>{
  event.currentTarget.disabled=true;lockWorkspace();const version=generation;
  try{
    const data=await deviceStatus();if(version!==generation)return;
    showDevice(data);
    if(data.status!=='approved'){message('아직 승인된 기기가 아니에요. 보호 자료는 표시하지 않습니다.');return;}
    if(await loadNotes()){
      approved=true;$('#workspace').hidden=false;
      message('서버에서 승인과 요청 서명을 확인했어요.');
    }
  }catch(e){message(e.message);}finally{$('#check-device').disabled=false;}
};
$('#editor').onsubmit = async event => {
  event.preventDefault(); $('#save').disabled = true;
  try { await api(editingId ? '/' + editingId : '', editingId ? 'PUT' : 'POST', { title: $('#title').value, body: $('#body').value }); resetEditor(); await loadNotes(); message('저장했어요.'); }
  catch (e) { message(e.message); } finally { $('#save').disabled = false; }
};
$('#cancel').onclick = resetEditor; $('#refresh').onclick = loadNotes;
window.addEventListener('offline',()=>{lockWorkspace();message('오프라인에서는 보호 자료를 표시하지 않습니다. 연결 후 승인 결과를 다시 확인해 주세요.');});
window.addEventListener('pagehide',()=>{lockWorkspace();clearDevice();});
window.addEventListener('pageshow',event=>{if(event.persisted){lockWorkspace();clearDevice();$('#device-status').textContent='다시 기기 승인을 요청해 주세요.';}});
const { data, error } = await auth.auth.getSession(); if (error) message(error.message); render(data.session);
