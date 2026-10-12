import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm';
const auth = createClient('https://mzxveixvhwsvkdzzjdoc.supabase.co', 'sb_publishable_Hdzt8NX91jem3oNeeQCprg_w0SWJIZ9');
const $ = selector => document.querySelector(selector);
let currentSession = null, editingId = null, generation = 0;
const message = text => { $('#message').textContent = text; };
function resetEditor() { editingId = null; $('#editor').reset(); $('#editor-heading').textContent = '메모 추가'; }
async function api(path = '', method = 'GET', body) {
  const { data, error } = await auth.auth.getSession();
  if (error || !data.session) throw new Error('로그인이 필요합니다.');
  const response = await fetch('/api/notes' + path, { method, cache: 'no-store', headers: { Authorization: `Bearer ${data.session.access_token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  let result; try { result = await response.json(); } catch { throw new Error('서버 응답을 확인할 수 없습니다.'); }
  if (!response.ok) throw new Error(result.error || '요청에 실패했습니다.');
  return result;
}
async function loadNotes() {
  const version = generation;
  try {
    const notes = await api();
    if (version !== generation || !currentSession) return;
    if (!Array.isArray(notes)) throw new Error('자료 형식이 맞지 않습니다.');
    $('#notes').replaceChildren();
    if (!notes.length) { const li = document.createElement('li'); li.textContent = '아직 내 메모가 없어요. 위에서 새 메모를 추가해 주세요.'; $('#notes').append(li); }
    for (const note of notes) {
      const li = document.createElement('li'), title = document.createElement('h3'), body = document.createElement('p'); title.textContent = note.title; body.textContent = note.body;
      const edit = document.createElement('button'); edit.textContent = '수정'; edit.onclick = () => { editingId = note.id; $('#title').value = note.title; $('#body').value = note.body; $('#editor-heading').textContent = '메모 수정'; $('#title').focus(); };
      const remove = document.createElement('button'); remove.textContent = '삭제'; remove.onclick = async () => { if (!confirm('이 메모를 삭제할까요?')) return; try { await api('/' + note.id, 'DELETE'); if (editingId === note.id) resetEditor(); await loadNotes(); message('삭제했어요.'); } catch (e) { message(e.message); } };
      li.append(title, body, edit, remove); $('#notes').append(li);
    }
  } catch (e) { if (version === generation) message(e.message); }
}
function render(session) {
  generation++; currentSession = session; $('#login').hidden = !!session; $('#workspace').hidden = !session; $('#notes').replaceChildren(); resetEditor();
  $('#status').textContent = session ? '로그인되어 있어요. 내 메모를 관리할 수 있어요.' : '메모를 보려면 로그인해 주세요.';
  if (session) void loadNotes();
}
auth.auth.onAuthStateChange((_event, session) => { render(session); });
$('#login-form').onsubmit = async event => {
  event.preventDefault(); message(''); const button = event.submitter; button.disabled = true;
  try { const { error } = await auth.auth.signInWithPassword({ email: $('#email').value.trim(), password: $('#password').value }); $('#password').value = ''; if (error) throw error; message('로그인했어요.'); }
  catch (e) { message(e.message === 'Invalid login credentials' ? '이메일 또는 비밀번호가 맞지 않습니다.' : e.message); }
  finally { button.disabled = false; }
};
$('#logout').onclick = async () => { const { error } = await auth.auth.signOut(); if (error) message(error.message); else { render(null); message('로그아웃했어요.'); } };
$('#editor').onsubmit = async event => {
  event.preventDefault(); $('#save').disabled = true;
  try { await api(editingId ? '/' + editingId : '', editingId ? 'PUT' : 'POST', { title: $('#title').value, body: $('#body').value }); resetEditor(); await loadNotes(); message('저장했어요.'); }
  catch (e) { message(e.message); } finally { $('#save').disabled = false; }
};
$('#cancel').onclick = resetEditor; $('#refresh').onclick = loadNotes;
const { data, error } = await auth.auth.getSession(); if (error) message(error.message); render(data.session);
