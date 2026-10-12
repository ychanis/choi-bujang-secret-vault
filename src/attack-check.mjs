// 실제 배포 요청만 기록합니다. 로그인 계정 점검은 직접 실행 전까지 미실행입니다.
export async function runAttackChecks(config) {
  const results = [];
  for (const [path, attackId, expected] of [
    ['/api/notes', 'anonymous_note_read', '로그인 없는 목록 요청에 401 또는 403과 JSON 오류'],
    ['/aleph.json', 'deployment_identity', '배포 식별 JSON의 단계와 저장점 커밋 확인'],
    ['/', 'security_headers', '첫 화면에 nosniff 보안 헤더'],
  ]) {
    try {
      const response = await fetch(new URL(path, config.publicAppUrl), { redirect: 'error', signal: AbortSignal.timeout(10000) });
      let observed;
      if (path === '/') observed = `HTTP ${response.status}, nosniff=${response.headers.get('x-content-type-options') === 'nosniff'}`;
      else {
        let data; try { data = await response.json(); } catch { data = null; }
        if (path === '/api/notes') observed = `HTTP ${response.status}, JSON 오류=${!!data?.error}, 메모 배열=${Array.isArray(data) || Array.isArray(data?.notes)}`;
        else observed = `HTTP ${response.status}, JSON=${!!data}, 단계=${data?.step ?? '없음'}, 커밋=${typeof data?.commit === 'string' && /^[a-f0-9]{40}$/i.test(data.commit) ? data.commit : '없음'}`;
      }
      results.push({ attackId, expected, observed });
    } catch { results.push({ attackId, expected, observed: '배포 요청 실패: 연결 또는 응답을 확인할 수 없음' }); }
  }
  results.push({ attackId: 'authenticated_crud', expected: '정상 A 로그인 후 추가·수정·삭제, 삭제 후 단건 GET 404', observed: '미실행: 실제 로그인 계정으로 배포 후 직접 확인 필요' });
  return results;
}
