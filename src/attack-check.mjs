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
  results.push({ attackId: 'authenticated_crud', expected: '정상 A 로그인 후 추가·수정·삭제, 삭제 후 단건 GET 404', observed: '11단계 이전 배포 기록: 사용자 실제 배포 확인: 로그인·메모 저장·수정·삭제 정상. 삭제 후 단건 GET은 별도 미실행' });

  results.push({
    attackId: 'stage7_reauthentication',
    expected: '엔진이 새 로그인 시각을 검증하는 환경에서 확인 전 자료 차단과 새 요청 허용',
    observed: '미실행: 현재 제공 계약에 새 로그인 시각 검증 절차가 명시되지 않음. 가상 사건 판정만 로컬 확인'
  });

  results.push(
    { attackId: 'stage8_other_note_read',
      expected: 'B의 A 메모 단건 조회 거부',
      observed: '11단계 이전 배포 기록: 사용자 실제 배포 API 확인: GET 404' },
    { attackId: 'stage8_other_note_update',
      expected: 'B의 A 메모 수정 거부',
      observed: '11단계 이전 배포 기록: 사용자 실제 배포 API 확인: PUT 404' },
    { attackId: 'stage8_other_note_list',
      expected: 'B 목록에서 A 메모 제외',
      observed: '11단계 이전 배포 기록: 사용자 실제 배포 API 확인: 목록 HTTP 200, A 메모 제외=true' },
    { attackId: 'stage8_student_announcement',
      expected: '학생이 본문 역할을 위조해도 공지 수정 거부',
      observed: '11단계 이전 배포 기록: 사용자 실제 배포 API 확인: PUT 403, instructor_required' }
  );
  results.push(
    {attackId:'stage10_tampered_restore',expected:'B 메모 변조 후 ID·소유자·해시 복원',observed:'11단계 이전 배포 기록: 사용자 실제 배포 확인: B 메모 변조 후 복원 성공, ID·소유자·내용 해시 일치'},
    {attackId:'stage10_deleted_restore',expected:'B 메모 삭제 후 같은 한 건 복원',observed:'11단계 이전 배포 기록: 사용자 실제 배포 확인: B 메모 삭제 후 복원 성공, ID·소유자·내용 해시 일치, 기존 B 메모 보존'},
    {attackId:'stage10_regression',expected:'복구 후 1~9단계 정상·금지 요청 재시험',observed:'11단계 이전 배포 기록: 복구 후 B의 A 조회·복구 요청 각각 404. 판정기 4건·7단계 연습·탐지 6건 통과. 나머지 실제 배포 재시험은 미실행'}
  );
  results.push(
    {attackId:'stage11_unsigned_request',expected:'서명 없는 보호 요청 403, 보호 자료 없음',observed:'로컬 서명/API 검사 통과. 실제 배포는 미실행'},
    {attackId:'stage11_path_tamper',expected:'서명 뒤 경로·쿼리·메서드 변경 403, 자료 처리 없음',observed:'로컬 서명/API 검사 통과. 실제 배포는 미실행'},
    {attackId:'stage11_body_tamper',expected:'서명 뒤 수정 본문 변경 403, 기존 자료 보존',observed:'로컬 서명/API 검사 통과. 실제 배포는 미실행'},
    {attackId:'stage11_approval_flow',expected:'pending에 자료 없음, 관리자 승인 후 서명된 기존 CRUD 정상',observed:'사용자 실제 배포 확인: B 기기 승인 후 기존 메모 조회·추가·수정·삭제 정상'}
  );

  {
    const expected = '무인증 작전실 요청 401, 요약 정보 없음';
    let observed;
    try {
      const response = await fetch(new URL('/api/operations', config.publicAppUrl), {
        redirect: 'error', signal: AbortSignal.timeout(10000)
      });
      let data;
      try { data = await response.json(); } catch { data = null; }
      const summaryPresent = !!data && ['rules','detection','revocation','recovery']
        .some(key => Object.hasOwn(data,key));
      observed = `HTTP ${response.status}, JSON 오류=${!!data?.error}, 요약 포함=${summaryPresent}, 요청 ID=${response.headers.get('x-request-id') || '미제공'}, 확인 시각=${new Date().toISOString()}`;
    } catch {
      observed = '미확인: 실제 배포 요청 실패';
    }
    results.push({attackId: 'stage12_operations_anonymous', expected, observed});
  }
  return results;
}
