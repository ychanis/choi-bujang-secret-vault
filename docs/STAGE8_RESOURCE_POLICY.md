# 8단계 자원별 경로 규칙

공식 안내: https://aleph-omega.vercel.app/assets/defense-ui/reason-guide.js 의 S08_OTHER_ZONE_ALLOWED.
계약 v1에는 강사 역할이 없으므로 판정기는 공지의 모든 쓰기를 거부합니다.
메모 한 건의 소유자 비교는 최종 API에서 검증된 사용자 ID와 저장된 owner_id로 수행합니다.
실제 사용자의 가명 subjectId와 Supabase UUID를 임의로 연결하지 않습니다.
판정기는 검증된 주체·기기 형식과 서비스·메서드·정확한 경로/route를 확인합니다.
알 수 없는 경로, 전체 메모 목록 /notes, 기능 이름 all/list/export/import/search/bulk/admin, 쿼리 기능 선택을 거부합니다.
기존 /api/notes GET은 최종 API가 본인 소유자 필터를 적용하는 경로이므로 유지합니다.
별도 자원 권한표 환경변수나 시험 사용자의 실사용 연결은 필요 없습니다.

실행: npm run decider:test && npm run fixture:7 && node --test test/stage8-decider.test.mjs
로컬 검사와 실제 배포/심판 판정을 구분합니다.
