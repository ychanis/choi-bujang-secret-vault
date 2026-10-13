# 8단계 제작 3 — 최종 자료 API

메모는 기존 소유자 필터를 보존합니다. 실제 URL의 정확한 /api/notes 또는 UUID 경로만 받으며 쿼리로 경로나 기능을 선택하지 않습니다.
공지 GET은 검증된 로그인 사용자에게 허용합니다. 공지 PUT은 검증된 사용자의 ID로 vault_roles 테이블을 조회하여 instructor일 때만 허용합니다.
요청 본문 role, owner_id, userId는 권한으로 사용하지 않습니다. 공지 수정은 title/body 두 항목만 허용합니다.
심판 A/B 시험 신원은 강사 역할을 받지 않습니다. 거부 로그는 고정된 짧은 이유 코드만 남기고 사용자·토큰·자료 내용은 남기지 않습니다.

1. sql/stage8-resources.sql을 기존 Supabase SQL Editor에서 실행합니다. 기존 메모를 수정하거나 삭제하지 않습니다.
2. node --test test/stage3.test.mjs test/stage8-api.test.mjs
3. 배포 후 정상 메모 CRUD와 B의 A 메모 단건 거부, 학생의 공지 PUT 403을 직접 확인합니다.

DB SQL 적용·실제 A/B 요청·실제 강사 역할 등록·심판 판정은 로컬 테스트 완료와 구분해서 기록합니다.
