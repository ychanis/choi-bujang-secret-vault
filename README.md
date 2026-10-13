# BYTE BACK 방어전 — 8단계 저장점

Supabase Auth 이메일·비밀번호 로그인과 로그아웃을 연결하고, 자료 API가 기존 `src/verify-login.mjs`로 인증 토큰을 확인합니다. 비로그인 또는 잘못된 토큰 요청은 메모 없이 JSON 오류로 거부합니다. 비밀번호와 JWT는 공식 SDK에서 처리하며 직접 만들지 않습니다.

## 기존 자료 보존

2단계 공개 정적 파일의 메모 제거, Supabase 자료 저장, RLS 및 브라우저 직접 접근 제한을 유지합니다. 기존 숫자 ID와 메모 본문을 보존하고 `api_id` UUID를 추가하여 API의 `id`로 사용합니다. DB `content`는 API `body`로 변환합니다. 기존 메모의 owner_id를 자동으로 변경하지 않으므로 소유자가 없는 기존 자료는 내 메모 목록에 나오지 않습니다.

## 배포 준비

1. 기존 Supabase 프로젝트 SQL Editor에서 `sql/stage3-notes.sql`을 실행합니다. 기존 메모는 삭제하지 않습니다.
2. Authentication → Users → Add user → Create new user에서 연습용 A와 B 계정을 만들고 이메일 인증 상태를 준비합니다. 비밀번호는 공식 입력란에 직접 입력합니다.
3. Vercel 기존 서버 환경변수 `SUPABASE_SECRET_KEY`를 유지합니다. 서버 전용 키를 브라우저 코드에 넣지 않습니다. 공개 프로젝트 URL과 publishable key만 `public/app.js`에 있습니다.
4. GitHub 연결 배포가 Ready가 된 뒤 공개 화면에서 A로 로그인하고 메모를 작성합니다.

## 화면 확인

- 시크릿 창: 로그인 화면과 로그인 안내만 표시. `/api/notes`는 HTTP 401 JSON 오류.
- A 로그인: 내 메모 배열을 읽고 추가·수정·삭제 가능. 로그아웃하면 메모와 작성 화면을 비웁니다.
- 삭제한 UUID의 GET은 404입니다.
- `/aleph.json`은 빌드에서 자동 생성합니다. 첫 화면에 `X-Content-Type-Options: nosniff` 헤더를 설정합니다.

## API 계약

| 메서드 | 경로 | 응답 |
| --- | --- | --- |
| GET | /api/notes | 로그인한 사용자 소유 메모 배열 |
| POST | /api/notes | `{id}`; 요청 `{id?,title,body}` |
| GET | /api/notes/:id | `{id,title,body}` 또는 404 |
| PUT | /api/notes/:id | `{id,title,body}`; 요청 `{title,body}` |
| DELETE | /api/notes/:id | `{id}` 또는 404 |

추가 시 owner_id는 서버가 검증한 사용자 ID로 저장합니다. 브라우저의 userId·role·owner_id는 신원으로 사용하지 않습니다. 단건 GET·PUT·DELETE는 검증된 사용자 ID와 owner_id가 일치하는 행만 허용합니다. 상대 메모는 404 JSON으로 거부하며, 추가·수정 본문의 owner_id 지정은 400으로 거부합니다. 현재 메모는 가상 자료만 사용합니다.

## 실행과 점검

- 설치: `npm ci`
- 로컬 계약 검사: `node --test test/stage3.test.mjs`
- 빌드: `npm run build` (Vercel 배포 식별 환경변수 필요)
- 제출 묶음: 커밋 후 `npm run bundle`

`bundle-notes.json`과 `artifacts/submission.json`은 Git에서 제외합니다. 실제 배포 익명 요청·배포 식별·헤더 결과는 자기 점검이며 심판 판정이 아닙니다. A 로그인 및 실제 DB CRUD는 계정과 DB 설정 후 직접 확인해야 하며, 로컬 모의 DB 검사로 실제 로그인 성공을 주장하지 않습니다.

## 4단계 소유권과 DB 권한

기존 가상 메모 4건을 A 소유로 연결하고 B 시험 메모 1건을 추가했습니다.
메모 테이블의 PUBLIC·anon·authenticated 권한을 회수한 뒤 authenticated에 SELECT·INSERT·UPDATE·DELETE만 허용했습니다.
RLS는 SELECT·DELETE의 USING, INSERT의 WITH CHECK, UPDATE의 USING과 WITH CHECK에서 auth.uid()와 owner_id를 비교합니다.
서버 API는 서버 전용 키를 사용하므로 API에서도 소유자를 별도로 검사합니다.
사용자가 SQL 적용 후 권한 결과를 확인했습니다. 실제 배포의 A/B CRUD와 상대 메모 거부는 배포 후 확인해야 합니다.

## 5단계 자료 요청을 서버 한곳으로 모읍니다

브라우저의 메모 CRUD는 이미 `/api/notes`와 `/api/notes/:id`만 호출합니다. 직접 자료 호출이 없어 화면과 Auth 코드는 변경하지 않았습니다. 서버 전용 키와 로그인·소유자 검사를 유지합니다.

`sql/stage5-notes.sql`은 public.notes만 대상으로 PUBLIC·anon·authenticated의 테이블 권한과 별도 컬럼 권한을 회수합니다. 기존 RLS·소유자·자료와 service_role 권한은 보존합니다. SQL은 준비만 했으며 학습 DB 적용은 사용자가 검토 후 실행해야 합니다.

1. 적용 전 SQL 파일의 권한 확인 SELECT 세 개를 실행해 결과를 보관합니다.
2. SQL 파일의 BEGIN부터 COMMIT까지 실행하고 같은 SELECT 세 개를 다시 실행합니다. PUBLIC 테이블 권한은 0행, anon·authenticated 테이블 권한은 모두 false, 컬럼 권한은 0행이어야 합니다.
3. 배포 후 A로 시험 메모를 추가·읽기·수정·삭제합니다. B에서는 A 메모 단건 GET·PUT·DELETE가 404이고, 로그아웃 후 API 요청은 401이어야 합니다. 개발자 도구 Network에서 메모 요청이 서버 API로만 가는지 확인합니다.
4. originalApiUrl에 공개 키만 사용한 요청, 그리고 공개 키와 로그인 사용자 토큰을 사용한 요청 모두 권한 오류가 나고 메모가 없어야 합니다. 비밀 키는 브라우저에 넣지 않습니다.

`originalApiUrl`은 쿼리 없는 HTTPS 원본 메모 경로입니다. allowedRoutes 다섯 개와 nosniff 헤더 설정을 유지했습니다. 공개 키는 Auth용으로 화면 코드에 남아 있으므로 공개 키 제거 가점은 구현하지 않았습니다.

검사: `npm ci` → `node --test test/stage3.test.mjs` → 저장점 커밋 후 `npm run bundle`. 로컬 모의 DB CRUD 통과는 실제 A/B 로그인 검사나 SQL 적용 완료를 뜻하지 않습니다. 제출 JSON과 설명 파일은 Git에서 제외합니다.

## 6단계 등록한 기기만 허용

판정기는 운영 엔진이 확인한 request.deviceRegistered가 true일 때만 allow·approved를 반환합니다.
false이거나 값이 없으면 deny·device_not_registered로 거부합니다.
구현한 규칙 ID는 device_registered입니다. 응답의 다섯 항목과 기존 로그인·메모 API·화면을 유지합니다.
인증서, CA, 서명 키, 기기 개인키는 생성하지 않았으며 별도 접속 프로그램 설치는 없습니다.

확인 순서:
1. npm run decider:test를 실행합니다.
2. 등록 기기의 정상 요청과 미등록 기기의 가상 요청이 모두 통과하는지 확인합니다.
3. 미등록 요청은 deny·device_not_registered이며, 등록 여부가 없는 요청도 같은 이유로 거부합니다.

이번 실행에서 등록·미등록 두 가상 요청 검사가 통과했습니다.
이는 로컬 연습 결과이며 실제 심판 판정이나 실제 기기 접속 확인이 아닙니다.
기존 배포 화면은 직접 열어 로그인과 본인 메모 조회를 확인합니다.
저장점 커밋 후 npm run bundle로 제출 묶음을 생성합니다.

## 7단계 평소와 다른 접속

기존 등록 기기 규칙을 유지하고 판정기 입력의 계약 항목과 신호 출처를 검사합니다.
누락되거나 출처가 불명확한 신호를 정상값으로 채우지 않습니다.
브라우저 헤더 등 계약 밖 항목은 정상 입력으로 인정하지 않습니다.
실제 접속의 source=none, region/network=unknown은 증거 없음으로 유지합니다.

judge_fixture 가상 사건에서 새벽 0~5시, unusual 네트워크,
최근 120초 이내 risk_signal 20건 이상이 겹치면
step_up·step_up_required와 step_up_required 사유를 반환합니다.
지역 하나만으로 차단하지 않습니다.

사용자 로컬 실행에서 정상 allow, 복합 이상 step_up,
미등록 기기 deny, 누락·출처 불명·위조 헤더 추가 확인을 확인했습니다.
가상 복합 이상 사건은 추가 확인 전 step_up이며, 계약 형식의 verified=true와 0~900초 authAgeSeconds가 확인되면 allow입니다.

현재 제공된 계약에는 같은 로그인 주체의 새 로그인 시각을 검증하는
절차가 명시되어 있지 않습니다.
실제 재로그인 전 자료 차단과 새 로그인 후 허용은 미실행입니다.
기존 자료 API에 가상 신호를 연결하거나 토큰 원문을 기록하지 않습니다.

재실행: npm run decider:test && npm run fixture:7
정상 사건은 allow, 복합 이상 사건은 step_up이어야 합니다.
가상 연습 결과는 실제 심판 판정이나 실제 자료 차단 증거가 아닙니다.

### 7단계 심판 피드백 수정
추가 확인 규칙 이름을 제공 연습 스크립트의 step_up_required에 맞췄습니다.
가상 재확인 뒤 허용 분기를 추가했습니다.
사용자 실행에서 정상·미등록·복합 이상·재확인 뒤 허용 4건이 통과했습니다.
실제 재로그인 전후 자료 차단 시험은 계속 미실행입니다.

## 8단계 자료마다 갈 수 있는 구역을 나눕니다

메모와 공지를 notes/UUID, announcements/UUID 자원 ID로 구분합니다.
기존 메모 ID·주소·본문·화면 메뉴와 6·7단계 규칙을 유지합니다.

판정기는 정확한 서비스·메서드·경로와 검증된 주체·기기 입력을 확인합니다.
알 수 없는 경로, 전체 메모 목록 /notes, 기능 경로와 쿼리 기능 선택을 거부합니다.
계약에 강사 역할이 없으므로 판정기의 공지 쓰기는 모두 거부합니다.
기존 /api/notes 목록은 서버의 본인 소유자 필터를 유지합니다.

최종 메모 API는 검증된 사용자와 저장된 owner_id를 대조합니다.
공지 수정 API는 보호된 vault_roles의 instructor 권한을 확인합니다.
요청 본문의 role·userId·owner_id로 권한을 부여하지 않습니다.
거부 로그에는 짧은 이유 코드만 남깁니다.

사용자가 공지·권한 테이블 SQL을 적용했습니다.
두 테이블의 RLS 활성화, anon·authenticated 읽기·수정 금지,
service_role 읽기·수정 허용을 사용자 실행 결과로 확인했습니다.

재실행:
npm run decider:test
npm run fixture:7
node --test test/stage3.test.mjs test/stage8-api.test.mjs test/stage8-decider.test.mjs

사용자 실행에서 로컬 검사 16개와 기존 판정기 연습이 통과했습니다.
실제 배포의 정상 CRUD·상대 메모 거부·학생 공지 수정 거부는 아직 미실행입니다.
로컬 검사 결과를 실제 심판 판정으로 보고하지 않습니다.
