# BYTE BACK 방어전 — 4단계 저장점

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
