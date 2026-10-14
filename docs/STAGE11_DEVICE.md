# 11단계 자료실 자체 기기 승인·서명 계약

이 문서는 현재 학생 자료 API의 계약입니다. 운영 반 엔진의 계약을 대신하지 않습니다.
운영 엔진이 제공하는 등록/서명 규격은 별도 확인이 필요하며, src/decider.mjs의 입력을 확장하지 않습니다.

- POST /api/device: Authorization 로그인 검증, JSON {publicKey:{crv:"P-256",kty:"EC",x,y}}.
  개인키 필드, status, role 등 다른 이름은 거부. 최초 상태 pending. 브라우저에서 승인할 API 없음.
- GET /api/device?id=공개기기지문: 로그인한 본인의 id/status/expiresAt만 반환.
- 관리자의 SQL 승인: 정확한 지문 한 행만 pending → approved, 유효기간 8시간.
- 개인키와 토큰은 저장소/캐시/cookie에 넣지 않음. 개인키는 현재 페이지의 비추출 CryptoKey.
  이는 페이지 수명에 한정된 접속 승인이고, 하드웨어/OS 관리 상태 증명은 아님.

## 보호 API의 네 요청 헤더

x-vault-device: JWK의 crv,kty,x,y 순서 JSON에 대한 소문자 SHA-256.
x-vault-time: Unix 초 문자열, 서버와 최대 60초 차이.
x-vault-nonce: UUID v4, DB에서 동일 기기와 조합하여 한 번만 소비.
x-vault-signature: ECDSA P-256/SHA-256, r||s 64바이트, 패딩 없는 base64url.
기존 Authorization: Bearer 로그인 토큰도 반드시 필요합니다.

서명 문자열은 아래 항목을 LF로 이어 붙이며 끝 LF는 붙이지 않습니다.

1. vault.device.v1
2. 설정된 배포 origin
3. 검증하는 로그인 토큰 원문의 SHA-256
4. 공개 기기 지문
5. 대문자 HTTP 메서드
6. 실제 요청 URL의 경로와 쿼리(원문, 순서 포함)
7. 본문 SHA-256
8. x-vault-time
9. x-vault-nonce

본문은 키를 정렬한 JSON입니다. 배열 순서는 보존하고 JSON 값만 허용하며 최대 깊이 20,
최대 65536 UTF-8 바이트입니다. 본문이 없는 경우 빈 문자열을 해시합니다.
공백/객체 키 순서 변경은 동일한 내용입니다. 제목/내용 등 값이 바뀌면 서명은 무효입니다.

서버는 검증된 로그인 사용자와 기기의 owner_id를 비교한 뒤 서명, 현재 승인과 유효기간,
원자적 nonce 소비를 확인합니다. 메모 소유자/공지 역할/복원 범위 검사는 그 뒤에 기존대로 수행합니다.
서명 없음·변조·미승인·회수·만료·재사용은 403; 로그인 실패 401; 기기 DB 장애 503.
서명 입력 문자열, 토큰, 개인키, 메모 본문은 로그에 쓰지 않습니다.
