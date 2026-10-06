# BYTE BACK 방어전 — 2단계

## 자료를 코드 밖으로 옮기기

1단계에서는 가상 메모가 `data.json`에 공개되어 있었습니다.

2단계에서는 가상 메모를 공개 파일에서 제거하고 Supabase 데이터베이스로 옮겼습니다.

현재 자료 조회 흐름은 다음과 같습니다.

브라우저 → `/api/notes` → Vercel 서버 → Supabase

## 적용한 내용

- `data.json`의 가상 메모 제거
- `public/data.json`의 가상 메모 제거
- Supabase `notes` 테이블에 가상 메모 4건 저장
- `owner_id`를 uuid 형식으로 준비
- Supabase RLS 활성화
- anon, authenticated 사용자의 직접 읽기 제한
- Vercel 서버 함수 `api/notes.js` 추가
- 화면에서 `/data.json` 대신 `/api/notes` 사용
- `SUPABASE_SECRET_KEY`는 Vercel 서버 환경변수로 관리

## 확인 결과

### /data.json

현재 결과:

```json
{
  "notes": []
}

공개 data.json에서는 가상 메모가 나오지 않습니다.
/api/notes
Supabase에 저장한 가상 메모 4건이 정상적으로 조회됩니다.
메인 화면에서도 다음 4개의 가상 자료가 정상적으로 표시됩니다.
- 과제
- 포트폴리오
- 아침 리추얼
- 훈련 행정 자료
현재 남아 있는 약점
현재 /api/notes는 아직 로그인 없이 접근할 수 있는 공개 주소입니다.
따라서 자료를 코드 밖으로 옮겼지만 접근 제어까지 완료된 것은 아닙니다. 인증과 접근 제어는 다음 단계에서 추가해야 합니다.
또한 1단계에서 공개했던 GitHub의 과거 커밋이나 이전 Vercel 배포가 남아 있다면 과거의 가상 메모도 확인될 수 있습니다.
따라서 최신 파일에서 메모를 제거했다고 해서 과거 노출까지 해결된 것은 아닙니다.
확인 방법
GitHub 최신 버전의 data.json과 public/data.json에서 가상 메모 문장이 남아 있지 않은지 확인합니다.
배포된 /data.json에서는 메모가 0건이어야 합니다.
배포된 /api/notes에서는 Supabase의 가상 메모 4건이 조회되어야 합니다.
메인 화면에서는 /api/notes를 통해 가상 메모 4건이 표시되어야 합니다.
public/aleph.json은 Vercel 빌드 과정에서 자동 생성하도록 기존 기능을 유지했습니다.
2단계 상태
- 공개 정적 파일의 메모 제거: 완료
- Supabase 자료 이동: 완료
- 서버 API 연결: 완료
- 메인 화면 가상 메모 4건 출력: 완료
- API 접근 제어: 다음 단계에서 진행
