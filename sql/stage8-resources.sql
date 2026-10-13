-- Existing notes, owners and permissions are preserved. No existing table is altered.
BEGIN;
CREATE TABLE IF NOT EXISTS public.vault_roles (
  user_id uuid PRIMARY KEY,
  role text NOT NULL CHECK (role IN ('student', 'instructor'))
);
CREATE TABLE IF NOT EXISTS public.announcements (
  api_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  title text NOT NULL,
  content text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.vault_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.announcements ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.vault_roles, public.announcements FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.vault_roles, public.announcements TO service_role;
-- Publicly shareable fictitious announcement only. The fixed ID makes reruns safe.
INSERT INTO public.announcements (api_id,title,content)
VALUES ('88888888-8888-4888-8888-888888888888','연습용 강사 공지','이 공지는 자원별 권한 확인에 사용하는 가상 자료입니다.')
ON CONFLICT (api_id) DO NOTHING;
COMMIT;
-- No student is automatically promoted to instructor.
-- Instructor roles, if needed, must be registered by the DB administrator.
