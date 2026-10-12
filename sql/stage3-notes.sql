-- 기존 숫자 ID와 가상 메모를 보존하고 API용 UUID를 추가합니다.
begin;
alter table public.notes add column if not exists api_id uuid not null default gen_random_uuid();
create unique index if not exists notes_api_id_key on public.notes(api_id);
alter table public.notes enable row level security;
revoke all on table public.notes from anon, authenticated;
grant select, insert, update, delete on table public.notes to service_role;
grant usage, select on all sequences in schema public to service_role;
commit;
