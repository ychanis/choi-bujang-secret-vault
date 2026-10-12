-- PUBLIC 직접 테이블 권한 확인: 적용 후 0행이어야 합니다.
select a.privilege_type
from pg_class c join pg_namespace n on n.oid = c.relnamespace
cross join lateral aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
where n.nspname = 'public' and c.relname = 'notes' and a.grantee = 0;

-- 적용 전후 각각 실행: 실제 유효 테이블 권한 확인
select r.role_name, p.privilege,
       has_table_privilege(r.role_name, 'public.notes', p.privilege) as allowed
from (values ('anon'), ('authenticated')) r(role_name)
cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) p(privilege)
order by r.role_name, p.privilege;

-- 적용 전후 각각 실행: PUBLIC 및 두 역할의 별도 컬럼 권한 확인
select grantee, column_name, privilege_type
from information_schema.column_privileges
where table_schema = 'public' and table_name = 'notes'
  and grantee in ('PUBLIC', 'anon', 'authenticated');

-- 검토 후 아래 묶음만 실행. 다른 테이블·RLS·자료는 변경하지 않습니다.
begin;
revoke all privileges on table public.notes from PUBLIC, anon, authenticated;
-- 테이블 REVOKE만으로 남을 수 있는 별도 컬럼 권한도 회수합니다.
do $$
declare col record;
begin
  for col in select attname from pg_attribute
    where attrelid = 'public.notes'::regclass and attnum > 0 and not attisdropped
  loop
    execute format('revoke select (%1$I), insert (%1$I), update (%1$I), references (%1$I) on table public.notes from PUBLIC, anon, authenticated', col.attname);
  end loop;
end $$;
commit;
