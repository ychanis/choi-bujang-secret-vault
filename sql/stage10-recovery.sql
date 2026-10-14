-- 새 가상 메모의 최초 사본만 저장합니다. 기존 자료는 소급 백업하지 않습니다.
BEGIN;
CREATE TABLE IF NOT EXISTS public.vault_note_backups (
 api_id uuid PRIMARY KEY, owner_id uuid NOT NULL, snapshot jsonb NOT NULL,
 content_hash text NOT NULL, captured_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.vault_recovery_audit (
 event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 api_id uuid NOT NULL, owner_id uuid NOT NULL, content_hash text NOT NULL,
 restored_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.vault_note_backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_recovery_audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.vault_note_backups,public.vault_recovery_audit FROM PUBLIC,anon,authenticated,service_role;
CREATE OR REPLACE FUNCTION public.vault_capture_new_note() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NEW.owner_id IS NOT NULL THEN
  INSERT INTO public.vault_note_backups(api_id,owner_id,snapshot,content_hash)
  VALUES(NEW.api_id,NEW.owner_id,to_jsonb(NEW),
   encode(sha256(convert_to(jsonb_build_array(NEW.title,NEW.content)::text,'UTF8')),'hex'))
  ON CONFLICT(api_id) DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.vault_capture_new_note() FROM PUBLIC,anon,authenticated,service_role;
DROP TRIGGER IF EXISTS vault_backup_new_note ON public.notes;
CREATE TRIGGER vault_backup_new_note AFTER INSERT ON public.notes
FOR EACH ROW EXECUTE FUNCTION public.vault_capture_new_note();
CREATE OR REPLACE FUNCTION public.vault_restore_note(p_id uuid,p_owner uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE b public.vault_note_backups%ROWTYPE; n public.notes%ROWTYPE; h text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(p_id::text,0));
 SELECT * INTO b FROM public.vault_note_backups WHERE api_id=p_id AND owner_id=p_owner FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'backup_not_found' USING ERRCODE='P0002'; END IF;
 n:=jsonb_populate_record(NULL::public.notes,b.snapshot);
 h:=encode(sha256(convert_to(jsonb_build_array(n.title,n.content)::text,'UTF8')),'hex');
 IF n.api_id IS DISTINCT FROM b.api_id OR n.owner_id IS DISTINCT FROM b.owner_id OR h IS DISTINCT FROM b.content_hash THEN
  RAISE EXCEPTION 'backup_verification_failed';
 END IF;
 IF EXISTS(SELECT 1 FROM public.notes WHERE api_id=p_id AND owner_id IS DISTINCT FROM p_owner) THEN
  RAISE EXCEPTION 'owner_conflict';
 END IF;
 -- 지정한 한 건만 복원하고 기존 내부 ID와 다른 열은 보존합니다.
 UPDATE public.notes SET title=n.title,content=n.content WHERE api_id=p_id AND owner_id=p_owner;
 IF NOT FOUND THEN
  INSERT INTO public.notes SELECT (jsonb_populate_record(NULL::public.notes,b.snapshot)).*;
 END IF;
 SELECT * INTO n FROM public.notes WHERE api_id=p_id AND owner_id=p_owner;
 IF NOT FOUND THEN RAISE EXCEPTION 'restore_verification_failed'; END IF;
 h:=encode(sha256(convert_to(jsonb_build_array(n.title,n.content)::text,'UTF8')),'hex');
 IF h IS DISTINCT FROM b.content_hash THEN RAISE EXCEPTION 'restore_verification_failed'; END IF;
 INSERT INTO public.vault_recovery_audit(api_id,owner_id,content_hash) VALUES(p_id,p_owner,h);
 RETURN jsonb_build_object('id',p_id,'ownerId',p_owner,'contentHash',h,'verified',true);
END $$;
REVOKE ALL ON FUNCTION public.vault_restore_note(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.vault_restore_note(uuid,uuid) TO service_role;
COMMIT;
