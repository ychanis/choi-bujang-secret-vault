-- Supabase SQL Editor. Existing notes, backups and audit records are preserved.
BEGIN;
CREATE TABLE IF NOT EXISTS public.vault_devices (
  id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{64}$'),
  owner_id uuid NOT NULL,
  public_key jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  expires_at timestamptz NOT NULL DEFAULT (now() + interval '8 hours')
);
CREATE TABLE IF NOT EXISTS public.vault_device_nonces (
  device_id text NOT NULL REFERENCES public.vault_devices(id),
  nonce uuid NOT NULL,
  used_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id,nonce)
);
ALTER TABLE public.vault_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_device_nonces ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.vault_devices, public.vault_device_nonces FROM PUBLIC, anon, authenticated;
REVOKE ALL ON public.vault_devices, public.vault_device_nonces FROM service_role;
GRANT SELECT, INSERT ON public.vault_devices TO service_role;

CREATE OR REPLACE FUNCTION public.vault_consume_device_nonce(
  p_device text, p_owner uuid, p_nonce uuid, p_at bigint
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE inserted_count integer;
BEGIN
  IF abs(extract(epoch from clock_timestamp()) - p_at) > 60 THEN RETURN false; END IF;
  -- Serialize with administrative approval/revocation changes.
  PERFORM 1 FROM public.vault_devices
  WHERE id=p_device AND owner_id=p_owner AND status='approved' AND expires_at>clock_timestamp()
  FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;
  INSERT INTO public.vault_device_nonces(device_id,nonce) VALUES (p_device,p_nonce)
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_count=ROW_COUNT;
  RETURN inserted_count=1;
END;
$$;
REVOKE ALL ON FUNCTION public.vault_consume_device_nonce(text,uuid,uuid,bigint) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.vault_consume_device_nonce(text,uuid,uuid,bigint) TO service_role;
COMMIT;

-- Approval is performed by the administrator in SQL Editor, never by the browser.
-- Replace the placeholder with the public fingerprint displayed in your app:
-- UPDATE public.vault_devices SET status='approved', approved_at=now(),
-- expires_at=now()+interval '8 hours'
-- WHERE id='화면에서 확인한 64자리 기기 지문' AND status='pending'
-- RETURNING id,status,expires_at;
