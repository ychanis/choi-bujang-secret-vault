import {createClient} from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.117.2/+esm';
// Remove only this app's old SDK session, without reading or printing its value.
try {
  const key='sb-mzxveixvhwsvkdzzjdoc-auth-token';
  localStorage.removeItem(key);
  localStorage.removeItem(key+'-code-verifier');
  sessionStorage.removeItem(key);
  sessionStorage.removeItem(key+'-code-verifier');
} catch {}
export const auth=createClient('https://mzxveixvhwsvkdzzjdoc.supabase.co','sb_publishable_Hdzt8NX91jem3oNeeQCprg_w0SWJIZ9',{
  auth:{persistSession:false,detectSessionInUrl:false,autoRefreshToken:true},
});
