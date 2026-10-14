import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';

const HEX = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const sha256 = value => createHash('sha256').update(value).digest('hex');

export function publicDeviceKey(value) {
  if (!value || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'crv,kty,x,y'
      || value.kty !== 'EC' || value.crv !== 'P-256'
      || !/^[A-Za-z0-9_-]{43}$/.test(value.x ?? '') || !/^[A-Za-z0-9_-]{43}$/.test(value.y ?? ''))
    throw new Error('invalid_device_key');
  const jwk = { crv: value.crv, kty: value.kty, x: value.x, y: value.y };
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const exported = key.export({format:'jwk'});
  if (exported.x !== jwk.x || exported.y !== jwk.y) throw new Error('invalid_device_key');
  return { jwk, key, id: sha256(JSON.stringify(jwk)) };
}

// The signed body is canonical JSON. Key order and transport whitespace are not data.
export function canonicalJson(value, depth = 0) {
  if (depth > 20) throw new Error('invalid_body');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(v => canonicalJson(v, depth + 1)).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonicalJson(value[k], depth + 1)).join(',') + '}';
  }
  throw new Error('invalid_body');
}

export function proofMessage({origin, token, deviceId, method, path, bodyHash, at, nonce}) {
  return ['vault.device.v1', origin, sha256(token), deviceId, method, path, bodyHash, at, nonce].join('\n');
}

// Vercel can append the matched dynamic id to the internal request URL.
// Only a single, identical id on the same UUID resource is equivalent.
function routingEquivalentPath(req) {
  const match = /^(\/api\/(?:notes|announcements)\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))\?id=([0-9a-f-]{36})$/i.exec(req.url);
  if (!match || match[2] !== match[3] || req.query?.id !== match[2]
      || Object.keys(req.query).length !== 1) return req.url;
  return match[1];
}

export function makeDeviceVerifier({db, origin, clock = Date.now}) {
  return async (req, identity) => {
    try {
      const h = req.headers ?? {};
      const deviceId = h['x-vault-device'], at = h['x-vault-time'], nonce = h['x-vault-nonce'];
      const signature = h['x-vault-signature'];
      if (!HEX.test(deviceId ?? '') || !/^[0-9]{10}$/.test(at ?? '') || !UUID.test(nonce ?? '')
          || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)
          || Math.abs(clock() / 1000 - Number(at)) > 60
          || typeof h.authorization !== 'string' || !h.authorization.startsWith('Bearer ')
          || typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')
          || /[\r\n#\\]/.test(req.url) || !['GET','POST','PUT','DELETE'].includes(req.method))
        return {ok:false, code:'device_signature_required'};
      let body = req.body;
      if (typeof body === 'string') body = JSON.parse(body);
      const encoded = body === undefined || body === null ? '' : canonicalJson(body);
      if (Buffer.byteLength(encoded) > 65536) return {ok:false, code:'invalid_body'};
      const {data: device, error} = await db.from('vault_devices')
        .select('id,public_key,status,expires_at').eq('id',deviceId).eq('owner_id',identity.userId).maybeSingle();
      if (error) return {ok:false, code:'device_service_unavailable', status:503};
      if (!device || device.status !== 'approved' || !(Date.parse(device.expires_at) > clock()))
        return {ok:false, code:'device_not_approved'};
      const {key, id} = publicDeviceKey(device.public_key);
      if (id !== deviceId) return {ok:false, code:'device_key_mismatch'};
      const bytes = Buffer.from(signature,'base64url');
      if (bytes.length !== 64 || bytes.toString('base64url') !== signature)
        return {ok:false, code:'invalid_device_signature'};
      const matches = path => verifySignature('sha256', Buffer.from(proofMessage({
        origin, token:h.authorization.slice(7), deviceId, method:req.method,
        path, bodyHash:sha256(encoded), at, nonce,
      })), {key, dsaEncoding:'ieee-p1363'}, bytes);
      const equivalentPath = routingEquivalentPath(req);
      if (!matches(req.url) && (equivalentPath === req.url || !matches(equivalentPath)))
        return {ok:false, code:'invalid_device_signature'};
      // The DB rechecks approval while atomically consuming this request nonce.
      const {data: consumed, error: consumeError} = await db.rpc('vault_consume_device_nonce', {
        p_device:deviceId, p_owner:identity.userId, p_nonce:nonce, p_at:Number(at),
      });
      if (consumeError) return {ok:false, code:'device_service_unavailable', status:503};
      return consumed === true ? {ok:true} : {ok:false, code:'device_request_rejected'};
    } catch { return {ok:false, code:'invalid_device_signature'}; }
  };
}

export async function requireDevice(req, res, identity, verifier) {
  const result = typeof verifier === 'function' ? await verifier(req, identity) : {ok:false, code:'device_signature_required'};
  if (result?.ok === true) return true;
  res.status(result?.status === 503 ? 503 : 403).json({error:'기기 승인과 요청 서명 확인이 필요합니다.', reasonCode:result?.code ?? 'device_signature_required'});
  return false;
}
