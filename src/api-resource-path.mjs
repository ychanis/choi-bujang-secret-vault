const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Routing uses the actual URL. Query values never select a function or override the path.
export function parseResourcePath(req, type) {
  if (typeof req.url !== 'string' || !req.url.startsWith('/') || req.url.startsWith('//')) return null;
  const [path, search = ''] = req.url.split('?');
  if (req.url.includes('#') || req.url.includes('%') || req.url.includes('\\')) return null;
  const base = '/api/' + type;
  if (path !== base && !path.startsWith(base + '/')) return null;
  const id = path === base ? undefined : path.slice(base.length + 1);
  if (id !== undefined && !UUID.test(id)) return null;
  const params = new URLSearchParams(search);
  if ([...params.keys()].some(key => key !== 'id')) return null;
  const queryIds = params.getAll('id');
  if (queryIds.length > 1) return null;
  if (queryIds.length && (!id || queryIds[0] !== id)) return null;
  const query = req.query ?? {};
  if (Object.keys(query).some(key => key !== 'id')) return null;
  // Vercel's dynamic routing supplies id in req.query. It must match the URL.
  if (query.id !== undefined && query.id !== id) return null;
  return { id };
}
export function rejectResource(res, status, code, error) {
  // No identity, token, resource ID or content goes into the refusal log.
  console.warn('resource_api_deny', code);
  return res.status(status).json({ error, reasonCode: code });
}
