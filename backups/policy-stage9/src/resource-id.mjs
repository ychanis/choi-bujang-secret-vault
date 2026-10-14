// 기존 UUID는 유지하고 자원 종류를 접두사로 구분합니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TYPES = new Set(['notes', 'announcements']);

export function resourceId(type, id) {
  if (!TYPES.has(type) || typeof id !== 'string' || !UUID.test(id)) {
    throw new TypeError('알 수 없는 자원 종류 또는 잘못된 UUID입니다.');
  }
  return type + '/' + id.toLowerCase();
}
