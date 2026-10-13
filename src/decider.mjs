import { checkResourceAccess } from './resource-policy.mjs';
// 엔진이 검증해 전달한 계약 입력만 사용합니다.
// 브라우저 헤더를 읽거나 누락된 신호를 정상값으로 채우지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'input_signal_validation',
  'step_up_required',
  'resource_scope',
  'note_api_owner_required',
  'announcement_read_only',
]);

const REQUEST_KEYS = [
  'schema', 'requestId', 'classId', 'projectId', 'subjectId',
  'deviceId', 'service', 'method', 'path', 'route',
  'queryLength', 'querySha256', 'at', 'policyRevision',
  'deviceRegistered', 'stepUp', 'recentEvents', 'signals',
];

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function validSignals(request) {
  if (!exactKeys(request, REQUEST_KEYS)
      || request.schema !== 'aleph.decision.v1') return false;

  const signals = request.signals;
  if (!exactKeys(signals, ['source', 'region', 'network', 'hour']))
    return false;

  if (!['none', 'judge_fixture'].includes(signals.source))
    return false;

  if (typeof signals.region !== 'string' || !signals.region.trim()
      || typeof signals.network !== 'string' || !signals.network.trim()
      || !Number.isInteger(signals.hour)
      || signals.hour < 0 || signals.hour > 23) return false;

  // 실제 접속의 증거 없음은 unknown 그대로 취급합니다.
  if (signals.source === 'none'
      && (signals.region !== 'unknown' || signals.network !== 'unknown'))
    return false;

  if (!Array.isArray(request.recentEvents)
      || request.recentEvents.length > 12) return false;

  return request.recentEvents.every(event =>
    exactKeys(event, ['kind', 'ageSeconds', 'count'])
    && typeof event.kind === 'string' && event.kind.trim().length > 0
    && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
    && Number.isInteger(event.count) && event.count >= 0
  );
}

export async function decide(request) {
  const result = (decision, reasonCode, ruleIds) => ({
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision,
    reasonCode,
    ruleIds,
  });

  if (request?.deviceRegistered !== true) {
    return result('deny', 'device_not_registered', ['device_registered']);
  }

  if (!validSignals(request)) {
    return result('step_up', 'step_up_required', ['input_signal_validation']);
  }


  const resourceAccess = checkResourceAccess(request);
  if (!resourceAccess.allowed) {
    // Existing starter deny code; ruleIds identifies the resource policy rejection.
    return result('deny', 'starter_not_ready', ['resource_scope']);
  }

  // 심판 가상 사건만 검사합니다. 실제 위치 증거로 사용하지 않습니다.
  const signals = request.signals;
  const unusualHour = signals.hour >= 0 && signals.hour < 6;
  const unusualNetwork = signals.network === 'unusual';
  const burstRead = request.recentEvents.some(event =>
    event.kind === 'risk_signal'
    && event.ageSeconds <= 120
    && event.count >= 20
  );

  if (signals.source === 'judge_fixture'
      && unusualHour && unusualNetwork && burstRead) {

    // 엔진 계약으로 전달된 가상 재확인 결과만 검사합니다.
    const confirmation = request.stepUp;
    const confirmed = exactKeys(confirmation, ['verified', 'authAgeSeconds'])
      && confirmation.verified === true
      && Number.isFinite(confirmation.authAgeSeconds)
      && confirmation.authAgeSeconds >= 0
      && confirmation.authAgeSeconds <= 900;

    if (confirmed) {
      return result('allow', 'approved', ['device_registered', 'step_up_required', ...resourceAccess.ruleIds]);
    }

    return result('step_up', 'step_up_required', ['step_up_required']);
  }

  return result('allow', 'approved', ['device_registered', 'input_signal_validation', ...resourceAccess.ruleIds]);
}
