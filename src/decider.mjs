// ALEPH SDP 엔진이 확인한 요청만 받습니다.
// 기기 등록 여부가 명시적으로 true일 때만 허용합니다.
export const RULE_IDS = Object.freeze(['device_registered']);

export async function decide(request) {
  const registered = request.deviceRegistered === true;

  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: registered ? 'allow' : 'deny',
    reasonCode: registered ? 'approved' : 'device_not_registered',
    ruleIds: ['device_registered'],
  };
}
