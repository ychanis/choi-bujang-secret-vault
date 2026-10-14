// patterns.json의 두 패턴을 내장합니다.
// 임계값은 연습용 정책이며 MITRE가 지정한 수치가 아닙니다.
const PATTERNS = Object.freeze([
  {
    name: '반복 비밀번호 추측',
    condition: {
      required: '유효한 출발 주소·계정, T1110 근거, 인증 실패 설명과 양의 정수 실패 횟수',
      strong: '실패 30건 이상·규칙 수준 10 이상이며, 3분 이내 집중 또는 반복·연속·비밀번호 변경 대입 또는 성공 없음이 설명에 명시됨',
      uncertain: '인증 실패가 있으나 명확한 공격 기준에는 미달함',
      guard: '실패 횟수가 적은 사건과 비밀번호 변경 화면의 실패는 자동 차단하지 않음',
    },
    evidence: 'MITRE ATT&CK T1110은 비밀번호를 반복적으로 추측하는 공격과 다수 인증 실패의 상관 분석을 설명한다.',
    source: 'https://attack.mitre.org/techniques/T1110/',
  },
  {
    name: '여러 계정 대상 비밀번호 살포',
    condition: {
      required: '유효한 출발 주소, T1110 근거, 여러 계정에 대한 인증 실패 또는 연속 대입 설명',
      strong: '규칙 수준 10 이상이며 같은 비밀번호를 여러 계정에 대입한 증거가 있거나, 10개 이상 계정에 반복·일정 간격으로 실패한 증거가 있음',
      uncertain: '여러 계정의 실패는 있으나 동일 비밀번호나 반복 자동화의 근거가 부족함',
      guard: '계정 수만으로 같은 비밀번호를 사용했다고 단정하지 않으며 비밀번호 원문은 읽거나 기록하지 않음',
    },
    evidence: 'MITRE ATT&CK T1110.003은 하나 또는 소수의 비밀번호를 여러 계정에 시도하는 Password Spraying을 설명한다.',
    source: 'https://attack.mitre.org/techniques/T1110/003/',
  },
]);

function result(confidence, reason) {
  return {
    action: confidence >= 0.85 ? 'block'
      : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason,
  };
}

function validIp(value) {
  return typeof value === 'string'
    && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
    && value.split('.').every(part => Number(part) <= 255);
}

function positiveInteger(value) {
  if (typeof value !== 'number'
      && !(typeof value === 'string' && /^\d+$/.test(value))) {
    return 0;
  }
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : 0;
}

export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const level = alert?.rule?.level;
  const mitre = alert?.rule?.mitre;
  const count = positiveInteger(alert?.data?.count);

  const technique = Array.isArray(mitre)
    && mitre.some(id => typeof id === 'string'
      && /^T1110(?:\.\d{3})?$/.test(id));
  const validSource = validIp(alert?.data?.srcip);
  const validAccount = typeof alert?.data?.srcuser === 'string'
    && /^user\d{2}$/.test(alert.data.srcuser);
  const validLevel = Number.isInteger(level) && level >= 0 && level <= 16;

  const failure = /실패/.test(description);
  const sequence = /연속|반복|이어졌|이어졌습니다|이어진|이어졌|이어졌|이어/.test(description);
  const passwordAttempt = /비밀번호/.test(description)
    && /넣|대입|시도/.test(description);

  if (!technique || !validLevel || (!failure && !passwordAttempt)) {
    return result(0.1, '근거 패턴 없음');
  }

  // 경보에 실제로 있는 계정 수만 사용합니다.
  const listedAccounts = typeof alert?.data?.accounts === 'string'
    ? [...new Set(alert.data.accounts.split(',')
      .map(value => value.trim())
      .filter(value => /^user\d{2}$/.test(value)))]
    : [];
  const accountMatch = description.match(/계정\s*(\d+)\s*개/);
  const accountCount = Math.max(
    listedAccounts.length,
    accountMatch ? positiveInteger(accountMatch[1]) : 0,
  );
  const multipleAccounts = accountCount >= 2
    || /여러 계정|서로 다른 계정|계정 이름을 바꿔|두 계정/.test(description);
  const samePassword = /같은 비밀번호/.test(description);
  const regularAttempts = /같은 간격|일정한 간격|일정 간격/.test(description);

  if (multipleAccounts) {
    const strongSpray = validSource && level >= 10
      && ((samePassword && (failure || sequence))
        || (accountCount >= 10 && failure
          && (regularAttempts || sequence)));

    if (strongSpray) return result(0.95, PATTERNS[1].name);
  }

  const minutes = [...description.matchAll(/(\d+)\s*분/g)]
    .map(match => Number(match[1]));
  const shortWindow = minutes.some(value => value > 0 && value <= 3);
  const variedPassword = /비밀번호/.test(description)
    && /바꿔|변경/.test(description)
    && /넣|대입/.test(description);
  const noSuccess = /성공(?:은|이)?\s*없/.test(description);
  const passwordChangeScreen = /비밀번호 변경 화면/.test(description);

  const strongGuess = validSource && validAccount
    && failure && count >= 30 && level >= 10
    && !passwordChangeScreen
    && (shortWindow || sequence || variedPassword || noSuccess);

  if (strongGuess) return result(0.92, PATTERNS[0].name);

  // 증거가 부족하거나 소수 실패인 사건은 차단하지 않습니다.
  return result(0.6, multipleAccounts ? PATTERNS[1].name : PATTERNS[0].name);
}
