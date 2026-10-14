const PATTERNS = [
  {
    "name": "관리자 그룹 이상 변경",
    "condition": "관리자 그룹 추가와 원격 주소·다수 계정·빠른 재가입·직후 명령 중 하나가 겹치고 수준 10 이상",
    "evidence": "T1078: 탈취한 정상 계정의 권한 악용과 관련된 수업용 복합 신호. 그룹 변경만으로 계정 도용을 확정하지 않음. https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "낯선 관리자 권한 사용",
    "condition": "직전 권한 상승 후 관리자 명령, 낯선 주소에서 관리자 세션 전환, 다른 계정 권한 사용, 또는 업무 밖과 낯선 주소의 관리자 명령이 겹치고 수준 10 이상",
    "evidence": "T1068은 취약점 악용에 의한 권한 상승, T1078은 정상 계정 악용을 설명함. 이 신호만으로 취약점 악용을 확정하지 않음. https://attack.mitre.org/techniques/T1068/ https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "불확실한 권한 변경 경보",
    "condition": "T1068 또는 T1078 경보 수준 5 이상이나 단독 관리자 명령·그룹 변경·업무 밖 사용이며 복합 공격 증거 부족",
    "evidence": "T1068/T1078 관련 경보는 조사 후보이며 단독 시간·수준·기법 표시는 차단 근거가 아님. https://attack.mitre.org/techniques/T1078/"
  }
];

// 수치와 문구는 수업용 정책입니다. 외부 상태나 경보 ID를 사용하지 않습니다.
export function decide(alert) {
  const text = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const level = Number(alert?.rule?.level);
  const data = alert?.data ?? {};
  const mitre = alert?.rule?.mitre;
  const techniques = Array.isArray(mitre) ? mitre : (Array.isArray(mitre?.id) ? mitre.id : []);
  const tagged = techniques.some(id => id === 'T1068' || id === 'T1078');
  const negated = /취소|실패|명령은 없습니다|변경은 없습니다|아닙니다|읽기만/.test(text);
  const approved = data.authorized === true || data.approved === true;
  const groupChange = /관리자 그룹/.test(text) && /추가|들어가|들어왔/.test(text);
  const adminGroup = /^(administrators|administrator|관리자)$/i.test(String(data.group ?? ''));
  const command = /관리자 명령|권한 명령|명령 실행/.test(text);
  const remote = /원격 주소/.test(text);
  const unfamiliar = /처음 보는|처음 봅니다|낯선/.test(text);
  const outside = /시간 밖|업무.*않는 시각|업무 시간 밖/.test(text) || data.outsideBusinessHours === true;
  const repeated = Number(data.count) >= 3 || /1분 뒤.*다시/.test(text);
  const promoted = /방금 관리자가|곧바로|관리자 권한으로 바뀌/.test(text);
  const impersonated = /다른 계정의 권한/.test(text);
  let confidence = 0.1;
  let reason = '정상 기록: 일치하는 권한 이상 패턴 없음';
  if (!approved && !negated && level >= 10 && groupChange && adminGroup
      && (remote || repeated || command)) {
    confidence = 0.95; reason = PATTERNS[0].name;
  } else if (!approved && !negated && level >= 10
      && ((command && (promoted || impersonated || (outside && unfamiliar)))
        || (promoted && unfamiliar))) {
    confidence = 0.95; reason = PATTERNS[1].name;
  } else if (!approved && level >= 5 && (tagged || command || groupChange || outside)) {
    confidence = 0.55; reason = PATTERNS[2].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
