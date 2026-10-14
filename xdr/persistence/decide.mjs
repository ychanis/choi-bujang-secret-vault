const PATTERNS = [
  {
    "name": "unsigned-service",
    "condition": "서비스 등록·실행 파일 변경 + 서명 없음 + 임시 실행 파일 또는 반복 등록 + 수준 10 이상",
    "evidence": "MITRE T1543: 서비스 생성·변경을 통한 지속 실행. https://attack.mitre.org/techniques/T1543/"
  },
  {
    "name": "unfamiliar-task",
    "condition": "예약 작업 + 임시 실행 파일 + 낯선 이름·비정상 시각·시작 항목 연계 + 수준 10 이상",
    "evidence": "MITRE T1053: 예약 작업을 통한 지속 실행. https://attack.mitre.org/techniques/T1053/"
  },
  {
    "name": "unlisted-startup",
    "condition": "시작 폴더 경로 + 평소 목록 밖 프로그램 추가 + 수준 10 이상",
    "evidence": "MITRE T1547.001: 시작 폴더 자동 실행; T1543과 구분한다. https://attack.mitre.org/techniques/T1547/001/"
  }
];

// 수업용 설명 신호를 계산합니다. ID·주소·계정은 판단 기준이 아닙니다.
export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const tags = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const has = id => tags.some(tag => (typeof tag === 'string' ? tag : tag?.id)?.startsWith(id));
  const temp = /[\\/]Temp[\\/].+\.(exe|cmd|bat|ps1)$/i.test(path);
  const unsigned = /서명 없는|서명이 없습니다/.test(description);
  const serviceChange = (/서비스.*(?:등록|바뀌|변경)/.test(description) || /새 서비스/.test(description))
    && !/서비스 등록은 없습니다|실행 파일은 그대로/.test(description);
  const repeated = Number(alert?.data?.count) >= 3;
  const unlisted = /평소 목록에 없는/.test(description);
  let pattern = null;
  if (has('T1543') && serviceChange && ((unsigned && (temp || repeated))
      || (unlisted && /다시 켜도/.test(description) && temp))) pattern = PATTERNS[0];
  else if (has('T1053') && /예약 작업/.test(description) && temp
      && /처음 보는|임의 문자열|수업 시간 밖|함께 가리/.test(description)) pattern = PATTERNS[1];
  else if ((has('T1547.001') || has('T1543')) && /[\\/]Startup[\\/]/i.test(path)
      && /시작 폴더/.test(description) && unlisted && /추가/.test(description)) pattern = PATTERNS[2];
  let confidence = pattern ? (level >= 10 ? 0.95 : 0.7) : 0.1;
  if (!pattern && level >= 5 && (has('T1543') || has('T1053') || has('T1547.001'))) {
    pattern = /예약 작업/.test(description) ? PATTERNS[1]
      : /시작/.test(description) ? PATTERNS[2] : PATTERNS[0];
    confidence = 0.55;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: pattern ? pattern.name : '정상 또는 지속성 근거 부족' };
}
