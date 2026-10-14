const PATTERNS = [
  {
    "name": "sql_injection",
    "condition": "요청 인자의 UNION SELECT, OR 비교, SQL 연속 구문 또는 수업용 SQL 표식",
    "evidence": "MITRE T1190: 공개 웹 앱에 조작된 입력을 보내 SQL 주입을 시도함.",
    "markers": [
      "doc-sql-chain",
      "doc-sql-or",
      "doc-sql-select-chain"
    ]
  },
  {
    "name": "script_injection",
    "condition": "요청 인자의 script 태그 또는 수업용 스크립트 삽입 표식",
    "evidence": "MITRE T1190 관련 XSS: 웹 입력에 실행 가능한 스크립트를 삽입함.",
    "markers": [
      "doc-script-marker"
    ]
  },
  {
    "name": "path_traversal",
    "condition": "요청 인자의 ../ 반복 또는 수업용 경로 이탈 반복 표식",
    "evidence": "MITRE T1190: 공개 앱의 입력 검증 취약점을 악용하는 경로 이탈 신호.",
    "markers": [
      "doc-up-repeat"
    ]
  },
  {
    "name": "mixed_injection",
    "condition": "수업용 SQL 및 스크립트 혼합 표식",
    "evidence": "MITRE T1190: SQL 주입과 스크립트 삽입 입력 신호의 결합.",
    "markers": [
      "doc-mixed-marker"
    ]
  },
  {
    "name": "command_injection",
    "condition": "명령 구분자와 명령이 함께 있거나 수업용 명령 구분자 표식",
    "evidence": "MITRE T1190: 공개 앱의 명령 주입 취약점 악용 신호.",
    "markers": [
      "doc-cmd-separator"
    ]
  },
  {
    "name": "ambiguous_injection_signal",
    "condition": "단독 따옴표·주입 조각 또는 T1190 저수준 경보; 확증 없으므로 알림만",
    "evidence": "MITRE T1190 관련 입력 이상 신호이며 공격 성공 증거가 아님; 정상 수업 단어도 포함 가능.",
    "markers": []
  }
];

// 파일, 네트워크, 패키지, 상태 없이 경보 한 건만 판정합니다.
function decode(value) {
  let text = typeof value === 'string' ? value.slice(0, 16000) : '';
  for (let i = 0; i < 2; i++) {
    try { const next = decodeURIComponent(text.replace(/\+/g, ' '));
      if (next === text) break;
      text = next;
    } catch { break; }
  }
  return text;
}
export function decide(alert) {
  const data = alert?.data ?? {};
  const url = typeof data.url === 'string' ? data.url : '';
  const query = decode(url.includes('?') ? url.slice(url.indexOf('?') + 1) : '');
  const text = query + ' ' + decode(data.args) + ' ' + decode(data.body);
  const level = alert?.rule?.level;
  const count = Number(data.count);
  const matches = PATTERNS.filter(pattern => pattern.markers.some(marker =>
    new RegExp('(?:^|[= &])' + marker + '(?:$|[ &])', 'i').test(text)));
  const actual = [
    /\bunion\s+(?:all\s+)?select\b|['"]\s*or\s+['"\d]+\s*=|;\s*(?:select|drop|insert|update|delete)\b/i,
    /<\s*script\b/i,
    /(?:\.\.\/){2,}/,
    /$a/,
    /(?:;|&&|\|\||\$\()\s*(?:cat|curl|wget|sh|bash|whoami)\b/i,
  ];
  actual.forEach((regex, i) => { if (regex.test(text) && !matches.includes(PATTERNS[i])) matches.push(PATTERNS[i]); });
  let confidence = 0.1;
  let reason = 'normal_no_pattern';
  if (matches.length) {
    confidence = Number.isInteger(count) && count >= 5 && Number.isInteger(level) && level >= 10 ? 0.95 : 0.7;
    reason = matches.map(p => p.name).join(', ');
  } else if (/doc-one-(?:fragment|marker)(?:$|[ &])/i.test(text)
      || (alert?.rule?.mitre?.includes('T1190') && Number.isInteger(level) && level >= 5)) {
    confidence = 0.55;
    reason = 'ambiguous_injection_signal';
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
