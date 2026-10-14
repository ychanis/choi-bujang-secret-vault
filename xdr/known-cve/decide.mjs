const PATTERNS = [
  {
    "name": "log4shell_remote_lookup",
    "condition": "요청 머리글·인자에 완전한 ${jndi:ldap/ldaps/rmi/dns://호스트/…} 조회 구문; URL 인코딩도 확인",
    "evidence": "CVE-2021-44228: 공격자가 제어하는 로그 입력의 JNDI 원격 조회 악용 형태. https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
  },
  {
    "name": "incomplete_lookup_or_scanner",
    "condition": "잘린 JNDI 조회 또는 log4j-scan/log4shell-scanner 표식, 또는 T1190 수준 5 이상 경보; 알림만",
    "evidence": "MITRE ATT&CK T1190: 공개 앱 취약점 악용 시도 관련 신호이며 도구명·CVE 이름만으로 공격을 확정하지 않음. https://attack.mitre.org/techniques/T1190/"
  }
];

// 경보 한 건만 계산합니다. 파일·패키지·네트워크·공유 상태를 사용하지 않습니다.
function decode(value) {
  let text = typeof value === 'string' ? value.slice(0, 16000) : '';
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(text);
      if (next === text) break;
      text = next;
    } catch { break; }
  }
  return text;
}
export function decide(alert) {
  const data = alert?.data ?? {};
  const values = [data.url, data.useragent, data.args, data.body];
  for (const headers of [data.headers, data.request?.headers]) {
    if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
      values.push(...Object.values(headers));
    }
  }
  const fields = values.map(decode);
  const complete = /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns):\/\/[^\s{}/?#]+[^\s{}]*\}/i;
  const remoteLookup = fields.some(text => complete.test(text));
  const fragment = fields.some(text => /\$\{\s*jndi\s*:|\b(?:log4j-scan|log4shell-scanner)\b/i.test(text));
  const level = alert?.rule?.level;
  const contextual = Array.isArray(alert?.rule?.mitre)
    && alert.rule.mitre.includes('T1190')
    && Number.isInteger(level) && level >= 5;
  const confidence = remoteLookup ? 0.95 : fragment || contextual ? 0.55 : 0.1;
  const reason = remoteLookup ? PATTERNS[0].name
    : fragment || contextual ? PATTERNS[1].name : 'normal_no_pattern';
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}
