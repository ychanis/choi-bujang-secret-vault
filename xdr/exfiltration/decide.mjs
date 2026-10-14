const PATTERNS = [
  {
    name: '낯선 목적지 대용량 자료 반출',
    condition: '처음 보는 외부 목적지로 대량의 파일이나 자료를 전송하고, 전송량과 경보 수준이 모두 높은 경우',
    evidence: 'MITRE ATT&CK T1048: 공격자가 대체 통신 프로토콜을 이용해 정보를 외부로 반출할 수 있음.'
  },
  {
    name: '명령 통로 반복 전송',
    condition: '명령 통로를 이용한 대용량 전송이 여러 번 반복되고 외부 목적지가 확인된 경우',
    evidence: 'MITRE ATT&CK T1041: 공격자가 명령 및 제어 통신 경로를 이용해 정보를 반출할 수 있음.'
  },
  {
    name: '업무 시간 외 압축 파일 반출',
    condition: '업무 시간 외에 압축 파일을 낯선 외부 목적지로 대량 전송한 경우',
    evidence: 'MITRE ATT&CK T1048: 압축된 자료가 대체 통신 경로를 통해 외부로 반출되는 정황을 조사할 수 있음.'
  },
  {
    name: '불확실한 외부 전송 경보',
    condition: '낯선 목적지 또는 비정상 전송량이 확인되지만 대량 반출이나 반복 전송 증거가 부족한 경우',
    evidence: 'MITRE ATT&CK T1041/T1048: 외부 전송 신호만으로 악성 행위를 확정할 수 없어 추가 확인이 필요함.'
  }
];

// 외부 파일, 패키지, 네트워크를 사용하지 않는 독립 판정기
export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description : '';
  const level = Number(alert?.rule?.level ?? 0);
  const data = alert?.data ?? {};
  const bytes = Number(data.bytes ?? 0);
  const files = Number(data.files ?? 0);
  const count = Number(data.count ?? 0);
  const destination = typeof data.dstip === 'string' && data.dstip.length > 0;

  const mitre = alert?.rule?.mitre;
  const techniques = Array.isArray(mitre)
    ? mitre : Array.isArray(mitre?.id) ? mitre.id : [];

  const t1041 = techniques.includes('T1041');
  const t1048 = techniques.includes('T1048');

  const unfamiliar = /처음 보는|평소에 쓰지 않던|낯선/.test(description);
  const large = bytes >= 50000000;
  const repeated = count >= 5 || /반복|연속|여러 번/.test(description);
  const compressed = /압축 파일/.test(description);
  const outside = /시간 밖/.test(description);
  const commandChannel = /명령 통로/.test(description);
  const massFiles = files >= 50 || /자료실 전체/.test(description);
  const unusualPort = /쓰지 않던 포트/.test(description);
  const bulkTransfer = /대용량|큰 파일|큰 전송|대량/.test(description);

  const failed = /전송이 실패|전송은 아직 없|전송은 없습니다/.test(description);
  const normal = /수업 자료 주소|평소 목적지|백업처럼|작은 동기화|내 메모|반 공지|검색 결과|새로고침|세션 확인|로그아웃|다음 수업 공지/.test(description);

  let confidence = 0.1;
  let reason = '정상 기록: 일치하는 자료 반출 패턴 없음';

  if (failed || !destination || bytes <= 0) {
    return { action: 'record', confidence, reason };
  }

  if (!normal && level >= 10 && large) {
    if (t1041 && commandChannel && repeated) {
      confidence = 0.96;
      reason = PATTERNS[1].name;
    } else if (t1048 && compressed && outside && unfamiliar) {
      confidence = 0.97;
      reason = PATTERNS[2].name;
    } else if ((t1041 || t1048)
        && ((unfamiliar && (massFiles || compressed || bulkTransfer))
          || (repeated && bulkTransfer)
          || (unusualPort && massFiles)
          || (massFiles && bulkTransfer))) {
      confidence = 0.94;
      reason = PATTERNS[0].name;
    }
  }

  // 대량 반복 전송 또는 자료실 전체 반출
  if (!normal && !failed && destination && level >= 10
      && (t1041 || t1048)
      && ((count >= 8 && bytes >= 100000000)
        || (massFiles && bytes >= 200000000))) {
    confidence = 0.96;
    reason = PATTERNS[0].name;
  }

  if (confidence < 0.85 && !normal && level >= 5
      && (t1041 || t1048)
      && (unfamiliar || repeated || compressed || bulkTransfer
          || unusualPort || bytes >= 5000000)) {
    confidence = 0.6;
    reason = PATTERNS[3].name;
  }

  return {
    action: confidence >= 0.85 ? 'block'
      : confidence >= 0.5 ? 'alert' : 'record',
    confidence,
    reason
  };
}
