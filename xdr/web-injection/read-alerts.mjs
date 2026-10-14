import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function safeDescription(value) {
  if (typeof value !== 'string') return null;

  // 비밀값 대입 표기나 토큰·개인키가 보이면 설명 전체를 숨깁니다.
  if (/(?:password|passwd|비밀번호|token|토큰|secret|api[_-]?key)\s*[:=]|Bearer\s+\S+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN .*PRIVATE KEY/i.test(value)) {
    return '[비밀값 의심 설명 숨김]';
  }

  return value.replace(/[\r\n\t]/g, ' ').slice(0, 500);
}

export function readAlerts(fixture) {
  if (fixture?.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }

  return fixture.alerts.map(alert => {
    const timestamp = alert?.timestamp;
    const srcip = alert?.data?.srcip;
    const account = alert?.data?.srcuser;
    const level = alert?.rule?.level;

    return {
      timestamp: typeof timestamp === 'string'
        && Number.isFinite(Date.parse(timestamp)) ? timestamp : null,
      srcip: typeof srcip === 'string'
        && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(srcip)
        && srcip.split('.').every(part => Number(part) <= 255)
          ? srcip : null,
      account: typeof account === 'string'
        && /^user\d{2}$/.test(account) ? account : null,
      level: Number.isInteger(level)
        && level >= 0 && level <= 16 ? level : null,
      description: safeDescription(alert?.rule?.description),
    };
  });
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  try {
    const fixture = JSON.parse(await readFile(
      new URL('../fixtures/web-injection.json', import.meta.url),
      'utf8',
    ));
    const rows = readAlerts(fixture);

    for (const row of rows) {
      console.log(JSON.stringify(row));
    }

    console.log(`경보 ${fixture.alerts.length}건 / 추출 ${rows.length}줄`);
    if (fixture.alerts.length !== rows.length) process.exitCode = 1;
  } catch {
    console.error('경보 읽기 실패: 파일과 JSON 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
