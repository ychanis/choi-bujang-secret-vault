import { readFile } from 'node:fs/promises';

const url = new URL('../fixtures/exfiltration.json', import.meta.url);

export async function readAlerts() {
  const fixture = JSON.parse(await readFile(url, 'utf8'));

  if (fixture.schema !== 'aleph.xdr.fixture.v1'
      || fixture.moduleKey !== 'exfiltration'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 형식 오류');
  }

  return fixture.alerts.map(alert => ({
    timestamp: alert.timestamp,
    sourceIp: alert.data?.srcip,
    account: alert.data?.srcuser,
    level: alert.rule?.level,
    description: alert.rule?.description
  }));
}

const alerts = await readAlerts();
const fixture = JSON.parse(await readFile(url, 'utf8'));

console.log('원본 경보:', fixture.alerts.length);
console.log('추출한 줄:', alerts.length);
console.log('건수 일치:', fixture.alerts.length === alerts.length);
