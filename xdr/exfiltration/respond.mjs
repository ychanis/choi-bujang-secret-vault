import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const RULES_URL = new URL('./deny-rules.json', import.meta.url);
const LOG_URL = new URL('../alerts.log', import.meta.url);
const TTL_MS = 15 * 60 * 1000;

function validIp(value) {
  return typeof value === 'string'
    && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
    && value.split('.').every(part => Number(part) <= 255);
}

function validAccount(value) {
  return typeof value === 'string'
    && /^(?:user\d{2}|admin\d{2}|svc-lab)$/.test(value);
}

export async function respond(alerts, { now = Date.now() } = {}) {
  if (!Array.isArray(alerts) || !Number.isFinite(now)) {
    throw new Error('경보 목록 또는 처리 시각 오류');
  }

  let previous = { rules: [] };

  try {
    previous = JSON.parse(await readFile(RULES_URL, 'utf8'));
    if (!Array.isArray(previous.rules)) throw new Error('규칙 형식 오류');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const rules = previous.rules.filter(rule =>
    rule?.ruleId === 'xdr_exfiltration'
    && rule.action === 'deny'
    && validIp(rule.sourceIp)
    && validAccount(rule.account)
    && validIp(rule.destinationIp)
    && Date.parse(rule.expiresAt) > now
    && Array.isArray(rule.evidenceAlertIds)
    && rule.evidenceAlertIds.every(id => /^ex-\d+$/.test(id))
  );

  const notices = [];

  for (const alert of alerts) {
    const decision = decide(alert);
    const id = alert?.id;
    const sourceIp = alert?.data?.srcip;
    const account = alert?.data?.srcuser;
    const destinationIp = alert?.data?.dstip;

    if (decision.action === 'record') continue;
    if (typeof id !== 'string' || !/^ex-\d+$/.test(id)) continue;

    notices.push(JSON.stringify({
      processedAt: new Date(now).toISOString(),
      alertId: id,
      action: decision.action,
      confidence: decision.confidence,
      reason: decision.reason
    }));

    if (decision.action !== 'block'
        || decision.confidence < 0.85
        || !validIp(sourceIp)
        || !validAccount(account)
        || !validIp(destinationIp)) continue;

    // 같은 계정·출발지·목적지에 정상 또는 애매한 경보가 있으면 차단하지 않음
    if (alerts.some(other =>
      other?.data?.srcip === sourceIp
      && other?.data?.srcuser === account
      && other?.data?.dstip === destinationIp
      && decide(other).action !== 'block'
    )) continue;

    let rule = rules.find(r =>
      r.sourceIp === sourceIp
      && r.account === account
      && r.destinationIp === destinationIp
    );

    if (!rule) {
      rule = {
        ruleId: 'xdr_exfiltration',
        action: 'deny',
        sourceIp,
        account,
        destinationIp,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + TTL_MS).toISOString(),
        evidenceAlertIds: []
      };
      rules.push(rule);
    }

    if (!rule.evidenceAlertIds.includes(id)) {
      rule.evidenceAlertIds.push(id);
    }
  }

  await writeFile(RULES_URL, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    scope: 'local-adapter',
    operationalConnection: 'not_connected',
    rules
  }, null, 2) + '\n', 'utf8');

  if (notices.length) {
    await appendFile(LOG_URL, notices.join('\n') + '\n', 'utf8');
  }

  return rules;
}

// 기존 판정기의 허용 결과에만 XDR 임시 거부 규칙을 추가 적용
export async function decideWithXdr(
  request,
  { trustedSourceIp, trustedAccount, trustedDestinationIp,
    rules, baseDecide, now = Date.now() }
) {
  if (typeof baseDecide !== 'function'
      || !Array.isArray(rules)
      || !Number.isFinite(now)) {
    throw new Error('연결 입력 오류');
  }

  const original = await baseDecide(request);
  if (original?.decision !== 'allow') return original;

  const blocked = validIp(trustedSourceIp)
    && validAccount(trustedAccount)
    && validIp(trustedDestinationIp)
    && rules.some(rule =>
      rule.ruleId === 'xdr_exfiltration'
      && rule.action === 'deny'
      && rule.sourceIp === trustedSourceIp
      && rule.account === trustedAccount
      && rule.destinationIp === trustedDestinationIp
      && Date.parse(rule.expiresAt) > now
      && Array.isArray(rule.evidenceAlertIds)
      && rule.evidenceAlertIds.length > 0
    );

  if (!blocked) return original;

  return {
    ...original,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [
      ...new Set([...(original.ruleIds ?? []), 'xdr_exfiltration'])
    ]
  };
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  try {
    const fixture = JSON.parse(
      await readFile(
        new URL('../fixtures/exfiltration.json', import.meta.url),
        'utf8'
      )
    );

    if (fixture.schema !== 'aleph.xdr.fixture.v1'
        || fixture.moduleKey !== 'exfiltration') {
      throw new Error('경보 묶음 오류');
    }

    const rules = await respond(fixture.alerts);
    console.log('유효한 임시 거부 규칙:', rules.length);
    console.log('알림 기록 완료 / 운영 판정기 연결: 미연결');
  } catch {
    console.error('응답 처리 실패: 경보와 규칙 파일 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
