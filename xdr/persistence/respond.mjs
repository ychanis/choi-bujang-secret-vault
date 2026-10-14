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
    rule?.ruleId === 'xdr_persistence'
    && rule.action === 'deny'
    && validIp(rule.sourceIp)
    && Date.parse(rule.expiresAt) > now
    && Array.isArray(rule.evidenceAlertIds)
    && rule.evidenceAlertIds.length > 0
    && rule.evidenceAlertIds.every(id => /^ps-\d+$/.test(id))
    && !alerts.some(alert => alert?.data?.srcip === rule.sourceIp
      && decide(alert).action !== 'block')
  );
  const notices = [];

  for (const alert of alerts) {
    const decision = decide(alert);
    const id = alert?.id;
    const sourceIp = alert?.data?.srcip;

    if (decision.action === 'record') continue;
    if (typeof id !== 'string' || !/^ps-\d+$/.test(id)) continue;

    notices.push(JSON.stringify({
      processedAt: new Date(now).toISOString(),
      alertId: id,
      action: decision.action,
      confidence: decision.confidence,
      reason: decision.reason,
    }));

    if (decision.action !== 'block'
        || decision.confidence < 0.85 || !validIp(sourceIp)) continue;

    // 이 시험 묶음에 정상 또는 애매한 요청도 있는 주소는 주소 단위 차단하지 않습니다.
    if (alerts.some(other => other?.data?.srcip === sourceIp
        && decide(other).action !== 'block')) continue;

    let rule = rules.find(value => value.sourceIp === sourceIp);
    if (!rule) {
      rule = {
        ruleId: 'xdr_persistence',
        action: 'deny',
        sourceIp,
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + TTL_MS).toISOString(),
        evidenceAlertIds: [],
      };
      rules.push(rule);
    }
    if (!rule.evidenceAlertIds.includes(id)) rule.evidenceAlertIds.push(id);
    rule.expiresAt = new Date(now + TTL_MS).toISOString();
  }

  await writeFile(RULES_URL, JSON.stringify({
    schema: 'aleph.xdr.deny-rules.v1',
    scope: 'local-adapter',
    operationalConnection: 'not_connected',
    rules,
  }, null, 2) + '\n', 'utf8');

  if (notices.length) {
    await appendFile(LOG_URL, notices.join('\n') + '\n', 'utf8');
  }

  return rules;
}

// trustedSourceIp는 서버/엔진이 확인한 주소여야 합니다.
// 브라우저 본문·임의 헤더·request에 추가한 항목을 사용하지 않습니다.
// 기존 판정기에 이 함수를 호출하는 운영 연결은 아직 없습니다.
export async function decideWithXdr(
  request, { trustedSourceIp, rules, baseDecide, now = Date.now() }
) {
  if (typeof baseDecide !== 'function' || !Array.isArray(rules)
      || !Number.isFinite(now)) throw new Error('연결 입력 오류');

  const original = await baseDecide(request);
  if (original?.decision !== 'allow') return original;

  const blocked = validIp(trustedSourceIp) && rules.some(rule =>
    rule?.ruleId === 'xdr_persistence'
    && rule.action === 'deny'
    && rule.sourceIp === trustedSourceIp
    && Date.parse(rule.expiresAt) > now
    && Array.isArray(rule.evidenceAlertIds)
    && rule.evidenceAlertIds.length > 0
    && rule.evidenceAlertIds.every(id => /^ps-\d+$/.test(id))
  );

  if (!blocked) return original;

  return {
    ...original,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [...new Set([...(original.ruleIds ?? []), 'xdr_persistence'])],
  };
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  try {
    const fixture = JSON.parse(await readFile(
      new URL('../fixtures/persistence.json', import.meta.url), 'utf8'
    ));
    if (fixture.schema !== 'aleph.xdr.fixture.v1'
        || fixture.moduleKey !== 'persistence') {
      throw new Error('경보 묶음 오류');
    }
    const rules = await respond(fixture.alerts);
    console.log(`유효한 임시 거부 규칙: ${rules.length}`);
    console.log('알림 기록 완료 / 운영 판정기 연결: 미연결');
  } catch {
    console.error('응답 처리 실패: 경보와 규칙 파일 형식을 확인하세요.');
    process.exitCode = 1;
  }
}
