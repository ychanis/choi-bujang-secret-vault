// 운영 엔진이 검증한 가상 사건만 전달받습니다.
function readEvents(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  return events.flatMap((event) => {
    if (!event || typeof event !== 'object') return [];

    const at = typeof event.at === 'string'
      ? Date.parse(event.at) : NaN;
    const method = event.method;
    const subject = event.identity?.sub;

    if (!Number.isFinite(at)
      || typeof method !== 'string'
      || typeof subject !== 'string'
      || subject.trim() === '') {
      return [];
    }

    return [{ at, method, subject }];
  });
}

export function detect(events) {
  const subject = findBurstSubject(events);
  if (subject !== null) {
    return {
      action: 'propose_revocation',
      reasonCode: 'burst_read',
      subject
    };
  }
  return { action: 'observe' };
}

export function findBurstSubject(events) {
  const bySubject = new Map();

  for (const event of readEvents(events)) {
    if (event.method !== 'GET') continue;
    const times = bySubject.get(event.subject) ?? [];
    times.push(event.at);
    bySubject.set(event.subject, times);
  }

  for (const [subject, times] of bySubject) {
    times.sort((a, b) => a - b);
    let left = 0;

    for (let right = 0; right < times.length; right++) {
      while (times[right] - times[left] > 600_000) left++;
      if (right - left + 1 > 120) return subject;
    }
  }

  return null;
}
