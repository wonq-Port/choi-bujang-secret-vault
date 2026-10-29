// 9단계에서 학생이 채우는 탐지 함수입니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const BURST_THRESHOLD = 120;

export function detect(events) {
  if (!Array.isArray(events)) {
    throw new TypeError('invalid_detection_events');
  }

  const bySubject = new Map();

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;

    const at = event.at;
    const method = event.method;
    const sub = event.identity?.sub;

    if (typeof at !== 'string' || typeof method !== 'string' || typeof sub !== 'string') {
      continue;
    }

    const trimmedSub = sub.trim();
    if (!trimmedSub || method.toUpperCase() !== 'GET') {
      continue;
    }

    const timestamp = Date.parse(at);
    if (!Number.isFinite(timestamp)) {
      continue;
    }

    let list = bySubject.get(trimmedSub);
    if (!list) {
      list = [];
      bySubject.set(trimmedSub, list);
    }
    list.push(timestamp);
  }

  for (const [subject, timestamps] of bySubject.entries()) {
    if (timestamps.length <= BURST_THRESHOLD) {
      continue;
    }

    timestamps.sort((a, b) => a - b);

    let left = 0;
    for (let right = 0; right < timestamps.length; right += 1) {
      while (timestamps[right] - timestamps[left] > WINDOW_MS) {
        left += 1;
      }
      const countInWindow = right - left + 1;
      if (countInWindow > BURST_THRESHOLD) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return { action: 'observe' };
}
