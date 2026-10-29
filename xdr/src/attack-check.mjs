// src/attack-check.mjs
// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (
    app.protocol !== 'https:' ||
    app.username ||
    app.password ||
    app.search ||
    app.hash ||
    app.pathname !== '/' ||
    app.hostname.endsWith('.example')
  ) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) {
    throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  }

  // 1단계 기본 시험(test/r5.test.mjs) 호환성 유지
  if (config.step === 1) {
    const response = await fetch(new URL('/data.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    let visible = false;
    if (response.ok) {
      try {
        const data = await response.json();
        visible =
          data?.sampleMarker === config.sampleMarker &&
          Array.isArray(data.notes) &&
          data.notes.length > 0;
      } catch {
        // A non-JSON response is a failed check, not a successful deployment.
      }
    }
    return [
      {
        attackId: 'anonymous_note_read',
        expected: '비로그인 화면에서 가상 메모를 확인',
        observed: visible
          ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
          : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})`,
      },
    ];
  }

  // 12단계: 실제 요청 기록과 대조하여 기록이 없으면 받은 적 없는 상태를 적지 않고 'not_run'으로 유지
  const recorded =
    config?.recordedRequests && typeof config.recordedRequests === 'object'
      ? config.recordedRequests
      : {};

  const observedDataJson =
    typeof recorded.public_data_json_blocked === 'number' ||
    typeof recorded.public_data_json_blocked === 'string'
      ? String(recorded.public_data_json_blocked)
      : 'not_run';

  const observedApiMemos =
    typeof recorded.unauthenticated_api_memos_denied === 'number' ||
    typeof recorded.unauthenticated_api_memos_denied === 'string'
      ? String(recorded.unauthenticated_api_memos_denied)
      : 'not_run';

  return [
    {
      attackId: 'public_data_json_blocked',
      expected: 'HTTP 404',
      observed: observedDataJson,
    },
    {
      attackId: 'unauthenticated_api_memos_denied',
      expected: 'HTTP 401',
      observed: observedApiMemos,
    },
  ];
}
