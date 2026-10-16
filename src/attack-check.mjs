// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (!config || typeof config.step !== 'number' || config.step < 1 || config.step > 12) {
    throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  }
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

  if (config.step === 1) {
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

  const results = [
    {
      attackId: 'public_data_json_blocked',
      expected: '비로그인 /data.json 요청에서 가상 메모 비노출 (HTTP 404)',
      observed: !visible
        ? `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})`
        : '비로그인 요청에서 공개 가상 메모 확인 표시가 보임',
    },
  ];

  try {
    const apiRes = await fetch(new URL('/api/memos', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    results.push({
      attackId: 'unauthenticated_api_memos_denied',
      expected: '토큰 없는 GET /api/memos 요청 거부 (HTTP 401)',
      observed: `실측 응답 HTTP ${apiRes.status} (${apiRes.status === 401 ? '거부 확인' : '상태 확인'})`,
    });
  } catch {
    results.push({
      attackId: 'unauthenticated_api_memos_denied',
      expected: '토큰 없는 GET /api/memos 요청 거부 (HTTP 401)',
      observed: '미실행 (네트워크 연결 전)',
    });
  }

  return results;
}
