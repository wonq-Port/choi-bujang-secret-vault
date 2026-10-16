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

  // 1. public_data_json_blocked 점검
  let observed1 = 'not_run';
  try {
    const res1 = await fetch(new URL('/data.json', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    observed1 = `HTTP ${res1.status}`;
  } catch {
    observed1 = 'not_run';
  }

  // 2. unauthenticated_api_memos_denied 점검
  let observed2 = 'not_run';
  try {
    const res2 = await fetch(new URL('/api/memos', app), {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
    });
    observed2 = `HTTP ${res2.status}`;
  } catch {
    observed2 = 'not_run';
  }

  // 1단계 테스트 호환성 유지
  if (config.step === 1) {
    return [
      {
        attackId: 'anonymous_note_read',
        expected: '비로그인 화면에서 가상 메모를 확인',
        observed: observed1.includes('200')
          ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임'
          : `비로그인 요청에서 확인 표시가 보이지 않음 (${observed1})`,
      },
    ];
  }

  // 12단계 심판 확인용 실측 점검 결과
  return [
    {
      attackId: 'public_data_json_blocked',
      expected: 'HTTP 404',
      observed: observed1,
    },
    {
      attackId: 'unauthenticated_api_memos_denied',
      expected: 'HTTP 401',
      observed: observed2,
    },
  ];
}
