export const PATTERNS = Object.freeze([
  {
    id: 't1110-rapid-single-source-failures',
    name: '단시간 동일 주소 연속 로그인 실패',
    condition:
      'rule.mitre 에 T1110 이 포함되고 rule.level >= 10 이며 같은 출발 주소(data.srcip)에서 짧은 시간 동안 로그인 실패(data.count >= 15)가 연속 누적된 경우',
    basis:
      'MITRE ATT&CK T1110 (T1110.001 Password Guessing): 짧은 시간에 같은 출발 주소에서 반복적으로 비밀번호를 대입해 로그인 실패가 수십 건 쌓이는 전형적인 무차별 대입 공격 신호입니다.',
  },
  {
    id: 't1110-multi-account-password-spray',
    name: '다수 계정 동일 비밀번호 연속 대입',
    condition:
      'rule.mitre 에 T1110 이 포함되고 rule.level >= 10 이며 같은 출발 주소(data.srcip)에서 여러 계정 목록(data.accounts 5개 이상) 또는 다수 계정(data.count >= 15)에 로그인 실패가 이어진 경우',
    basis:
      'MITRE ATT&CK T1110 (T1110.003 Password Spraying): 계정 잠금을 우회하기 위해 하나의 주소에서 여러 계정에 같은 비밀번호나 유출된 자격증명을 연속 대입하는 공격 신호입니다.',
  },
  {
    id: 't1110-low-volume-repeated-failures',
    name: '소규모 반복 로그인 실패 의심 징후',
    condition:
      'rule.mitre 에 T1110 이 포함되고 rule.level 이 5~9 사이이거나 로그인 실패(data.count 3~14)가 소규모로 발생해 오타·잠금 후 재시도와 저속 대입 공격의 경계에 있는 경우',
    basis:
      'MITRE ATT&CK T1110 (Brute Force): 소규모 연속 실패(3~14건)는 저속 무차별 대입의 초기 징후일 수 있으나 정상 사용자의 비밀번호 오입력 가능성도 있어 차단 대신 알림(alert)으로 감시합니다.',
  },
]);

function parseCount(rawCount) {
  if (typeof rawCount === 'number' && Number.isFinite(rawCount)) return rawCount;
  if (typeof rawCount === 'string' && rawCount.trim() !== '') {
    const parsed = Number(rawCount);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function parseAccountsCount(rawAccounts) {
  if (Array.isArray(rawAccounts)) return rawAccounts.filter(Boolean).length;
  if (typeof rawAccounts === 'string' && rawAccounts.trim() !== '') {
    return rawAccounts
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean).length;
  }
  return 0;
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return {
      action: 'record',
      confidence: 0,
      reason: '정상 인증 이벤트 (T1110 패턴 미일치)',
    };
  }

  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level) ? alert.rule.level : 0;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const mitreList = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1110 = mitreList.some((code) => typeof code === 'string' && code.toUpperCase().startsWith('T1110'));
  const count = parseCount(alert?.data?.count);
  const accountsCount = parseAccountsCount(alert?.data?.accounts);

  const isMultiAccountDesc = /여러\s*계정|계정\s*\d+\s*개|서로\s*다른\s*계정|계정\s*이름을\s*바꿔/u.test(description);
  const isFailureDesc = /실패/u.test(description);

  // 1. 다수 계정 동일 비밀번호 대입 (명확한 공격: confidence >= 0.85 -> block)
  if ((hasT1110 || level >= 10) && (accountsCount >= 5 || (isMultiAccountDesc && (count >= 15 || level >= 10)))) {
    const confidence = level >= 12 || accountsCount >= 8 || count >= 30 ? 0.95 : 0.9;
    return {
      action: confidence >= 0.85 ? 'block' : 'alert',
      confidence,
      reason: PATTERNS[1].name,
    };
  }

  // 2. 단시간 동일 주소 연속 로그인 실패 (명확한 공격: confidence >= 0.85 -> block)
  if ((hasT1110 && level >= 10 && count >= 15) || (level >= 10 && count >= 15) || count >= 30) {
    const confidence = count >= 60 ? 0.98 : count >= 40 ? 0.94 : 0.9;
    return {
      action: confidence >= 0.85 ? 'block' : 'alert',
      confidence,
      reason: PATTERNS[0].name,
    };
  }

  // 3. 소규모 반복 로그인 실패 의심 징후 (애매한 시도: 0.5 <= confidence < 0.85 -> alert)
  if (
    (hasT1110 && (level >= 5 || count >= 3)) ||
    (level >= 5 && level <= 9 && (count >= 2 || isFailureDesc)) ||
    (count >= 3 && count < 15)
  ) {
    const confidence = level >= 8 || count >= 8 ? 0.75 : level >= 6 || count >= 4 ? 0.65 : 0.55;
    return {
      action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
      confidence,
      reason: PATTERNS[2].name,
    };
  }

  // 4. 정상 인증·세션 이벤트 (confidence < 0.5 -> record)
  const confidence = count === 1 ? 0.2 : 0.1;
  return {
    action: 'record',
    confidence,
    reason: '정상 인증 이벤트 (T1110 패턴 미일치)',
  };
}
