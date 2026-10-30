export const PATTERNS = Object.freeze([
  {
    id: 't1078-unauthorized-admin-group-addition',
    name: '비정상적인 관리자 그룹(administrators) 추가 및 복수 계정 권한 부여',
    condition:
      "rule.mitre 에 T1078 이 포함되고 rule.level >= 10 이며 평범한 계정이 원격 주소에서 관리자 그룹(data.group === 'administrators')에 추가되거나 다수 계정 추가·반복 재진입이 발생한 경우",
    basis:
      'MITRE ATT&CK T1078 (Valid Accounts): 탈취하거나 도용한 일반 계정을 관리자 그룹에 편입시켜 시스템 제어권을 확보하려는 명확한 권한 상승 및 계정 악용 신호입니다.',
  },
  {
    id: 't1068-t1078-off-hours-or-unfamiliar-admin-command',
    name: '업무·수업 시간 밖 또는 처음 보는 주소에서의 관리자 권한 변경 및 명령 실행',
    condition:
      'rule.mitre 에 T1068 또는 T1078 이 포함되고 rule.level >= 10 이며 수업·업무 시간 밖이나 처음 보는 주소에서 세션이 관리자 권한으로 바뀌거나 관리자 명령이 실행된 경우',
    basis:
      'MITRE ATT&CK T1068 (Exploitation for Privilege Escalation) 및 T1078: 정상 업무 시간이나 지정된 관리 경로 밖에서 관리자 권한을 획득해 명령을 내리는 명확한 권한 가로채기 신호입니다.',
  },
  {
    id: 't1068-immediate-admin-command-or-impersonation',
    name: '관리자 승격 직후 연속 명령 실행 및 타 계정 권한 도용 실행',
    condition:
      'rule.mitre 에 T1068 이 포함되고 rule.level >= 10 이며 방금 관리자가 된 계정이 곧바로 관리자 명령을 실행하거나 다른 계정의 권한을 빌려 관리자 명령을 실행한 경우',
    basis:
      'MITRE ATT&CK T1068 (Exploitation for Privilege Escalation): 권한 상승 직후 관리자 명령을 연달아 수행하거나 타 계정 권한을 가로채 실행하는 명확한 공격 신호입니다.',
  },
  {
    id: 't1068-t1078-ambiguous-group-or-single-elevation-event',
    name: '비관리자 수업 그룹 변경 또는 후속 명령 없는 단발성 권한 이벤트',
    condition:
      'rule.mitre 에 T1068 또는 T1078 이 포함되고 rule.level 이 5~9 사이이며 일반 과제·수업 그룹 변경, 취소된 권한 창, 후속 동작 없는 단발성 권한 상승이나 실패 1건에 그친 경우',
    basis:
      'MITRE ATT&CK T1068 및 T1078: 단발성 권한 확인이나 일반 수업 그룹 변경은 초기 탐색일 수 있으나 정상적인 수업 활동과 겹치므로 세션을 차단하지 않고 알림(alert)으로 감시합니다.',
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

export function decide(alert) {
  if (!alert || typeof alert !== 'object') {
    return {
      action: 'record',
      confidence: 0,
      reason: '정상 계정 및 세션 이벤트 (권한 가로채기 위협 미일치)',
    };
  }

  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level) ? alert.rule.level : 0;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const group = typeof alert?.data?.group === 'string' ? alert.data.group.trim().toLowerCase() : '';
  const mitreList = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1068 = mitreList.some((code) => typeof code === 'string' && code.toUpperCase().startsWith('T1068'));
  const hasT1078 = mitreList.some((code) => typeof code === 'string' && code.toUpperCase().startsWith('T1078'));
  const hasPrivilegeMitre = hasT1068 || hasT1078;
  const count = parseCount(alert?.data?.count);

  const isAdminGroup = group === 'administrators' || /관리자\s*그룹|다시\s*관리자로/iu.test(description);
  const isOffHoursOrNewAddress = /수업\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|처음\s*보는\s*주소|주소는\s*처음\s*봅니다/iu.test(
    description,
  );
  const isImmediateOrImpersonation = /방금\s*관리자가\s*된|곧바로\s*권한\s*명령|다른\s*계정의\s*권한으로/iu.test(description);

  // 1~3. 명확한 권한 가로채기·권한 상승 공격 (level >= 10 및 T1068/T1078 신호)
  if ((hasPrivilegeMitre || level >= 10) && level >= 10) {
    const confidence = level >= 12 || count >= 2 || (hasT1068 && hasT1078) ? 0.95 : 0.9;
    if (isOffHoursOrNewAddress) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[1].name,
      };
    }
    if (isImmediateOrImpersonation && hasT1068) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[2].name,
      };
    }
    if (isAdminGroup || hasT1078) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[0].name,
      };
    }
    return {
      action: confidence >= 0.85 ? 'block' : 'alert',
      confidence,
      reason: PATTERNS[2].name,
    };
  }

  // 4. 애매한 시도: 중간 위험도(level 5~9) 또는 비관리자 그룹 변경·단발성 권한 이벤트
  if (hasPrivilegeMitre || (level >= 5 && level <= 9)) {
    const confidence = level >= 8 ? 0.75 : level >= 6 ? 0.65 : 0.55;
    return {
      action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
      confidence,
      reason: PATTERNS[3].name,
    };
  }

  // 5. 정상 계정·세션 이벤트 (level < 5: 일반 로그인·로그아웃, 정식 관리 계정 평소 주소 로그인 등 -> record)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 계정 및 세션 이벤트 (권한 가로채기 위협 미일치)',
  };
}
