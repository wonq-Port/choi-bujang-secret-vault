export const PATTERNS = Object.freeze([
  {
    id: 't1190-cve-2021-44228-header-jndi-lookup',
    name: '요청 머리글 안의 CVE-2021-44228 원격 조회 구문(jndi 형태) 악용 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 요청 머리글(data.useragent 등)에 CVE-2021-44228 형태의 원격 조회 구문(jndi 형태)이 포함된 경우',
    basis:
      'CVE-2021-44228 및 MITRE ATT&CK T1190 (Exploit Public-Facing Application): 로그 라이브러리가 기록하는 요청 머리글에 jndi 원격 조회 구문을 심어 외부 명령 실행을 유도하는 명확한 취약점 악용 신호입니다.',
  },
  {
    id: 't1190-cve-2021-44228-url-jndi-lookup',
    name: '요청 주소 인자 안의 CVE-2021-44228 원격 조회 구문(jndi 형태) 악용 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 요청 주소·인자(data.url)에 CVE-2021-44228 형태의 원격 조회 구문(jndi 형태)이 단발 또는 반복 포함된 경우',
    basis:
      'CVE-2021-44228 및 MITRE ATT&CK T1190 (Exploit Public-Facing Application): 웹 요청 주소 인자에 jndi 원격 조회 구문을 넣어 취약한 서버의 원격 조회를 유발하는 명확한 공개 취약점 악용 신호입니다.',
  },
  {
    id: 't1190-cve-scanner-probe-with-jndi-lookup',
    name: '알려진 취약점 점검 도구 흔적과 원격 조회 구문(jndi 형태) 결합 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 알려진 취약점 점검 흔적(probe 등)이나 머리글·주소 동시 주입과 함께 CVE-2021-44228 원격 조회 구문이 나타난 경우',
    basis:
      'CVE-2021-44228 및 MITRE ATT&CK T1190 (Exploit Public-Facing Application): 자동화된 취약점 점검 도구나 다중 위치(머리글·인자)에 원격 조회 구문을 함께 보내 취약 여부를 탐색·악용하는 명확한 공격 신호입니다.',
  },
  {
    id: 't1190-ambiguous-cve-keyword-or-partial-syntax',
    name: '원격 조회 구문 없는 취약점·라이브러리 단어 검색 또는 잘린 표기',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level 이 5~9 사이이며 실제 원격 조회 구문 없이 CVE 번호·jndi 단어·점검 도구 유사 이름·중괄호 조각만 포함된 경우',
    basis:
      'CVE-2021-44228 및 MITRE ATT&CK T1190 (Exploit Public-Facing Application): 완전한 원격 조회 구문 없는 취약점 이름 검색이나 잘린 문자열은 초기 정찰일 수 있으나 정상적인 수업 자료 조회와 겹치므로 알림(alert)으로만 감시합니다.',
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
      reason: '정상 웹 접근 이벤트 (T1190 패턴 미일치)',
    };
  }

  const level = typeof alert?.rule?.level === 'number' && Number.isFinite(alert.rule.level) ? alert.rule.level : 0;
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const url = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  const useragent = typeof alert?.data?.useragent === 'string' ? alert.data.useragent : '';
  const mitreList = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1190 = mitreList.some((code) => typeof code === 'string' && code.toUpperCase().startsWith('T1190'));
  const count = parseCount(alert?.data?.count);

  const jndiPattern = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http)\s*:/iu;
  const hasUrlJndi = jndiPattern.test(url);
  const hasHeaderJndi = jndiPattern.test(useragent);
  const hasJndiLookup = hasUrlJndi || hasHeaderJndi;
  const isScannerOrMultiVector =
    /점검\s*흔적|머리글과\s*주소에\s*같이|probe=/iu.test(description) ||
    /probe=/iu.test(url) ||
    (hasUrlJndi && hasHeaderJndi);

  // 1~3. 명확한 공개 취약점(CVE-2021-44228) 악용 시도: 원격 조회 구문(jndi 형태) 존재 및 높은 위험도(level >= 10)
  if ((hasT1190 || level >= 10) && level >= 10 && hasJndiLookup) {
    const confidence = level >= 13 || count >= 4 || (hasUrlJndi && hasHeaderJndi) ? 0.96 : 0.92;
    if (isScannerOrMultiVector) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[2].name,
      };
    }
    if (hasHeaderJndi) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[0].name,
      };
    }
    return {
      action: confidence >= 0.85 ? 'block' : 'alert',
      confidence,
      reason: PATTERNS[1].name,
    };
  }

  // 4. 애매한 시도: 원격 조회 구문은 없으나 T1190 신호 또는 중간 위험도(level 5~9)의 취약점 키워드·점검 도구 유사 흔적
  if (hasT1190 || (level >= 5 && level <= 9)) {
    const confidence = level >= 8 ? 0.75 : level >= 6 ? 0.65 : 0.55;
    return {
      action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
      confidence,
      reason: PATTERNS[3].name,
    };
  }

  // 5. 정상 웹 접근 이벤트 (confidence < 0.5 -> record)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 웹 접근 이벤트 (T1190 패턴 미일치)',
  };
}
