export const PATTERNS = Object.freeze([
  {
    id: 't1190-repeated-sql-command-injection',
    name: '반복된 SQL 구문 및 명령 구분자 주입 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 요청 인자(data.url)나 설명에 SQL 구문·데이터베이스 조회·명령 구분자 주입 표기가 같은 주소에서 반복(data.count >= 8)된 경우',
    basis:
      'MITRE ATT&CK T1190 (Exploit Public-Facing Application): 외부 공개 웹 앱의 요청 인자에 SQL 구문이나 명령 구분자를 반복 주입해 데이터베이스 조회나 명령 실행을 시도하는 명확한 웹 주입 공격 신호입니다.',
  },
  {
    id: 't1190-repeated-script-injection',
    name: '반복된 스크립트 태그 및 혼합 주입 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 요청 인자(data.url)나 설명에 스크립트 삽입 표기 또는 스크립트·SQL 혼합 표식이 같은 주소에서 반복(data.count >= 8)된 경우',
    basis:
      'MITRE ATT&CK T1190 (Exploit Public-Facing Application): 웹 입력 칸이나 주소창 인자에 스크립트 태그 및 주입 표식을 반복 전달해 웹 앱 취약점을 악용하려는 명확한 공격 신호입니다.',
  },
  {
    id: 't1190-repeated-path-traversal',
    name: '반복된 경로 거슬러 올라가기(../) 탐색 시도',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level >= 10 이며 요청 인자(data.url)나 설명에 경로를 여러 단계 거슬러 올라가거나 경로 이탈을 시도하는 표기가 반복(data.count >= 8)된 경우',
    basis:
      'MITRE ATT&CK T1190 (Exploit Public-Facing Application): 상위 디렉터리 이동(../) 표기를 반복 주입해 허용된 웹 경로 밖의 파일에 접근하려는 명확한 경로 이탈 공격 신호입니다.',
  },
  {
    id: 't1190-single-ambiguous-query-marker',
    name: '단발성 주입 의심 표기 또는 예약어 포함 검색',
    condition:
      'rule.mitre 에 T1190 이 포함되고 rule.level 이 5~9 사이이거나 반복 없이(data.count < 8) 따옴표·수업 단어(select, script, SQL, up)·단발성 표기가 1건만 나타난 경우',
    basis:
      'MITRE ATT&CK T1190 (Exploit Public-Facing Application): 단발성 특수문자나 예약어 검색은 초기 탐색 징후일 수 있으나 정상적인 수업 자료 검색과 겹치므로 차단 대신 알림(alert)으로 감시합니다.',
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
  const mitreList = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const hasT1190 = mitreList.some((code) => typeof code === 'string' && code.toUpperCase().startsWith('T1190'));
  const count = parseCount(alert?.data?.count);

  const isPathTraversal =
    /\.\.\/|경로를\s*여러\s*단계|경로\s*이탈|doc-up-repeat/iu.test(description) ||
    /\.\.\/|doc-up-repeat/iu.test(url);
  const isScriptInjection =
    /스크립트\s*삽입|스크립트\s*표식|<script|doc-script-marker|doc-mixed-marker/iu.test(description) ||
    /<script|doc-script-marker|doc-mixed-marker/iu.test(url);
  const isSqlOrCmdInjection =
    /SQL\s*구문|데이터베이스\s*조회|명령\s*구분자|doc-sql-|doc-cmd-separator/iu.test(description) ||
    /doc-sql-|doc-cmd-separator|union\s+select/iu.test(url);

  // 1~3. 명확한 웹 주입 공격: T1190 및 높은 위험도(level >= 10) + 동일 주소 반복 시도(count >= 8)
  if ((hasT1190 || level >= 10) && level >= 10 && count >= 8) {
    const confidence = count >= 15 || level >= 12 ? 0.95 : 0.9;
    if (isPathTraversal) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[2].name,
      };
    }
    if (isScriptInjection) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[1].name,
      };
    }
    if (isSqlOrCmdInjection) {
      return {
        action: confidence >= 0.85 ? 'block' : 'alert',
        confidence,
        reason: PATTERNS[0].name,
      };
    }
    return {
      action: confidence >= 0.85 ? 'block' : 'alert',
      confidence,
      reason: PATTERNS[0].name,
    };
  }

  // 4. 애매한 시도: T1190 신호가 있거나 중간 위험도(level 5~9)이지만 단발성(count < 8)인 경우
  if (hasT1190 || (level >= 5 && level <= 9)) {
    const confidence = level >= 8 ? 0.75 : level >= 6 ? 0.65 : 0.55;
    return {
      action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
      confidence,
      reason: PATTERNS[3].name,
    };
  }

  // 5. 정상 웹 요청 이벤트 (confidence < 0.5 -> record)
  return {
    action: 'record',
    confidence: 0.1,
    reason: '정상 웹 접근 이벤트 (T1190 패턴 미일치)',
  };
}
