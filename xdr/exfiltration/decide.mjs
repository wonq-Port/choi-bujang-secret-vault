// 이 파일은 심판이 단독으로 불러 실행하므로 import, 파일 접근, 네트워크 접근을 하지 않습니다.
export const PATTERNS = Object.freeze([
  Object.freeze({
    id: 't1041-t1048-high-volume-unfamiliar-destination',
    name: '낯선 목적지로 향하는 고위험 대용량 외부 전송',
    condition:
      'rule.mitre 에 T1041 또는 T1048 이 포함되고 rule.level >= 10 이며 data.dstip 가 있고 data.bytes >= 70000000 인 동시에 설명에 처음 보는 목적지·외부 전송·반복 전송·압축 파일·비정상 포트 등 전송 이상 징후가 나타나는 경우. 반복 횟수(data.count >= 8) 또는 다수 파일(data.files >= 30)도 강한 보조 신호로 봅니다.',
    basis:
      'MITRE ATT&CK T1041은 기존 명령·제어(C2) 통로를 통한 유출, T1048은 기존 C2와 다른 프로토콜을 통한 유출을 다룹니다. 높은 경보 수준, 대량 전송량, 목적지 및 전송 이상 징후가 함께 나타날 때만 차단 후보로 판단합니다.',
  }),
  Object.freeze({
    id: 't1041-t1048-ambiguous-outbound-anomaly',
    name: '낯선 목적지·압축·반복 전송의 불확실한 유출 징후',
    condition:
      'rule.mitre 에 T1041 또는 T1048 이 포함되고 rule.level 이 5~9 사이이며, 처음 보는 목적지·평소보다 큰 전송량·압축 파일 생성 또는 전송·업무 시간 밖 전송·명령 통로 반복·읽은 자료 뒤이은 전송·실패한 외부 전송 중 하나가 보이는 경우. 전송량이 적거나 전송이 실패했거나 실제 외부 전송 전 단계이면 차단하지 않고 알림만 남깁니다.',
    basis:
      'MITRE ATT&CK T1041 및 T1048은 유출 통로와 외부 전송 행위를 설명합니다. 단일 이상 징후만으로 실제 유출을 확정할 수는 없으므로, 중간 수준 경보와 보조 신호는 추가 확인이 필요한 알림으로만 취급합니다.',
  }),
]);

const HIGH_VOLUME_BYTES = 70_000_000;
const SUPPORTED_TECHNIQUES = new Set(['T1041', 'T1048']);
const STRONG_DESCRIPTION_SIGNAL = /처음\s*보는|외부\s*주소|외부\s*전송|반복|연속|압축\s*파일|비정상\s*포트|사용하지\s*않던\s*포트|자료실\s*전체|큰\s*파일/iu;
const AMBIGUOUS_DESCRIPTION_SIGNAL = /처음\s*보는|처음\s*봅니다|평소보다|평소와\s*다른|다른\s*주소|압축\s*파일|압축|업무\s*시간\s*밖|수업\s*시간\s*밖|백업|읽힌\s*뒤|명령\s*통로|파일\s*수가|전송이\s*실패|일부만/iu;

function finiteNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function hasTechnique(alert) {
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  return mitre.some((item) => typeof item === 'string' && SUPPORTED_TECHNIQUES.has(item.toUpperCase()));
}

function hasDestination(alert) {
  return typeof alert?.data?.dstip === 'string' && alert.data.dstip.trim().length > 0;
}

function makeDecision(action, confidence, patternName) {
  return { action, confidence, reason: patternName };
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
    return makeDecision('record', 0.1, '유출 의심 패턴 미충족');
  }

  const level = finiteNumber(alert?.rule?.level);
  const bytes = finiteNumber(alert?.data?.bytes);
  const count = finiteNumber(alert?.data?.count);
  const files = finiteNumber(alert?.data?.files);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const hasSupportedTechnique = hasTechnique(alert);
  const hasTarget = hasDestination(alert);

  // 강한 차단은 공격 기법, 고위험 경보, 대용량, 목적지, 설명상 이상 징후가 모두 있을 때만 수행합니다.
  if (
    hasSupportedTechnique &&
    level >= 10 &&
    bytes >= HIGH_VOLUME_BYTES &&
    hasTarget &&
    (STRONG_DESCRIPTION_SIGNAL.test(description) || count >= 8 || files >= 30)
  ) {
    const confidence = bytes >= 250_000_000 ? 0.98 : bytes >= 150_000_000 ? 0.95 : 0.9;
    return makeDecision('block', confidence, PATTERNS[0].name);
  }

  // 중간 수준·약한 신호는 차단하지 않고 알림으로만 보냅니다.
  if (
    hasSupportedTechnique &&
    level >= 5 &&
    level <= 9 &&
    AMBIGUOUS_DESCRIPTION_SIGNAL.test(description)
  ) {
    const confidence = level >= 8 ? 0.75 : level >= 6 ? 0.65 : 0.55;
    return makeDecision('alert', confidence, PATTERNS[1].name);
  }

  return makeDecision('record', 0.1, '유출 의심 패턴 미충족');
}
