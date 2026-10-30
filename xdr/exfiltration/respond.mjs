import { appendFile, mkdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide as decideZtna } from '../../src/decider.mjs';
import { decide as decideExfiltration } from './decide.mjs';

const DEFAULT_BLOCK_TTL_MS = 30 * 60 * 1000;
const HIGH_VOLUME_BYTES = 70_000_000;
const XDR_REASON_CODE = 'xdr_exfiltration_blocked';
const IPV4_PART = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';
const IPV4_PATTERN = new RegExp(`^${IPV4_PART}(?:\\.${IPV4_PART}){3}$`, 'u');
const SECRET_PATTERN = /(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|bearer|authorization)\s*[:=]\s*[^\s,;]+|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/giu;

function safeText(value) {
  return typeof value === 'string'
    ? value.replace(SECRET_PATTERN, '[REDACTED]').replace(/[\r\n\t]+/gu, ' ').trim()
    : '';
}

function parseNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 0;
}

function isIpv4(value) {
  return typeof value === 'string' && IPV4_PATTERN.test(value.trim());
}

export function createBlockRule(alert, decision, ttlMs = DEFAULT_BLOCK_TTL_MS) {
  if (!alert || typeof alert !== 'object' || decision?.action !== 'block') return null;

  const destinationIp = typeof alert?.data?.dstip === 'string' ? alert.data.dstip.trim() : '';
  const alertId = typeof alert?.id === 'string' ? alert.id.trim() : '';
  const level = parseNumber(alert?.rule?.level);
  const bytes = parseNumber(alert?.data?.bytes);
  const baseTimeMs = Date.parse(alert?.timestamp);
  const duration = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : DEFAULT_BLOCK_TTL_MS;

  // 송신 PC 전체가 아닌, 확인된 외부 목적지만 짧은 기간 차단합니다.
  // 판단 결과 외에도 높은 위험도·전송량·목적지·근거 경보를 다시 확인합니다.
  if (
    !isIpv4(destinationIp) ||
    !alertId ||
    !Number.isFinite(baseTimeMs) ||
    level < 10 ||
    bytes < HIGH_VOLUME_BYTES ||
    !Number.isFinite(decision.confidence) ||
    decision.confidence < 0.85
  ) {
    return null;
  }

  return {
    ruleId: 'xdr.exfiltration.deny_destination',
    effect: 'deny',
    dstip: destinationIp,
    alertId,
    expiresAt: new Date(baseTimeMs + duration).toISOString(),
    confidence: decision.confidence,
    reason: safeText(decision.reason),
  };
}

export function formatAlertLogLine(alert, decision) {
  const destinationIp = typeof alert?.data?.dstip === 'string' && isIpv4(alert.data.dstip)
    ? alert.data.dstip.trim()
    : '-';
  return JSON.stringify({
    timestamp: safeText(alert?.timestamp) || new Date().toISOString(),
    alertId: safeText(alert?.id) || 'unknown',
    action: decision.action,
    confidence: decision.confidence,
    destinationIp,
    reason: safeText(decision.reason),
  });
}

export async function processAlerts(
  alerts,
  { rootDir, logPath, ttlMs = DEFAULT_BLOCK_TTL_MS } = {},
) {
  const moduleRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const effectiveRoot = rootDir || moduleRoot;
  const targetLogPath = logPath || join(effectiveRoot, 'xdr', 'alerts.log');
  await mkdir(dirname(targetLogPath), { recursive: true });

  const blockRules = [];
  const logLines = [];
  const decisions = [];

  for (const alert of Array.isArray(alerts) ? alerts : []) {
    const decision = decideExfiltration(alert);
    decisions.push({ alertId: safeText(alert?.id) || 'unknown', ...decision });

    if (decision.action === 'block') {
      const rule = createBlockRule(alert, decision, ttlMs);
      if (rule) blockRules.push(rule);
    }

    if (decision.action === 'block' || decision.action === 'alert') {
      const line = formatAlertLogLine(alert, decision);
      logLines.push(line);
      await appendFile(targetLogPath, `${line}\n`, 'utf8');
    }
  }

  return { blockRules, decisions, logLines, logPath: targetLogPath };
}

// 목적지 주소는 판정 요청 계약에 없는 값이므로 request 본문에서 읽지 않습니다.
// 신뢰된 네트워크 관찰 계층이 별도 context.destinationIp 로 전달해야 합니다.
export function createXdrDecider(blockRules = []) {
  return async function decideWithXdr(request, trustedContext = {}) {
    const requestId = typeof request?.requestId === 'string' ? request.requestId : '';
    const destinationIp = typeof trustedContext?.destinationIp === 'string'
      ? trustedContext.destinationIp.trim()
      : '';
    const nowValue = trustedContext?.now;
    const nowMs = typeof nowValue === 'string' || typeof nowValue === 'number'
      ? new Date(nowValue).getTime()
      : Date.now();

    const matchedRule = isIpv4(destinationIp)
      ? blockRules.find((rule) => {
          if (!rule || rule.effect !== 'deny' || rule.dstip !== destinationIp) return false;
          const expiryMs = Date.parse(rule.expiresAt);
          return Number.isFinite(expiryMs) && Number.isFinite(nowMs) && nowMs < expiryMs;
        })
      : null;

    if (matchedRule) {
      return {
        schema: 'aleph.decision.v1',
        requestId,
        decision: 'deny',
        reasonCode: XDR_REASON_CODE,
        ruleIds: [matchedRule.ruleId],
      };
    }

    // 목적지 차단 규칙과 일치하지 않으면 기존 ZTNA 판정기를 그대로 실행합니다.
    return decideZtna(request);
  };
}

function makeReplayRequest(alert) {
  return {
    schema: 'aleph.decision.v1',
    requestId: `req-${safeText(alert?.id) || 'unknown'}`,
    classId: 'class-fixture',
    projectId: 'project-fixture',
    subjectId: 'subject-fixture',
    deviceId: '0123456789abcdef',
    service: 'notes',
    method: 'GET',
    path: '/api/memos/memo-1',
    route: 'GET /api/memos/:id',
    queryLength: 0,
    querySha256: '0'.repeat(64),
    at: typeof alert?.timestamp === 'string' ? alert.timestamp : new Date().toISOString(),
    policyRevision: 1,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 10 },
  };
}

export async function replayFixture(alerts, options = {}) {
  const processed = await processAlerts(alerts, options);
  const decideWithXdr = createXdrDecider(processed.blockRules);
  let replayBlockedAttacks = 0;
  let normalRequestsPassed = 0;
  let normalRequestsBlocked = 0;
  let ambiguousRequestsNotBlocked = 0;

  for (const alert of Array.isArray(alerts) ? alerts : []) {
    const sourceDecision = decideExfiltration(alert);
    const eventTimeMs = Date.parse(alert?.timestamp);
    const checkTime = Number.isFinite(eventTimeMs)
      ? new Date(eventTimeMs + 60 * 1000).toISOString()
      : new Date().toISOString();
    const response = await decideWithXdr(makeReplayRequest(alert), {
      destinationIp: alert?.data?.dstip,
      now: checkTime,
    });
    const deniedByXdr = response.decision === 'deny' && response.reasonCode === XDR_REASON_CODE;

    if (sourceDecision.action === 'block' && deniedByXdr) replayBlockedAttacks += 1;
    if (sourceDecision.action === 'record') {
      if (deniedByXdr) normalRequestsBlocked += 1;
      if (response.decision === 'allow') normalRequestsPassed += 1;
    }
    if (sourceDecision.action === 'alert' && !deniedByXdr) ambiguousRequestsNotBlocked += 1;
  }

  return {
    blockRulesCreated: processed.blockRules.length,
    alertLogLinesWritten: processed.logLines.length,
    replayBlockedAttacks,
    ambiguousRequestsNotBlocked,
    normalRequestsPassed,
    normalRequestsBlocked,
    logPath: processed.logPath,
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixturePath = join(rootDir, 'xdr', 'fixtures', 'exfiltration.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));
  const report = await replayFixture(fixture.alerts, { rootDir });
  console.log(JSON.stringify(report));
}
