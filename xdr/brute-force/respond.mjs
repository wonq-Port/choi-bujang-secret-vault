import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide as decideZtna } from '../../src/decider.mjs';
import { decide as decideBruteForce } from './decide.mjs';

const DEFAULT_BLOCK_TTL_MS = 30 * 60 * 1000; // 30분 만료

export function createBlockRule(alert, decision, ttlMs = DEFAULT_BLOCK_TTL_MS) {
  if (!alert || typeof alert !== 'object' || decision?.action !== 'block') {
    return null;
  }
  const srcip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip.trim() : '';
  const alertId = typeof alert?.id === 'string' ? alert.id.trim() : '';
  const level = typeof alert?.rule?.level === 'number' ? alert.rule.level : 0;

  // 정상 사용자를 막는 규칙은 넣지 않음 (명확한 공격 조건 재확인)
  if (!srcip || !alertId || decision.confidence < 0.85 || level < 10) {
    return null;
  }

  const baseTimeMs = Date.parse(alert.timestamp);
  const startMs = Number.isFinite(baseTimeMs) ? baseTimeMs : Date.now();
  const expiresAt = new Date(startMs + ttlMs).toISOString();

  return {
    ruleId: 'xdr.brute_force.block_ip',
    effect: 'deny',
    srcip,
    srcuser: typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : null,
    alertId,
    expiresAt,
    confidence: decision.confidence,
    reason: decision.reason,
  };
}

export function formatAlertLogLine(alert, decision) {
  const timestamp = typeof alert?.timestamp === 'string' ? alert.timestamp : new Date().toISOString();
  const alertId = typeof alert?.id === 'string' ? alert.id : 'unknown';
  const srcip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '-';
  const srcuser = typeof alert?.data?.srcuser === 'string' ? alert.data.srcuser : '-';
  return JSON.stringify({
    timestamp,
    alertId,
    action: decision.action,
    confidence: decision.confidence,
    srcip,
    srcuser,
    reason: decision.reason,
  });
}

export async function processAlerts(alerts, { logPath, resetLog = false, ttlMs = DEFAULT_BLOCK_TTL_MS } = {}) {
  const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const targetLogPath = logPath || join(rootDir, 'xdr', 'alerts.log');
  await mkdir(dirname(targetLogPath), { recursive: true });
  if (resetLog) {
    await writeFile(targetLogPath, '', 'utf8');
  }

  const blockRules = [];
  const logLines = [];

  for (const alert of alerts) {
    const decision = await decideBruteForce(alert);
    if (decision.action === 'block') {
      const rule = createBlockRule(alert, decision, ttlMs);
      if (rule) {
        blockRules.push(rule);
      }
      const line = formatAlertLogLine(alert, decision);
      logLines.push(line);
      await appendFile(targetLogPath, `${line}\n`, 'utf8');
    } else if (decision.action === 'alert') {
      const line = formatAlertLogLine(alert, decision);
      logLines.push(line);
      await appendFile(targetLogPath, `${line}\n`, 'utf8');
    }
  }

  return { blockRules, logLines, logPath: targetLogPath };
}

export function createXdrDecider(blockRules = []) {
  return async function decideWithXdr(request, options = {}) {
    const requestId = typeof request?.requestId === 'string' ? request.requestId : '';
    const candidateIp =
      typeof request?.srcip === 'string'
        ? request.srcip.trim()
        : typeof request?.signals?.srcip === 'string'
          ? request.signals.srcip.trim()
          : '';

    const nowMs =
      typeof options?.now === 'string' || typeof options?.now === 'number'
        ? new Date(options.now).getTime()
        : Date.now();

    if (candidateIp) {
      const matchedRule = blockRules.find((rule) => {
        if (!rule || rule.effect !== 'deny' || rule.srcip !== candidateIp) return false;
        const expMs = Date.parse(rule.expiresAt);
        return Number.isFinite(expMs) && nowMs < expMs;
      });

      if (matchedRule) {
        return {
          schema: 'aleph.decision.v1',
          requestId,
          decision: 'deny',
          reasonCode: 'xdr_brute_force_blocked',
          ruleIds: [matchedRule.ruleId],
          alertId: matchedRule.alertId,
          expiresAt: matchedRule.expiresAt,
        };
      }
    }

    // 차단 대상이 아니면 기존 ZTNA 판정기 규칙을 그대로 수행
    return decideZtna(request);
  };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (isMain) {
  const rootDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const fixturePath = join(rootDir, 'xdr', 'fixtures', 'brute-force.json');
  const fixture = JSON.parse(await readFile(fixturePath, 'utf8'));

  const { blockRules, logLines } = await processAlerts(fixture.alerts, { resetLog: true });
  const decideWithXdr = createXdrDecider(blockRules);

  let blockedAttackCount = 0;
  let passedNormalCount = 0;

  for (const alert of fixture.alerts) {
    const checkTime = new Date(Date.parse(alert.timestamp) + 60 * 1000).toISOString();
    const ztnaRequest = {
      schema: 'aleph.decision.request.v1',
      requestId: `req-${alert.id}`,
      deviceRegistered: true,
      policyRevision: 1,
      service: 'notes',
      method: 'GET',
      path: '/api/memos/memo-1',
      route: 'GET /api/memos/:id',
      queryLength: 0,
      srcip: alert?.data?.srcip,
      stepUp: { verified: false, authAgeSeconds: null },
      signals: { source: 'none', region: 'local', network: 'usual', hour: 10 },
      recentEvents: [],
    };
    const res = await decideWithXdr(ztnaRequest, { now: checkTime });
    if (res.decision === 'deny' && res.reasonCode === 'xdr_brute_force_blocked') {
      blockedAttackCount += 1;
    } else if (res.decision === 'allow') {
      passedNormalCount += 1;
    }
  }

  console.log(
    JSON.stringify({
      blockRulesCreated: blockRules.length,
      alertLogLinesWritten: logLines.length,
      replayBlockedAttacks: blockedAttackCount,
      replayPassedRequests: passedNormalCount,
    }),
  );
}
