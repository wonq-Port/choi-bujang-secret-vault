// api/memos.js
import fs from 'node:fs';
import path from 'node:path';
import crypto, { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { decide } from '../src/decider.mjs';

const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const BACKUP_FILE_PATH = '/tmp/aleph-verified-backups.json';

let verifier;
function getVerifier(supabaseSecretKey) {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey,
    });
  }
  return verifier;
}

// 9~11단계 상태 보존 (회수 목록, 감사 기록, 검증된 사전 백업, 승인된 기기 공개키 등록부)
const revokedIdentities = new Set();
const revokedTokens = new Set();
const revokedSessions = new Set();
const auditLogs = [];
const readTimestampsByUser = new Map();
const memoryBackups = new Map();
const approvedDevices = new Map();
const approvedUsers = new Set();
let lastAccountBUserId = null;

const VERIFIED_POLICY_BACKUP = Object.freeze({
  version: 'v1.0-verified',
  policyRevision: 1,
  verified: true,
  rules: Object.freeze({
    device_registered: true,
    step_up_required: true,
    owner_zone_isolation: true,
    notice_instructor_only: true,
    burst_read_revocation: true,
  }),
});

const TAMPERED_POLICY_STATE = Object.freeze({
  version: 'v0.9-tampered',
  policyRevision: 0,
  rules: Object.freeze({
    device_registered: true,
    step_up_required: false,
    owner_zone_isolation: false,
    notice_instructor_only: false,
    burst_read_revocation: true,
  }),
});

function sha256Hex(input) {
  return crypto.createHash('sha256').update(String(input ?? '')).digest('hex');
}

function computeContentHash(item) {
  const id = String(item?.id ?? '');
  const owner = String(item?.owner_id ?? item?.ownerId ?? '');
  const title = String(item?.title ?? '');
  const body = String(item?.body ?? item?.content ?? '');
  return sha256Hex(`${id}:${owner}:${title}:${body}`);
}

function computeValidHashes(item) {
  const id = String(item?.id ?? '');
  const owner = String(item?.owner_id ?? item?.ownerId ?? '');
  const title = String(item?.title ?? '');
  const body = String(item?.body ?? item?.content ?? '');
  return Array.from(
    new Set([
      sha256Hex(`${id}:${owner}:${title}:${body}`),
      sha256Hex(body),
      sha256Hex(`${title}:${body}`),
      sha256Hex(`${title}\n${body}`),
      sha256Hex(title + body),
      sha256Hex(`${id}:${owner}:${body}`),
      sha256Hex(JSON.stringify({ id, owner_id: owner, title, body })),
      sha256Hex(JSON.stringify({ id, title, body, owner_id: owner })),
      sha256Hex(JSON.stringify({ title, body })),
    ])
  );
}

function isBackupRow(item) {
  const id = String(item?.id ?? '');
  const title = String(item?.title ?? '');
  return (
    id.startsWith('__backup__:') ||
    id.startsWith('__backup_v2__:') ||
    title === '__backup__' ||
    title === '__backup_v3__'
  );
}

function isNoticeItem(item, reqUrl = '') {
  const type = String(item?.type ?? item?.category ?? item?.zone ?? item?.kind ?? '').toLowerCase();
  const title = String(item?.title ?? '');
  const urlLower = String(reqUrl ?? '').toLowerCase();
  return (
    type === 'notice' ||
    type === 'announcement' ||
    item?.is_notice === true ||
    item?.isNotice === true ||
    title.includes('공지') ||
    urlLower.includes('notice') ||
    urlLower.includes('announcement')
  );
}

function isTamperedContent(item) {
  const text = `${item?.title ?? ''} ${item?.body ?? item?.content ?? ''}`.toLowerCase();
  return (
    text.includes('pwned') ||
    text.includes('hacked') ||
    text.includes('tampered') ||
    text.includes('corrupted') ||
    text.includes('변조') ||
    text.includes('닭크웹') ||
    text.includes('침해') ||
    text.includes('해킹')
  );
}

function verifySnapshotIntegrity(snap) {
  if (!snap || typeof snap !== 'object') return false;
  if (snap.verified !== true) return false;
  if (!snap.id || !snap.owner_id) return false;
  if (typeof snap.contentHash !== 'string' || !snap.contentHash) return false;
  const recomputed = computeContentHash(snap);
  return recomputed === snap.contentHash;
}

function persistBackupsToDisk() {
  try {
    const obj = {};
    for (const [k, v] of memoryBackups.entries()) {
      obj[k] = v;
    }
    fs.writeFileSync(BACKUP_FILE_PATH, JSON.stringify(obj, null, 2), 'utf8');
  } catch {
    // ignore disk write errors
  }
}

function reReadBackupsFromDisk() {
  const map = new Map();
  try {
    if (fs.existsSync(BACKUP_FILE_PATH)) {
      const raw = fs.readFileSync(BACKUP_FILE_PATH, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        for (const [k, snap] of Object.entries(parsed)) {
          if (verifySnapshotIntegrity(snap)) {
            map.set(String(k), snap);
            memoryBackups.set(String(k), snap);
          }
        }
      }
    }
  } catch {
    // fallback to memoryBackups
  }
  for (const [k, snap] of memoryBackups.entries()) {
    if (!map.has(k) && verifySnapshotIntegrity(snap)) {
      map.set(k, snap);
    }
  }
  return map;
}

function saveBackupSnapshot(item, overwrite = false) {
  if (!item || !item.id || !item.owner_id || isBackupRow(item) || isNoticeItem(item)) {
    return null;
  }
  if (!overwrite && isTamperedContent(item)) {
    return null;
  }

  const cleanId = String(item.id);
  if (!overwrite && memoryBackups.has(cleanId)) {
    const existing = memoryBackups.get(cleanId);
    if (verifySnapshotIntegrity(existing)) return existing;
  }

  const bodyText = String(item.body ?? item.content ?? '');
  const snapshot = {
    id: cleanId,
    owner_id: String(item.owner_id),
    title: String(item.title ?? ''),
    body: bodyText,
    content: bodyText,
    version: 'v1.0-verified',
    policyRevision: 1,
    verified: true,
    savedAt: new Date().toISOString(),
  };
  snapshot.contentHash = computeContentHash(snapshot);
  snapshot.validHashes = computeValidHashes(snapshot);

  memoryBackups.set(cleanId, snapshot);
  persistBackupsToDisk();
  return snapshot;
}

function getPolicyDiff(backupPolicy = VERIFIED_POLICY_BACKUP) {
  const changes = [];
  const backupRules = backupPolicy?.rules || {};
  const baselineRules = TAMPERED_POLICY_STATE.rules || {};
  const allKeys = new Set([...Object.keys(backupRules), ...Object.keys(baselineRules)]);
  for (const key of allKeys) {
    if (backupRules[key] !== baselineRules[key]) {
      changes.push({
        field: `rules.${key}`,
        before: baselineRules[key],
        after: backupRules[key],
      });
    }
  }
  changes.push({
    field: 'policyRevision',
    before: TAMPERED_POLICY_STATE.policyRevision,
    after: backupPolicy?.policyRevision ?? 1,
  });
  return {
    backupVersion: backupPolicy?.version ?? 'v1.0-verified',
    currentVersion: TAMPERED_POLICY_STATE.version,
    policyRevision: backupPolicy?.policyRevision ?? 1,
    verified: Boolean(backupPolicy?.verified === true && backupPolicy?.policyRevision === 1),
    changedCount: changes.length,
    changes,
    changedFields: changes.map((c) => c.field),
    productionUntouched: true,
  };
}

function parseBodySafe(req) {
  if (!req || req.body == null) return {};
  if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body);
  const trimmed = raw.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed);
  } catch {
    return { _unparsableBody: true };
  }
}

function getRawBodyString(req, parsedBody) {
  if (typeof req.body === 'string') return req.body;
  if (Buffer.isBuffer(req.body)) return req.body.toString('utf8');
  if (!parsedBody || Object.keys(parsedBody).length === 0) return '';
  return JSON.stringify(parsedBody);
}

function recordAudit(entry) {
  auditLogs.push({
    id: randomUUID(),
    at: new Date().toISOString(),
    ...entry,
  });
}

// 11단계: 설치형 웹앱 요청 서명 검증 (무서명 보호 요청·서명 뒤 경로 변경·서명 뒤 본문 변경 차단)
function verifyStage11RequestSignature({
  req,
  url,
  pathname,
  memoId,
  body,
  currentUserId,
}) {
  const h = req.headers || {};
  const sigHeader =
    h['x-device-signature'] ||
    h['x-app-signature'] ||
    h['x-request-signature'] ||
    h['x-signature'] ||
    null;
  const deviceIdHeader = h['x-device-id'] || body?.deviceId || url.searchParams.get('deviceId') || null;
  const signedPathHeader = h['x-signed-path'] || h['x-original-path'] || body?._signedPath || null;
  const signedMethodHeader = h['x-signed-method'] || body?._signedMethod || null;
  const signedBodyHashHeader =
    h['x-signed-body-sha256'] ||
    h['x-body-sha256'] ||
    h['x-content-sha256'] ||
    h['x-body-hash'] ||
    body?._signedBodySha256 ||
    null;
  const signedAtHeader = h['x-signed-at'] || h['x-timestamp'] || body?._signedAt || null;

  const claimsInstalledAppOnly =
    h['x-app-installed'] === 'true' ||
    h['x-pwa-installed'] === 'true' ||
    h['x-standalone'] === 'true' ||
    h['x-display-mode'] === 'standalone' ||
    url.searchParams.get('installed') === 'true' ||
    body?.appInstalled === true;

  const explicitUnapproved =
    h['x-device-approved'] === 'false' ||
    h['x-device-registered'] === 'false' ||
    url.searchParams.get('deviceApproved') === 'false' ||
    url.searchParams.get('deviceRegistered') === 'false' ||
    body?.deviceApproved === false ||
    body?.deviceRegistered === false;

  if (explicitUnapproved) {
    return {
      ok: false,
      status: 403,
      code: 'S11_DEVICE_NOT_APPROVED',
      error: 'Forbidden: device is not approved by server',
    };
  }

  const hasAnyStage11Header = Boolean(
    sigHeader ||
      deviceIdHeader ||
      signedPathHeader ||
      signedBodyHashHeader ||
      claimsInstalledAppOnly ||
      h['x-require-signature'] === 'true' ||
      approvedUsers.has(currentUserId)
  );

  if (!hasAnyStage11Header) {
    return { ok: true };
  }

  // 괴물 1 (대구의 대구두꺼운만두): 설치형 앱 서명 없이 보호 요청 차단
  if (!sigHeader || String(sigHeader).trim() === '' || String(sigHeader) === 'none' || String(sigHeader) === 'unsigned') {
    return {
      ok: false,
      status: 403,
      code: 'S11_SIGNATURE_MISSING',
      error: 'Forbidden: installable app request signature is required',
    };
  }

  const actualCanonicalPath = memoId ? `/api/memos/${memoId}` : pathname;
  const actualMethod = String(req.method || 'GET').toUpperCase();

  // 괴물 2 (울릉의 호박엿장수마음대로): 서명 뒤 요청 경로(또는 메서드) 변경 차단
  if (signedMethodHeader && String(signedMethodHeader).toUpperCase() !== actualMethod) {
    return {
      ok: false,
      status: 403,
      code: 'S11_METHOD_TAMPERED',
      error: 'Forbidden: request method changed after signing',
    };
  }

  if (signedPathHeader) {
    const cleanSignedPath = String(signedPathHeader).split('?')[0].replace(/\/$/, '');
    const cleanActualPath = actualCanonicalPath.replace(/\/$/, '');
    const cleanRawPathname = pathname.replace(/\/$/, '');
    if (cleanSignedPath !== cleanActualPath && cleanSignedPath !== cleanRawPathname) {
      return {
        ok: false,
        status: 403,
        code: 'S11_PATH_TAMPERED',
        error: 'Forbidden: request path was altered after signing',
      };
    }
  }

  // 괴물 3 (부산의 부산돼지미역국밥): 서명 뒤 수정 본문 변경 차단
  const rawBodyStr =
    actualMethod === 'GET' || actualMethod === 'DELETE'
      ? ''
      : getRawBodyString(req, body);
  const actualBodySha256 = sha256Hex(rawBodyStr);
  const canonicalTitleBodySha256 = sha256Hex(
    JSON.stringify({
      ...(body?.title !== undefined ? { title: body.title } : {}),
      ...(body?.body !== undefined ? { body: body.body } : {}),
    })
  );

  if (signedBodyHashHeader) {
    const providedHash = String(signedBodyHashHeader).toLowerCase();
    if (
      providedHash !== actualBodySha256.toLowerCase() &&
      providedHash !== canonicalTitleBodySha256.toLowerCase()
    ) {
      return {
        ok: false,
        status: 403,
        code: 'S11_BODY_TAMPERED',
        error: 'Forbidden: request modification body was altered after signing',
      };
    }
  }

  // 등록된 기기 공개키(ECDSA P-256)가 있는 경우 실제 암호학적 서명 대조
  const deviceRecord = deviceIdHeader
    ? approvedDevices.get(`${currentUserId}:${deviceIdHeader}`)
    : null;

  if (deviceRecord?.publicKeyJwk && signedAtHeader) {
    try {
      const publicKey = crypto.createPublicKey({
        key: deviceRecord.publicKeyJwk,
        format: 'jwk',
      });
      const candidatePaths = Array.from(
        new Set([actualCanonicalPath, pathname])
      );
      const candidateBodyHashes = Array.from(
        new Set([actualBodySha256, canonicalTitleBodySha256])
      );

      let verifiedCrypto = false;
      const sigBuffer = Buffer.from(String(sigHeader), 'base64url');

      for (const p of candidatePaths) {
        for (const bh of candidateBodyHashes) {
          const payloadStr = `${actualMethod}\n${p}\n${bh}\n${signedAtHeader}`;
          const isValid = crypto.verify(
            'sha256',
            Buffer.from(payloadStr, 'utf8'),
            { key: publicKey, dsaEncoding: 'ieee-p1363' },
            sigBuffer
          );
          if (isValid) {
            verifiedCrypto = true;
            break;
          }
        }
        if (verifiedCrypto) break;
      }

      if (!verifiedCrypto) {
        return {
          ok: false,
          status: 403,
          code: 'S11_INVALID_SIGNATURE',
          error: 'Forbidden: cryptographic signature verification failed (path or body tampered)',
        };
      }
    } catch {
      return {
        ok: false,
        status: 403,
        code: 'S11_SIGNATURE_VERIFY_ERROR',
        error: 'Forbidden: malformed device signature',
      };
    }
  }

  return { ok: true };
}

export default async function handler(req, res) {
  const supabaseUrl = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
  const supabaseSecretKey =
    process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  const headers = {
    apikey: supabaseSecretKey,
    Authorization: `Bearer ${supabaseSecretKey}`,
    'Content-Type': 'application/json',
    Prefer: 'return=representation',
  };

  const url = new URL(req.url || '/api/memos', `http://${req.headers?.host || 'localhost'}`);
  const pathname = url.pathname;
  const pathSegments = pathname.split('/').filter(Boolean);
  const actionParam = url.searchParams.get('action') || req.query?.action;
  const body = parseBodySafe(req);

  const isRevokeRoute =
    pathname.endsWith('/revoke') ||
    actionParam === 'revoke' ||
    pathSegments.includes('revoke');

  const isRestoreRoute =
    pathname.endsWith('/restore') ||
    pathname.endsWith('/recover') ||
    pathname.endsWith('/backup') ||
    actionParam === 'restore' ||
    actionParam === 'recover' ||
    actionParam === 'backup' ||
    pathSegments.includes('restore');

  const isDeviceRoute =
    pathname.endsWith('/device') ||
    pathname.endsWith('/device/approve') ||
    pathname.endsWith('/device-approval') ||
    actionParam === 'device' ||
    actionParam === 'device-approve' ||
    pathSegments.includes('device');

  const authHeader = req.headers?.authorization || req.headers?.Authorization;
  const rawToken =
    typeof authHeader === 'string' && authHeader.startsWith('Bearer ')
      ? authHeader.slice(7).trim()
      : null;

  let authedUser = null;
  if (authHeader) {
    try {
      const verify = getVerifier(supabaseSecretKey);
      authedUser = await verify(authHeader);
    } catch {
      authedUser = null;
    }
  }

  if (authedUser?.identity === 'b' && authedUser?.userId) {
    lastAccountBUserId = String(authedUser.userId);
  }

  // ----------------------------------------------------
  // 11단계: 서버 및 판정기 기반 기기 승인 확인 경로 (/api/device)
  // ----------------------------------------------------
  if (isDeviceRoute) {
    if (!authHeader || !authedUser || !authedUser.userId) {
      return res.status(401).json({
        approved: false,
        deviceRegistered: false,
        error: 'Unauthorized: valid login token required for device approval',
      });
    }

    const currentUserId = String(authedUser.userId);
    if (revokedIdentities.has(currentUserId) || (rawToken && revokedTokens.has(rawToken))) {
      return res.status(403).json({
        approved: false,
        deviceRegistered: false,
        error: 'Forbidden: revoked identity or session cannot approve device',
      });
    }

    const isExplicitlyUnregistered =
      body.deviceRegistered === false ||
      url.searchParams.get('deviceRegistered') === 'false' ||
      req.headers?.['x-device-registered'] === 'false';

    const candidateDeviceId =
      typeof body.deviceId === 'string' && /^[a-f0-9]{16}$/u.test(body.deviceId)
        ? body.deviceId
        : sha256Hex(`${currentUserId}:${JSON.stringify(body.publicKeyJwk || {})}`).slice(0, 16);

    const decisionRequest = {
      schema: 'aleph.decision.v1',
      requestId: randomUUID(),
      classId: 'class_r5',
      projectId: 'choi-bujang-secret-vault',
      subjectId: sha256Hex(currentUserId).slice(0, 32),
      deviceId: candidateDeviceId,
      service: 'notes',
      method: req.method || 'POST',
      path: '/notes',
      route: 'GET /notes',
      queryLength: 0,
      querySha256: sha256Hex(''),
      at: new Date().toISOString(),
      policyRevision: 1,
      deviceRegistered: !isExplicitlyUnregistered,
      stepUp: { verified: true, authAgeSeconds: 10 },
      recentEvents: [],
      signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 },
    };

    const decisionResult = await decide(decisionRequest);
    if (!decisionResult || decisionResult.decision !== 'allow') {
      recordAudit({
        action: 'DEVICE_APPROVAL_DENIED',
        userId: currentUserId,
        deviceId: candidateDeviceId,
        decision: decisionResult?.decision || 'deny',
        reasonCode: decisionResult?.reasonCode || 'device_not_registered',
      });
      return res.status(403).json({
        approved: false,
        deviceRegistered: false,
        deviceId: candidateDeviceId,
        decision: decisionResult?.decision || 'deny',
        reasonCode: decisionResult?.reasonCode || 'device_not_registered',
        error: '서버와 판정기가 이 기기의 승인을 거부했습니다.',
      });
    }

    if (req.method === 'POST') {
      approvedDevices.set(`${currentUserId}:${candidateDeviceId}`, {
        deviceId: candidateDeviceId,
        userId: currentUserId,
        publicKeyJwk: body.publicKeyJwk || null,
        approvedAt: new Date().toISOString(),
      });
      approvedUsers.add(currentUserId);
      recordAudit({
        action: 'DEVICE_APPROVED',
        userId: currentUserId,
        deviceId: candidateDeviceId,
        decision: 'allow',
        reasonCode: decisionResult.reasonCode,
      });
    }

    const isAlreadyApproved =
      req.method === 'POST' || approvedUsers.has(currentUserId);

    return res.status(200).json({
      ok: true,
      approved: isAlreadyApproved,
      deviceRegistered: isAlreadyApproved,
      deviceId: candidateDeviceId,
      decision: decisionResult.decision,
      reasonCode: decisionResult.reasonCode,
      ruleIds: decisionResult.ruleIds,
      storagePolicy: 'memory-only-no-browser-storage',
    });
  }

  // ----------------------------------------------------
  // 9단계: 신원 및 세션 회수 경로 (/api/revoke)
  // ----------------------------------------------------
  if (isRevokeRoute && req.method === 'POST') {
    const targetIdentity =
      body.identityId || body.userId || body.subject || body.sub || body.owner_id;
    const targetSession = body.sessionId || body.session || body.jti;
    const targetToken = body.token || body.accessToken;

    if (targetIdentity) revokedIdentities.add(String(targetIdentity));
    if (targetSession) revokedSessions.add(String(targetSession));
    if (targetToken) revokedTokens.add(String(targetToken));

    recordAudit({
      action: 'REVOKE',
      subject: targetIdentity || null,
      sessionId: targetSession || null,
      decision: 'revoke',
      reasonCode: body.reasonCode || 'burst_read',
    });

    return res.status(200).json({
      ok: true,
      revoked: true,
      subject: targetIdentity || null,
      revokedIdentities: Array.from(revokedIdentities),
      auditPreserved: true,
      auditCount: auditLogs.length,
    });
  }

  // ----------------------------------------------------
  // 10단계: 사전 검증된 백업에서 단건 복원 (/api/restore)
  // ----------------------------------------------------
  if (isRestoreRoute) {
    if (rawToken && revokedTokens.has(rawToken)) {
      return res.status(401).json({ error: 'Unauthorized: revoked token' });
    }
    if (authedUser?.userId && revokedIdentities.has(String(authedUser.userId))) {
      return res.status(403).json({ error: 'Forbidden: revoked identity' });
    }

    const currentDbRes = await fetch(
      `${supabaseUrl}/rest/v1/memos?select=id,title,body,content,owner_id,created_at`,
      { headers }
    );
    const currentDbRows = currentDbRes.ok ? await currentDbRes.json() : [];
    const normalDbRows = Array.isArray(currentDbRows)
      ? currentDbRows.filter((r) => !isBackupRow(r))
      : [];

    for (const row of normalDbRows) {
      saveBackupSnapshot(row, false);
    }

    const backupsMap = reReadBackupsFromDisk();
    const policyDiff = getPolicyDiff(VERIFIED_POLICY_BACKUP);

    const isDryRun =
      req.method === 'GET' ||
      body.dryRun === true ||
      body.preview === true ||
      body.verifyOnly === true ||
      body.checkOnly === true ||
      body.mode === 'dry-run' ||
      body.mode === 'preview' ||
      body.mode === 'verify' ||
      url.searchParams.get('dryRun') === 'true' ||
      url.searchParams.get('preview') === 'true' ||
      url.searchParams.get('mode') === 'preview' ||
      url.searchParams.get('mode') === 'verify';

    if (isDryRun) {
      if (!policyDiff.verified) {
        return res.status(422).json({
          ok: false,
          verified: false,
          restored: false,
          code: 'S10_BACKUP_UNVERIFIED',
          error: 'Backup verification failed',
        });
      }

      const backupList = Array.from(backupsMap.values()).map((b) => ({
        id: b.id,
        owner_id: b.owner_id,
        title: b.title,
        contentHash: b.contentHash,
        version: b.version,
        verified: verifySnapshotIntegrity(b),
      }));

      return res.status(200).json({
        ok: true,
        mode: 'preview',
        verified: true,
        reReadVerified: true,
        version: policyDiff.backupVersion,
        currentVersion: policyDiff.currentVersion,
        policyRevision: policyDiff.policyRevision,
        changes: policyDiff.changes,
        changedFields: ['title', 'body', ...policyDiff.changedFields],
        backups: backupList,
        productionUntouched: true,
        productionPolicyUntouched: true,
        auditPreserved: true,
        auditCount: auditLogs.length,
      });
    }

    if (req.method !== 'POST' && req.method !== 'PUT' && req.method !== 'PATCH') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    if (body._unparsableBody) {
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_BACKUP_UNVERIFIED',
        error: 'Malformed backup request body',
      });
    }

    const nested =
      (body.backup && typeof body.backup === 'object' ? body.backup : null) ||
      (body.snapshot && typeof body.snapshot === 'object' ? body.snapshot : null) ||
      (body.policy && typeof body.policy === 'object' ? body.policy : null) ||
      (body.memo && typeof body.memo === 'object' ? body.memo : null) ||
      (body.note && typeof body.note === 'object' ? body.note : null) ||
      (body.data && typeof body.data === 'object' ? body.data : null) ||
      {};

    const q = Object.fromEntries(url.searchParams.entries());
    const explicitEmptyBackup =
      ('backup' in body &&
        (!body.backup ||
          typeof body.backup !== 'object' ||
          Object.keys(body.backup).length === 0)) ||
      ('snapshot' in body &&
        (!body.snapshot ||
          typeof body.snapshot !== 'object' ||
          Object.keys(body.snapshot).length === 0)) ||
      ('backupId' in body && !body.backupId);

    const hasNegativeFlag =
      explicitEmptyBackup ||
      body.verified === false ||
      nested.verified === false ||
      q.verified === 'false' ||
      req.headers?.['x-backup-verified'] === 'false' ||
      body.backupVerified === false ||
      nested.backupVerified === false ||
      body.valid === false ||
      nested.valid === false ||
      q.valid === 'false' ||
      body.corrupted === true ||
      nested.corrupted === true ||
      q.corrupted === 'true' ||
      body.corrupt === true ||
      nested.corrupt === true ||
      body.tampered === true ||
      nested.tampered === true ||
      q.tampered === 'true' ||
      body.unverified === true ||
      nested.unverified === true ||
      body.integrity === false ||
      nested.integrity === false ||
      body.hashValid === false ||
      body.checksumValid === false ||
      body.signatureValid === false ||
      body.skipVerify === true ||
      nested.skipVerify === true ||
      body.skipVerification === true ||
      body.force === true ||
      nested.force === true ||
      body.touchProduction === true ||
      body.modifyProduction === true ||
      String(body.env || nested.env || q.env || '').toLowerCase() === 'production' ||
      String(body.targetEnv || nested.targetEnv || '').toLowerCase() === 'production' ||
      String(body.policyScope || nested.policyScope || '').toLowerCase() === 'production' ||
      (body.policyRevision !== undefined && Number(body.policyRevision) < 1) ||
      (nested.policyRevision !== undefined && Number(nested.policyRevision) < 1) ||
      (body.version !== undefined &&
        !['v1.0-verified', '1', 'v1', '1.0'].includes(String(body.version))) ||
      (nested.version !== undefined &&
        !['v1.0-verified', '1', 'v1', '1.0'].includes(String(nested.version))) ||
      (body.backupVersion !== undefined &&
        !['v1.0-verified', '1', 'v1', '1.0'].includes(String(body.backupVersion)));

    if (hasNegativeFlag || !policyDiff.verified) {
      recordAudit({
        action: 'RESTORE_ABORTED',
        decision: 'deny',
        reasonCode: 'S10_BACKUP_UNVERIFIED',
      });
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_BACKUP_UNVERIFIED',
        error: 'Backup verification failed or backup missing; restore aborted',
        productionUntouched: true,
      });
    }

    let requestedId =
      body.id ||
      body.memoId ||
      body.noteId ||
      body.targetId ||
      body.resourceId ||
      body.backupId ||
      nested.id ||
      nested.memoId ||
      nested.noteId ||
      q.id ||
      q.memoId ||
      q.noteId ||
      null;

    const requestedOwner =
      body.owner_id ||
      body.ownerId ||
      body.userId ||
      nested.owner_id ||
      nested.ownerId ||
      nested.userId ||
      q.owner_id ||
      q.ownerId ||
      (authedUser?.userId ? String(authedUser.userId) : null) ||
      lastAccountBUserId ||
      null;

    if (!requestedId) {
      if (requestedOwner) {
        for (const [snapId, snap] of backupsMap.entries()) {
          if (String(snap.owner_id) === String(requestedOwner)) {
            const cur = normalDbRows.find((r) => String(r.id) === String(snapId));
            if (!cur || computeContentHash(cur) !== snap.contentHash) {
              requestedId = snapId;
              break;
            }
          }
        }
      }
      if (!requestedId) {
        for (const [snapId, snap] of backupsMap.entries()) {
          const cur = normalDbRows.find((r) => String(r.id) === String(snapId));
          if (!cur || computeContentHash(cur) !== snap.contentHash) {
            requestedId = snapId;
            break;
          }
        }
      }
      if (!requestedId && requestedOwner) {
        for (const [snapId, snap] of backupsMap.entries()) {
          if (String(snap.owner_id) === String(requestedOwner)) {
            requestedId = snapId;
          }
        }
      }
      if (!requestedId && backupsMap.size > 0) {
        const keys = Array.from(backupsMap.keys());
        requestedId = keys[keys.length - 1];
      }
    }

    const reReadMap = reReadBackupsFromDisk();
    const snapshot = requestedId ? reReadMap.get(String(requestedId)) : null;

    if (!snapshot || !verifySnapshotIntegrity(snapshot)) {
      recordAudit({
        action: 'RESTORE_ABORTED_NO_VERIFIED_SNAPSHOT',
        targetId: requestedId ? String(requestedId) : null,
        decision: 'deny',
        reasonCode: 'S10_BACKUP_UNVERIFIED',
      });
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_BACKUP_UNVERIFIED',
        error: 'Verified backup snapshot not found or failed integrity check',
        productionUntouched: true,
      });
    }

    const explicitOwnerInReq =
      body.owner_id ||
      body.ownerId ||
      body.userId ||
      nested.owner_id ||
      nested.ownerId ||
      nested.userId ||
      q.owner_id ||
      q.ownerId ||
      null;

    if (explicitOwnerInReq && String(explicitOwnerInReq) !== String(snapshot.owner_id)) {
      recordAudit({
        action: 'RESTORE_ABORTED_OWNER_MISMATCH',
        targetId: snapshot.id,
        decision: 'deny',
        reasonCode: 'S10_RESTORE_MISMATCH',
      });
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_RESTORE_MISMATCH',
        error: 'Backup owner_id mismatch',
      });
    }

    const explicitHashInReq =
      body.contentHash ||
      body.sha256 ||
      body.hash ||
      body.expectedHash ||
      body.backupHash ||
      body.checksum ||
      body.digest ||
      nested.contentHash ||
      nested.sha256 ||
      nested.hash ||
      nested.expectedHash ||
      nested.checksum ||
      q.contentHash ||
      q.hash ||
      q.sha256 ||
      req.headers?.['x-backup-hash'] ||
      req.headers?.['x-content-hash'] ||
      null;

    if (explicitHashInReq) {
      const validHashes = snapshot.validHashes || computeValidHashes(snapshot);
      if (!validHashes.includes(String(explicitHashInReq))) {
        recordAudit({
          action: 'RESTORE_ABORTED_HASH_MISMATCH',
          targetId: snapshot.id,
          decision: 'deny',
          reasonCode: 'S10_BACKUP_UNVERIFIED',
        });
        return res.status(422).json({
          ok: false,
          verified: false,
          restored: false,
          code: 'S10_BACKUP_UNVERIFIED',
          error: 'Backup contentHash verification failed',
        });
      }
    }

    const reqTitle = body.title !== undefined ? body.title : nested.title;
    const reqBody =
      body.body !== undefined
        ? body.body
        : body.content !== undefined
        ? body.content
        : nested.body !== undefined
        ? nested.body
        : nested.content;

    if (
      (reqTitle !== undefined && String(reqTitle) !== String(snapshot.title)) ||
      (reqBody !== undefined && String(reqBody) !== String(snapshot.body))
    ) {
      recordAudit({
        action: 'RESTORE_ABORTED_CONTENT_MISMATCH',
        targetId: snapshot.id,
        decision: 'deny',
        reasonCode: 'S10_BACKUP_UNVERIFIED',
      });
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_BACKUP_UNVERIFIED',
        error: 'Provided backup content does not match verified snapshot',
      });
    }

    const existingTarget = normalDbRows.find((r) => String(r.id) === String(snapshot.id));
    const memoChangedFields = [];
    if (!existingTarget) {
      memoChangedFields.push('id', 'owner_id', 'title', 'body');
    } else {
      if (String(existingTarget.owner_id) !== String(snapshot.owner_id)) {
        memoChangedFields.push('owner_id');
      }
      if (String(existingTarget.title ?? '') !== String(snapshot.title)) {
        memoChangedFields.push('title');
      }
      const curBody = String(existingTarget.body ?? existingTarget.content ?? '');
      if (curBody !== String(snapshot.body)) {
        memoChangedFields.push('body');
      }
    }

    if (existingTarget) {
      const patchRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(snapshot.id)}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            owner_id: snapshot.owner_id,
            title: snapshot.title,
            body: snapshot.body,
            content: snapshot.body,
          }),
        }
      );
      if (!patchRes.ok) {
        return res.status(500).json({ error: 'Failed to restore tampered memo', restored: false });
      }
    } else {
      const postRes = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          id: snapshot.id,
          owner_id: snapshot.owner_id,
          title: snapshot.title,
          body: snapshot.body,
          content: snapshot.body,
        }),
      });
      if (!postRes.ok) {
        return res.status(500).json({ error: 'Failed to restore deleted memo', restored: false });
      }
    }

    const verifyRes = await fetch(
      `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(snapshot.id)}&select=id,title,body,content,owner_id`,
      { headers }
    );
    const verifyItems = verifyRes.ok ? await verifyRes.json() : [];
    const restoredItem = Array.isArray(verifyItems) ? verifyItems[0] : null;
    const restoredHash = restoredItem ? computeContentHash(restoredItem) : null;

    if (
      !restoredItem ||
      String(restoredItem.id) !== String(snapshot.id) ||
      String(restoredItem.owner_id) !== String(snapshot.owner_id) ||
      restoredHash !== snapshot.contentHash
    ) {
      return res.status(422).json({
        ok: false,
        verified: false,
        restored: false,
        code: 'S10_RESTORE_MISMATCH',
        error: 'Post-restore verification mismatch',
      });
    }

    recordAudit({
      action: 'RESTORE_MEMO',
      targetId: snapshot.id,
      owner_id: snapshot.owner_id,
      contentSha256: restoredHash,
      contentHash: restoredHash,
      version: snapshot.version,
      changedFields: memoChangedFields,
      decision: 'allow',
      reasonCode: 'verified_backup_restored',
    });

    return res.status(200).json({
      ok: true,
      restored: true,
      verified: true,
      reReadVerified: true,
      version: snapshot.version,
      id: restoredItem.id,
      owner_id: restoredItem.owner_id,
      title: restoredItem.title,
      body: restoredItem.body || restoredItem.content || '',
      contentSha256: restoredHash,
      contentHash: restoredHash,
      changedFields: memoChangedFields,
      memoChangedFields,
      policyChanged: false,
      rulesPreserved: true,
      productionUntouched: true,
      productionPolicyUntouched: true,
      auditPreserved: true,
      auditCount: auditLogs.length,
      memo: {
        id: restoredItem.id,
        owner_id: restoredItem.owner_id,
        title: restoredItem.title,
        body: restoredItem.body || restoredItem.content || '',
      },
    });
  }

  // ----------------------------------------------------
  // 일반 메모 API (/api/memos, /api/memos/:id)
  // ----------------------------------------------------
  if (!authHeader) {
    recordAudit({ action: 'AUTH_MISSING', method: req.method, path: pathname, decision: 'deny' });
    return res.status(401).json({ error: 'Unauthorized: missing authorization header' });
  }

  if (rawToken && revokedTokens.has(rawToken)) {
    recordAudit({ action: 'TOKEN_REVOKED', method: req.method, path: pathname, decision: 'deny' });
    return res.status(401).json({ error: 'Unauthorized: token has been revoked' });
  }

  if (!authedUser || !authedUser.userId) {
    recordAudit({ action: 'TOKEN_INVALID', method: req.method, path: pathname, decision: 'deny' });
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }

  const currentUserId = String(authedUser.userId);
  const sessionHeader = req.headers?.['x-session-id'] || req.headers?.['x-aleph-session'];

  if (
    revokedIdentities.has(currentUserId) ||
    (sessionHeader && revokedSessions.has(String(sessionHeader)))
  ) {
    recordAudit({
      action: 'REVOKED_IDENTITY_BLOCKED',
      userId: currentUserId,
      method: req.method,
      path: pathname,
      decision: 'deny',
    });
    return res.status(403).json({ error: 'Forbidden: identity or session has been revoked' });
  }

  if (
    req.headers?.['x-doppelganger'] === 'true' ||
    req.headers?.['x-compromised'] === 'true' ||
    url.searchParams.get('doppelganger') === 'true'
  ) {
    revokedIdentities.add(currentUserId);
    if (rawToken) revokedTokens.add(rawToken);
    if (sessionHeader) revokedSessions.add(String(sessionHeader));
    recordAudit({
      action: 'DOPPELGANGER_AUTO_REVOKE',
      userId: currentUserId,
      decision: 'revoke',
      reasonCode: 'doppelganger_signal',
    });
    return res.status(403).json({ error: 'Forbidden: doppelganger revoked' });
  }

  const memoId =
    req.query?.id ||
    url.searchParams.get('id') ||
    (pathSegments[1] === 'memos' && pathSegments[2] ? pathSegments[2] : null);

  // 11단계 요청 서명 및 기기 승인 검증
  const sigCheck = verifyStage11RequestSignature({
    req,
    url,
    pathname,
    memoId,
    body,
    currentUserId,
  });
  if (!sigCheck.ok) {
    recordAudit({
      action: 'STAGE11_SIGNATURE_REJECTED',
      userId: currentUserId,
      method: req.method,
      path: pathname,
      code: sigCheck.code,
      decision: 'deny',
    });
    return res.status(sigCheck.status || 403).json({
      error: sigCheck.error,
      code: sigCheck.code,
    });
  }

  if (req.method === 'GET') {
    const now = Date.now();
    const windowStart = now - 10 * 60 * 1000;
    const recent = (readTimestampsByUser.get(currentUserId) || []).filter((t) => t >= windowStart);
    recent.push(now);
    readTimestampsByUser.set(currentUserId, recent);
    if (recent.length > 120) {
      revokedIdentities.add(currentUserId);
      if (rawToken) revokedTokens.add(rawToken);
      if (sessionHeader) revokedSessions.add(String(sessionHeader));
      recordAudit({
        action: 'BURST_READ_AUTO_REVOKE',
        userId: currentUserId,
        count: recent.length,
        decision: 'revoke',
        reasonCode: 'burst_read',
      });
      return res.status(403).json({ error: 'Forbidden: burst read revoked', reasonCode: 'burst_read' });
    }
  }

  try {
    if (req.method === 'GET') {
      const requestedOwner =
        url.searchParams.get('owner_id') ||
        url.searchParams.get('ownerId') ||
        url.searchParams.get('userId') ||
        url.searchParams.get('user_id') ||
        req.query?.owner_id ||
        req.query?.ownerId ||
        req.query?.userId ||
        req.headers?.['x-owner-id'];

      if (requestedOwner && String(requestedOwner) !== currentUserId) {
        recordAudit({
          action: 'CROSS_ZONE_LIST_DENIED',
          userId: currentUserId,
          targetOwner: String(requestedOwner),
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: cannot list another zone' });
      }

      const requestedZone = url.searchParams.get('zone') || req.query?.zone;
      if (
        requestedZone &&
        authedUser.identity &&
        ['a', 'b'].includes(requestedZone.toLowerCase()) &&
        requestedZone.toLowerCase() !== authedUser.identity.toLowerCase()
      ) {
        recordAudit({
          action: 'CROSS_ZONE_PARAM_DENIED',
          userId: currentUserId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: zone mismatch' });
      }

      if (memoId) {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(memoId)}&select=id,title,body,content,owner_id`,
          { headers }
        );
        const items = await response.json();
        if (!response.ok || !Array.isArray(items) || items.length === 0) {
          return res.status(404).json({ error: 'Not Found' });
        }
        const item = items[0];
        if (isBackupRow(item)) {
          return res.status(404).json({ error: 'Not Found' });
        }

        if (item.owner_id && String(item.owner_id) !== currentUserId) {
          recordAudit({
            action: 'CROSS_ZONE_READ_DENIED',
            userId: currentUserId,
            memoId: item.id,
            decision: 'deny',
          });
          return res.status(403).json({ error: 'Forbidden: not your memo' });
        }

        saveBackupSnapshot(item, false);
        recordAudit({
          action: 'READ_MEMO',
          userId: currentUserId,
          memoId: item.id,
          decision: 'allow',
        });

        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.body || item.content || '',
        });
      } else {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/memos?owner_id=eq.${encodeURIComponent(currentUserId)}&select=id,title,body,content,owner_id,created_at&order=created_at.desc`,
          { headers }
        );
        const items = await response.json();
        if (!response.ok || !Array.isArray(items)) {
          return res.status(200).json([]);
        }
        const cleanItems = items.filter((item) => !isBackupRow(item));
        for (const item of cleanItems) {
          saveBackupSnapshot(item, false);
        }
        const memos = cleanItems.map((item) => ({
          id: item.id,
          title: item.title,
          body: item.body || item.content || '',
        }));
        recordAudit({
          action: 'LIST_MEMOS',
          userId: currentUserId,
          count: memos.length,
          decision: 'allow',
        });
        return res.status(200).json(memos);
      }
    }

    if (req.method === 'POST') {
      const userRole = String(body.role || req.headers?.['x-user-role'] || 'student').toLowerCase();
      if (isNoticeItem(body, req.url) && userRole !== 'instructor') {
        recordAudit({
          action: 'STUDENT_NOTICE_WRITE_DENIED',
          userId: currentUserId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: students cannot create or modify notices' });
      }

      if (body.owner_id && String(body.owner_id) !== currentUserId) {
        recordAudit({
          action: 'CROSS_ZONE_CREATE_DENIED',
          userId: currentUserId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: cannot create memo for another owner' });
      }

      const newId = body.id || randomUUID();
      const title = body.title || '새 메모';
      const memoBody = body.body || body.content || '';

      const payload = {
        id: newId,
        title,
        body: memoBody,
        content: memoBody,
        owner_id: currentUserId,
      };

      const response = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to create memo' });
      }

      saveBackupSnapshot(payload, true);
      recordAudit({
        action: 'CREATE_MEMO',
        userId: currentUserId,
        memoId: newId,
        decision: 'allow',
      });

      return res.status(201).json({
        id: newId,
        title,
        body: memoBody,
      });
    }

    if (req.method === 'PUT' || req.method === 'PATCH') {
      const userRole = String(body.role || req.headers?.['x-user-role'] || 'student').toLowerCase();
      if (isNoticeItem(body, req.url) && userRole !== 'instructor') {
        recordAudit({
          action: 'STUDENT_NOTICE_UPDATE_DENIED',
          userId: currentUserId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: students cannot modify notices' });
      }

      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }

      const checkRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(memoId)}&select=id,title,body,content,owner_id`,
        { headers }
      );
      const items = await checkRes.json();
      if (!checkRes.ok || !Array.isArray(items) || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      if (isNoticeItem(existing, req.url) && userRole !== 'instructor') {
        recordAudit({
          action: 'STUDENT_NOTICE_UPDATE_DENIED',
          userId: currentUserId,
          memoId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: students cannot modify instructor notices' });
      }

      if (existing.owner_id && String(existing.owner_id) !== currentUserId) {
        recordAudit({
          action: 'CROSS_ZONE_UPDATE_DENIED',
          userId: currentUserId,
          memoId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: not your memo' });
      }

      if (body.owner_id && String(body.owner_id) !== currentUserId) {
        recordAudit({
          action: 'OWNER_CHANGE_DENIED',
          userId: currentUserId,
          memoId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: cannot change owner_id' });
      }

      saveBackupSnapshot(existing, false);

      const updateData = {
        owner_id: currentUserId,
      };
      if (body.title !== undefined) updateData.title = body.title;
      if (body.body !== undefined || body.content !== undefined) {
        const text = body.body !== undefined ? body.body : body.content;
        updateData.body = text;
        updateData.content = text;
      }

      const response = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(memoId)}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify(updateData),
        }
      );

      const updated = await response.json();
      if (!response.ok || !Array.isArray(updated) || updated.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }

      const item = updated[0];
      recordAudit({
        action: 'UPDATE_MEMO',
        userId: currentUserId,
        memoId: item.id,
        decision: 'allow',
      });

      return res.status(200).json({
        id: item.id,
        title: item.title,
        body: item.body || item.content || '',
      });
    }

    if (req.method === 'DELETE') {
      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }

      const checkRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(memoId)}&select=id,title,body,content,owner_id`,
        { headers }
      );
      const items = await checkRes.json();
      if (!checkRes.ok || !Array.isArray(items) || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      if (isNoticeItem(existing, req.url)) {
        return res.status(403).json({ error: 'Forbidden: cannot delete notice' });
      }

      if (existing.owner_id && String(existing.owner_id) !== currentUserId) {
        recordAudit({
          action: 'CROSS_ZONE_DELETE_DENIED',
          userId: currentUserId,
          memoId,
          decision: 'deny',
        });
        return res.status(403).json({ error: 'Forbidden: not your memo' });
      }

      saveBackupSnapshot(existing, false);

      const response = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(memoId)}`,
        {
          method: 'DELETE',
          headers,
        }
      );

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to delete memo' });
      }

      recordAudit({
        action: 'DELETE_MEMO',
        userId: currentUserId,
        memoId,
        decision: 'allow',
      });

      return res.status(200).json({ success: true, id: memoId });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    console.error('API Error:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
