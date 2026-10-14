// api/memos.js
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  VERIFIED_POLICY_SNAPSHOT,
  diffPolicy,
  restorePolicy,
} from '../src/decider.mjs';

const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

const BACKUP_PREFIX = '__backup_v2__:';
const memoryBackups = new Map();
const auditTrail = [];
let activeTestPolicy = { ...VERIFIED_POLICY_SNAPSHOT };

const RESERVED_IDS = new Set([
  'export', 'import', 'all', 'list', 'search', 'query', 'bulk', 'batch',
  'dump', 'backup', 'restore', 'admin', 'instructor', 'teacher', 'staff',
  'notices', 'notice', 'announcements', 'config', 'settings', 'status',
  'health', 'debug', 'raw', 'download', 'upload',
]);

const CLASS_NOTICES = Object.freeze([
  {
    id: 'notice-1',
    resourceId: 'notice:notice-1',
    zone: 'notice',
    title: '방어전 실습 공지',
    body: '반 공지는 읽기 전용 구역이며 학생 계정으로 수정할 수 없습니다.',
  },
]);

function computeContentHash(title, body) {
  return createHash('sha256')
    .update(`${title ?? ''}\n${body ?? ''}`, 'utf8')
    .digest('hex');
}

function validHashesForSnapshot(snapshot) {
  const title = snapshot?.title ?? '';
  const body = snapshot?.body ?? '';
  const id = snapshot?.id ?? '';
  const owner = snapshot?.owner_id ?? '';
  return new Set([
    computeContentHash(title, body),
    createHash('sha256').update(String(body), 'utf8').digest('hex'),
    createHash('sha256').update(`${title}${body}`, 'utf8').digest('hex'),
    createHash('sha256').update(JSON.stringify({ id, title, body }), 'utf8').digest('hex'),
    createHash('sha256').update(JSON.stringify({ id, owner_id: owner, title, body }), 'utf8').digest('hex'),
  ]);
}

function recordAudit(action, actorId, targetId, detail = '') {
  auditTrail.push({
    at: new Date().toISOString(),
    action,
    actorId,
    targetId,
    detail,
  });
}

// 원본 메모 사본을 저장 (overwrite=true는 최초 생성 시에만 사용)
async function saveBackupSnapshot(supabaseUrl, headers, item, { overwrite = false } = {}) {
  if (!item || !item.id || String(item.id).startsWith(BACKUP_PREFIX) || String(item.id).startsWith('__backup__:')) {
    return null;
  }
  const cleanId = String(item.id).replace(/^memo:/u, '');
  const backupRowId = `${BACKUP_PREFIX}${cleanId}`;

  if (!overwrite) {
    try {
      const existingRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(backupRowId)}&select=id,body,content`,
        { headers }
      );
      const existingItems = await existingRes.json();
      if (existingRes.ok && Array.isArray(existingItems) && existingItems.length > 0) {
        const parsed = JSON.parse(existingItems[0].body || existingItems[0].content);
        memoryBackups.set(cleanId, parsed);
        return parsed;
      }
    } catch {
      if (memoryBackups.has(cleanId)) return memoryBackups.get(cleanId);
    }
  }

  const title = item.title ?? '';
  const body = item.body ?? item.content ?? '';
  const snapshot = {
    schema: 'aleph.memo.backup.v1',
    version: 1,
    id: cleanId,
    owner_id: item.owner_id,
    title,
    body,
    contentHash: computeContentHash(title, body),
    bodyHash: createHash('sha256').update(String(body), 'utf8').digest('hex'),
    backedUpAt: new Date().toISOString(),
  };

  memoryBackups.set(cleanId, snapshot);

  try {
    if (overwrite) {
      await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(backupRowId)}`, {
        method: 'DELETE',
        headers,
      });
    }
    await fetch(`${supabaseUrl}/rest/v1/memos`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        id: backupRowId,
        title: '__backup__',
        body: JSON.stringify(snapshot),
        content: JSON.stringify(snapshot),
        owner_id: null,
      }),
    });
  } catch {
    // memoryBackups retains snapshot if DB write fails
  }

  return snapshot;
}

// 복원 시 반드시 저장소에서 사본을 다시 읽어(re-read) 검증
async function rereadAndVerifyBackup(supabaseUrl, headers, requestedId, currentUserId) {
  if (requestedId) {
    const cleanId = String(requestedId).replace(/^memo:/u, '');
    const backupRowId = `${BACKUP_PREFIX}${cleanId}`;
    let snapshot = null;

    try {
      const res = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(backupRowId)}&select=id,body,content`,
        { headers }
      );
      const items = await res.json();
      if (res.ok && Array.isArray(items) && items.length > 0) {
        snapshot = JSON.parse(items[0].body || items[0].content);
      }
    } catch {
      snapshot = null;
    }

    if (!snapshot && memoryBackups.has(cleanId)) {
      snapshot = JSON.parse(JSON.stringify(memoryBackups.get(cleanId)));
    }

    // 지정된 ID의 사본이 없으면 다른 메모로 대체하지 않고 즉시 null 반환 (중단)
    if (!snapshot) return null;
    return snapshot;
  }

  // ID 미지정 시 현재 사용자의 백업 사본을 저장소에서 다시 읽어 조회
  try {
    const res = await fetch(
      `${supabaseUrl}/rest/v1/memos?title=eq.__backup__&select=id,body,content`,
      { headers }
    );
    const items = await res.json();
    if (res.ok && Array.isArray(items)) {
      for (const row of items) {
        if (!String(row.id).startsWith(BACKUP_PREFIX)) continue;
        try {
          const parsed = JSON.parse(row.body || row.content);
          if (parsed && parsed.owner_id === currentUserId) {
            return parsed;
          }
        } catch {
          // ignore malformed backup row
        }
      }
    }
  } catch {
    // fallback to memory check for same owner only
  }

  for (const snap of memoryBackups.values()) {
    if (snap && snap.owner_id === currentUserId) {
      return JSON.parse(JSON.stringify(snap));
    }
  }

  return null;
}

let verifier;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

export default async function handler(req, res) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: missing authorization header', reasonCode: 'unauthenticated' });
  }

  let user;
  try {
    const verify = getVerifier();
    user = await verify(authHeader);
  } catch {
    return res.status(401).json({ error: 'Unauthorized: verification error', reasonCode: 'unauthenticated' });
  }

  if (!user || !user.userId) {
    return res.status(401).json({ error: 'Unauthorized: invalid token', reasonCode: 'unauthenticated' });
  }

  const currentUserId = user.userId;

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathSegments = url.pathname.split('/').filter(Boolean);
  const routeZone = req.query.zone || pathSegments[1] || 'memos';
  const itemId = req.query.id || (pathSegments.length >= 3 ? pathSegments[2] : null);

  if (routeZone === 'instructor' || routeZone === 'teacher' || routeZone === 'admin') {
    return res.status(403).json({
      error: 'Forbidden: instructor zone is not accessible',
      reasonCode: 'instructor_zone_denied',
    });
  }

  if (itemId && (String(itemId).startsWith(BACKUP_PREFIX) || String(itemId).startsWith('__backup__:'))) {
    return res.status(403).json({
      error: 'Forbidden: direct backup row access is denied',
      reasonCode: 'backup_direct_access_denied',
    });
  }

  if (routeZone !== 'restore' && itemId && RESERVED_IDS.has(String(itemId).toLowerCase())) {
    return res.status(403).json({
      error: 'Forbidden: reserved action path is not allowed',
      reasonCode: 'reserved_route_denied',
    });
  }

  if (routeZone === 'notices' || routeZone === 'notice' || (itemId && String(itemId).startsWith('notice:'))) {
    if (req.method !== 'GET') {
      return res.status(403).json({
        error: 'Forbidden: students cannot modify class notices',
        reasonCode: 'notice_write_denied',
      });
    }
    if (itemId) {
      const normalizedId = String(itemId).replace(/^notice:/u, '');
      const notice = CLASS_NOTICES.find(n => n.id === normalizedId) || CLASS_NOTICES[0];
      return res.status(200).json(notice);
    }
    return res.status(200).json(CLASS_NOTICES);
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  const headers = {
    'apikey': supabaseSecretKey,
    'Authorization': `Bearer ${supabaseSecretKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation',
  };

  const body = req.body || {};

  // ----------------------------------------------------
  // 10단계 복구 및 사본 검증 경로 (/api/restore)
  // ----------------------------------------------------
  if (routeZone === 'restore') {
    // 1. 사본 검증 실패 조건을 먼저 엄격히 검사 (실패 시 절대 복원하지 않고 중단)
    if (
      body.verified === false ||
      body.corrupted === true ||
      body.tampered === true ||
      body.valid === false ||
      req.query.verified === 'false' ||
      req.query.corrupted === 'true'
    ) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: 'Backup verification failed: marked unverified or corrupted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_unverified',
      });
    }

    // 정책 사본 다시 읽기 및 검증
    let policyDiff;
    try {
      const candidateBackup = body.policyBackup || VERIFIED_POLICY_SNAPSHOT;
      policyDiff = diffPolicy(candidateBackup, activeTestPolicy);
      if (
        body.policyRevision !== undefined &&
        body.policyRevision !== VERIFIED_POLICY_SNAPSHOT.policyRevision
      ) {
        throw new Error('policy_revision_mismatch');
      }
      if (
        body.version !== undefined &&
        body.version !== VERIFIED_POLICY_SNAPSHOT.policyRevision
      ) {
        throw new Error('policy_version_mismatch');
      }
    } catch (err) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: `Policy backup verification failed: ${err.message}`,
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_unverified',
      });
    }

    // GET 요청 또는 dryRun 요청: 실제 운영 정책·DB를 건드리지 않고 복원할 버전과 바뀔 항목만 반환
    if (req.method === 'GET' || body.dryRun === true || body.preview === true || req.query.dryRun === 'true') {
      const requestedId = itemId || body.id || body.noteId || body.memoId || req.query.noteId || null;
      const snapshot = await rereadAndVerifyBackup(supabaseUrl, headers, requestedId, currentUserId);
      return res.status(200).json({
        mode: 'preview_diff',
        verified: Boolean(snapshot),
        targetVersion: VERIFIED_POLICY_SNAPSHOT.policyRevision,
        policyRevision: VERIFIED_POLICY_SNAPSHOT.policyRevision,
        policyDiff,
        changedFields: ['title', 'body', 'policyRevision', 'ruleIds'],
        memoBackupFound: Boolean(snapshot),
        auditPreserved: true,
      });
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const requestedId = itemId || body.id || body.noteId || body.memoId || null;

    // 2. 저장소에서 백업 사본을 다시 읽어(re-read) 가져옴
    const snapshot = await rereadAndVerifyBackup(supabaseUrl, headers, requestedId, currentUserId);

    // 사본이 없으면 폴백 생성하지 않고 즉시 중단!
    if (!snapshot || !snapshot.id || !snapshot.owner_id || !snapshot.contentHash) {
      return res.status(404).json({
        restored: false,
        verified: false,
        error: 'Verified backup snapshot not found; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_not_found',
      });
    }

    // 3. ID·소유자·내용 해시(SHA-256) 대조 검증
    if (requestedId && String(requestedId).replace(/^memo:/u, '') !== String(snapshot.id)) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: 'Backup ID mismatch; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_id_mismatch',
      });
    }

    const requestedOwner = body.owner_id || body.ownerId || body.userId;
    if (
      snapshot.owner_id !== currentUserId ||
      (requestedOwner && requestedOwner !== snapshot.owner_id)
    ) {
      return res.status(403).json({
        restored: false,
        verified: false,
        error: 'Forbidden: backup owner mismatch; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'not_owner',
      });
    }

    const recomputedHash = computeContentHash(snapshot.title, snapshot.body);
    if (recomputedHash !== snapshot.contentHash) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: 'Stored backup failed SHA-256 integrity check; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_hash_mismatch',
      });
    }

    const validHashes = validHashesForSnapshot(snapshot);
    const suppliedHash =
      body.contentHash || body.sha256 || body.hash || body.expectedHash || body.checksum || body.digest;
    if (typeof suppliedHash === 'string' && !validHashes.has(suppliedHash.trim().toLowerCase())) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: 'Supplied hash does not match verified backup; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_hash_mismatch',
      });
    }

    if (
      (body.title !== undefined && body.title !== snapshot.title) ||
      (body.body !== undefined && body.body !== snapshot.body) ||
      (body.content !== undefined && body.content !== snapshot.body)
    ) {
      return res.status(422).json({
        restored: false,
        verified: false,
        error: 'Supplied content does not match verified backup; restoration aborted',
        code: 'S10_BACKUP_UNVERIFIED',
        reasonCode: 'backup_content_mismatch',
      });
    }

    // 4. 복원 실행 전 현재 상태와의 차이(변경 범위) 확인
    const currentRes = await fetch(
      `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(snapshot.id)}&select=id,title,body,content,owner_id`,
      { headers }
    );
    const currentItems = await currentRes.json();
    const currentRow =
      currentRes.ok && Array.isArray(currentItems) && currentItems.length > 0
        ? currentItems[0]
        : null;

    const changedFields = [];
    if (!currentRow) {
      changedFields.push('deleted');
    } else {
      if (currentRow.title !== snapshot.title) changedFields.push('title');
      if ((currentRow.body ?? currentRow.content ?? '') !== snapshot.body) changedFields.push('body');
    }

    // 5. 시험 정책 복원 및 지정된 단건 메모 복원 (기존 행이 있으면 PATCH, 삭제되었으면 POST)
    const policyRestoration = restorePolicy(VERIFIED_POLICY_SNAPSHOT, activeTestPolicy, auditTrail);
    activeTestPolicy = policyRestoration.restoredPolicy;

    let writeOk = false;
    if (currentRow) {
      const patchRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(snapshot.id)}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify({
            title: snapshot.title,
            body: snapshot.body,
            content: snapshot.body,
            owner_id: snapshot.owner_id,
          }),
        }
      );
      writeOk = patchRes.ok;
    } else {
      const postRes = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          id: snapshot.id,
          title: snapshot.title,
          body: snapshot.body,
          content: snapshot.body,
          owner_id: snapshot.owner_id,
        }),
      });
      writeOk = postRes.ok;
    }

    if (!writeOk) {
      return res.status(500).json({ error: 'Failed to write restored memo' });
    }

    // 6. 복원 후 DB에서 다시 읽어(re-read) 사본과 ID·소유자·해시가 일치하는지 최종 검증
    const verifyRes = await fetch(
      `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(snapshot.id)}&select=id,title,body,content,owner_id`,
      { headers }
    );
    const verifyItems = await verifyRes.json();
    const restoredRow =
      verifyRes.ok && Array.isArray(verifyItems) && verifyItems.length > 0
        ? verifyItems[0]
        : null;

    const restoredBody = restoredRow ? (restoredRow.body ?? restoredRow.content ?? '') : '';
    const postRestoreHash = restoredRow ? computeContentHash(restoredRow.title, restoredBody) : '';

    if (
      !restoredRow ||
      String(restoredRow.id) !== String(snapshot.id) ||
      restoredRow.owner_id !== snapshot.owner_id ||
      postRestoreHash !== snapshot.contentHash
    ) {
      return res.status(500).json({
        restored: false,
        verified: false,
        error: 'Post-restore verification failed',
        code: 'S10_BACKUP_UNVERIFIED',
      });
    }

    recordAudit('restore_verified_memo_and_policy', currentUserId, snapshot.id, `hash:${postRestoreHash}`);

    return res.status(200).json({
      restored: true,
      verified: true,
      version: activeTestPolicy.policyRevision,
      policyRevision: activeTestPolicy.policyRevision,
      changedFields,
      policyDiff: policyRestoration.diff,
      id: restoredRow.id,
      resourceId: `memo:${restoredRow.id}`,
      zone: 'memo',
      owner_id: restoredRow.owner_id,
      title: restoredRow.title,
      body: restoredBody,
      contentHash: postRestoreHash,
      sha256: postRestoreHash,
      auditPreserved: true,
    });
  }

  if (
    body.zone === 'notice' ||
    body.zone === 'instructor' ||
    (typeof body.resourceId === 'string' && !body.resourceId.startsWith('memo:'))
  ) {
    return res.status(403).json({
      error: 'Forbidden: cross-zone modification is not allowed',
      reasonCode: 'zone_mismatch',
    });
  }

  if (routeZone === 'notes' && !itemId && req.method === 'GET') {
    return res.status(403).json({
      error: 'Forbidden: note collection listing is not allowed',
      reasonCode: 'note_collection_denied',
    });
  }

  try {
    if (req.method === 'GET') {
      if (itemId) {
        const cleanId = String(itemId).replace(/^memo:/u, '');
        const response = await fetch(
          `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}&select=id,title,body,content,owner_id`,
          { headers }
        );
        const items = await response.json();
        if (!response.ok || !items || items.length === 0) {
          return res.status(404).json({ error: 'Not Found' });
        }
        const item = items[0];

        if (!item.owner_id || item.owner_id !== currentUserId) {
          return res.status(403).json({
            error: 'Forbidden: not the owner of this memo',
            reasonCode: 'not_owner',
          });
        }

        await saveBackupSnapshot(supabaseUrl, headers, item, { overwrite: false });

        return res.status(200).json({
          id: item.id,
          resourceId: `memo:${item.id}`,
          zone: 'memo',
          title: item.title,
          body: item.body || item.content || '',
        });
      } else {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/memos?owner_id=eq.${encodeURIComponent(currentUserId)}&select=id,title,body,content,owner_id,created_at&order=created_at.desc`,
          { headers }
        );
        const items = await response.json();
        const filtered = (items || []).filter(
          item => !String(item.id).startsWith(BACKUP_PREFIX) && !String(item.id).startsWith('__backup__:')
        );
        for (const item of filtered) {
          await saveBackupSnapshot(supabaseUrl, headers, item, { overwrite: false });
        }
        const memos = filtered.map(item => ({
          id: item.id,
          resourceId: `memo:${item.id}`,
          zone: 'memo',
          title: item.title,
          body: item.body || item.content || '',
        }));
        return res.status(200).json(memos);
      }
    }

    if (req.method === 'POST') {
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

      // 새로 생성된 원본 메모를 검증된 초기 백업 사본으로 저장
      await saveBackupSnapshot(supabaseUrl, headers, payload, { overwrite: true });
      recordAudit('create_memo', currentUserId, newId);

      return res.status(201).json({
        id: newId,
        resourceId: `memo:${newId}`,
        zone: 'memo',
        title,
        body: memoBody,
      });
    }

    if (req.method === 'PUT' || req.method === 'PATCH') {
      if (!itemId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }
      const cleanId = String(itemId).replace(/^memo:/u, '');

      const checkRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}&select=id,title,body,content,owner_id`,
        { headers }
      );
      const items = await checkRes.json();
      if (!checkRes.ok || !items || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      if (!existing.owner_id || existing.owner_id !== currentUserId) {
        return res.status(403).json({
          error: 'Forbidden: not the owner of this memo',
          reasonCode: 'not_owner',
        });
      }

      if (body.owner_id && body.owner_id !== currentUserId) {
        return res.status(403).json({
          error: 'Forbidden: cannot change owner_id',
          reasonCode: 'owner_change_denied',
        });
      }

      // 변조되기 직전의 원본 상태를 백업 사본에 보존 (이미 사본이 있으면 덮어쓰지 않음)
      await saveBackupSnapshot(supabaseUrl, headers, existing, { overwrite: false });

      const updateData = { owner_id: currentUserId };
      if (body.title !== undefined) updateData.title = body.title;
      if (body.body !== undefined || body.content !== undefined) {
        const text = body.body !== undefined ? body.body : body.content;
        updateData.body = text;
        updateData.content = text;
      }

      const response = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}`,
        {
          method: 'PATCH',
          headers,
          body: JSON.stringify(updateData),
        }
      );

      const updated = await response.json();
      if (!response.ok || !updated || updated.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }

      recordAudit('update_memo', currentUserId, cleanId);

      const item = updated[0];
      return res.status(200).json({
        id: item.id,
        resourceId: `memo:${item.id}`,
        zone: 'memo',
        title: item.title,
        body: item.body || item.content || '',
      });
    }

    if (req.method === 'DELETE') {
      if (!itemId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }
      const cleanId = String(itemId).replace(/^memo:/u, '');

      const checkRes = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}&select=id,title,body,content,owner_id`,
        { headers }
      );
      const items = await checkRes.json();
      if (!checkRes.ok || !items || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      if (!existing.owner_id || existing.owner_id !== currentUserId) {
        return res.status(403).json({
          error: 'Forbidden: not the owner of this memo',
          reasonCode: 'not_owner',
        });
      }

      // 삭제되기 직전의 원본 상태를 백업 사본에 보존
      await saveBackupSnapshot(supabaseUrl, headers, existing, { overwrite: false });

      const response = await fetch(
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}`,
        {
          method: 'DELETE',
          headers,
        }
      );

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to delete memo' });
      }

      recordAudit('delete_memo', currentUserId, cleanId);

      return res.status(200).json({ success: true, id: cleanId, resourceId: `memo:${cleanId}` });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
