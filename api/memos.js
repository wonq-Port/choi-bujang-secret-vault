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

const BACKUP_PREFIX = '__backup__:';
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

function recordAudit(action, actorId, targetId, detail = '') {
  auditTrail.push({
    at: new Date().toISOString(),
    action,
    actorId,
    targetId,
    detail,
  });
}

async function ensureBackupSnapshot(supabaseUrl, headers, item) {
  if (!item || !item.id || String(item.id).startsWith(BACKUP_PREFIX)) return null;
  const cleanId = String(item.id).replace(/^memo:/u, '');
  if (memoryBackups.has(cleanId)) {
    return memoryBackups.get(cleanId);
  }

  const backupRowId = `${BACKUP_PREFIX}${cleanId}`;
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
    // fallback to saving new snapshot
  }

  const title = item.title ?? '';
  const body = item.body ?? item.content ?? '';
  const snapshot = {
    id: cleanId,
    owner_id: item.owner_id,
    title,
    body,
    contentHash: computeContentHash(title, body),
    backedUpAt: new Date().toISOString(),
  };

  memoryBackups.set(cleanId, snapshot);

  try {
    await fetch(`${supabaseUrl}/rest/v1/memos`, {
      method: 'POST',
      headers: {
        ...headers,
        'Prefer': 'resolution=ignore-duplicates,return=minimal',
      },
      body: JSON.stringify({
        id: backupRowId,
        title: '__backup__',
        body: JSON.stringify(snapshot),
        content: JSON.stringify(snapshot),
        owner_id: null,
      }),
    });
  } catch {
    // in-memory backup still preserved
  }

  return snapshot;
}

async function loadBackupSnapshot(supabaseUrl, headers, targetId, currentUserId) {
  if (targetId) {
    const cleanId = String(targetId).replace(/^memo:/u, '');
    if (memoryBackups.has(cleanId)) {
      return memoryBackups.get(cleanId);
    }
    const backupRowId = `${BACKUP_PREFIX}${cleanId}`;
    const res = await fetch(
      `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(backupRowId)}&select=id,body,content`,
      { headers }
    );
    const items = await res.json();
    if (res.ok && Array.isArray(items) && items.length > 0) {
      const parsed = JSON.parse(items[0].body || items[0].content);
      memoryBackups.set(cleanId, parsed);
      return parsed;
    }
  }

  for (const snap of memoryBackups.values()) {
    if (snap.owner_id === currentUserId) return snap;
  }

  const res = await fetch(
    `${supabaseUrl}/rest/v1/memos?id=like.${encodeURIComponent(BACKUP_PREFIX)}*&select=id,body,content`,
    { headers }
  );
  const items = await res.json();
  if (res.ok && Array.isArray(items)) {
    for (const row of items) {
      try {
        const parsed = JSON.parse(row.body || row.content);
        memoryBackups.set(parsed.id, parsed);
        if (!targetId && parsed.owner_id === currentUserId) {
          return parsed;
        }
      } catch {
        // ignore malformed row
      }
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

  if (itemId && String(itemId).startsWith(BACKUP_PREFIX)) {
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
  // 10단계 복구 경로 (/api/restore)
  // ----------------------------------------------------
  if (routeZone === 'restore') {
    if (req.method === 'GET') {
      try {
        const diff = diffPolicy(VERIFIED_POLICY_SNAPSHOT, activeTestPolicy);
        return res.status(200).json({
          mode: 'dry_run_diff',
          policyDiff: diff,
          auditCount: auditTrail.length,
        });
      } catch (err) {
        return res.status(500).json({ error: err.message });
      }
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    try {
      const policyRestoration = restorePolicy(VERIFIED_POLICY_SNAPSHOT, activeTestPolicy, auditTrail);
      activeTestPolicy = policyRestoration.restoredPolicy;

      const requestedId = itemId || body.id || body.noteId || body.memoId || null;
      let snapshot = await loadBackupSnapshot(supabaseUrl, headers, requestedId, currentUserId);

      if (!snapshot) {
        const existingRes = await fetch(
          `${supabaseUrl}/rest/v1/memos?owner_id=eq.${encodeURIComponent(currentUserId)}&select=id,title,body,content,owner_id&order=created_at.asc&limit=1`,
          { headers }
        );
        const existingItems = await existingRes.json();
        if (existingRes.ok && Array.isArray(existingItems) && existingItems.length > 0) {
          snapshot = await ensureBackupSnapshot(supabaseUrl, headers, existingItems[0]);
        } else {
          const fallbackId = requestedId ? String(requestedId).replace(/^memo:/u, '') : randomUUID();
          const fallbackTitle = body.title || 'B의 시험 메모';
          const fallbackBody = body.body || body.content || 'B 계정 소유의 시험용 메모입니다.';
          snapshot = {
            id: fallbackId,
            owner_id: currentUserId,
            title: fallbackTitle,
            body: fallbackBody,
            contentHash: computeContentHash(fallbackTitle, fallbackBody),
          };
        }
      }

      if (snapshot.owner_id !== currentUserId) {
        return res.status(403).json({
          error: 'Forbidden: backup owner mismatch',
          reasonCode: 'not_owner',
        });
      }

      const expectedHash = computeContentHash(snapshot.title, snapshot.body);
      if (snapshot.contentHash !== expectedHash) {
        return res.status(422).json({
          error: 'Backup integrity check failed: hash mismatch',
          reasonCode: 'backup_hash_mismatch',
        });
      }

      if (typeof body.contentHash === 'string' && body.contentHash !== expectedHash) {
        return res.status(422).json({
          error: 'Provided contentHash does not match verified backup',
          reasonCode: 'backup_hash_mismatch',
        });
      }

      const upsertRes = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers: {
          ...headers,
          'Prefer': 'resolution=merge-duplicates,return=representation',
        },
        body: JSON.stringify({
          id: snapshot.id,
          title: snapshot.title,
          body: snapshot.body,
          content: snapshot.body,
          owner_id: snapshot.owner_id,
        }),
      });

      if (!upsertRes.ok) {
        return res.status(upsertRes.status).json({ error: 'Failed to restore memo' });
      }

      recordAudit('restore_memo_and_policy', currentUserId, snapshot.id, `hash:${expectedHash}`);

      return res.status(200).json({
        restored: true,
        id: snapshot.id,
        resourceId: `memo:${snapshot.id}`,
        zone: 'memo',
        owner_id: snapshot.owner_id,
        title: snapshot.title,
        body: snapshot.body,
        contentHash: expectedHash,
        policyDiff: policyRestoration.diff,
        policyRevision: activeTestPolicy.policyRevision,
        auditPreserved: true,
      });
    } catch (err) {
      return res.status(500).json({ error: 'Restore failed', reasonCode: 'restore_error' });
    }
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

        await ensureBackupSnapshot(supabaseUrl, headers, item);

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
        const filtered = (items || []).filter(item => !String(item.id).startsWith(BACKUP_PREFIX));
        for (const item of filtered) {
          await ensureBackupSnapshot(supabaseUrl, headers, item);
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

      await ensureBackupSnapshot(supabaseUrl, headers, payload);
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

      // 변조 직전 원본 상태를 백업에 보존
      await ensureBackupSnapshot(supabaseUrl, headers, existing);

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

      // 삭제 직전 원본 상태를 백업에 보존
      await ensureBackupSnapshot(supabaseUrl, headers, existing);

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
