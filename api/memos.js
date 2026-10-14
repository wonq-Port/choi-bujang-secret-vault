// api/memos.js
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';

const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

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

  // 1. 강사 전용 구역 접근 전면 거부
  if (routeZone === 'instructor' || routeZone === 'teacher' || routeZone === 'admin') {
    return res.status(403).json({
      error: 'Forbidden: instructor zone is not accessible',
      reasonCode: 'instructor_zone_denied',
    });
  }

  // 2. 예약어 기능 경로(:id 위치의 export 등) 거부
  if (itemId && RESERVED_IDS.has(String(itemId).toLowerCase())) {
    return res.status(403).json({
      error: 'Forbidden: reserved action path is not allowed',
      reasonCode: 'reserved_route_denied',
    });
  }

  // 3. 강사 공지(반 공지) 구역 처리: resourceId를 notice:<id>로 구분하고 쓰기는 전면 거부
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

  // 4. 메모 구역에서 공지/강사 자원으로 위장하거나 role 변조를 시도하는 요청 차단
  const body = req.body || {};
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

  // /api/notes 경로에서는 ID 없는 전체 목록 조회를 거부
  if (routeZone === 'notes' && !itemId && req.method === 'GET') {
    return res.status(403).json({
      error: 'Forbidden: note collection listing is not allowed',
      reasonCode: 'note_collection_denied',
    });
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

        return res.status(200).json({
          id: item.id,
          resourceId: `memo:${item.id}`,
          zone: 'memo',
          title: item.title,
          body: item.body || item.content || '',
        });
      } else {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/memos?owner_id=eq.${encodeURIComponent(currentUserId)}&select=id,title,body,content,created_at&order=created_at.desc`,
          { headers }
        );
        const items = await response.json();
        const memos = (items || []).map(item => ({
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
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}&select=id,owner_id`,
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
        `${supabaseUrl}/rest/v1/memos?id=eq.${encodeURIComponent(cleanId)}&select=id,owner_id`,
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

      return res.status(200).json({ success: true, id: cleanId, resourceId: `memo:${cleanId}` });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
