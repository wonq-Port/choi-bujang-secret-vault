// api/memos.js
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';

const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

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
  // 1. 요청 토큰 검증
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: missing authorization header' });
  }

  let user;
  try {
    const verify = getVerifier();
    user = await verify(authHeader);
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: verification error' });
  }

  if (!user || !user.userId) {
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }

  const currentUserId = user.userId;

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  // URL에서 id 파라미터 추출 (/api/memos/:id)
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathSegments = url.pathname.split('/').filter(Boolean);
  const memoId = req.query.id || (pathSegments[1] === 'memos' && pathSegments[2] ? pathSegments[2] : null);

  const headers = {
    'apikey': supabaseSecretKey,
    'Authorization': `Bearer ${supabaseSecretKey}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };

  try {
    // ----------------------------------------------------
    // GET: 단건 조회 또는 목록 조회 (본인 메모만)
    // ----------------------------------------------------
    if (req.method === 'GET') {
      if (memoId) {
        // 단건 GET: DB의 owner_id와 로그인 사용자 비교
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}&select=id,title,body,content,owner_id`, { headers });
        const items = await response.json();
        if (!response.ok || !items || items.length === 0) {
          return res.status(404).json({ error: 'Not Found' });
        }
        const item = items[0];

        // 타인의 메모인 경우 접근 거부 (IDOR 차단)
        if (item.owner_id && item.owner_id !== currentUserId) {
          return res.status(403).json({ error: 'Forbidden: not your memo' });
        }

        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.body || item.content || ''
        });
      } else {
        // 목록 GET: 본인 소유의 메모 배열만 반환
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?owner_id=eq.${currentUserId}&select=id,title,body,content,created_at&order=created_at.desc`, { headers });
        const items = await response.json();
        const memos = (items || []).map(item => ({
          id: item.id,
          title: item.title,
          body: item.body || item.content || ''
        }));
        return res.status(200).json(memos);
      }
    }

    // ----------------------------------------------------
    // POST: 메모 추가
    // 요청 본문의 owner_id는 무시하고 검증된 currentUserId로 강제 저장
    // ----------------------------------------------------
    if (req.method === 'POST') {
      const body = req.body || {};
      const newId = body.id || randomUUID();
      const title = body.title || '새 메모';
      const memoBody = body.body || body.content || '';

      const payload = {
        id: newId,
        title: title,
        body: memoBody,
        content: memoBody,
        owner_id: currentUserId // 검증된 사용자 ID로 저장
      };

      const response = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to create memo' });
      }

      return res.status(201).json({
        id: newId,
        title: title,
        body: memoBody
      });
    }

    // ----------------------------------------------------
    // PUT: 메모 수정 (/api/memos/:id)
    // 기존 행의 소유자 확인 및 소유권 변경 시도 차단
    // ----------------------------------------------------
    if (req.method === 'PUT') {
      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }

      // 1. 기존 메모의 소유자 확인
      const checkRes = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}&select=id,owner_id`, { headers });
      const items = await checkRes.json();
      if (!checkRes.ok || !items || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      // 기존 소유자가 본인이 아니면 수정 거부
      if (existing.owner_id && existing.owner_id !== currentUserId) {
        return res.status(403).json({ error: 'Forbidden: not your memo' });
      }

      const body = req.body || {};

      // 본문으로 owner_id를 타인으로 변경하려는 시도 차단
      if (body.owner_id && body.owner_id !== currentUserId) {
        return res.status(403).json({ error: 'Forbidden: cannot change owner_id' });
      }

      const updateData = {
        owner_id: currentUserId
      };
      if (body.title !== undefined) updateData.title = body.title;
      if (body.body !== undefined || body.content !== undefined) {
        const text = body.body !== undefined ? body.body : body.content;
        updateData.body = text;
        updateData.content = text;
      }

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify(updateData)
      });

      const updated = await response.json();
      if (!response.ok || !updated || updated.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }

      const item = updated[0];
      return res.status(200).json({
        id: item.id,
        title: item.title,
        body: item.body || item.content || ''
      });
    }

    // ----------------------------------------------------
    // DELETE: 메모 삭제 (/api/memos/:id)
    // 기존 행 소유자가 본인인지 확인 후 삭제
    // ----------------------------------------------------
    if (req.method === 'DELETE') {
      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }

      // 기존 메모의 소유자 확인
      const checkRes = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}&select=id,owner_id`, { headers });
      const items = await checkRes.json();
      if (!checkRes.ok || !items || items.length === 0) {
        return res.status(404).json({ error: 'Not Found' });
      }
      const existing = items[0];

      // 기존 소유자가 본인이 아니면 삭제 거부
      if (existing.owner_id && existing.owner_id !== currentUserId) {
        return res.status(403).json({ error: 'Forbidden: not your memo' });
      }

      const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}`, {
        method: 'DELETE',
        headers
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to delete memo' });
      }

      return res.status(200).json({ success: true, id: memoId });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    console.error('API Error:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
