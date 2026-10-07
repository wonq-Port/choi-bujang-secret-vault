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
  // 1. 요청 토큰 검증 (미인증 시 401 JSON 반환)
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
    // GET: 단건 조회 또는 목록 조회
    // ----------------------------------------------------
    if (req.method === 'GET') {
      if (memoId) {
        // 단건 GET: /api/memos/:id -> { id, title, body }
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?id=eq.${memoId}&select=id,title,body,content`, { headers });
        const items = await response.json();
        if (!response.ok || !items || items.length === 0) {
          return res.status(404).json({ error: 'Not Found' });
        }
        const item = items[0];
        return res.status(200).json({
          id: item.id,
          title: item.title,
          body: item.body || item.content || ''
        });
      } else {
        // 목록 GET: /api/memos -> 로그인 사용자의 메모 배열 반환
        // (본인 owner_id 또는 초기 샘플 메모 조회)
        const response = await fetch(`${supabaseUrl}/rest/v1/memos?or=(owner_id.eq.${user.userId},owner_id.is.null)&select=id,title,body,content,created_at&order=created_at.desc`, { headers });
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
    // POST: 메모 추가 -> { id, title, body }
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
        owner_id: user.userId // 검증된 사용자 ID를 owner_id로 저장
      };

      const response = await fetch(`${supabaseUrl}/rest/v1/memos`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        return res.status(response.status).json({ error: 'Failed to create memo' });
      }

      const created = await response.json();
      return res.status(201).json({
        id: newId,
        title: title,
        body: memoBody
      });
    }

    // ----------------------------------------------------
    // PUT: 메모 수정 -> /api/memos/:id
    // (4단계 전까지는 타인 메모 소유권 검사 생략)
    // ----------------------------------------------------
    if (req.method === 'PUT') {
      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
      }

      const body = req.body || {};
      const title = body.title;
      const memoBody = body.body || body.content;

      const updateData = {};
      if (title !== undefined) updateData.title = title;
      if (memoBody !== undefined) {
        updateData.body = memoBody;
        updateData.content = memoBody;
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
    // DELETE: 메모 삭제 -> /api/memos/:id
    // ----------------------------------------------------
    if (req.method === 'DELETE') {
      if (!memoId) {
        return res.status(400).json({ error: 'Missing memo ID' });
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
